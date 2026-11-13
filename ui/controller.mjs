import {
  assertSelfTransferSigningBoundary,
  createSelfTransferReview,
  TESTNET_SELF_TRANSFER_ACCOUNT,
  TESTNET_SELF_TRANSFER_AMOUNT_NEAR,
  TESTNET_SELF_TRANSFER_AMOUNT_YOCTO,
} from "./self_transfer.mjs";

export const TESTNET_RECIPIENT = "defiaudit0x.testnet";
export const MAX_AMOUNT_YOCTO = 100000000000000000000000n;
const PREFLIGHT_TIMEOUT_MS = 15_000;
const YOCTO_PER_NEAR = 1000000000000000000000000n;
const NEAR_AMOUNT_PATTERN = /^(?:0|[1-9][0-9]*)(?:\.([0-9]{1,24}))?$/;

export function amountToYocto(amount) {
  if (typeof amount !== "string") throw new TypeError("Enter an amount in NEAR.");
  const value = amount.trim();
  const match = /^(0|[1-9][0-9]*)(?:\.([0-9]{1,24}))?$/.exec(value);
  if (!match || !NEAR_AMOUNT_PATTERN.test(value)) {
    throw new TypeError("Use a plain decimal amount with at most 24 decimal places.");
  }
  const fraction = (match[2] || "").padEnd(24, "0");
  const yocto = BigInt(match[1]) * YOCTO_PER_NEAR + BigInt(fraction || "0");
  if (yocto <= 0n) throw new RangeError("Amount must be greater than zero.");
  if (yocto > MAX_AMOUNT_YOCTO) throw new RangeError("Amount exceeds the 0.1 NEAR cap.");
  return yocto.toString();
}

function setText(element, text) {
  element.textContent = text;
}

function clearAccounts(select) {
  while (select.firstChild) select.removeChild(select.firstChild);
}

function optionalCount(input, label, context) {
  const raw = input.value.trim();
  if (raw === "") return;
  if (!/^(?:0|[1-9][0-9]*)$/.test(raw)) throw new TypeError(`${label} must be a whole number.`);
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${label} is outside the supported range.`);
  context[label] = value;
}

function readRiskContext(previousInput, ageInput) {
  const context = {};
  optionalCount(previousInput, "previous_interactions", context);
  optionalCount(ageInput, "account_age_days", context);
  return context;
}

function normalizeAccounts(accounts) {
  if (!Array.isArray(accounts)) return [];
  const valid = accounts.filter((account) => account
    && typeof account.accountId === "string"
    && account.accountId.length > 0);
  return [...new Map(valid.map((account) => [account.accountId, account])).values()];
}

export function mountUI({
  createConnector,
  document,
  fetchImpl = globalThis.fetch,
  connectionEnabled = false,
  clock = () => Date.now(),
  monotonicClock = () => globalThis.performance?.now?.(),
  setTimeoutImpl = globalThis.setTimeout,
  clearTimeoutImpl = globalThis.clearTimeout,
  windowObject = globalThis.window,
  cryptoObject = globalThis.crypto,
}) {
  if (typeof createConnector !== "function") {
    throw new TypeError("A lazy Meteor SDK connector factory is required.");
  }
  if (!document || typeof document.querySelector !== "function") {
    throw new TypeError("A document is required.");
  }
  if (typeof monotonicClock !== "function") throw new TypeError("A monotonic review clock is required.");
  if (typeof setTimeoutImpl !== "function" || typeof clearTimeoutImpl !== "function") {
    throw new TypeError("Review expiry and preflight timeout timers are required.");
  }
  const connectButton = document.querySelector("#connect-wallet");
  const accountSelect = document.querySelector("#account-select");
  const walletStatus = document.querySelector("#wallet-status");
  const form = document.querySelector("#preflight-form");
  const amountInput = document.querySelector("#amount");
  const previousInput = document.querySelector("#previous-interactions");
  const ageInput = document.querySelector("#account-age-days");
  const preflightButton = document.querySelector("#run-preflight");
  const resultCard = document.querySelector("#result-card");
  const resultStatus = document.querySelector("#result-status");
  const resultDetails = document.querySelector("#result-details");
  const prepareSelfTransferButton = document.querySelector("#prepare-self-transfer");
  const selfTransferStatus = document.querySelector("#self-transfer-status");
  const transferReview = document.querySelector("#transfer-review");
  const reviewStatus = document.querySelector("#review-status");
  const reviewDetails = document.querySelector("#review-details");
  const signSelfTransferButton = document.querySelector("#sign-self-transfer");
  const cancelSelfTransferButton = document.querySelector("#cancel-self-transfer");

  if ([connectButton, accountSelect, walletStatus, form, amountInput, previousInput,
    ageInput, preflightButton, resultCard, resultStatus, resultDetails,
    prepareSelfTransferButton, selfTransferStatus, transferReview, reviewStatus,
    reviewDetails, signSelfTransferButton, cancelSelfTransferButton].some((item) => !item)) {
    throw new TypeError("The local UI page is missing a required control.");
  }

  let connector = null;
  let wallet = null;
  let connected = false;
  let busy = false;
  let review = null;
  let reviewedUiSnapshot = null;
  let uiInputRevision = 0;
  let lifecycleGeneration = 0;
  let lifecycleVisible = document.visibilityState !== "hidden" && document.hidden !== true;
  let lifecycleFocused = true;
  let lifecyclePageActive = true;
  let reviewWallClockState = null;
  let reviewExpiryTimer = null;
  let walletRequestPending = false;
  let walletOutcomeRequiresVerification = false;
  const attemptedRequestIds = new Set();
  const consumedRequestIds = new Set();
  const canConnect = connectionEnabled === true;
  const documentHasFocus = () => {
    if (typeof document.hasFocus !== "function") return true;
    try {
      return document.hasFocus() === true;
    } catch {
      return false;
    }
  };
  const isLifecycleActive = () => lifecycleVisible && lifecycleFocused
    && lifecyclePageActive
    && document.visibilityState !== "hidden" && document.hidden !== true
    && documentHasFocus();

  const updateButtons = () => {
    connectButton.disabled = !canConnect || busy || connected;
    preflightButton.disabled = busy || !connected;
    prepareSelfTransferButton.disabled = busy || !connected || !isLifecycleActive()
      || walletOutcomeRequiresVerification;
    signSelfTransferButton.disabled = busy || !review || attemptedRequestIds.has(review.requestId);
    cancelSelfTransferButton.disabled = busy || !review || attemptedRequestIds.has(review.requestId);
  };
  const setBusy = (value) => {
    busy = value;
    updateButtons();
  };
  const fetchPreflight = async (url, options) => {
    const controller = new globalThis.AbortController();
    let timeoutId;
    const timeout = new Promise((_, reject) => {
      timeoutId = setTimeoutImpl(() => {
        controller.abort();
        reject(new Error("Local read-only preflight timed out. No transaction-signing or submission call was made."));
      }, PREFLIGHT_TIMEOUT_MS);
    });
    const request = Promise.resolve().then(async () => {
      const response = await fetchImpl(url, { ...options, signal: controller.signal });
      const result = await response.json();
      return { response, result };
    });
    try {
      return await Promise.race([request, timeout]);
    } finally {
      if (timeoutId !== undefined) clearTimeoutImpl(timeoutId);
    }
  };
  const clearReviewExpiryTimer = () => {
    if (reviewExpiryTimer !== null) {
      clearTimeoutImpl(reviewExpiryTimer);
      reviewExpiryTimer = null;
    }
  };
  const discardReview = (message) => {
    if (review && (walletRequestPending || walletOutcomeRequiresVerification)) {
      const outcomeMessage = walletRequestPending
        ? "A wallet request may still be pending. This page cannot cancel a wallet prompt after it opens; verify wallet/Testnet before any retry."
        : "A wallet request was handed off. This page cannot cancel it; verify the outcome in wallet/Testnet before any further action.";
      setText(reviewStatus, outcomeMessage);
      setText(selfTransferStatus, outcomeMessage);
      updateButtons();
      return;
    }
    clearReviewExpiryTimer();
    if (review) consumedRequestIds.add(review.requestId);
    review = null;
    reviewedUiSnapshot = null;
    reviewWallClockState = null;
    transferReview.hidden = true;
    signSelfTransferButton.disabled = true;
    cancelSelfTransferButton.disabled = true;
    if (message) setText(reviewStatus, message);
  };
  const scheduleReviewExpiry = (pendingReview) => {
    if (review !== pendingReview) return;
    clearReviewExpiryTimer();
    const wallNow = clock();
    const monotonicNow = monotonicClock();
    if (!reviewWallClockState || !Number.isSafeInteger(wallNow)
      || wallNow < reviewWallClockState.lastObserved || wallNow < pendingReview.createdAt
      || wallNow >= pendingReview.expiresAt || !Number.isFinite(monotonicNow)
      || monotonicNow < pendingReview.monotonicCreatedAt
      || monotonicNow >= pendingReview.monotonicExpiresAt) {
      const message = "Review expired or its clock became invalid; no wallet prompt was opened. Prepare a fresh review.";
      discardReview(message);
      setText(selfTransferStatus, message);
      updateButtons();
      return;
    }
    reviewWallClockState.lastObserved = wallNow;
    const remaining = Math.min(
      pendingReview.expiresAt - wallNow,
      pendingReview.monotonicExpiresAt - monotonicNow,
    );
    reviewExpiryTimer = setTimeoutImpl(() => {
      reviewExpiryTimer = null;
      scheduleReviewExpiry(pendingReview);
    }, Math.max(1, Math.ceil(remaining)));
  };
  const invalidateForLifecycle = (message) => {
    lifecycleGeneration += 1;
    if (walletRequestPending || walletOutcomeRequiresVerification) {
      const outcomeMessage = walletRequestPending
        ? "A wallet request may still be pending. This page cannot cancel a wallet prompt after it opens; verify wallet/Testnet before any retry."
        : "A wallet request was handed off. This page cannot cancel it; verify the outcome in wallet/Testnet before any further action.";
      setText(reviewStatus, outcomeMessage);
      setText(selfTransferStatus, outcomeMessage);
      updateButtons();
      return;
    }
    discardReview(message);
    setText(selfTransferStatus, message);
    updateButtons();
  };
  const listen = (target, eventName, listener) => {
    if (typeof target?.addEventListener === "function") target.addEventListener(eventName, listener);
  };
  const refreshVisibleState = () => {
    lifecycleVisible = document.visibilityState !== "hidden" && document.hidden !== true;
  };
  listen(document, "visibilitychange", () => {
    refreshVisibleState();
    invalidateForLifecycle(lifecycleVisible
      ? "Review cancelled when page visibility changed; prepare a fresh review."
      : "Review cancelled because the page became hidden; prepare a fresh review after returning.");
  });
  listen(windowObject, "pagehide", () => {
    lifecyclePageActive = false;
    invalidateForLifecycle("Review cancelled because the page was hidden or left; prepare a fresh review after returning.");
  });
  listen(windowObject, "pageshow", () => {
    lifecyclePageActive = true;
    refreshVisibleState();
    invalidateForLifecycle("Review cancelled after the page was restored; prepare a fresh review.");
  });
  listen(windowObject, "blur", () => {
    lifecycleFocused = false;
    invalidateForLifecycle("Review cancelled because the page lost focus; prepare a fresh review after returning.");
  });
  listen(windowObject, "focus", () => {
    lifecycleFocused = true;
    invalidateForLifecycle("Review cancelled when page focus resumed; prepare a fresh review.");
  });
  listen(document, "freeze", () => {
    lifecyclePageActive = false;
    invalidateForLifecycle("Review cancelled because the page was suspended; prepare a fresh review after resuming.");
  });
  listen(document, "resume", () => {
    lifecyclePageActive = true;
    refreshVisibleState();
    invalidateForLifecycle("Review cancelled after the page resumed; prepare a fresh review.");
  });
  const resetWallet = () => {
    connected = false;
    wallet = null;
    discardReview("No transfer review is active.");
    clearAccounts(accountSelect);
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "Connect a wallet first";
    accountSelect.appendChild(option);
    accountSelect.disabled = true;
    updateButtons();
    setText(walletStatus, canConnect
      ? "Not connected. Nothing connects automatically."
      : "Wallet connection is disabled until a Meteor Testnet adapter is configured.");
  };

  connectButton.disabled = !canConnect;
  accountSelect.disabled = true;
  transferReview.hidden = true;
  updateButtons();
  if (!canConnect) {
    setText(walletStatus, "Wallet connection is disabled until a Meteor Testnet adapter is configured.");
  }

  connectButton.addEventListener("click", async () => {
    if (!canConnect || busy || connected) return;
    setBusy(true);
    setText(walletStatus, "Requesting ordinary Meteor Testnet account sign-in…");
    try {
      // SDK loading, initialization, and sign-in all follow this explicit click.
      if (!connector) {
        const candidate = await createConnector();
        if (!candidate || candidate.network !== "testnet"
          || typeof candidate.connect !== "function") {
          throw new TypeError("The Meteor SDK factory must return a Testnet connector with the required API.");
        }
        connector = candidate;
      }
      const connectedWallet = await connector.connect();
      if (!connectedWallet || typeof connectedWallet.getAccounts !== "function") {
        throw new Error("The Meteor SDK adapter did not provide a Testnet account record.");
      }
      const accounts = normalizeAccounts(await connectedWallet.getAccounts({ network: "testnet" }));
      if (accounts.length === 0) throw new Error("Meteor SDK has no saved Testnet account record for this sign-in.");
      clearAccounts(accountSelect);
      for (const account of accounts) {
        const option = document.createElement("option");
        option.value = account.accountId;
        option.textContent = account.accountId;
        accountSelect.appendChild(option);
      }
      accountSelect.disabled = false;
      wallet = connectedWallet;
      connected = true;
      setText(walletStatus, "Connected to NEAR testnet. Choose the account to inspect.");
    } catch (error) {
      resetWallet();
      setText(walletStatus, error instanceof Error ? error.message : "Wallet connection failed.");
    } finally {
      setBusy(false);
    }
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy || !connected) return;
    discardReview("The prior self-transfer review was cancelled before running this read-only preflight.");
    const accountId = accountSelect.value;
    if (!accountId) {
      setText(resultStatus, "Choose a connected account first.");
      resultCard.hidden = false;
      return;
    }
    let amountYocto;
    let context;
    try {
      amountYocto = amountToYocto(amountInput.value);
      context = readRiskContext(previousInput, ageInput);
    } catch (error) {
      resultCard.hidden = false;
      setText(resultStatus, error instanceof Error ? error.message : "Invalid input.");
      setText(resultDetails, "");
      return;
    }
    resultCard.hidden = false;
    setText(resultStatus, "Running local policy and read-only testnet checks…");
    setText(resultDetails, "");
    setBusy(true);
    try {
      const { response, result } = await fetchPreflight("/api/preflight", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          accountId,
          recipient: TESTNET_RECIPIENT,
          amountYocto,
          context,
        }),
      });
      if (!response.ok) throw new Error(result.error || `Local preflight failed (${response.status}).`);
      setText(resultStatus, `${result.status} · guard ${result.guard?.decision || "UNKNOWN"}`);
      setText(resultDetails, JSON.stringify({
        network: result.account?.network || "testnet configured; account lookup not performed",
        accountRead: Boolean(result.account),
        accountId: result.account?.accountId || accountId,
        balanceYocto: result.account?.balanceYocto ?? null,
        recipient: result.intent?.transaction?.recipient || TESTNET_RECIPIENT,
        amountYocto: result.intent?.transaction?.amount_yocto || amountYocto,
        submitted: result.submitted,
        recipientCodeCheck: result.recipientCodeCheck
          ? {
            status: result.recipientCodeCheck.status,
            reason: result.recipientCodeCheck.reason ?? null,
          }
          : null,
        note: "This generic preflight is read-only and does not call transaction signing or submission.",
      }, null, 2));
    } catch (error) {
      setText(resultStatus, error instanceof Error ? error.message : "Local preflight failed.");
      setText(resultDetails, "The generic preflight made no transaction signing or submission call.");
    } finally {
      setBusy(false);
    }
  });

  prepareSelfTransferButton.addEventListener("click", async () => {
    if (busy || !connected || walletOutcomeRequiresVerification) return;
    if (!isLifecycleActive()) {
      invalidateForLifecycle("The page is not active; return to it and prepare a fresh review.");
      return;
    }
    discardReview("Preparing a fresh fixed-intent review; no wallet action has been requested.");
    const uiSnapshot = {
      amount: amountInput.value,
      previousInteractions: previousInput.value,
      accountAgeDays: ageInput.value,
      accountId: accountSelect.value,
    };
    const uiSnapshotRevision = uiInputRevision;
    const uiLifecycleGeneration = lifecycleGeneration;
    const assertUiSnapshotCurrent = () => {
      if (!isLifecycleActive() || lifecycleGeneration !== uiLifecycleGeneration
        || uiInputRevision !== uiSnapshotRevision
        || uiSnapshot.amount !== amountInput.value
        || uiSnapshot.previousInteractions !== previousInput.value
        || uiSnapshot.accountAgeDays !== ageInput.value
        || uiSnapshot.accountId !== accountSelect.value) {
        throw new Error("A reviewed input changed while preflight was pending; prepare a fresh guarded review.");
      }
    };
    let context;
    try {
      context = readRiskContext(
        { value: uiSnapshot.previousInteractions },
        { value: uiSnapshot.accountAgeDays },
      );
    } catch (error) {
      setText(selfTransferStatus, error instanceof Error ? error.message : "Invalid risk context.");
      return;
    }
    setBusy(true);
    setText(selfTransferStatus, "Checking Meteor SDK's saved Testnet account record and running the fixed local preflight…");
    try {
      if (connector?.network !== "testnet" || !wallet || typeof wallet.getAccounts !== "function") {
        throw new Error("A signed-in NEAR Testnet account record is required.");
      }
      const savedTestnetAccounts = normalizeAccounts(await wallet.getAccounts({ network: "testnet" }));
      assertUiSnapshotCurrent();
      const sender = savedTestnetAccounts.find((account) => account.accountId === TESTNET_SELF_TRANSFER_ACCOUNT);
      if (!sender || uiSnapshot.accountId !== sender.accountId) {
        throw new Error(`Select ${TESTNET_SELF_TRANSFER_ACCOUNT} from Meteor SDK's saved Testnet account record first.`);
      }

      // The server uses accountId only for read-only RPC; this saved record is not a live ownership check.
      const { response, result } = await fetchPreflight("/api/preflight", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          accountId: sender.accountId,
          recipient: TESTNET_SELF_TRANSFER_ACCOUNT,
          amountYocto: TESTNET_SELF_TRANSFER_AMOUNT_YOCTO,
          context,
        }),
      });
      assertUiSnapshotCurrent();
      if (!response.ok) throw new Error(result.error || `Local preflight failed (${response.status}).`);
      if (result?.guard?.decision !== "ALLOW") {
        setText(selfTransferStatus, `${result?.status || "BLOCKED"} · guard ${result?.guard?.decision || "UNKNOWN"}; no wallet action was requested.`);
        return;
      }
      const nextReview = await createSelfTransferReview({
        result,
        senderAccountId: sender.accountId,
        context,
        now: clock(),
        clock,
        monotonicClock,
        cryptoObject,
      });
      assertUiSnapshotCurrent();
      const reviewWallNow = clock();
      if (!Number.isSafeInteger(reviewWallNow) || reviewWallNow < nextReview.createdAt
        || reviewWallNow >= nextReview.expiresAt) {
        throw new Error("Transfer review expired or the wall clock moved backward while being displayed.");
      }
      reviewWallClockState = { lastObserved: reviewWallNow };
      if (consumedRequestIds.has(nextReview.requestId)) {
        throw new Error("This guard request was already consumed; prepare a fresh review.");
      }
      review = nextReview;
      reviewedUiSnapshot = uiSnapshot;
      const signingParams = review.signingParams;
      transferReview.hidden = false;
      setText(reviewDetails, JSON.stringify({
        network: signingParams.network,
        sender: signingParams.signerId,
        receiver: signingParams.receiverId,
        action: `${signingParams.actions[0].type} (native NEAR transfer)`,
        amountNear: TESTNET_SELF_TRANSFER_AMOUNT_NEAR,
        amountYocto: signingParams.actions[0].params.deposit,
        latestBalanceYocto: review.balanceYocto,
        guardRequestId: review.requestId,
        guardedIntentHash: review.intentHash,
        reviewBindingHash: review.bindingHash,
        expiresAt: new Date(review.expiresAt).toISOString(),
        feeNote: "No transaction-fee estimate is provided. The wallet must show its own confirmation; verify the exact details there.",
      }, null, 2));
      setText(selfTransferStatus, "Local guard ALLOW. Review every detail below; no wallet signing or submission has been requested yet.");
      setText(reviewStatus, "This review expires in two minutes and is bound to the exact guarded intent and saved Testnet account record.");
      scheduleReviewExpiry(nextReview);
    } catch (error) {
      transferReview.hidden = true;
      review = null;
      reviewWallClockState = null;
      setText(selfTransferStatus, error instanceof Error ? error.message : "Self-transfer preflight failed closed.");
    } finally {
      setBusy(false);
    }
  });

  signSelfTransferButton.addEventListener("click", async () => {
    if (busy || !review || attemptedRequestIds.has(review.requestId)) return;
    if (!isLifecycleActive()) {
      invalidateForLifecycle("The page is not active; the review was cancelled. Prepare a fresh review after returning.");
      return;
    }
    const approvedReview = review;
    const signingLifecycleGeneration = lifecycleGeneration;
    setBusy(true);
    let walletPromptStarted = false;
    setText(reviewStatus, "Rechecking the exact immutable review and Meteor SDK's saved Testnet account record before opening the wallet…");
    try {
      if (!reviewedUiSnapshot
        || reviewedUiSnapshot.amount !== amountInput.value
        || reviewedUiSnapshot.previousInteractions !== previousInput.value
        || reviewedUiSnapshot.accountAgeDays !== ageInput.value
        || reviewedUiSnapshot.accountId !== accountSelect.value) {
        throw new Error("A reviewed input changed; prepare a fresh guarded review.");
      }
      await assertSelfTransferSigningBoundary({
        connector,
        wallet,
        selectedAccountId: accountSelect.value,
        review: approvedReview,
        wallClockState: reviewWallClockState,
        clock,
        monotonicClock,
        cryptoObject,
      });
      if (review !== approvedReview || consumedRequestIds.has(approvedReview.requestId)) {
        throw new Error("The reviewed intent changed or was cancelled; prepare a fresh review.");
      }
      if (!isLifecycleActive() || lifecycleGeneration !== signingLifecycleGeneration) {
        throw new Error("The page lifecycle changed; prepare a fresh guarded review before continuing.");
      }
      const signingWallNow = clock();
      if (!reviewWallClockState || !Number.isSafeInteger(signingWallNow)
        || signingWallNow < reviewWallClockState.lastObserved
        || signingWallNow < approvedReview.createdAt
        || signingWallNow >= approvedReview.expiresAt) {
        throw new Error("Transfer review expired or the wall clock moved backward; run a fresh preflight before continuing.");
      }
      reviewWallClockState.lastObserved = signingWallNow;
      const signingMonotonicNow = monotonicClock();
      if (!Number.isFinite(signingMonotonicNow)
        || signingMonotonicNow < approvedReview.monotonicCreatedAt
        || signingMonotonicNow >= approvedReview.monotonicExpiresAt) {
        throw new Error("Transfer review expired; run a fresh preflight before continuing.");
      }
      attemptedRequestIds.add(approvedReview.requestId);
      consumedRequestIds.add(approvedReview.requestId);
      clearReviewExpiryTimer();
      setText(reviewStatus, "Preparing the wallet request for the exact displayed Testnet transfer…");
      // Pass the exact frozen payload reviewed above. Never reconstruct from mutable form fields.
      const reviewDeadline = Object.freeze({
        createdAt: approvedReview.createdAt,
        expiresAt: approvedReview.expiresAt,
        wallClockHighWater: reviewWallClockState.lastObserved,
        monotonicCreatedAt: approvedReview.monotonicCreatedAt,
        monotonicExpiresAt: approvedReview.monotonicExpiresAt,
        isLifecycleActive: () => isLifecycleActive()
          && lifecycleGeneration === signingLifecycleGeneration,
        onWalletPromptStarted: () => {
          walletPromptStarted = true;
          walletRequestPending = true;
          walletOutcomeRequiresVerification = true;
          setText(reviewStatus, "The wallet prompt is opening for the exact displayed Testnet transfer; its result may remain pending.");
          setText(selfTransferStatus, "A wallet prompt request has started. This page cannot cancel it; verify wallet/Testnet before any retry.");
          updateButtons();
        },
      });
      await wallet.signAndSendTransaction(approvedReview.signingParams, reviewDeadline);
      setText(reviewStatus, "The wallet returned a result. The fixed-transfer flow is locked for this page session; verify the outcome in wallet/Testnet before reloading or taking another action.");
    } catch (error) {
      if (walletPromptStarted) {
        walletOutcomeRequiresVerification = true;
        const message = `The wallet request returned an error or was rejected: ${error instanceof Error ? error.message : "unknown error"}. This page cannot cancel a prompt after it opens, and the outcome may be unknown. The fixed-transfer flow is locked for this page session; verify in wallet/Testnet before reloading or retrying.`;
        setText(reviewStatus, message);
        setText(selfTransferStatus, message);
      } else {
        clearReviewExpiryTimer();
        consumedRequestIds.add(approvedReview.requestId);
        review = null;
        reviewedUiSnapshot = null;
        reviewWallClockState = null;
        transferReview.hidden = true;
        const message = `The wallet prompt was not opened; no wallet action was requested. ${error instanceof Error ? error.message : "Signing-boundary validation failed closed."}`;
        setText(reviewStatus, message);
        setText(selfTransferStatus, message);
      }
    } finally {
      walletRequestPending = false;
      setBusy(false);
    }
  });

  cancelSelfTransferButton.addEventListener("click", () => {
    if (busy || !review || attemptedRequestIds.has(review.requestId)) return;
    discardReview("Review cancelled. No wallet signing or submission call was made.");
    setText(selfTransferStatus, "Transfer review cancelled; prepare a fresh review if needed.");
    updateButtons();
  });

  for (const input of [amountInput, previousInput, ageInput, accountSelect]) {
    const invalidate = () => {
      uiInputRevision += 1;
      if (!review) return;
      if (attemptedRequestIds.has(review.requestId)) {
        updateButtons();
        return;
      }
      discardReview("Review cancelled because a reviewed input or selected account changed. Run a fresh preflight.");
      setText(selfTransferStatus, "A reviewed value changed; no wallet action was requested.");
      updateButtons();
    };
    input.addEventListener("input", invalidate);
    input.addEventListener("change", invalidate);
  }

  return { resetWallet };
}
