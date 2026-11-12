import {
  assertSelfTransferSigningBoundary,
  createSelfTransferReview,
  TESTNET_SELF_TRANSFER_ACCOUNT,
  TESTNET_SELF_TRANSFER_AMOUNT_NEAR,
  TESTNET_SELF_TRANSFER_AMOUNT_YOCTO,
} from "./self_transfer.mjs";

export const TESTNET_RECIPIENT = "defiaudit0x.testnet";
export const MAX_AMOUNT_YOCTO = 100000000000000000000000n;
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
  cryptoObject = globalThis.crypto,
}) {
  if (typeof createConnector !== "function") {
    throw new TypeError("A lazy NEAR Connect factory is required.");
  }
  if (!document || typeof document.querySelector !== "function") {
    throw new TypeError("A document is required.");
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
  const attemptedRequestIds = new Set();
  const consumedRequestIds = new Set();
  const canConnect = connectionEnabled === true;

  const updateButtons = () => {
    connectButton.disabled = !canConnect || busy || connected;
    preflightButton.disabled = busy || !connected;
    prepareSelfTransferButton.disabled = busy || !connected;
    signSelfTransferButton.disabled = busy || !review || attemptedRequestIds.has(review.requestId);
    cancelSelfTransferButton.disabled = busy || !review;
  };
  const setBusy = (value) => {
    busy = value;
    updateButtons();
  };
  const discardReview = (message) => {
    if (review) consumedRequestIds.add(review.requestId);
    review = null;
    reviewedUiSnapshot = null;
    transferReview.hidden = true;
    signSelfTransferButton.disabled = true;
    cancelSelfTransferButton.disabled = true;
    if (message) setText(reviewStatus, message);
  };
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
      : "Wallet connection is disabled until this app can enforce a reviewed Meteor-only provider.");
  };

  connectButton.disabled = !canConnect;
  accountSelect.disabled = true;
  transferReview.hidden = true;
  updateButtons();
  if (!canConnect) {
    setText(walletStatus, "Wallet connection is disabled until this app can enforce a reviewed Meteor-only provider.");
  }

  connectButton.addEventListener("click", async () => {
    if (!canConnect || busy || connected) return;
    setBusy(true);
    setText(walletStatus, "Connecting to the pinned Meteor Wallet…");
    try {
      // Construction, connector module loading, and connection all follow this click.
      if (!connector) {
        const candidate = await createConnector();
        if (!candidate || candidate.network !== "testnet"
          || typeof candidate.connect !== "function" || typeof candidate.on !== "function") {
          throw new TypeError("The NEAR Connect factory must return a Testnet connector with the required API.");
        }
        candidate.on("wallet:signOut", resetWallet);
        connector = candidate;
      }
      const connectedWallet = await connector.connect();
      if (!connectedWallet || typeof connectedWallet.getAccounts !== "function") {
        throw new Error("The wallet did not return a readable account list.");
      }
      const accounts = normalizeAccounts(await connectedWallet.getAccounts({ network: "testnet" }));
      if (accounts.length === 0) throw new Error("The connected wallet returned no accounts.");
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
      const response = await fetchImpl("/api/preflight", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          accountId,
          recipient: TESTNET_RECIPIENT,
          amountYocto,
          context,
        }),
      });
      const result = await response.json();
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
    if (busy || !connected) return;
    discardReview("Preparing a fresh fixed-intent review; no wallet action has been requested.");
    let context;
    try {
      context = readRiskContext(previousInput, ageInput);
    } catch (error) {
      setText(selfTransferStatus, error instanceof Error ? error.message : "Invalid risk context.");
      return;
    }
    setBusy(true);
    setText(selfTransferStatus, "Checking the connected Testnet account and running the fixed local preflight…");
    try {
      if (connector?.network !== "testnet" || !wallet || typeof wallet.getAccounts !== "function") {
        throw new Error("A directly connected NEAR Testnet wallet is required.");
      }
      const liveAccounts = normalizeAccounts(await wallet.getAccounts({ network: "testnet" }));
      const sender = liveAccounts.find((account) => account.accountId === TESTNET_SELF_TRANSFER_ACCOUNT);
      if (!sender || accountSelect.value !== sender.accountId) {
        throw new Error(`Select ${TESTNET_SELF_TRANSFER_ACCOUNT} from the connected Testnet wallet first.`);
      }

      // The server uses accountId only for a read-only public RPC lookup; ownership is checked above in-browser.
      const response = await fetchImpl("/api/preflight", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          accountId: sender.accountId,
          recipient: TESTNET_SELF_TRANSFER_ACCOUNT,
          amountYocto: TESTNET_SELF_TRANSFER_AMOUNT_YOCTO,
          context,
        }),
      });
      const result = await response.json();
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
        cryptoObject,
      });
      if (consumedRequestIds.has(nextReview.requestId)) {
        throw new Error("This guard request was already consumed; prepare a fresh review.");
      }
      review = nextReview;
      reviewedUiSnapshot = {
        amount: amountInput.value,
        previousInteractions: previousInput.value,
        accountAgeDays: ageInput.value,
        accountId: accountSelect.value,
      };
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
      setText(reviewStatus, "This review expires in two minutes and is bound to the exact guarded intent and connected account.");
    } catch (error) {
      transferReview.hidden = true;
      review = null;
      setText(selfTransferStatus, error instanceof Error ? error.message : "Self-transfer preflight failed closed.");
    } finally {
      setBusy(false);
    }
  });

  signSelfTransferButton.addEventListener("click", async () => {
    if (busy || !review || attemptedRequestIds.has(review.requestId)) return;
    const approvedReview = review;
    setBusy(true);
    setText(reviewStatus, "Rechecking the exact immutable review and connected Testnet account before opening the wallet…");
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
        now: clock(),
        cryptoObject,
      });
      if (review !== approvedReview || consumedRequestIds.has(approvedReview.requestId)) {
        throw new Error("The reviewed intent changed or was cancelled; prepare a fresh review.");
      }
      attemptedRequestIds.add(approvedReview.requestId);
      consumedRequestIds.add(approvedReview.requestId);
      setText(reviewStatus, "Requesting the wallet’s confirmation for the exact displayed Testnet transfer…");
      // Pass the exact frozen payload reviewed above. Never reconstruct from mutable form fields.
      await wallet.signAndSendTransaction(approvedReview.signingParams);
      setText(reviewStatus, "The wallet returned a result. Verify the outcome in the wallet/Testnet before taking any further action.");
    } catch (error) {
      if (attemptedRequestIds.has(approvedReview.requestId)) {
        setText(reviewStatus, `The wallet request returned an error or was rejected: ${error instanceof Error ? error.message : "unknown error"}. An error does not prove that nothing was broadcast; verify before any retry.`);
      } else {
        consumedRequestIds.add(approvedReview.requestId);
        review = null;
        reviewedUiSnapshot = null;
        transferReview.hidden = true;
        setText(selfTransferStatus, error instanceof Error ? error.message : "Signing-boundary validation failed closed.");
      }
    } finally {
      setBusy(false);
    }
  });

  cancelSelfTransferButton.addEventListener("click", () => {
    if (busy || !review) return;
    discardReview("Review cancelled. No wallet signing or submission call was made.");
    setText(selfTransferStatus, "Transfer review cancelled; prepare a fresh review if needed.");
    updateButtons();
  });

  for (const input of [amountInput, previousInput, ageInput, accountSelect]) {
    const invalidate = () => {
      if (!review) return;
      discardReview("Review cancelled because a reviewed input or selected account changed. Run a fresh preflight.");
      setText(selfTransferStatus, "A reviewed value changed; no wallet action was requested.");
      updateButtons();
    };
    input.addEventListener("input", invalidate);
    input.addEventListener("change", invalidate);
  }

  return { resetWallet };
}
