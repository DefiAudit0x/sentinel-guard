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

  if ([connectButton, accountSelect, walletStatus, form, amountInput, previousInput,
    ageInput, preflightButton, resultCard, resultStatus, resultDetails].some((item) => !item)) {
    throw new TypeError("The local UI page is missing a required control.");
  }

  let connector = null;
  let connected = false;
  let busy = false;
  const canConnect = connectionEnabled === true;
  const setBusy = (value) => {
    busy = value;
    connectButton.disabled = !canConnect || value || connected;
    preflightButton.disabled = value || !connected;
  };
  const resetWallet = () => {
    connected = false;
    clearAccounts(accountSelect);
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "Connect a wallet first";
    accountSelect.appendChild(option);
    accountSelect.disabled = true;
    connectButton.disabled = !canConnect;
    preflightButton.disabled = true;
    setText(walletStatus, canConnect
      ? "Not connected. Nothing connects automatically."
      : "Wallet connection is disabled until this app can enforce a reviewed Meteor-only provider.");
  };

  connectButton.disabled = !canConnect;
  accountSelect.disabled = true;
  preflightButton.disabled = true;
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
        if (!candidate || typeof candidate.connect !== "function" || typeof candidate.on !== "function") {
          throw new TypeError("The NEAR Connect factory returned an invalid connector.");
        }
        candidate.on("wallet:signOut", resetWallet);
        connector = candidate;
      }
      const wallet = await connector.connect();
      if (!wallet || typeof wallet.getAccounts !== "function") {
        throw new Error("The wallet did not return a readable account list.");
      }
      const accounts = normalizeAccounts(await wallet.getAccounts());
      if (accounts.length === 0) throw new Error("The connected wallet returned no accounts.");
      clearAccounts(accountSelect);
      for (const account of accounts) {
        const option = document.createElement("option");
        option.value = account.accountId;
        option.textContent = account.accountId;
        accountSelect.appendChild(option);
      }
      accountSelect.disabled = false;
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
        note: "The application preflight did not call transaction signing or submission.",
      }, null, 2));
    } catch (error) {
      setText(resultStatus, error instanceof Error ? error.message : "Local preflight failed.");
      setText(resultDetails, "The application preflight made no transaction signing or submission call.");
    } finally {
      setBusy(false);
    }
  });

  return { resetWallet };
}
