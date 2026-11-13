"use strict";

/**
 * NEAR testnet preflight only. Requires a wallet already connected by the host
 * app; this module never connects, signs, or submits a transaction.
 */
const { randomUUID } = require("node:crypto");
const { evaluateIntent, evaluatePolicyIntent } = require("./guarded_agent_bridge.js");

const TESTNET_RPC_URL = "https://rpc.testnet.near.org";
const RPC_TIMEOUT_MS = 5000;
const MAX_AMOUNT_DIGITS = 80;
const CODE_HASH_BASELINES_ENV_VAR = "SENTINEL_GUARD_CODE_HASH_BASELINES";
const EMPTY_CODE_HASH = "1".repeat(32);
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const RESERVED_CONTEXT_FIELDS = ["recipient_is_contract", "recipient_code_changed"];
const DECIMAL_PATTERN = new RegExp(`^(?:0|[1-9][0-9]{0,${MAX_AMOUNT_DIGITS - 1}})$`);
const ACCOUNT_ID_PATTERN = /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?![\s\S])/;

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertAccountId(accountId, label) {
  if (typeof accountId !== "string" || accountId.length < 2 || accountId.length > 64
    || !ACCOUNT_ID_PATTERN.test(accountId)) {
    throw new TypeError(`${label} must be a valid lowercase NEAR account ID`);
  }
}

function isValidCodeHash(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 44) return false;
  let decoded = 0n;
  for (const character of value) {
    const digit = BASE58_ALPHABET.indexOf(character);
    if (digit < 0) return false;
    decoded = decoded * 58n + BigInt(digit);
  }
  const leadingZeroBytes = value.match(/^1*/)[0].length;
  const decodedHex = decoded === 0n ? "" : decoded.toString(16);
  const decodedBytes = Math.ceil(decodedHex.length / 2);
  return leadingZeroBytes + decodedBytes === 32;
}

function assertJsonValue(value, label) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number" && Number.isFinite(value)) return;
  if (Array.isArray(value)) {
    for (const item of value) assertJsonValue(item, label);
    return;
  }
  if (isPlainObject(value)) {
    for (const item of Object.values(value)) assertJsonValue(item, label);
    return;
  }
  throw new TypeError(`${label} must contain only JSON values`);
}

function freezeRecursively(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) freezeRecursively(child);
  }
  return value;
}

function snapshotJsonObject(value, label) {
  if (!isPlainObject(value)) throw new TypeError(`${label} must be a plain JSON object`);
  assertJsonValue(value, label);
  let encoded;
  try {
    encoded = JSON.stringify(value);
    if (typeof encoded !== "string") throw new TypeError("not JSON serializable");
    const snapshot = JSON.parse(encoded);
    if (!isPlainObject(snapshot)) throw new TypeError("not a JSON object");
    return snapshot;
  } catch (error) {
    throw new TypeError(`${label} must contain only JSON values: ${error.message}`);
  }
}

function makeTransferIntent({ recipient, amountYocto, context = {} }) {
  assertAccountId(recipient, "recipient");
  if (typeof amountYocto !== "string" || !DECIMAL_PATTERN.test(amountYocto)) {
    throw new TypeError(`amountYocto must be a canonical decimal string of at most ${MAX_AMOUNT_DIGITS} digits`);
  }
  const contextSnapshot = snapshotJsonObject(context, "context");
  if (Object.hasOwn(contextSnapshot, "recipient") || Object.hasOwn(contextSnapshot, "amount_yocto")) {
    throw new TypeError("context must not override recipient or amount_yocto");
  }
  const reservedField = RESERVED_CONTEXT_FIELDS.find((field) => Object.hasOwn(contextSnapshot, field));
  if (reservedField) {
    throw new TypeError(`context must not provide reserved field ${reservedField}`);
  }
  return freezeRecursively({
    action: "transfer",
    resource: recipient,
    transaction: {
      recipient,
      amount_yocto: amountYocto,
      ...contextSnapshot,
    },
  });
}

function withDerivedRecipientSignals(intent, recipientAccount, baselineHash) {
  const recipientIsContract = recipientAccount.codeHash !== EMPTY_CODE_HASH;
  const recipientCodeChanged = recipientAccount.codeHash !== baselineHash;
  return freezeRecursively({
    ...intent,
    transaction: {
      ...intent.transaction,
      recipient_is_contract: recipientIsContract,
      recipient_code_changed: recipientCodeChanged,
    },
  });
}

function configuredBaselineFor(recipient) {
  if (typeof process === "undefined" || process.release?.name !== "node") return null;
  const raw = process.env[CODE_HASH_BASELINES_ENV_VAR];
  if (typeof raw !== "string" || !raw.trim()) return null;
  let entries;
  try {
    entries = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!Array.isArray(entries) || entries.length === 0) return null;

  const seenAccounts = new Set();
  for (const entry of entries) {
    if (!isPlainObject(entry)
      || Object.keys(entry).length !== 3
      || !Object.hasOwn(entry, "network")
      || !Object.hasOwn(entry, "account_id")
      || !Object.hasOwn(entry, "code_hash")
      || entry.network !== "testnet"
      || typeof entry.account_id !== "string"
      || entry.account_id.length < 2
      || entry.account_id.length > 64
      || !ACCOUNT_ID_PATTERN.test(entry.account_id)
      || !isValidCodeHash(entry.code_hash)
      || seenAccounts.has(entry.account_id)) {
      return null;
    }
    seenAccounts.add(entry.account_id);
  }
  const match = entries.find((entry) => entry.account_id === recipient);
  return match ? match.code_hash : null;
}

function makeNeedsReview({ intent, policyResult, reason, codeHashStatus = "UNKNOWN", account = null }) {
  return {
    mode: "TESTNET_PREFLIGHT_READ_ONLY",
    status: "NEEDS_REVIEW",
    intent,
    guard: null,
    preliminaryPolicy: policyResult,
    account,
    recipientCodeCheck: { status: codeHashStatus, reason },
    submitted: false,
  };
}

async function callTestnetRpc(method, params, fetchImpl = globalThis.fetch) {
  if (typeof fetchImpl !== "function") throw new TypeError("fetch is not available");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), RPC_TIMEOUT_MS);
  try {
    const response = await fetchImpl(TESTNET_RPC_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: "sentinel-guard-testnet-preflight",
        method,
        params,
      }),
      signal: controller.signal,
    });
    if (!response || response.ok !== true) {
      throw new Error(`testnet RPC HTTP request failed${response ? ` (${response.status})` : ""}`);
    }
    const payload = await response.json();
    if (!isPlainObject(payload) || payload.jsonrpc !== "2.0"
      || payload.id !== "sentinel-guard-testnet-preflight") {
      throw new Error("testnet RPC returned an invalid JSON-RPC envelope");
    }
    if (Object.hasOwn(payload, "error")) {
      const message = typeof payload.error?.message === "string" ? payload.error.message : "RPC error";
      throw new Error(`testnet RPC ${method} failed: ${message}`);
    }
    if (!Object.hasOwn(payload, "result")) throw new Error("testnet RPC response has no result");
    return payload.result;
  } finally {
    clearTimeout(timer);
  }
}

async function readTestnetAccount(accountId, fetchImpl = globalThis.fetch) {
  assertAccountId(accountId, "accountId");
  const status = await callTestnetRpc("status", {}, fetchImpl);
  if (!isPlainObject(status) || status.chain_id !== "testnet") {
    throw new Error("RPC endpoint did not confirm the NEAR testnet network");
  }
  const account = await callTestnetRpc("query", {
    request_type: "view_account",
    finality: "final",
    account_id: accountId,
  }, fetchImpl);
  if (!isPlainObject(account)
    || typeof account.amount !== "string" || !DECIMAL_PATTERN.test(account.amount)
    || typeof account.locked !== "string" || !DECIMAL_PATTERN.test(account.locked)
    || !Number.isSafeInteger(account.storage_usage) || account.storage_usage < 0
    || !isValidCodeHash(account.code_hash)) {
    throw new Error("testnet RPC returned an invalid account snapshot");
  }
  return {
    network: "testnet",
    accountId,
    balanceYocto: account.amount,
    lockedYocto: account.locked,
    storageUsage: account.storage_usage,
    codeHash: account.code_hash,
  };
}

async function preflightTestnetNativeTransfer({
  connector,
  recipient,
  amountYocto,
  context = {},
  accountId,
  requestId = randomUUID(),
  fetchImpl = globalThis.fetch,
  adapterRunner,
  policyAdapterRunner,
}) {
  const intent = makeTransferIntent({ recipient, amountYocto, context });
  if (!connector || typeof connector !== "object" || connector.network !== "testnet"
    || typeof connector.wallet !== "function") {
    throw new Error('connector must be a NEAR Connect instance configured with { network: "testnet" }');
  }

  // Policy is checked independently before any wallet access or RPC. Risk is
  // evaluated only after the read-only sender and recipient account checks.
  const request = { request_id: requestId, intent };
  const policyOptions = policyAdapterRunner ? { adapterRunner: policyAdapterRunner } : {};
  const policyGate = evaluatePolicyIntent(request, policyOptions);
  if (policyGate.error) {
    return makeNeedsReview({
      intent,
      policyResult: null,
      reason: "Policy-only evaluation failed before wallet or RPC access",
    });
  }
  const policyResult = policyGate.response;
  if (policyResult.status === "POLICY_EVALUATED" && policyResult.allowed === false) {
    return {
      mode: "TESTNET_PREFLIGHT_READ_ONLY",
      status: "BLOCKED",
      intent,
      guard: null,
      policy: policyResult,
      account: null,
      recipientCodeCheck: { status: "NOT_CHECKED", reason: "local policy denied the transfer" },
      submitted: false,
    };
  }
  if (policyResult.status !== "POLICY_EVALUATED" || policyResult.allowed !== true) {
    return makeNeedsReview({
      intent,
      policyResult,
      reason: "Policy-only evaluation did not return a valid allow decision",
    });
  }

  const baselineHash = configuredBaselineFor(recipient);
  if (!baselineHash) {
    return makeNeedsReview({
      intent,
      policyResult,
      reason: "No valid operator code-hash baseline is configured for this testnet recipient",
    });
  }

  // wallet() and getAccounts() read the current connection; connect() is never called.
  const wallet = await connector.wallet();
  if (!wallet || typeof wallet.getAccounts !== "function") {
    throw new Error("no already-connected wallet is available; connect manually in the host app, then retry preflight");
  }
  const accounts = await wallet.getAccounts();
  if (!Array.isArray(accounts) || accounts.length === 0) {
    throw new Error("the connected wallet returned no accounts");
  }
  const selectedAccount = accountId === undefined
    ? (accounts.length === 1 ? accounts[0] : null)
    : accounts.find((account) => account && account.accountId === accountId);
  if (!selectedAccount || typeof selectedAccount.accountId !== "string") {
    throw new Error(accounts.length > 1 && accountId === undefined
      ? "choose accountId explicitly when the wallet has multiple accounts"
      : "accountId is not present in the connected wallet");
  }

  let account;
  let recipientAccount;
  try {
    account = await readTestnetAccount(selectedAccount.accountId, fetchImpl);
    recipientAccount = await readTestnetAccount(recipient, fetchImpl);
  } catch {
    return makeNeedsReview({
      intent,
      policyResult,
      reason: "Testnet account or RPC verification failed; code-hash status is unknown",
    });
  }

  const finalIntent = withDerivedRecipientSignals(intent, recipientAccount, baselineHash);
  const riskOptions = adapterRunner ? { adapterRunner } : {};
  const finalGuard = evaluateIntent({ request_id: requestId, intent: finalIntent }, riskOptions);
  const codeHashStatus = recipientAccount.codeHash === baselineHash ? "MATCHED" : "CHANGED";
  const recipientCodeCheck = {
    status: codeHashStatus,
    network: "testnet",
    accountId: recipient,
    codeHash: recipientAccount.codeHash,
  };
  if (finalGuard.error || finalGuard.response.status !== "COMPLETED") {
    return makeNeedsReview({
      intent,
      policyResult,
      account,
      codeHashStatus,
      reason: "Final risk evaluation failed after the code-hash comparison",
    });
  }
  if (finalGuard.response.decision !== "ALLOW") {
    return {
      mode: "TESTNET_PREFLIGHT_READ_ONLY",
      status: finalGuard.response.decision === "BLOCK" ? "BLOCKED" : "NEEDS_REVIEW",
      intent,
      guard: finalGuard.response,
      account,
      recipientCodeCheck,
      submitted: false,
    };
  }

  return {
    mode: "TESTNET_PREFLIGHT_READ_ONLY",
    status: "PREPARED_NOT_SUBMITTED",
    intent,
    guard: finalGuard.response,
    account,
    recipientCodeCheck,
    submitted: false,
  };
}

module.exports = {
  CODE_HASH_BASELINES_ENV_VAR,
  EMPTY_CODE_HASH,
  RPC_TIMEOUT_MS,
  TESTNET_RPC_URL,
  makeTransferIntent,
  preflightTestnetNativeTransfer,
  readTestnetAccount,
};
