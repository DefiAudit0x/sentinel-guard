"use strict";

/**
 * NEAR testnet preflight only. Requires a wallet already connected by the host
 * app; this module never connects, signs, or submits a transaction.
 */
const { randomUUID } = require("node:crypto");
const { evaluateIntent } = require("./guarded_agent_bridge.js");

const TESTNET_RPC_URL = "https://rpc.testnet.near.org";
const RPC_TIMEOUT_MS = 5000;
const MAX_AMOUNT_DIGITS = 80;
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
    if (payload.error) {
      const message = typeof payload.error.message === "string" ? payload.error.message : "RPC error";
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
    || typeof account.code_hash !== "string") {
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
}) {
  const intent = makeTransferIntent({ recipient, amountYocto, context });
  if (!connector || typeof connector !== "object" || connector.network !== "testnet"
    || typeof connector.wallet !== "function") {
    throw new Error('connector must be a NEAR Connect instance configured with { network: "testnet" }');
  }

  // Validate the exact action/resource/transaction before any RPC reads.
  const request = { request_id: requestId, intent };
  const guardResult = evaluateIntent(request, adapterRunner ? { adapterRunner } : {});
  if (guardResult.error) throw new Error(`Sentinel Guard evaluation failed: ${guardResult.error}`);
  if (guardResult.response.status !== "COMPLETED" || guardResult.response.decision !== "ALLOW") {
    return {
      mode: "TESTNET_PREFLIGHT_READ_ONLY",
      status: guardResult.response.decision === "BLOCK" ? "BLOCKED" : "NEEDS_REVIEW",
      intent,
      guard: guardResult.response,
      account: null,
      submitted: false,
    };
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

  const account = await readTestnetAccount(selectedAccount.accountId, fetchImpl);
  return {
    mode: "TESTNET_PREFLIGHT_READ_ONLY",
    status: "PREPARED_NOT_SUBMITTED",
    intent,
    guard: guardResult.response,
    account,
    submitted: false,
  };
}

module.exports = {
  RPC_TIMEOUT_MS,
  TESTNET_RPC_URL,
  makeTransferIntent,
  preflightTestnetNativeTransfer,
  readTestnetAccount,
};
