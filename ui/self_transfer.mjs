export const TESTNET_SELF_TRANSFER_ACCOUNT = "defiaudit0x.testnet";
export const TESTNET_SELF_TRANSFER_AMOUNT_YOCTO = "1000000000000000000000";
export const TESTNET_SELF_TRANSFER_AMOUNT_NEAR = "0.001";
export const SELF_TRANSFER_REVIEW_TTL_MS = 120_000;

const NETWORK = "testnet";
const ACCOUNT_ID_PATTERN = /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?![\s\S])/;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]{0,79})$/;
const REQUEST_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HASH_PATTERN = /^[0-9a-f]{64}$/;
const CONTEXT_FIELDS = new Set(["previous_interactions", "account_age_days"]);

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, keys) {
  return isPlainObject(value)
    && Object.keys(value).length === keys.length
    && keys.every((key) => Object.hasOwn(value, key));
}

function canonicalJson(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("Canonical JSON cannot contain a non-finite number.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (isPlainObject(value)) {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  throw new TypeError("Guarded intent must contain only plain JSON values.");
}

async function sha256Hex(value, cryptoObject = globalThis.crypto) {
  if (!cryptoObject?.subtle || typeof TextEncoder !== "function") {
    throw new Error("Secure browser hashing is unavailable; transfer review is blocked.");
  }
  const digest = await cryptoObject.subtle.digest("SHA-256", new TextEncoder().encode(canonicalJson(value)));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function clonePlainJson(value, label) {
  if (!isPlainObject(value)) throw new TypeError(`${label} must be a JSON object.`);
  let encoded;
  try {
    encoded = JSON.stringify(value);
    if (typeof encoded !== "string") throw new TypeError("not serializable");
    const copy = JSON.parse(encoded);
    if (!isPlainObject(copy)) throw new TypeError("not an object");
    return copy;
  } catch (error) {
    throw new TypeError(`${label} must contain plain JSON values: ${error.message}`);
  }
}

function freezeRecursively(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) freezeRecursively(child);
  }
  return value;
}

function validateContext(context) {
  if (!isPlainObject(context)) throw new TypeError("Risk context must be a plain object.");
  const copy = {};
  for (const [key, value] of Object.entries(context)) {
    if (!CONTEXT_FIELDS.has(key) || !Number.isSafeInteger(value) || value < 0) {
      throw new TypeError("Risk context contains an unsupported or invalid value.");
    }
    copy[key] = value;
  }
  return copy;
}

function validateGuardedIntent(intent, context) {
  if (!exactKeys(intent, ["action", "resource", "transaction"])
    || intent.action !== "transfer"
    || intent.resource !== TESTNET_SELF_TRANSFER_ACCOUNT
    || !isPlainObject(intent.transaction)) {
    throw new Error("Guarded result does not describe the exact testnet self-transfer.");
  }
  const transaction = intent.transaction;
  const expectedKeys = ["recipient", "amount_yocto", ...Object.keys(context)];
  if (Object.keys(transaction).length !== expectedKeys.length
    || !expectedKeys.every((key) => Object.hasOwn(transaction, key))) {
    throw new Error("Guarded transaction fields differ from the submitted intent.");
  }
  if (transaction.recipient !== TESTNET_SELF_TRANSFER_ACCOUNT
    || transaction.amount_yocto !== TESTNET_SELF_TRANSFER_AMOUNT_YOCTO) {
    throw new Error("Guarded receiver or amount does not match the fixed transfer.");
  }
  for (const [key, value] of Object.entries(context)) {
    if (transaction[key] !== value) throw new Error("Guarded risk context differs from the reviewed request.");
  }
}

function bindingMaterial(requestId, intentHash, expiresAt, signingParams) {
  const [action] = signingParams.actions;
  return {
    requestId,
    intentHash,
    expiresAt,
    network: signingParams.network,
    senderAccountId: signingParams.signerId,
    receiverId: signingParams.receiverId,
    action: action.type,
    amountYocto: action.params.deposit,
  };
}

function validateSigningParams(signingParams, intent) {
  if (!exactKeys(signingParams, ["network", "signerId", "receiverId", "actions"])
    || signingParams.network !== NETWORK
    || signingParams.signerId !== TESTNET_SELF_TRANSFER_ACCOUNT
    || signingParams.receiverId !== TESTNET_SELF_TRANSFER_ACCOUNT
    || !Array.isArray(signingParams.actions)
    || signingParams.actions.length !== 1) {
    throw new Error("Signing payload does not match the fixed Testnet self-transfer.");
  }
  const [action] = signingParams.actions;
  if (!exactKeys(action, ["type", "params"])
    || action.type !== "Transfer"
    || !exactKeys(action.params, ["deposit"])
    || action.params.deposit !== TESTNET_SELF_TRANSFER_AMOUNT_YOCTO
    || intent.action !== "transfer"
    || intent.resource !== signingParams.receiverId
    || intent.transaction.recipient !== signingParams.receiverId
    || intent.transaction.amount_yocto !== action.params.deposit) {
    throw new Error("Signing action or amount differs from the exact guarded intent.");
  }
}

export async function createSelfTransferReview({
  result,
  senderAccountId,
  context = {},
  now = Date.now(),
  cryptoObject = globalThis.crypto,
}) {
  if (!Number.isSafeInteger(now) || now < 0) throw new TypeError("Review clock value is invalid.");
  if (senderAccountId !== TESTNET_SELF_TRANSFER_ACCOUNT
    || typeof senderAccountId !== "string" || !ACCOUNT_ID_PATTERN.test(senderAccountId)) {
    throw new Error("The connected Testnet account is not the fixed self-transfer account.");
  }
  const contextSnapshot = validateContext(context);
  if (!isPlainObject(result)
    || result.mode !== "TESTNET_PREFLIGHT_READ_ONLY"
    || result.status !== "PREPARED_NOT_SUBMITTED"
    || result.submitted !== false
    || !isPlainObject(result.guard)
    || result.guard.status !== "COMPLETED"
    || result.guard.decision !== "ALLOW") {
    throw new Error("A completed local ALLOW and read-only Testnet result are required.");
  }
  if (!isPlainObject(result.account)
    || result.account.network !== NETWORK
    || result.account.accountId !== senderAccountId
    || typeof result.account.balanceYocto !== "string"
    || !DECIMAL_PATTERN.test(result.account.balanceYocto)) {
    throw new Error("The read-only Testnet account snapshot does not match the connected account.");
  }
  if (BigInt(result.account.balanceYocto) < BigInt(TESTNET_SELF_TRANSFER_AMOUNT_YOCTO)) {
    throw new Error("The latest read-only balance is below 0.001 NEAR; the transfer is blocked.");
  }

  const guardedIntent = freezeRecursively(clonePlainJson(result.intent, "Guarded intent"));
  validateGuardedIntent(guardedIntent, contextSnapshot);
  const { request_id: requestId, intent_hash: intentHash } = result.guard;
  if (typeof requestId !== "string" || !REQUEST_ID_PATTERN.test(requestId)
    || typeof intentHash !== "string" || !HASH_PATTERN.test(intentHash)) {
    throw new Error("Guard response has an invalid request ID or intent hash.");
  }
  if (await sha256Hex(guardedIntent, cryptoObject) !== intentHash) {
    throw new Error("Guard intent hash does not match the exact returned intent.");
  }

  const signingParams = freezeRecursively({
    network: NETWORK,
    signerId: senderAccountId,
    receiverId: guardedIntent.transaction.recipient,
    actions: [{
      type: "Transfer",
      params: { deposit: guardedIntent.transaction.amount_yocto },
    }],
  });
  validateSigningParams(signingParams, guardedIntent);
  const expiresAt = now + SELF_TRANSFER_REVIEW_TTL_MS;
  const bindingHash = await sha256Hex(
    bindingMaterial(requestId, intentHash, expiresAt, signingParams),
    cryptoObject,
  );
  return freezeRecursively({
    requestId,
    intentHash,
    guardedIntent,
    context: freezeRecursively(contextSnapshot),
    signingParams,
    balanceYocto: result.account.balanceYocto,
    createdAt: now,
    expiresAt,
    bindingHash,
  });
}

export async function assertSelfTransferSigningBoundary({
  connector,
  wallet,
  selectedAccountId,
  review,
  now = Date.now(),
  cryptoObject = globalThis.crypto,
}) {
  if (connector?.network !== NETWORK) throw new Error("The connected wallet is not on NEAR Testnet.");
  if (!wallet || typeof wallet.getAccounts !== "function"
    || typeof wallet.signAndSendTransaction !== "function") {
    throw new Error("The connected wallet cannot provide the required Testnet transfer API.");
  }
  if (!review || !Object.isFrozen(review) || !Object.isFrozen(review.signingParams)
    || !Object.isFrozen(review.signingParams.actions)
    || !Object.isFrozen(review.signingParams.actions[0])
    || !Object.isFrozen(review.signingParams.actions[0]?.params)) {
    throw new Error("Transfer review is missing or its payload is not immutable.");
  }
  if (!Number.isSafeInteger(now) || now < review.createdAt || now >= review.expiresAt
    || review.expiresAt - review.createdAt !== SELF_TRANSFER_REVIEW_TTL_MS) {
    throw new Error("Transfer review expired; run a fresh preflight before continuing.");
  }
  if (typeof review.requestId !== "string" || !REQUEST_ID_PATTERN.test(review.requestId)
    || typeof review.intentHash !== "string" || !HASH_PATTERN.test(review.intentHash)
    || typeof review.bindingHash !== "string" || !HASH_PATTERN.test(review.bindingHash)) {
    throw new Error("Transfer review identity is malformed.");
  }
  const context = validateContext(review.context);
  validateGuardedIntent(review.guardedIntent, context);
  if (await sha256Hex(review.guardedIntent, cryptoObject) !== review.intentHash) {
    throw new Error("Guarded intent changed after review.");
  }
  validateSigningParams(review.signingParams, review.guardedIntent);
  if (selectedAccountId !== review.signingParams.signerId) {
    throw new Error("Selected account changed after review.");
  }
  const expectedBindingHash = await sha256Hex(
    bindingMaterial(review.requestId, review.intentHash, review.expiresAt, review.signingParams),
    cryptoObject,
  );
  if (expectedBindingHash !== review.bindingHash) {
    throw new Error("Transfer review binding changed after the local guard decision.");
  }

  const savedTestnetAccounts = await wallet.getAccounts({ network: NETWORK });
  if (!Array.isArray(savedTestnetAccounts)
    || !savedTestnetAccounts.some((account) => account && account.accountId === review.signingParams.signerId)) {
    throw new Error("The exact Testnet sender is no longer in Meteor SDK's saved account record; this is not a live ownership check.");
  }
}
