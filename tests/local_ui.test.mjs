import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { amountToYocto, mountUI, TESTNET_RECIPIENT } from "../ui/controller.mjs";
import {
  createMeteorConnectAdapter,
  mountLocalUI,
} from "../ui/main.mjs";
import {
  TESTNET_SELF_TRANSFER_ACCOUNT,
  TESTNET_SELF_TRANSFER_AMOUNT_YOCTO,
} from "../ui/self_transfer.mjs";

let guardRequestCounter = 1;

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

async function hashIntent(intent) {
  const bytes = new TextEncoder().encode(canonicalJson(intent));
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function makeSelfTransferResult({
  context = { previous_interactions: 3, account_age_days: 365 },
  intent: suppliedIntent,
  guard: suppliedGuard = {},
  account: suppliedAccount = {},
  ...topLevel
} = {}) {
  const intent = suppliedIntent || {
    action: "transfer",
    resource: TESTNET_SELF_TRANSFER_ACCOUNT,
    transaction: {
      recipient: TESTNET_SELF_TRANSFER_ACCOUNT,
      amount_yocto: TESTNET_SELF_TRANSFER_AMOUNT_YOCTO,
      ...context,
    },
  };
  const requestId = suppliedGuard.request_id
    || `00000000-0000-4000-8000-${String(guardRequestCounter++).padStart(12, "0")}`;
  return {
    mode: "TESTNET_PREFLIGHT_READ_ONLY",
    status: "PREPARED_NOT_SUBMITTED",
    submitted: false,
    intent,
    guard: {
      request_id: requestId,
      intent_hash: await hashIntent(intent),
      status: "COMPLETED",
      decision: "ALLOW",
      ...suppliedGuard,
    },
    account: {
      network: "testnet",
      accountId: TESTNET_SELF_TRANSFER_ACCOUNT,
      balanceYocto: "5000000000000000000000",
      ...suppliedAccount,
    },
    ...topLevel,
  };
}

async function makeSelfTransferApp({
  result,
  walletAccounts = [
    { accountId: TESTNET_SELF_TRANSFER_ACCOUNT },
    { accountId: "secondary.testnet" },
  ],
  getAccountsImpl,
  network = "testnet",
  now = 1_800_000_000_000,
  monotonicNow = 0,
  monotonicClockImpl,
  jsonError,
  walletError,
  fetchImpl: customFetchImpl,
} = {}) {
  const initialWallNow = now;
  const initialMonotonicNow = monotonicNow;
  const calls = {
    createConnector: 0,
    connect: 0,
    getAccounts: 0,
    connectorWallet: 0,
    signAndSendTransaction: 0,
    signAndSendTransactions: 0,
    signTransaction: 0,
    requests: [],
  };
  const document = makeDocument();
  const windowObject = new FakeWindow();
  const timers = [];
  const setTimeoutImpl = (callback, delay) => {
    const timer = { callback, delay, cleared: false, fired: false };
    timers.push(timer);
    return timer;
  };
  const clearTimeoutImpl = (timer) => { timer.cleared = true; };
  document.elements.get("#previous-interactions").value = "3";
  document.elements.get("#account-age-days").value = "365";
  const wallet = makeConnectedWallet(calls, getAccountsImpl || (async () => walletAccounts));
  wallet.signAndSendTransaction = async (params, options) => {
    calls.signAndSendTransaction += 1;
    calls.signingParams = params;
    calls.signingOptions = options;
    options.onWalletPromptStarted?.();
    if (walletError) throw walletError;
    return { transaction: "mock-only" };
  };
  const connector = makeConnector(calls, wallet);
  connector.network = network;
  mountUI({
    createConnector() { calls.createConnector += 1; return connector; },
    document,
    connectionEnabled: true,
    clock: () => now,
    monotonicClock: monotonicClockImpl || (() => monotonicNow),
    setTimeoutImpl,
    clearTimeoutImpl,
    windowObject,
    async fetchImpl(url, options) {
      calls.requests.push({ url, options });
      if (customFetchImpl) return customFetchImpl(url, options);
      return {
        ok: true,
        async json() {
          if (jsonError) throw jsonError;
          return result;
        },
      };
    },
  });
  await document.elements.get("#connect-wallet").emit("click");
  return {
    calls,
    document,
    windowObject,
    wallet,
    connector,
    setNow(value) {
      now = value;
      monotonicNow = initialMonotonicNow + (value - initialWallNow);
    },
    setWallNow(value) { now = value; },
    setMonotonicNow(value) { monotonicNow = value; },
    fireTimer(delay) {
      const timer = timers.find((item) => item.delay === delay && !item.cleared && !item.fired);
      assert.ok(timer, `no active timer with delay ${delay}`);
      timer.fired = true;
      timer.callback();
    },
  };
}

class FakeElement {
  constructor() {
    this.listeners = new Map();
    this.children = [];
    this.disabled = false;
    this.hidden = false;
    this.value = "";
    this.textContent = "";
  }
  get firstChild() { return this.children[0] || null; }
  addEventListener(type, listener) {
    const current = this.listeners.get(type) || [];
    current.push(listener);
    this.listeners.set(type, current);
  }
  async emit(type, event = {}) {
    for (const listener of this.listeners.get(type) || []) await listener(event);
  }
  appendChild(child) {
    this.children.push(child);
    if (this.children.length === 1 && this.value === "") this.value = child.value;
    return child;
  }
  removeChild(child) {
    this.children = this.children.filter((item) => item !== child);
    if (this.value === child.value) this.value = this.children[0]?.value || "";
    return child;
  }
}

function makeDocument() {
  const ids = [
    "#connect-wallet", "#account-select", "#wallet-status", "#preflight-form",
    "#amount", "#previous-interactions", "#account-age-days", "#run-preflight",
    "#result-card", "#result-status", "#result-details", "#prepare-self-transfer",
    "#self-transfer-status", "#transfer-review", "#review-status", "#review-details",
    "#sign-self-transfer", "#cancel-self-transfer",
  ];
  const elements = new Map(ids.map((id) => [id, new FakeElement()]));
  const listeners = new Map();
  elements.get("#amount").value = "0.05";
  const appScript = { nonce: "test-csp-nonce", getAttribute(name) { return name === "nonce" ? this.nonce : null; } };
  return {
    elements,
    listeners,
    hidden: false,
    visibilityState: "visible",
    addEventListener(type, listener) {
      const current = listeners.get(type) || [];
      current.push(listener);
      listeners.set(type, current);
    },
    async emit(type, event = {}) {
      for (const listener of listeners.get(type) || []) await listener(event);
    },
    querySelector(selector) {
      if (selector === 'script[type="module"][nonce]' || selector === "script[nonce]") return appScript;
      return elements.get(selector) || null;
    },
    createElement() { return new FakeElement(); },
  };
}

class FakeWindow {
  constructor() {
    this.location = { origin: "http://127.0.0.1:4173" };
    this.listeners = new Map();
  }
  addEventListener(type, listener) {
    const current = this.listeners.get(type) || [];
    current.push(listener);
    this.listeners.set(type, current);
  }
  async emit(type, event = {}) {
    for (const listener of this.listeners.get(type) || []) await listener(event);
  }
}

function makeConnectedWallet(calls, getAccounts = async () => [
  { accountId: "defiaudit0x.testnet" }, { accountId: "secondary.testnet" },
]) {
  return {
    async getAccounts(options) {
      calls.getAccounts += 1;
      calls.getAccountsOptions = options;
      return getAccounts();
    },
    async signAndSendTransaction(params) {
      calls.signAndSendTransaction += 1;
      calls.signingParams = params;
      throw new Error("must not run");
    },
    async signAndSendTransactions() { calls.signAndSendTransactions += 1; throw new Error("must not run"); },
    async signTransaction() { calls.signTransaction += 1; throw new Error("must not run"); },
  };
}

function makeConnector(calls, wallet) {
  const handlers = new Map();
  return {
    network: "testnet",
    async connect() { calls.connect += 1; return wallet; },
    async wallet() { calls.connectorWallet += 1; throw new Error("wallet() must not be called by the UI"); },
    on(event, callback) { handlers.set(event, callback); },
    handlers,
  };
}

test("converts decimal NEAR exactly and enforces positive amount and 0.1 NEAR cap", () => {
  assert.equal(amountToYocto("0.05"), "50000000000000000000000");
  assert.equal(amountToYocto("0.1"), "100000000000000000000000");
  assert.throws(() => amountToYocto("0"), /greater than zero/);
  assert.throws(() => amountToYocto("0.100000000000000000000001"), /0.1 NEAR cap/);
  assert.throws(() => amountToYocto("1e-3"), /plain decimal/);
  assert.throws(() => amountToYocto("0.0000000000000000000000001"), /plain decimal/);
});

test("discloses Meteor SDK sign-in scope, separate transfer review, and RPC data use", () => {
  const markup = readFileSync(new URL("../ui/index.html", import.meta.url), "utf8");
  const riskIndex = markup.indexOf('id="meteor-sdk-disclosure"');
  const connectIndex = markup.indexOf('id="connect-wallet"');
  const rpcIndex = markup.indexOf('id="rpc-disclosure"');
  const preflightIndex = markup.indexOf('id="run-preflight"');
  assert.ok(riskIndex >= 0 && riskIndex < connectIndex, "SDK scope must precede Connect");
  assert.ok(rpcIndex >= 0 && rpcIndex < preflightIndex, "RPC disclosure must precede preflight");
  const riskDisclosure = markup.slice(riskIndex, connectIndex);
  assert.match(riskDisclosure, /@meteorwallet\/sdk/i);
  assert.match(riskDisclosure, /requests only ordinary NEAR Testnet account sign-in/i);
  assert.match(riskDisclosure, /does not request a function-call key, a message signature, or a transaction/i);
  assert.match(riskDisclosure, /fixed self-transfer is a separate flow/i);
  assert.match(riskDisclosure, /live transfer has not been tested/i);
  assert.match(markup, /Testnet account record saved by Meteor SDK/i);
  assert.match(markup, /not a live wallet account list/i);
  assert.match(markup, /not proof of current wallet ownership/i);
  assert.match(markup, /two-minute deadline from review creation.*remains active after you click Sign and ends only when the wallet prompt starts.*If it expires before then, the wallet prompt will not open/i);
  assert.match(markup, /this page cannot cancel it/i);
  const rpcDisclosure = markup.slice(rpcIndex, preflightIndex);
  assert.match(rpcDisclosure, /policy-only check runs before any RPC/i);
  assert.match(rpcDisclosure, /If policy allows the request and the other preflight checks pass,.*selected sender and recipient public account IDs to <code>https:\/\/rpc\.testnet\.near\.org<\/code> for read-only account lookups/i);
  assert.match(rpcDisclosure, /Final risk evaluation runs after those account reads and may return WARN or BLOCK/i);
  assert.doesNotMatch(rpcDisclosure, /WARN or BLOCK stops before that RPC read/i);
});

test("UI does not connect on mount and runs only read-only preflight after an explicit click", async () => {
  const calls = {
    createConnector: 0,
    connect: 0,
    getAccounts: 0,
    connectorWallet: 0,
    signAndSendTransaction: 0,
    signAndSendTransactions: 0,
    signTransaction: 0,
  };
  const document = makeDocument();
  const connector = makeConnector(calls, makeConnectedWallet(calls));
  const requests = [];
  const result = {
    mode: "TESTNET_PREFLIGHT_READ_ONLY",
    status: "PREPARED_NOT_SUBMITTED",
    submitted: false,
    guard: { decision: "ALLOW" },
    account: { network: "testnet", accountId: "defiaudit0x.testnet", balanceYocto: "900000000000000000000000" },
    intent: { transaction: { recipient: TESTNET_RECIPIENT, amount_yocto: "50000000000000000000000" } },
  };
  mountUI({
    createConnector() { calls.createConnector += 1; return connector; },
    document,
    connectionEnabled: true,
    async fetchImpl(url, options) {
      requests.push({ url, options });
      return { ok: true, async json() { return result; } };
    },
  });

  assert.equal(calls.createConnector, 0);
  assert.equal(calls.connect, 0);
  assert.equal(calls.getAccounts, 0);
  assert.equal(calls.connectorWallet, 0);
  assert.equal(document.elements.get("#run-preflight").disabled, true);

  await document.elements.get("#connect-wallet").emit("click");
  assert.equal(calls.createConnector, 1);
  assert.equal(calls.connect, 1);
  assert.equal(calls.getAccounts, 1);
  assert.equal(document.elements.get("#account-select").disabled, false);
  assert.equal(document.elements.get("#account-select").children.length, 2);
  assert.equal(document.elements.get("#account-select").value, "defiaudit0x.testnet");
  assert.equal(document.elements.get("#run-preflight").disabled, false);

  document.elements.get("#previous-interactions").value = "3";
  document.elements.get("#account-age-days").value = "365";
  await document.elements.get("#preflight-form").emit("submit", { preventDefault() {} });
  assert.equal(requests.length, 1);
  assert.equal(requests[0].url, "/api/preflight");
  assert.equal(requests[0].options.method, "POST");
  assert.deepEqual(JSON.parse(requests[0].options.body), {
    accountId: "defiaudit0x.testnet",
    recipient: "defiaudit0x.testnet",
    amountYocto: "50000000000000000000000",
    context: { previous_interactions: 3, account_age_days: 365 },
  });
  assert.match(document.elements.get("#result-status").textContent, /PREPARED_NOT_SUBMITTED/);
  assert.equal(calls.connectorWallet, 0);
  assert.equal(calls.signAndSendTransaction, 0);
  assert.equal(calls.signAndSendTransactions, 0);
  assert.equal(calls.signTransaction, 0);
});

test("entry point lazy loads Meteor SDK and requests ordinary sign-in only after an explicit click", async () => {
  const calls = { moduleLoad: 0, construct: 0, initialize: 0, actions: [], prompts: [], getAccount: 0 };
  const storage = { async getItem() { return null; }, async setItem() {}, async removeItem() {} };
  const signedInAccount = {
    identifier: { blockchain: "near", network: "testnet", accountId: "sample.testnet" },
  };
  class StubMeteorConnect {
    constructor() { calls.construct += 1; }
    async initialize(options) {
      calls.initialize += 1;
      calls.initializeOptions = options;
    }
    async createAction(request) {
      calls.actions.push(request);
      return {
        async promptForExecution() {
          calls.prompts.push(request.id);
          if (request.id !== "near::sign_in") throw new Error("Unexpected action in sign-in test");
          calls.storedAccount = signedInAccount;
          return signedInAccount;
        },
      };
    }
    async getAccount(identifier) {
      calls.getAccount += 1;
      const account = calls.storedAccount;
      return account?.identifier.blockchain === identifier.blockchain
        && account.identifier.network === identifier.network
        && account.identifier.accountId === identifier.accountId
        ? account
        : undefined;
    }
  }
  const document = makeDocument();
  const windowObject = new FakeWindow();
  mountLocalUI({
    document,
    windowObject,
    async loadMeteorSdk() {
      calls.moduleLoad += 1;
      return { MeteorConnect: StubMeteorConnect, webpage_local_storage: storage };
    },
  });

  assert.equal(document.elements.get("#connect-wallet").disabled, false);
  assert.equal(calls.moduleLoad, 0);
  assert.equal(calls.construct, 0);
  assert.equal(calls.initialize, 0);
  assert.equal(calls.actions.length, 0);
  assert.equal(calls.getAccount, 0);
  await document.elements.get("#connect-wallet").emit("click");

  assert.equal(calls.moduleLoad, 1);
  assert.equal(calls.construct, 1);
  assert.equal(calls.initialize, 1);
  assert.equal(calls.initializeOptions.storage, storage);
  assert.equal(calls.initializeOptions.mobileBridge.enabled, false);
  assert.equal(calls.initializeOptions.mobileBridge.autoOpenPairedWallet, false);
  assert.deepEqual(calls.initializeOptions.mobileBridge.partnerMetadata, {
    name: "Sentinel Guard Local Testnet Demo",
    description: "NEAR Testnet account sign-in and fixed-transfer review",
    originUrl: "http://127.0.0.1:4173",
  });
  assert.deepEqual(calls.initializeOptions.mobileBridge.transferAccounts, { enabled: false });
  assert.deepEqual(calls.initializeOptions.mobileBridge.newKeyTransfer, { enabled: false });
  assert.deepEqual(calls.actions, [{
    id: "near::sign_in",
    input: { target: { blockchain: "near", network: "testnet" } },
  }]);
  assert.equal(Object.hasOwn(calls.actions[0].input, "addFunctionCallKey"), false);
  assert.deepEqual(calls.prompts, ["near::sign_in"]);
  assert.equal(calls.actions.some(({ id }) => id === "near::sign_transactions"), false);
  assert.equal(calls.getAccount, 2);
  assert.equal(document.elements.get("#account-select").children.length, 1);
  assert.equal(document.elements.get("#account-select").value, "sample.testnet");
  assert.equal(document.elements.get("#run-preflight").disabled, false);
});

test("mocked fixed transfer uses the Testnet account record saved by Meteor SDK only after ALLOW and review", async () => {
  const calls = { actions: [], prompts: [], getAccount: 0 };
  const signedInAccount = {
    identifier: {
      blockchain: "near",
      network: "testnet",
      accountId: TESTNET_SELF_TRANSFER_ACCOUNT,
    },
  };
  class StubMeteorConnect {
    async initialize() {}
    async createAction(request) {
      calls.actions.push(request);
      return {
        async promptForExecution() {
          calls.prompts.push(request.id);
          if (request.id === "near::sign_in") {
            calls.storedAccount = signedInAccount;
            return signedInAccount;
          }
          return [{ mockOnly: true }];
        },
      };
    }
    async getAccount(identifier) {
      calls.getAccount += 1;
      const account = calls.storedAccount;
      return account?.identifier.blockchain === identifier.blockchain
        && account.identifier.network === identifier.network
        && account.identifier.accountId === identifier.accountId
        ? account
        : undefined;
    }
  }
  const adapter = createMeteorConnectAdapter({
    MeteorConnect: StubMeteorConnect,
    webpage_local_storage: {},
    windowObject: new FakeWindow(),
  });
  const document = makeDocument();
  document.elements.get("#previous-interactions").value = "3";
  document.elements.get("#account-age-days").value = "365";
  const result = await makeSelfTransferResult();
  mountUI({
    createConnector: () => adapter,
    document,
    connectionEnabled: true,
    async fetchImpl() { return { ok: true, async json() { return result; } }; },
  });

  assert.equal(calls.actions.length, 0, "mount must not initialize or connect to Meteor");
  await document.elements.get("#connect-wallet").emit("click");
  assert.deepEqual(calls.prompts, ["near::sign_in"]);
  assert.equal(calls.actions.some(({ id }) => id === "near::sign_transactions"), false);

  await document.elements.get("#prepare-self-transfer").emit("click");
  assert.equal(document.elements.get("#transfer-review").hidden, false);
  assert.deepEqual(calls.prompts, ["near::sign_in"], "ALLOW and review must not open a transaction prompt");
  assert.equal(calls.actions.some(({ id }) => id === "near::sign_transactions"), false);

  await document.elements.get("#sign-self-transfer").emit("click");
  assert.deepEqual(calls.prompts, ["near::sign_in", "near::sign_transactions"]);
  const transactionRequest = calls.actions.find(({ id }) => id === "near::sign_transactions");
  assert.ok(transactionRequest);
  assert.deepEqual(transactionRequest.input.target, {
    blockchain: "near",
    network: "testnet",
    accountId: TESTNET_SELF_TRANSFER_ACCOUNT,
  });
  assert.equal(transactionRequest.input.useFunctionCallKey, false);
  assert.equal(transactionRequest.input.transactions.length, 1);
  const [transaction] = transactionRequest.input.transactions;
  assert.equal(transaction.receiverId, TESTNET_SELF_TRANSFER_ACCOUNT);
  assert.equal(transaction.actions.length, 1);
  assert.equal(transaction.actions[0].enum, "transfer");
  assert.equal(transaction.actions[0].transfer.deposit, BigInt(TESTNET_SELF_TRANSFER_AMOUNT_YOCTO));
  assert.equal(document.elements.get("#prepare-self-transfer").disabled, true, "a completed wallet prompt keeps this page session locked");
});

test("Meteor adapter does not open the wallet prompt when SDK action creation outlives the review", async () => {
  const calls = { actions: [], prompts: [] };
  const actionStarted = deferred();
  const releaseAction = deferred();
  let promptStarted = 0;
  const signedInAccount = {
    identifier: {
      blockchain: "near",
      network: "testnet",
      accountId: TESTNET_SELF_TRANSFER_ACCOUNT,
    },
  };
  let now = 1_800_000_000_000;
  let monotonicNow = 5;
  class DelayedMeteorConnect {
    async initialize() {}
    async createAction(request) {
      calls.actions.push(request);
      if (request.id === "near::sign_transactions") {
        actionStarted.resolve();
        await releaseAction.promise;
      }
      return {
        async promptForExecution() {
          calls.prompts.push(request.id);
          if (request.id === "near::sign_in") return signedInAccount;
          return [{ mockOnly: true }];
        },
      };
    }
    async getAccount(identifier) {
      return identifier.accountId === signedInAccount.identifier.accountId
        ? signedInAccount
        : undefined;
    }
  }
  const adapter = createMeteorConnectAdapter({
    MeteorConnect: DelayedMeteorConnect,
    webpage_local_storage: {},
    windowObject: new FakeWindow(),
    clock: () => now,
    monotonicClock: () => monotonicNow,
  });
  const wallet = await adapter.connect();
  const createdAt = now;
  const expiresAt = now + 120_000;
  const monotonicCreatedAt = monotonicNow;
  const monotonicExpiresAt = monotonicCreatedAt + 120_000;
  const signing = wallet.signAndSendTransaction({
    network: "testnet",
    signerId: TESTNET_SELF_TRANSFER_ACCOUNT,
    receiverId: TESTNET_SELF_TRANSFER_ACCOUNT,
    actions: [{ type: "Transfer", params: { deposit: TESTNET_SELF_TRANSFER_AMOUNT_YOCTO } }],
  }, {
    createdAt,
    expiresAt,
    monotonicCreatedAt,
    monotonicExpiresAt,
    onWalletPromptStarted() { promptStarted += 1; },
  });

  await actionStarted.promise;
  now = expiresAt;
  monotonicNow = monotonicCreatedAt + 1;
  releaseAction.resolve();
  await assert.rejects(signing, /Transfer review expired before the wallet prompt could open/);
  assert.equal(calls.actions.filter(({ id }) => id === "near::sign_transactions").length, 1);
  assert.deepEqual(calls.prompts, ["near::sign_in"]);
  assert.equal(promptStarted, 0, "an error before promptForExecution must not signal a wallet prompt");
});

test("Meteor adapter blocks a late wallet prompt when wall time moves backward during SDK action creation", async () => {
  const calls = { actions: [], prompts: [] };
  const actionStarted = deferred();
  const releaseAction = deferred();
  const signedInAccount = {
    identifier: {
      blockchain: "near",
      network: "testnet",
      accountId: TESTNET_SELF_TRANSFER_ACCOUNT,
    },
  };
  let wallNow = 1_800_000_000_000;
  let monotonicNow = 42.25;
  class DelayedMeteorConnect {
    async initialize() {}
    async createAction(request) {
      calls.actions.push(request);
      if (request.id === "near::sign_transactions") {
        actionStarted.resolve();
        await releaseAction.promise;
      }
      return {
        async promptForExecution() {
          calls.prompts.push(request.id);
          if (request.id === "near::sign_in") return signedInAccount;
          return [{ mockOnly: true }];
        },
      };
    }
    async getAccount(identifier) {
      return identifier.accountId === signedInAccount.identifier.accountId
        ? signedInAccount
        : undefined;
    }
  }
  const adapter = createMeteorConnectAdapter({
    MeteorConnect: DelayedMeteorConnect,
    webpage_local_storage: {},
    windowObject: new FakeWindow(),
    clock: () => wallNow,
    monotonicClock: () => monotonicNow,
  });
  const wallet = await adapter.connect();
  const createdAt = wallNow;
  const monotonicCreatedAt = monotonicNow;
  const monotonicExpiresAt = monotonicCreatedAt + 120_000;
  const signing = wallet.signAndSendTransaction({
    network: "testnet",
    signerId: TESTNET_SELF_TRANSFER_ACCOUNT,
    receiverId: TESTNET_SELF_TRANSFER_ACCOUNT,
    actions: [{ type: "Transfer", params: { deposit: TESTNET_SELF_TRANSFER_AMOUNT_YOCTO } }],
  }, {
    createdAt,
    expiresAt: createdAt + 120_000,
    monotonicCreatedAt,
    monotonicExpiresAt,
  });

  await actionStarted.promise;
  wallNow -= 60_000;
  monotonicNow = monotonicCreatedAt + 1;
  assert.ok(wallNow < 1_800_000_000_000, "the mocked system clock moved backward");
  releaseAction.resolve();
  await assert.rejects(signing, /Transfer review expired before the wallet prompt could open/);
  assert.equal(calls.actions.filter(({ id }) => id === "near::sign_transactions").length, 1);
  assert.deepEqual(calls.prompts, ["near::sign_in"]);
});

test("Meteor SDK adapter rejects a non-Testnet sign-in result", async () => {
  class MainnetMeteorConnect {
    async initialize() {}
    async createAction() {
      return { async promptForExecution() {
        return { identifier: { blockchain: "near", network: "mainnet", accountId: "sample.near" } };
      } };
    }
  }
  const adapter = createMeteorConnectAdapter({
    MeteorConnect: MainnetMeteorConnect,
    webpage_local_storage: {},
    windowObject: new FakeWindow(),
  });
  await assert.rejects(adapter.connect(), /NEAR Testnet account/);
});

test("leaves unknown risk context out instead of inventing history", async () => {
  const calls = { createConnector: 0, connect: 0, getAccounts: 0, connectorWallet: 0, signAndSendTransaction: 0, signAndSendTransactions: 0, signTransaction: 0 };
  const document = makeDocument();
  const connector = makeConnector(calls, makeConnectedWallet(calls));
  let body;
  mountUI({
    createConnector() { calls.createConnector += 1; return connector; },
    document,
    connectionEnabled: true,
    async fetchImpl(_url, options) {
      body = JSON.parse(options.body);
      return { ok: true, async json() {
        return { status: "NEEDS_REVIEW", submitted: false, guard: { decision: "WARN" }, account: null, intent: { transaction: { recipient: TESTNET_RECIPIENT, amount_yocto: body.amountYocto } } };
      } };
    },
  });
  await document.elements.get("#connect-wallet").emit("click");
  await document.elements.get("#preflight-form").emit("submit", { preventDefault() {} });
  assert.deepEqual(body.context, {});
  assert.match(document.elements.get("#result-status").textContent, /NEEDS_REVIEW/);
  const displayed = JSON.parse(document.elements.get("#result-details").textContent);
  assert.equal(displayed.accountRead, false);
  assert.match(displayed.network, /lookup not performed/);
  assert.equal(calls.signAndSendTransaction + calls.signAndSendTransactions + calls.signTransaction, 0);
});


test("fixed self-transfer requires a separate click and sends the same frozen exact payload once", async () => {
  const result = await makeSelfTransferResult();
  const app = await makeSelfTransferApp({ result });
  await app.document.elements.get("#prepare-self-transfer").emit("click");

  assert.equal(app.calls.requests.length, 1);
  const requestBody = JSON.parse(app.calls.requests[0].options.body);
  assert.deepEqual(requestBody, {
    accountId: TESTNET_SELF_TRANSFER_ACCOUNT,
    recipient: TESTNET_SELF_TRANSFER_ACCOUNT,
    amountYocto: TESTNET_SELF_TRANSFER_AMOUNT_YOCTO,
    context: { previous_interactions: 3, account_age_days: 365 },
  });
  assert.equal(app.calls.getAccountsOptions.network, "testnet");
  assert.equal(app.calls.signAndSendTransaction, 0, "ALLOW must never call the wallet automatically");
  assert.equal(app.document.elements.get("#transfer-review").hidden, false);
  const displayed = JSON.parse(app.document.elements.get("#review-details").textContent);
  assert.equal(displayed.network, "testnet");
  assert.equal(displayed.sender, TESTNET_SELF_TRANSFER_ACCOUNT);
  assert.equal(displayed.receiver, TESTNET_SELF_TRANSFER_ACCOUNT);
  assert.equal(displayed.action, "Transfer (native NEAR transfer)");
  assert.equal(displayed.amountNear, "0.001");
  assert.equal(displayed.amountYocto, TESTNET_SELF_TRANSFER_AMOUNT_YOCTO);

  await app.document.elements.get("#sign-self-transfer").emit("click");
  assert.equal(app.calls.signAndSendTransaction, 1);
  assert.deepEqual(app.calls.signingParams, {
    network: "testnet",
    signerId: TESTNET_SELF_TRANSFER_ACCOUNT,
    receiverId: TESTNET_SELF_TRANSFER_ACCOUNT,
    actions: [{ type: "Transfer", params: { deposit: TESTNET_SELF_TRANSFER_AMOUNT_YOCTO } }],
  });
  assert.equal(Object.isFrozen(app.calls.signingParams), true);
  assert.equal(Object.isFrozen(app.calls.signingParams.actions[0].params), true);
  assert.equal(app.calls.signingOptions.expiresAt, Date.parse(displayed.expiresAt));
  assert.equal(app.calls.signingOptions.monotonicExpiresAt,
    app.calls.signingOptions.monotonicCreatedAt + 120_000);
  assert.deepEqual(app.calls.getAccountsOptions, { network: "testnet" });
  await app.document.elements.get("#sign-self-transfer").emit("click");
  assert.equal(app.calls.signAndSendTransaction, 1, "one guard request can reach the mock signer at most once");
});

test("hiding and resuming the page invalidates the visible review and does not restore it", async () => {
  const app = await makeSelfTransferApp({ result: await makeSelfTransferResult() });
  await app.document.elements.get("#prepare-self-transfer").emit("click");
  assert.equal(app.document.elements.get("#transfer-review").hidden, false);

  app.document.hidden = true;
  app.document.visibilityState = "hidden";
  await app.document.emit("visibilitychange");
  assert.equal(app.document.elements.get("#transfer-review").hidden, true);

  app.document.hidden = false;
  app.document.visibilityState = "visible";
  await app.document.emit("visibilitychange");
  await app.windowObject.emit("blur");
  await app.windowObject.emit("focus");
  await app.document.elements.get("#prepare-self-transfer").emit("click");
  await app.document.emit("freeze");
  await app.document.emit("resume");
  assert.equal(app.document.elements.get("#transfer-review").hidden, true);
  await app.document.elements.get("#sign-self-transfer").emit("click");
  assert.equal(app.calls.signAndSendTransaction, 0);
});

test("a pending ALLOW cannot recreate a review after lifecycle invalidation", async () => {
  const result = await makeSelfTransferResult();
  const response = deferred();
  const requestStarted = deferred();
  const app = await makeSelfTransferApp({
    result,
    fetchImpl() {
      requestStarted.resolve();
      return response.promise;
    },
  });
  const preparing = app.document.elements.get("#prepare-self-transfer").emit("click");
  await requestStarted.promise;
  app.document.hidden = true;
  app.document.visibilityState = "hidden";
  await app.document.emit("visibilitychange");
  app.document.hidden = false;
  app.document.visibilityState = "visible";
  await app.document.emit("visibilitychange");
  response.resolve({ ok: true, async json() { return result; } });
  await preparing;

  assert.equal(app.document.elements.get("#transfer-review").hidden, true);
  assert.match(app.document.elements.get("#self-transfer-status").textContent, /changed while preflight was pending/i);
  await app.document.elements.get("#sign-self-transfer").emit("click");
  assert.equal(app.calls.signAndSendTransaction, 0);
});

test("BFCache pagehide/pageshow invalidates a fixed-transfer review", async () => {
  const app = await makeSelfTransferApp({ result: await makeSelfTransferResult() });
  await app.document.elements.get("#prepare-self-transfer").emit("click");
  await app.windowObject.emit("pagehide", { persisted: true });
  assert.equal(app.document.elements.get("#transfer-review").hidden, true);
  await app.windowObject.emit("pageshow", { persisted: true });
  await app.document.elements.get("#sign-self-transfer").emit("click");
  assert.equal(app.calls.signAndSendTransaction, 0);
});

test("wall-clock rollback invalidates a review even while the monotonic deadline remains active", async () => {
  const app = await makeSelfTransferApp({ result: await makeSelfTransferResult() });
  await app.document.elements.get("#prepare-self-transfer").emit("click");
  app.setWallNow(1_799_999_999_999);
  await app.document.elements.get("#sign-self-transfer").emit("click");

  assert.equal(app.calls.signAndSendTransaction, 0);
  assert.equal(app.document.elements.get("#transfer-review").hidden, true);
  assert.match(app.document.elements.get("#self-transfer-status").textContent, /wall clock moved backward/i);
});

test("a partial wall-clock rollback after an earlier check cannot extend the review", async () => {
  const accountReadStarted = deferred();
  const releaseAccountRead = deferred();
  let delayNextAccountRead = false;
  const initialWallNow = 1_800_000_000_000;
  const app = await makeSelfTransferApp({
    result: await makeSelfTransferResult(),
    now: initialWallNow,
    getAccountsImpl: async () => {
      if (delayNextAccountRead) {
        delayNextAccountRead = false;
        accountReadStarted.resolve();
        await releaseAccountRead.promise;
      }
      return [{ accountId: TESTNET_SELF_TRANSFER_ACCOUNT }];
    },
  });
  await app.document.elements.get("#prepare-self-transfer").emit("click");
  delayNextAccountRead = true;
  app.setWallNow(initialWallNow + 30_000);
  const signing = app.document.elements.get("#sign-self-transfer").emit("click");
  await accountReadStarted.promise;
  app.setWallNow(initialWallNow + 10_000);
  releaseAccountRead.resolve();
  await signing;

  assert.equal(app.calls.signAndSendTransaction, 0);
  assert.equal(app.document.elements.get("#transfer-review").hidden, true);
  assert.match(app.document.elements.get("#self-transfer-status").textContent, /wall clock moved backward/i);
});

test("ALLOW cannot create a review when risk inputs change during the pending preflight", async () => {
  const result = await makeSelfTransferResult();
  const response = deferred();
  const requestStarted = deferred();
  const app = await makeSelfTransferApp({
    result,
    fetchImpl() {
      requestStarted.resolve();
      return response.promise;
    },
  });
  const preparing = app.document.elements.get("#prepare-self-transfer").emit("click");
  await requestStarted.promise;
  const previousInteractions = app.document.elements.get("#previous-interactions");
  previousInteractions.value = "4";
  await previousInteractions.emit("input");
  response.resolve({ ok: true, async json() { return result; } });
  await preparing;

  assert.deepEqual(JSON.parse(app.calls.requests[0].options.body).context, {
    previous_interactions: 3,
    account_age_days: 365,
  });
  assert.equal(app.document.elements.get("#transfer-review").hidden, true);
  assert.match(app.document.elements.get("#self-transfer-status").textContent, /changed while preflight was pending/i);
  await app.document.elements.get("#sign-self-transfer").emit("click");
  assert.equal(app.calls.signAndSendTransaction, 0);
});

test("a stalled read-only preflight times out, aborts the fetch, and releases the UI", async () => {
  const request = deferred();
  const requestStarted = deferred();
  let requestSignal;
  const app = await makeSelfTransferApp({
    result: await makeSelfTransferResult(),
    fetchImpl(_url, options) {
      requestSignal = options.signal;
      requestStarted.resolve();
      return request.promise;
    },
  });
  const preparing = app.document.elements.get("#prepare-self-transfer").emit("click");
  await requestStarted.promise;
  assert.equal(app.document.elements.get("#prepare-self-transfer").disabled, true);

  app.fireTimer(15_000);
  await preparing;

  assert.equal(requestSignal.aborted, true);
  assert.equal(app.document.elements.get("#transfer-review").hidden, true);
  assert.match(app.document.elements.get("#self-transfer-status").textContent, /read-only preflight timed out/i);
  assert.equal(app.document.elements.get("#prepare-self-transfer").disabled, false);
  assert.equal(app.calls.signAndSendTransaction, 0);
});

test("review expiry while awaiting the saved account record blocks before calling the wallet", async () => {
  const accountReadStarted = deferred();
  const releaseAccountRead = deferred();
  let delayNextAccountRead = false;
  const app = await makeSelfTransferApp({
    result: await makeSelfTransferResult(),
    getAccountsImpl: async () => {
      if (delayNextAccountRead) {
        delayNextAccountRead = false;
        accountReadStarted.resolve();
        await releaseAccountRead.promise;
      }
      return [{ accountId: TESTNET_SELF_TRANSFER_ACCOUNT }];
    },
  });
  await app.document.elements.get("#prepare-self-transfer").emit("click");
  const expiresAt = Date.parse(JSON.parse(app.document.elements.get("#review-details").textContent).expiresAt);
  delayNextAccountRead = true;
  const signing = app.document.elements.get("#sign-self-transfer").emit("click");
  await accountReadStarted.promise;
  app.setNow(expiresAt);
  releaseAccountRead.resolve();
  await signing;

  assert.equal(app.calls.signAndSendTransaction, 0);
  assert.equal(app.document.elements.get("#transfer-review").hidden, true);
  assert.match(app.document.elements.get("#self-transfer-status").textContent, /review expired/i);
});

test("an untouched fixed-transfer review closes automatically at its deadline", async () => {
  const app = await makeSelfTransferApp({ result: await makeSelfTransferResult() });
  await app.document.elements.get("#prepare-self-transfer").emit("click");
  const expiresAt = Date.parse(JSON.parse(app.document.elements.get("#review-details").textContent).expiresAt);
  assert.equal(app.document.elements.get("#transfer-review").hidden, false);
  assert.equal(app.document.elements.get("#sign-self-transfer").disabled, false);

  app.setNow(expiresAt);
  app.fireTimer(120_000);

  assert.equal(app.document.elements.get("#transfer-review").hidden, true);
  assert.equal(app.document.elements.get("#sign-self-transfer").disabled, true);
  assert.match(app.document.elements.get("#review-status").textContent, /no wallet prompt was opened/i);
  await app.document.elements.get("#sign-self-transfer").emit("click");
  assert.equal(app.calls.signAndSendTransaction, 0);
});

test("fixed self-transfer review fails closed when a monotonic clock is unavailable", async () => {
  const app = await makeSelfTransferApp({
    result: await makeSelfTransferResult(),
    monotonicClockImpl: () => undefined,
  });
  await app.document.elements.get("#prepare-self-transfer").emit("click");
  assert.equal(app.document.elements.get("#transfer-review").hidden, true);
  assert.match(app.document.elements.get("#self-transfer-status").textContent, /monotonic review clock is unavailable/i);
  await app.document.elements.get("#sign-self-transfer").emit("click");
  assert.equal(app.calls.signAndSendTransaction, 0);
});

test("fixed self-transfer WARN and BLOCK decisions never show signing approval or call the wallet", async () => {
  for (const decision of ["WARN", "BLOCK"]) {
    const result = await makeSelfTransferResult({ guard: { decision } });
    const app = await makeSelfTransferApp({ result });
    await app.document.elements.get("#prepare-self-transfer").emit("click");
    assert.equal(app.document.elements.get("#transfer-review").hidden, true, decision);
    assert.match(app.document.elements.get("#self-transfer-status").textContent, new RegExp(`guard ${decision}`));
    await app.document.elements.get("#sign-self-transfer").emit("click");
    assert.equal(app.calls.signAndSendTransaction, 0, decision);
  }
});

test("fixed self-transfer fails closed for mismatched account, network, receiver, action, amount, balance, status, or hash", async () => {
  const goodContext = { previous_interactions: 3, account_age_days: 365 };
  const wrongIntents = [
    ["action", { action: "function_call", resource: TESTNET_SELF_TRANSFER_ACCOUNT, transaction: {
      recipient: TESTNET_SELF_TRANSFER_ACCOUNT, amount_yocto: TESTNET_SELF_TRANSFER_AMOUNT_YOCTO, ...goodContext,
    } }],
    ["receiver", { action: "transfer", resource: "attacker.testnet", transaction: {
      recipient: "attacker.testnet", amount_yocto: TESTNET_SELF_TRANSFER_AMOUNT_YOCTO, ...goodContext,
    } }],
    ["amount", { action: "transfer", resource: TESTNET_SELF_TRANSFER_ACCOUNT, transaction: {
      recipient: TESTNET_SELF_TRANSFER_ACCOUNT, amount_yocto: "1000000000000000000001", ...goodContext,
    } }],
  ];
  const cases = [
    ["wrong account snapshot", { account: { accountId: "other.testnet" } }],
    ["wrong network snapshot", { account: { network: "mainnet" } }],
    ["insufficient balance", { account: { balanceYocto: "0" } }],
    ["bad request ID", { guard: { request_id: "not-a-uuid" } }],
    ["bad guard hash", { guard: { intent_hash: "0".repeat(64) } }],
    ["not prepared", { status: "NEEDS_REVIEW" }],
    ["already submitted", { submitted: true }],
    ...wrongIntents.map(([label, intent]) => [label, { intent }]),
  ];
  for (const [label, resultOptions] of cases) {
    const result = await makeSelfTransferResult({ context: goodContext, ...resultOptions });
    const app = await makeSelfTransferApp({ result });
    await app.document.elements.get("#prepare-self-transfer").emit("click");
    assert.equal(app.document.elements.get("#transfer-review").hidden, true, label);
    await app.document.elements.get("#sign-self-transfer").emit("click");
    assert.equal(app.calls.signAndSendTransaction, 0, label);
  }
});

test("the controller rejects a server account absent from its adapter's Testnet account record", async () => {
  const result = await makeSelfTransferResult();
  const app = await makeSelfTransferApp({
    result,
    walletAccounts: [{ accountId: "secondary.testnet" }],
  });
  await app.document.elements.get("#prepare-self-transfer").emit("click");
  assert.equal(app.calls.requests.length, 0);
  assert.equal(app.document.elements.get("#transfer-review").hidden, true);
  assert.equal(app.calls.signAndSendTransaction, 0);
});

test("network or connected-account changes at the signing boundary prevent the mock signer", async () => {
  for (const change of ["network", "account"]) {
    const result = await makeSelfTransferResult();
    const app = await makeSelfTransferApp({ result });
    await app.document.elements.get("#prepare-self-transfer").emit("click");
    if (change === "network") app.connector.network = "mainnet";
    else app.wallet.getAccounts = async () => [{ accountId: "secondary.testnet" }];
    await app.document.elements.get("#sign-self-transfer").emit("click");
    assert.equal(app.calls.signAndSendTransaction, 0, change);
    assert.equal(app.document.elements.get("#transfer-review").hidden, true, change);
  }
});

test("mutating a reviewed input invalidates the review and cannot reach the mock signer", async () => {
  const result = await makeSelfTransferResult();
  const app = await makeSelfTransferApp({ result });
  await app.document.elements.get("#prepare-self-transfer").emit("click");
  assert.equal(app.document.elements.get("#transfer-review").hidden, false);
  app.document.elements.get("#previous-interactions").value = "4";
  await app.document.elements.get("#previous-interactions").emit("input");
  assert.equal(app.document.elements.get("#transfer-review").hidden, true);
  await app.document.elements.get("#sign-self-transfer").emit("click");
  assert.equal(app.calls.signAndSendTransaction, 0);
});

test("cancelled review and an expired review never call the mock signer", async () => {
  const cancelled = await makeSelfTransferApp({ result: await makeSelfTransferResult() });
  await cancelled.document.elements.get("#prepare-self-transfer").emit("click");
  await cancelled.document.elements.get("#cancel-self-transfer").emit("click");
  await cancelled.document.elements.get("#sign-self-transfer").emit("click");
  assert.equal(cancelled.calls.signAndSendTransaction, 0);
  assert.match(cancelled.document.elements.get("#review-status").textContent, /cancelled/i);

  const expired = await makeSelfTransferApp({ result: await makeSelfTransferResult() });
  await expired.document.elements.get("#prepare-self-transfer").emit("click");
  expired.setNow(1_800_000_121_000);
  await expired.document.elements.get("#sign-self-transfer").emit("click");
  assert.equal(expired.calls.signAndSendTransaction, 0);
  assert.equal(expired.document.elements.get("#transfer-review").hidden, true);
});

test("malformed preflight response cannot expose or invoke the mock signer", async () => {
  const app = await makeSelfTransferApp({ result: null, jsonError: new SyntaxError("invalid JSON") });
  await app.document.elements.get("#prepare-self-transfer").emit("click");
  assert.equal(app.document.elements.get("#transfer-review").hidden, true);
  await app.document.elements.get("#sign-self-transfer").emit("click");
  assert.equal(app.calls.signAndSendTransaction, 0);
});

test("page blur during a pending wallet prompt is not shown as cancellation and locks another attempt", async () => {
  const app = await makeSelfTransferApp({ result: await makeSelfTransferResult() });
  const prompt = deferred();
  const requestStarted = deferred();
  await app.document.elements.get("#prepare-self-transfer").emit("click");
  app.wallet.signAndSendTransaction = async (params, options) => {
    app.calls.signAndSendTransaction += 1;
    app.calls.signingParams = params;
    app.calls.signingOptions = options;
    requestStarted.resolve();
    return prompt.promise;
  };

  const signing = app.document.elements.get("#sign-self-transfer").emit("click");
  await requestStarted.promise;
  app.calls.signingOptions.onWalletPromptStarted?.();
  await app.windowObject.emit("blur");

  const pendingStatus = app.document.elements.get("#review-status").textContent;
  assert.match(pendingStatus, /cannot cancel/i);
  assert.match(pendingStatus, /may still be pending/i);
  assert.doesNotMatch(pendingStatus, /review cancelled/i);
  assert.equal(app.document.elements.get("#cancel-self-transfer").disabled, true);
  assert.equal(app.document.elements.get("#prepare-self-transfer").disabled, true);
  await app.document.elements.get("#cancel-self-transfer").emit("click");
  assert.equal(app.calls.signAndSendTransaction, 1);

  prompt.resolve({ transaction: "mock-only" });
  await signing;
  await app.document.elements.get("#prepare-self-transfer").emit("click");
  assert.equal(app.document.elements.get("#prepare-self-transfer").disabled, true);
  assert.equal(app.calls.signAndSendTransaction, 1);
  assert.match(app.document.elements.get("#review-status").textContent, /locked for this page session/i);
});

test("a wallet-reported rejection is attempted once and is not retried automatically", async () => {
  const app = await makeSelfTransferApp({
    result: await makeSelfTransferResult(),
    walletError: new Error("User rejected the request"),
  });
  await app.document.elements.get("#prepare-self-transfer").emit("click");
  await app.document.elements.get("#sign-self-transfer").emit("click");
  await app.document.elements.get("#sign-self-transfer").emit("click");
  assert.equal(app.calls.signAndSendTransaction, 1);
  assert.match(app.document.elements.get("#review-status").textContent, /outcome may be unknown/i);
  assert.equal(app.document.elements.get("#prepare-self-transfer").disabled, true);
});

test("a pre-prompt adapter failure is not classified as an unknown wallet outcome", async () => {
  const app = await makeSelfTransferApp({
    fetchImpl: async () => ({ ok: true, async json() { return makeSelfTransferResult(); } }),
  });
  await app.document.elements.get("#prepare-self-transfer").emit("click");
  app.wallet.signAndSendTransaction = async (params, options) => {
    app.calls.signAndSendTransaction += 1;
    app.calls.signingParams = params;
    app.calls.signingOptions = options;
    throw new Error("Meteor action creation failed");
  };

  await app.document.elements.get("#sign-self-transfer").emit("click");

  const status = app.document.elements.get("#self-transfer-status").textContent;
  assert.match(status, /wallet prompt was not opened/i);
  assert.match(status, /no wallet action was requested/i);
  assert.match(status, /Meteor action creation failed/i);
  assert.doesNotMatch(status, /outcome may be unknown/i);
  assert.equal(app.document.elements.get("#transfer-review").hidden, true);
  assert.equal(app.document.elements.get("#prepare-self-transfer").disabled, false);
  await app.document.elements.get("#prepare-self-transfer").emit("click");
  assert.equal(app.document.elements.get("#transfer-review").hidden, false, "a fresh review remains available after a pre-prompt failure");
  assert.equal(app.calls.signAndSendTransaction, 1);
});


test("silent mutation of reviewed form fields is caught again at the signing boundary", async () => {
  const app = await makeSelfTransferApp({ result: await makeSelfTransferResult() });
  await app.document.elements.get("#prepare-self-transfer").emit("click");
  app.document.elements.get("#account-age-days").value = "366";
  await app.document.elements.get("#sign-self-transfer").emit("click");
  assert.equal(app.calls.signAndSendTransaction, 0);
  assert.equal(app.document.elements.get("#transfer-review").hidden, true);
  assert.match(app.document.elements.get("#self-transfer-status").textContent, /reviewed input changed/i);
});
