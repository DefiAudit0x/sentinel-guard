import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { amountToYocto, mountUI, TESTNET_RECIPIENT } from "../ui/controller.mjs";
import {
  createGuardedMeteorConnector,
  METEOR_EXECUTOR_URL,
  METEOR_WALLET_ID,
  mountLocalUI,
} from "../ui/main.mjs";

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
    "#result-card", "#result-status", "#result-details",
  ];
  const elements = new Map(ids.map((id) => [id, new FakeElement()]));
  elements.get("#amount").value = "0.05";
  const appScript = { nonce: "test-csp-nonce", getAttribute(name) { return name === "nonce" ? this.nonce : null; } };
  return {
    elements,
    querySelector(selector) {
      if (selector === 'script[type="module"][nonce]' || selector === "script[nonce]") return appScript;
      return elements.get(selector) || null;
    },
    createElement() { return new FakeElement(); },
  };
}

class FakeWindow {
  constructor() { this.listeners = new Map(); }
  addEventListener(type, listener, capture = false) {
    const listeners = this.listeners.get(type) || [];
    listeners.push({ listener, capture: capture === true });
    this.listeners.set(type, listeners);
  }
  removeEventListener(type, listener, capture = false) {
    const listeners = this.listeners.get(type) || [];
    this.listeners.set(type, listeners.filter((entry) => entry.listener !== listener
      || entry.capture !== (capture === true)));
  }
  dispatch(type, values = {}) {
    let stopped = false;
    const event = {
      ...values,
      type,
      stopImmediatePropagation() { stopped = true; },
      preventDefault() {},
    };
    const listeners = this.listeners.get(type) || [];
    for (const capture of [true, false]) {
      for (const entry of listeners) {
        if (entry.capture !== capture) continue;
        entry.listener(event);
        if (stopped) return event;
      }
    }
    return event;
  }
}

function makeConnectedWallet(calls) {
  return {
    async getAccounts() {
      calls.getAccounts += 1;
      return [{ accountId: "defiaudit0x.testnet" }, { accountId: "secondary.testnet" }];
    },
    async signAndSendTransaction() { calls.signAndSendTransaction += 1; throw new Error("must not run"); },
    async signAndSendTransactions() { calls.signAndSendTransactions += 1; throw new Error("must not run"); },
    async signTransaction() { calls.signTransaction += 1; throw new Error("must not run"); },
  };
}

function makeConnector(calls, wallet) {
  const handlers = new Map();
  return {
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

test("discloses third-party executor risk before Connect and RPC data use before preflight", () => {
  const markup = readFileSync(new URL("../ui/index.html", import.meta.url), "utf8");
  const riskIndex = markup.indexOf('id="executor-risk-disclosure"');
  const connectIndex = markup.indexOf('id="connect-wallet"');
  const rpcIndex = markup.indexOf('id="rpc-disclosure"');
  const preflightIndex = markup.indexOf('id="run-preflight"');
  assert.ok(riskIndex >= 0 && riskIndex < connectIndex, "executor risk must precede Connect");
  assert.ok(rpcIndex >= 0 && rpcIndex < preflightIndex, "RPC disclosure must precede preflight");
  const riskDisclosure = markup.slice(riskIndex, connectIndex);
  assert.match(riskDisclosure, /Meteor's executor.*pinned to commit <code>6369ad7<\/code>/i);
  assert.match(riskDisclosure, /requests wallet account sign-in/i);
  assert.match(riskDisclosure, /storage permission.*meteorCom.*meteorComV2/i);
  assert.match(riskDisclosure, /not been audited here/i);
  assert.match(riskDisclosure, /cannot guarantee what its code does when you connect/i);
  assert.match(riskDisclosure, /application's code contains no transaction-signing or submission call/i);
  const rpcDisclosure = markup.slice(rpcIndex, preflightIndex);
  assert.match(rpcDisclosure, /If the local guard returns ALLOW.*selected public account ID to <code>https:\/\/rpc\.testnet\.near\.org<\/code> for a read-only account lookup/i);
  assert.match(rpcDisclosure, /WARN or BLOCK stops before that RPC read/i);
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

test("entry point lazily creates a testnet connector with only the pinned Meteor executor", async () => {
  const calls = {
    moduleLoad: 0,
    construct: 0,
    connect: 0,
    injectedHandler: 0,
    getAccounts: 0,
    connectorWallet: 0,
    signAndSendTransaction: 0,
    signAndSendTransactions: 0,
    signTransaction: 0,
  };
  const document = makeDocument();
  const windowObject = new FakeWindow();
  const wallet = makeConnectedWallet(calls);
  let connectorOptions;
  class StubNearConnector {
    constructor(options) {
      calls.construct += 1;
      connectorOptions = options;
      this.network = options.network;
      wallet.manifest = options.manifest.wallets[0];
      this.handlers = new Map();
      windowObject.addEventListener("near-wallet-injected", () => { calls.injectedHandler += 1; });
      windowObject.addEventListener("message", () => { calls.injectedHandler += 1; });
    }
    async connect(options) {
      calls.connect += 1;
      calls.connectOptions = options;
      return wallet;
    }
    on(event, callback) { this.handlers.set(event, callback); }
  }
  mountLocalUI({
    document,
    windowObject,
    async loadConnector() {
      calls.moduleLoad += 1;
      return { NearConnector: StubNearConnector };
    },
  });

  assert.equal(document.elements.get("#connect-wallet").disabled, false);
  assert.equal(calls.moduleLoad, 0);
  assert.equal(calls.construct, 0);
  assert.equal(calls.connect, 0);
  assert.equal(calls.getAccounts, 0);
  await document.elements.get("#connect-wallet").emit("click");
  assert.equal(calls.moduleLoad, 1);
  assert.equal(calls.construct, 1);
  assert.equal(calls.connect, 1);
  assert.deepEqual(calls.connectOptions, { walletId: METEOR_WALLET_ID });
  assert.equal(connectorOptions.network, "testnet");
  assert.equal(connectorOptions.autoConnect, false);
  assert.equal(connectorOptions.cspNonce, "test-csp-nonce");
  assert.deepEqual(connectorOptions.manifest.wallets.map(({ id }) => id), [METEOR_WALLET_ID]);
  assert.equal(connectorOptions.manifest.wallets[0].executor, METEOR_EXECUTOR_URL);
  assert.equal(connectorOptions.manifest.wallets[0].features.testnet, true);
  assert.equal(connectorOptions.manifest.wallets[0].features.signAndSendTransaction, false);
  assert.equal(calls.getAccounts, 1);
  assert.equal(document.elements.get("#account-select").disabled, false);
  assert.equal(document.elements.get("#run-preflight").disabled, false);
  assert.equal(calls.injectedHandler || 0, 0);
  assert.equal(calls.connectorWallet, 0);
  assert.equal(calls.signAndSendTransaction + calls.signAndSendTransactions + calls.signTransaction, 0);
});

for (const [label, inject] of [
  ["CustomEvent", (windowObject) => windowObject.dispatch("near-wallet-injected", {
    detail: { manifest: { id: METEOR_WALLET_ID } },
  })],
  ["parent-frame message", (windowObject) => windowObject.dispatch("message", {
    data: { type: "near-wallet-injected", manifest: { id: METEOR_WALLET_ID } },
  })],
]) {
  test(`blocks and rejects same-ID injected provider via ${label}`, async () => {
    const windowObject = new FakeWindow();
    const calls = { connectorInjectionHandler: 0, connectOptions: null };
    let pinnedManifest;
    class StubNearConnector {
      constructor(options) {
        this.network = options.network;
        pinnedManifest = options.manifest.wallets[0];
        windowObject.addEventListener("near-wallet-injected", () => { calls.connectorInjectionHandler += 1; });
        windowObject.addEventListener("message", (event) => {
          if (event.data?.type === "near-wallet-injected") calls.connectorInjectionHandler += 1;
        });
      }
      on() {}
      async connect(options) {
        calls.connectOptions = options;
        inject(windowObject);
        return { manifest: pinnedManifest, async getAccounts() { return []; } };
      }
    }
    const connector = createGuardedMeteorConnector({ NearConnector: StubNearConnector, windowObject });
    await assert.rejects(connector.connect(), /wallet-injected provider was blocked/);
    assert.deepEqual(calls.connectOptions, { walletId: METEOR_WALLET_ID });
    assert.equal(calls.connectorInjectionHandler, 0, "NearConnector must not receive the injected event");
  });
}

test("rejects a returned provider with a cloned Meteor ID/manifest instead of the pinned manifest object", async () => {
  const windowObject = new FakeWindow();
  let pinnedManifest;
  class StubNearConnector {
    constructor(options) {
      this.network = options.network;
      pinnedManifest = options.manifest.wallets[0];
    }
    on() {}
    async connect() {
      return {
        manifest: { ...pinnedManifest },
        async getAccounts() { return []; },
      };
    }
  }
  const connector = createGuardedMeteorConnector({ NearConnector: StubNearConnector, windowObject });
  await assert.rejects(connector.connect(), /unexpected provider/);
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
