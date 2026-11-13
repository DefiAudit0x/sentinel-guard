"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { Readable } = require("node:stream");
const test = require("node:test");
const {
  FIXED_RECIPIENT,
  assertPrivatePolicyPath,
  createLocalUiServer,
  readJsonBody,
  validateLocalRequest,
} = require("../app/local_ui_server.js");
const {
  CODE_HASH_BASELINES_ENV_VAR,
  EMPTY_CODE_HASH,
  preflightTestnetNativeTransfer,
  TESTNET_RPC_URL,
} = require("../examples/near_testnet_preflight.js");
const {
  runPythonAdapter,
  runPythonPolicyAdapter,
} = require("../examples/guarded_agent_bridge.js");

const projectPolicyDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-ui-policy-"));
const testPolicyPath = path.join(projectPolicyDirectory, "policy.json");
fs.writeFileSync(testPolicyPath, JSON.stringify({
  version: 1,
  default: "deny",
  allowed_recipients: [FIXED_RECIPIENT],
  max_amount_yocto: "100000000000000000000000",
}), { mode: 0o600 });

test.after(() => fs.rmSync(projectPolicyDirectory, { recursive: true, force: true }));

function rpcFetchStub() {
  const calls = [];
  const fetchImpl = async (url, options) => {
    assert.equal(url, "https://rpc.testnet.near.org");
    assert.equal(options.method, "POST");
    const request = JSON.parse(options.body);
    calls.push(request);
    const result = request.method === "status"
      ? { chain_id: "testnet" }
      : {
        amount: "900000000000000000000000",
        locked: "0",
        storage_usage: 180,
        code_hash: "11111111111111111111111111111111",
      };
    return {
      ok: true,
      status: 200,
      async json() { return { jsonrpc: "2.0", id: request.id, result }; },
    };
  };
  return { calls, fetchImpl };
}

async function withRecipientBaseline(accountId, callback) {
  const previous = process.env[CODE_HASH_BASELINES_ENV_VAR];
  process.env[CODE_HASH_BASELINES_ENV_VAR] = JSON.stringify([{
    network: "testnet",
    account_id: accountId,
    code_hash: EMPTY_CODE_HASH,
  }]);
  try {
    return await callback();
  } finally {
    if (previous === undefined) delete process.env[CODE_HASH_BASELINES_ENV_VAR];
    else process.env[CODE_HASH_BASELINES_ENV_VAR] = previous;
  }
}

async function withServer(options, callback) {
  const server = createLocalUiServer(options);
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  const base = `http://127.0.0.1:${address.port}`;
  try { await callback(base); }
  finally { await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); }
}

async function postIntent(base, body, headers = {}) {
  return fetch(`${base}/api/preflight`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

function validRequest(updates = {}) {
  return {
    accountId: "defiaudit0x.testnet",
    recipient: FIXED_RECIPIENT,
    amountYocto: "50000000000000000000000",
    context: { previous_interactions: 3, account_age_days: 365 },
    ...updates,
  };
}

test("server rejects other recipients, amounts above 0.1 NEAR, and invalid context before any preflight or RPC call", async () => {
  let preflightCalls = 0;
  let rpcCalls = 0;
  const noCall = async () => { preflightCalls += 1; throw new Error("must not run"); };
  const fetchImpl = async () => { rpcCalls += 1; throw new Error("must not run"); };
  await withServer({ preflight: noCall, fetchImpl }, async (base) => {
    const wrongRecipient = await postIntent(base, validRequest({ recipient: "mallory.testnet" }));
    assert.equal(wrongRecipient.status, 403);
    assert.match((await wrongRecipient.json()).error, /recipient/);
    const overLimit = await postIntent(base, validRequest({ amountYocto: "100000000000000000000001" }));
    assert.equal(overLimit.status, 403);
    const invalidContext = await postIntent(base, validRequest({ context: { known_malicious: false } }));
    assert.equal(invalidContext.status, 400);
    assert.equal(preflightCalls, 0);
    assert.equal(rpcCalls, 0);
  });
});

test("server preflight uses only a synthetic read-only account connector and mocked testnet RPC", async () => {
  const { calls: rpcCalls, fetchImpl } = rpcFetchStub();
  let capturedConnector;
  const preflight = (options) => {
    capturedConnector = options.connector;
    return preflightTestnetNativeTransfer(options);
  };
  const adapterRunner = (serialized) => runPythonAdapter(serialized, undefined, testPolicyPath);
  const policyAdapterRunner = (serialized) => runPythonPolicyAdapter(serialized, undefined, testPolicyPath);
  await withRecipientBaseline(FIXED_RECIPIENT, () => withServer({ preflight, adapterRunner, policyAdapterRunner, fetchImpl }, async (base) => {
    const response = await postIntent(base, validRequest(), { origin: base });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("cache-control"), "no-store");
    const result = await response.json();
    assert.equal(result.mode, "TESTNET_PREFLIGHT_READ_ONLY");
    assert.equal(result.status, "PREPARED_NOT_SUBMITTED");
    assert.equal(result.guard.decision, "ALLOW");
    assert.equal(result.account.accountId, "defiaudit0x.testnet");
    assert.equal(result.recipientCodeCheck.status, "MATCHED");
    assert.equal(result.submitted, false);
    assert.deepEqual(rpcCalls.map(({ method }) => method), ["status", "query", "status", "query"]);
    assert.deepEqual(Object.keys(capturedConnector).sort(), ["network", "wallet"]);
    assert.equal(capturedConnector.network, "testnet");
    const wallet = await capturedConnector.wallet();
    assert.deepEqual(Object.keys(wallet), ["getAccounts"]);
    assert.deepEqual(await wallet.getAccounts(), [{ accountId: "defiaudit0x.testnet" }]);
    assert.equal(typeof wallet.signAndSendTransaction, "undefined");
    assert.equal(typeof wallet.signAndSendTransactions, "undefined");
    assert.equal(typeof wallet.signTransaction, "undefined");
  }));
});

test("blank context remains a final warning after policy-only gate and read-only account checks", async () => {
  const { calls: rpcCalls, fetchImpl } = rpcFetchStub();
  const adapterRunner = (serialized) => runPythonAdapter(serialized, undefined, testPolicyPath);
  const policyAdapterRunner = (serialized) => runPythonPolicyAdapter(serialized, undefined, testPolicyPath);
  const riskRequests = [];
  const policyRequests = [];
  const captureRisk = (serialized) => {
    riskRequests.push(JSON.parse(serialized));
    return adapterRunner(serialized);
  };
  const capturePolicy = (serialized) => {
    policyRequests.push(JSON.parse(serialized));
    return policyAdapterRunner(serialized);
  };
  await withRecipientBaseline(FIXED_RECIPIENT, () => withServer({
    adapterRunner: captureRisk,
    policyAdapterRunner: capturePolicy,
    fetchImpl,
  }, async (base) => {
    const response = await postIntent(base, validRequest({ context: {} }));
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.equal(result.status, "NEEDS_REVIEW");
    assert.equal(result.guard.decision, "WARN");
    assert.equal(result.account.accountId, FIXED_RECIPIENT);
    assert.equal(Object.hasOwn(policyRequests[0].intent.transaction, "account_age_days"), false);
    assert.equal(Object.hasOwn(policyRequests[0].intent.transaction, "previous_interactions"), false);
    assert.equal(Object.hasOwn(riskRequests[0].intent.transaction, "account_age_days"), false);
    assert.equal(Object.hasOwn(riskRequests[0].intent.transaction, "previous_interactions"), false);
    assert.equal(result.submitted, false);
    assert.deepEqual(rpcCalls.map(({ method }) => method), ["status", "query", "status", "query"]);
  }));
});

test("rejects cross-origin requests and never serves files outside the UI asset allow-list", async () => {
  const allowedConnectOrigins = [new URL(TESTNET_RPC_URL).origin];
  const allowedImageSources = ["'self'", "data:"];
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-ui-static-"));
  const staticRoot = path.join(temp, "public");
  const privatePolicy = path.join(temp, "private-policy.json");
  try {
    fs.mkdirSync(path.join(staticRoot, "assets"), { recursive: true });
    fs.writeFileSync(path.join(staticRoot, "index.html"), '<!doctype html><script type="module" crossorigin src="/assets/main.mjs"></script>');
    fs.writeFileSync(path.join(staticRoot, "assets", "main.mjs"), "local script");
    fs.writeFileSync(privatePolicy, "private policy");
    fs.symlinkSync(privatePolicy, path.join(staticRoot, "assets", "policy-link.json"));
    await withServer({ staticRoot }, async (base) => {
      const page = await fetch(`${base}/`);
      assert.equal(page.status, 200);
      assert.equal(page.headers.get("x-frame-options"), "DENY");
      const markup = await page.text();
      const nonce = markup.match(/<script type="module"[^>]*\bnonce="([^"]+)"/)?.[1];
      assert.match(nonce || "", /^[A-Za-z0-9+/=]+$/);
      const csp = page.headers.get("content-security-policy");
      assert.equal(csp, [
        "default-src 'self'",
        `script-src 'self' 'nonce-${nonce}'`,
        "style-src 'self' 'unsafe-inline'",
        `connect-src 'self' ${allowedConnectOrigins.join(" ")}`,
        `img-src ${allowedImageSources.join(" ")}`,
        "frame-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "frame-ancestors 'none'",
      ].join("; "));
      assert.doesNotMatch(csp, /\*/);
      assert.doesNotMatch(csp, /raw\.githubusercontent\.com/);
      assert.doesNotMatch(csp.split("; ").find((directive) => directive.startsWith("script-src ")), /unsafe-inline/);
      assert.match(markup, /<script type="module" crossorigin src="\/assets\/main\.mjs" nonce="[A-Za-z0-9+/=]+">/);
      const secondPage = await fetch(`${base}/`);
      const secondNonce = (await secondPage.text()).match(/nonce="([^"]+)"/)?.[1];
      assert.ok(secondNonce);
      assert.notEqual(secondNonce, nonce, "HTML responses must receive distinct nonces");
      assert.deepEqual(
        csp.split("; ").find((directive) => directive.startsWith("connect-src ")).split(" ").slice(1),
        ["'self'", ...allowedConnectOrigins],
      );
      assert.deepEqual(
        csp.split("; ").find((directive) => directive.startsWith("img-src ")).split(" ").slice(1),
        allowedImageSources,
      );
      assert.doesNotMatch(csp, /hot-dao\/near-selector|azbang\/hot-connector/);
      const privatePath = await fetch(`${base}/policy.json`);
      assert.equal(privatePath.status, 404);
      const encodedTraversal = await fetch(`${base}/assets/%2e%2e/policy.json`);
      assert.equal(encodedTraversal.status, 404);
      const policySymlink = await fetch(`${base}/assets/policy-link.json`);
      assert.equal(policySymlink.status, 404);
      const crossOrigin = await fetch(`${base}/api/preflight`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: "http://evil.example" },
        body: JSON.stringify(validRequest()),
      });
      assert.equal(crossOrigin.status, 403);
    });
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test("policy path must be absolute and outside the generated static UI directory", () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-ui-public-"));
  const staticRoot = path.join(temp, "public");
  const policyInsideStatic = path.join(staticRoot, "assets", "policy.json");
  const privatePolicy = path.join(temp, "private-policy.json");
  fs.mkdirSync(path.dirname(policyInsideStatic), { recursive: true });
  fs.writeFileSync(policyInsideStatic, "{}", { mode: 0o600 });
  fs.writeFileSync(privatePolicy, "{}", { mode: 0o600 });
  try {
    assert.throws(() => assertPrivatePolicyPath(undefined, staticRoot), /absolute local policy path/);
    assert.throws(() => assertPrivatePolicyPath(policyInsideStatic, staticRoot), /must not be inside/);
    assert.doesNotThrow(() => assertPrivatePolicyPath(privatePolicy, staticRoot));
    assert.throws(
      () => assertPrivatePolicyPath(path.join(temp, "missing-policy.json"), staticRoot),
      /resolve to existing real paths/,
    );
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test("an external policy symlink into static assets prevents serving policy content", () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-ui-policy-link-"));
  const staticRoot = path.join(temp, "public");
  const policyAsset = path.join(staticRoot, "assets", "private-policy.json");
  const externalPolicyLink = path.join(temp, "configured-policy.json");
  const policyContents = '{"version":1,"default":"deny","allowed_recipients":[]}';
  fs.mkdirSync(path.dirname(policyAsset), { recursive: true });
  fs.writeFileSync(policyAsset, policyContents, { mode: 0o600 });
  fs.symlinkSync(policyAsset, externalPolicyLink);
  try {
    assert.equal(fs.realpathSync(externalPolicyLink), fs.realpathSync(policyAsset));
    assert.throws(
      () => assertPrivatePolicyPath(externalPolicyLink, staticRoot),
      /must not be inside/,
    );
    assert.throws(
      () => createLocalUiServer({ staticRoot, policyPath: externalPolicyLink }),
      /must not be inside/,
    );
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test("readJsonBody rejects oversized bodies and non-JSON content types directly", async () => {
  const oversizedRequest = Readable.from([Buffer.alloc(8193, 0x20)]);
  oversizedRequest.headers = { "content-type": "application/json" };
  await assert.rejects(readJsonBody(oversizedRequest), (error) => error.status === 413);

  const nonJsonRequest = Readable.from([Buffer.from("{}")]);
  nonJsonRequest.headers = { "content-type": "text/plain" };
  await assert.rejects(readJsonBody(nonJsonRequest), (error) => error.status === 415);
});

test("request schema is exact and requires canonical positive values within the cap", () => {
  assert.throws(() => validateLocalRequest(validRequest({ extra: true })), /only accountId/);
  assert.throws(() => validateLocalRequest(validRequest({ amountYocto: "01" })), /canonical/);
  assert.throws(() => validateLocalRequest(validRequest({ amountYocto: "0" })), /greater than zero/);
  assert.doesNotThrow(() => validateLocalRequest(validRequest({ amountYocto: "100000000000000000000000" })));
});

test("account IDs require an exact full-string match and reject trailing LF and CR", () => {
  const valid = validateLocalRequest(validRequest({ accountId: "alice.testnet" }));
  assert.equal(valid.accountId, "alice.testnet");
  for (const suffix of ["\n", "\r"]) {
    assert.throws(
      () => validateLocalRequest(validRequest({ accountId: `alice.testnet${suffix}` })),
      /valid connected NEAR account/,
    );
  }
});
