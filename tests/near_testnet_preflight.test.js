"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { runPythonAdapter } = require("../examples/guarded_agent_bridge.js");
const {
  RPC_TIMEOUT_MS,
  TESTNET_RPC_URL,
  makeTransferIntent,
  preflightTestnetNativeTransfer,
  readTestnetAccount,
} = require("../examples/near_testnet_preflight.js");

const policyDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-guard-near-policy-"));
const testPolicyPath = path.join(policyDirectory, "policy.json");
fs.writeFileSync(testPolicyPath, JSON.stringify({
  version: 1,
  default: "deny",
  allowed_recipients: ["alice.testnet"],
  max_amount_yocto: "20000000000000000000000000",
}));

function runWithTestPolicy(serializedRequest) {
  return runPythonAdapter(serializedRequest, undefined, testPolicyPath);
}

test.after(() => fs.rmSync(policyDirectory, { recursive: true, force: true }));

function rpcFetchStub({ chainId = "testnet", account = {} } = {}) {
  const calls = [];
  const fetchImpl = async (url, options) => {
    assert.equal(url, TESTNET_RPC_URL);
    assert.equal(options.method, "POST");
    const request = JSON.parse(options.body);
    calls.push(request);
    let result;
    if (request.method === "status") {
      result = { chain_id: chainId };
    } else if (request.method === "query") {
      result = {
        amount: "10000000000000000000000000",
        locked: "0",
        storage_usage: 182,
        code_hash: "11111111111111111111111111111111",
        ...account,
      };
    } else {
      throw new Error(`unexpected RPC method ${request.method}`);
    }
    return {
      ok: true,
      status: 200,
      json: async () => ({
        jsonrpc: "2.0",
        id: request.id,
        result,
      }),
    };
  };
  return { calls, fetchImpl };
}

function connectedTestnetConnector(accountIds = ["sender.testnet"], calls = {}) {
  const wallet = {
    async getAccounts() {
      calls.getAccounts = (calls.getAccounts || 0) + 1;
      return accountIds.map((accountId) => ({ accountId }));
    },
    async signAndSendTransaction() {
      calls.signAndSendTransaction = (calls.signAndSendTransaction || 0) + 1;
      throw new Error("must never be called by preflight");
    },
    async signAndSendTransactions() {
      calls.signAndSendTransactions = (calls.signAndSendTransactions || 0) + 1;
      throw new Error("must never be called by preflight");
    },
    async signTransaction() {
      calls.signTransaction = (calls.signTransaction || 0) + 1;
      throw new Error("must never be called by preflight");
    },
  };
  const connectorPrototype = {
    async wallet() {
      calls.wallet = (calls.wallet || 0) + 1;
      return wallet;
    },
    async connect() {
      calls.connect = (calls.connect || 0) + 1;
      throw new Error("connect must be initiated manually by the host app");
    },
  };
  return Object.assign(Object.create(connectorPrototype), { network: "testnet" });
}

const allowedContext = {
  previous_interactions: 8,
  account_age_days: 400,
  recipient_is_contract: false,
};

async function assertPreflightRpcFailure(fetchImpl, expectedError) {
  const walletCalls = {};
  let returnedResult;
  await assert.rejects((async () => {
    returnedResult = await preflightTestnetNativeTransfer({
      connector: connectedTestnetConnector(["sender.testnet"], walletCalls),
      recipient: "alice.testnet",
      amountYocto: "1000000000000000000000000",
      context: allowedContext,
      fetchImpl,
      adapterRunner: runWithTestPolicy,
    });
  })(), expectedError);
  assert.equal(returnedResult, undefined, "RPC failure must not produce a success result");
  assert.equal(walletCalls.connect || 0, 0);
  assert.equal(walletCalls.signAndSendTransaction || 0, 0);
  assert.equal(walletCalls.signAndSendTransactions || 0, 0);
  assert.equal(walletCalls.signTransaction || 0, 0);
}

test("builds a simple native transfer intent without changing recipient or context", () => {
  const context = { ...allowedContext };
  const intent = makeTransferIntent({
    recipient: "alice.testnet",
    amountYocto: "1000000000000000000000000",
    context,
  });
  assert.deepEqual(intent, {
    action: "transfer",
    resource: "alice.testnet",
    transaction: {
      recipient: "alice.testnet",
      amount_yocto: "1000000000000000000000000",
      ...allowedContext,
    },
  });
  assert.equal(Object.isFrozen(intent), true);
  assert.equal(Object.isFrozen(intent.transaction), true);
  assert.deepEqual(context, allowedContext);
});

test("account IDs require an exact full-string match and reject trailing LF and CR", async () => {
  const { calls, fetchImpl } = rpcFetchStub();
  const account = await readTestnetAccount("alice.testnet", fetchImpl);
  assert.equal(account.accountId, "alice.testnet");
  assert.deepEqual(calls.map(({ method }) => method), ["status", "query"]);

  for (const suffix of ["\n", "\r"]) {
    const callsBefore = calls.length;
    await assert.rejects(
      readTestnetAccount(`alice.testnet${suffix}`, fetchImpl),
      /accountId must be a valid lowercase NEAR account ID/,
    );
    assert.equal(calls.length, callsBefore, "invalid account IDs must be rejected before RPC");
    assert.throws(
      () => makeTransferIntent({ recipient: `alice.testnet${suffix}`, amountYocto: "1" }),
      /recipient must be a valid lowercase NEAR account ID/,
    );
  }
});

test("runs testnet preflight through Sentinel Guard and never signs or submits", async () => {
  const walletCalls = {};
  const connector = connectedTestnetConnector(["sender.testnet"], walletCalls);
  const { calls: rpcCalls, fetchImpl } = rpcFetchStub();
  let guardRequest;
  const result = await preflightTestnetNativeTransfer({
    connector,
    recipient: "alice.testnet",
    amountYocto: "1000000000000000000000000",
    context: allowedContext,
      requestId: "near-preflight-test",
      fetchImpl,
      adapterRunner(serializedRequest) {
        guardRequest = JSON.parse(serializedRequest);
        return runWithTestPolicy(serializedRequest);
      },
  });

  assert.equal(guardRequest.request_id, "near-preflight-test");
  assert.deepEqual(guardRequest.intent, {
    action: "transfer",
    resource: "alice.testnet",
    transaction: {
      recipient: "alice.testnet",
      amount_yocto: "1000000000000000000000000",
      ...allowedContext,
    },
  });
  assert.equal(result.mode, "TESTNET_PREFLIGHT_READ_ONLY");
  assert.equal(result.status, "PREPARED_NOT_SUBMITTED");
  assert.equal(result.guard.status, "COMPLETED");
  assert.equal(result.guard.decision, "ALLOW");
  assert.equal(result.account.accountId, "sender.testnet");
  assert.equal(result.account.network, "testnet");
  assert.equal(result.account.balanceYocto, "10000000000000000000000000");
  assert.equal(result.submitted, false);
  assert.deepEqual(rpcCalls.map(({ method }) => method), ["status", "query"]);
  assert.deepEqual(rpcCalls[1].params, {
    request_type: "view_account",
    finality: "final",
    account_id: "sender.testnet",
  });
  assert.equal(walletCalls.connect || 0, 0);
  assert.equal(walletCalls.signAndSendTransaction || 0, 0);
  assert.equal(walletCalls.signAndSendTransactions || 0, 0);
  assert.equal(walletCalls.signTransaction || 0, 0);
});

test("does not read RPC or touch a wallet when Sentinel Guard returns WARN", async () => {
  let rpcCalls = 0;
  let walletCalls = 0;
  const result = await preflightTestnetNativeTransfer({
    connector: {
      network: "testnet",
      async wallet() {
        walletCalls += 1;
        return null;
      },
    },
    recipient: "alice.testnet",
    amountYocto: "1000000000000000000000000",
    context: {},
    fetchImpl: async () => { rpcCalls += 1; throw new Error("RPC should not run"); },
    adapterRunner: runWithTestPolicy,
  });
  assert.equal(result.status, "NEEDS_REVIEW");
  assert.equal(result.guard.decision, "WARN");
  assert.equal(result.account, null);
  assert.equal(result.submitted, false);
  assert.equal(walletCalls, 0);
  assert.equal(rpcCalls, 0);
});

test("rejects a mainnet-configured connector before wallet or RPC access", async () => {
  let touched = 0;
  await assert.rejects(
    preflightTestnetNativeTransfer({
      connector: {
        network: "mainnet",
        async wallet() { touched += 1; return null; },
      },
      recipient: "alice.testnet",
      amountYocto: "1",
      context: allowedContext,
      fetchImpl: async () => { touched += 1; },
    }),
    /configured with.*testnet/,
  );
  assert.equal(touched, 0);
});

test("requires explicit account selection when a wallet has multiple accounts", async () => {
  let rpcCalls = 0;
  await assert.rejects(
    preflightTestnetNativeTransfer({
      connector: connectedTestnetConnector(["sender.testnet", "other.testnet"]),
      recipient: "alice.testnet",
      amountYocto: "1",
      context: allowedContext,
      fetchImpl: async () => { rpcCalls += 1; },
      adapterRunner: runWithTestPolicy,
    }),
    /choose accountId explicitly/,
  );
  assert.equal(rpcCalls, 0);
});

test("rejects an RPC endpoint that does not identify itself as testnet", async () => {
  const { calls, fetchImpl } = rpcFetchStub({ chainId: "mainnet" });
  await assert.rejects(readTestnetAccount("sender.testnet", fetchImpl), /did not confirm.*testnet/);
  assert.deepEqual(calls.map(({ method }) => method), ["status"]);
});

test("fails closed on an HTTP error without signing, submission, or false success", async () => {
  await assertPreflightRpcFailure(async (url) => {
    assert.equal(url, TESTNET_RPC_URL);
    return { ok: false, status: 503 };
  }, /HTTP request failed \(503\)/);
});

test("fails closed on a JSON-RPC error without signing, submission, or false success", async () => {
  await assertPreflightRpcFailure(async (_url, options) => {
    const request = JSON.parse(options.body);
    return {
      ok: true,
      status: 200,
      json: async () => ({
        jsonrpc: "2.0",
        id: request.id,
        error: { code: -32000, message: "account lookup unavailable" },
      }),
    };
  }, /account lookup unavailable/);
});

test("fails closed on a malformed JSON-RPC envelope", async () => {
  await assertPreflightRpcFailure(async () => ({
    ok: true,
    status: 200,
    json: async () => ({ jsonrpc: "1.0", id: "wrong", result: { chain_id: "testnet" } }),
  }), /invalid JSON-RPC envelope/);
});

test("fails closed when the RPC response body is malformed JSON", async () => {
  await assertPreflightRpcFailure(async () => ({
    ok: true,
    status: 200,
    json: async () => { throw new SyntaxError("malformed JSON body"); },
  }), /malformed JSON body/);
});

test("fails closed on a malformed account payload", async () => {
  let requestCount = 0;
  await assertPreflightRpcFailure(async (_url, options) => {
    const request = JSON.parse(options.body);
    requestCount += 1;
    const result = request.method === "status"
      ? { chain_id: "testnet" }
      : { amount: "not-an-amount", locked: "0", storage_usage: 1, code_hash: "hash" };
    return {
      ok: true,
      status: 200,
      json: async () => ({ jsonrpc: "2.0", id: request.id, result }),
    };
  }, /invalid account snapshot/);
  assert.equal(requestCount, 2);
});

test("fails closed when the testnet RPC request is aborted at the timeout", {
  timeout: RPC_TIMEOUT_MS + 2000,
}, async () => {
  let aborted = false;
  await assertPreflightRpcFailure((_url, options) => new Promise((_resolve, reject) => {
    options.signal.addEventListener("abort", () => {
      aborted = true;
      reject(Object.assign(new Error("RPC request aborted"), { name: "AbortError" }));
    }, { once: true });
  }), /RPC request aborted/);
  assert.equal(aborted, true);
});

test("fails closed for malformed intent inputs or context overrides", () => {
  assert.throws(() => makeTransferIntent({ recipient: "Alice.testnet", amountYocto: "1" }), /account ID/);
  assert.throws(() => makeTransferIntent({ recipient: "alice.testnet", amountYocto: "01" }), /canonical decimal/);
  assert.throws(() => makeTransferIntent({
    recipient: "alice.testnet",
    amountYocto: "1",
    context: { recipient: "attacker.testnet" },
  }), /must not override/);
  assert.throws(() => makeTransferIntent({
    recipient: "alice.testnet",
    amountYocto: "1",
    context: { account_age_days: undefined },
  }), /only JSON values/);
});
