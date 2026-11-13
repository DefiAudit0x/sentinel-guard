"use strict";

const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const {
  runPythonAdapter,
  runPythonPolicyAdapter,
} = require("../examples/guarded_agent_bridge.js");
const {
  CODE_HASH_BASELINES_ENV_VAR,
  EMPTY_CODE_HASH,
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

function runWithTestPolicyOnly(serializedRequest) {
  return runPythonPolicyAdapter(serializedRequest, undefined, testPolicyPath);
}

function base58Encode(bytes) {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let value = BigInt(`0x${Buffer.from(bytes).toString("hex")}`);
  let encoded = "";
  while (value > 0n) {
    const digit = Number(value % 58n);
    encoded = alphabet[digit] + encoded;
    value /= 58n;
  }
  const leadingZeroes = Buffer.from(bytes).findIndex((byte) => byte !== 0);
  const zeroCount = leadingZeroes === -1 ? bytes.length : leadingZeroes;
  return "1".repeat(zeroCount) + encoded;
}

const CONTRACT_HASH_A = base58Encode(createHash("sha256").update("baseline-contract").digest());
const CONTRACT_HASH_B = base58Encode(createHash("sha256").update("changed-contract").digest());
const baselineForAlice = (codeHash = EMPTY_CODE_HASH) => JSON.stringify([{
  network: "testnet",
  account_id: "alice.testnet",
  code_hash: codeHash,
}]);
const originalBaselineEnv = process.env[CODE_HASH_BASELINES_ENV_VAR];

test.beforeEach(() => {
  process.env[CODE_HASH_BASELINES_ENV_VAR] = baselineForAlice();
});

test.after(() => {
  if (originalBaselineEnv === undefined) delete process.env[CODE_HASH_BASELINES_ENV_VAR];
  else process.env[CODE_HASH_BASELINES_ENV_VAR] = originalBaselineEnv;
  fs.rmSync(policyDirectory, { recursive: true, force: true });
});

function rpcFetchStub({
  chainId = "testnet",
  account = {},
  accountsById = {},
  errorsByAccountId = {},
} = {}) {
  const calls = [];
  const fetchImpl = async (url, options) => {
    assert.equal(url, TESTNET_RPC_URL);
    assert.equal(options.method, "POST");
    const request = JSON.parse(options.body);
    calls.push(request);
    let payload;
    if (request.method === "status") {
      payload = { result: { chain_id: chainId } };
    } else if (request.method === "query") {
      const accountId = request.params.account_id;
      if (errorsByAccountId[accountId]) {
        payload = { error: { code: -32000, message: errorsByAccountId[accountId] } };
      } else {
        payload = {
          result: {
            amount: "10000000000000000000000000",
            locked: "0",
            storage_usage: 182,
            code_hash: EMPTY_CODE_HASH,
            ...account,
            ...(accountsById[accountId] || {}),
          },
        };
      }
    } else {
      throw new Error(`unexpected RPC method ${request.method}`);
    }
    return {
      ok: true,
      status: 200,
      json: async () => ({
        jsonrpc: "2.0",
        id: request.id,
        ...payload,
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
};

function assertNoSigningOrSending(walletCalls) {
  assert.equal(walletCalls.connect || 0, 0);
  assert.equal(walletCalls.signAndSendTransaction || 0, 0);
  assert.equal(walletCalls.signAndSendTransactions || 0, 0);
  assert.equal(walletCalls.signTransaction || 0, 0);
}

async function runPreflight({
  recipient = "alice.testnet",
  context = allowedContext,
  fetchImpl,
  adapterRunner = runWithTestPolicy,
  policyAdapterRunner = runWithTestPolicyOnly,
  walletCalls = {},
} = {}) {
  return preflightTestnetNativeTransfer({
    connector: connectedTestnetConnector(["sender.testnet"], walletCalls),
    recipient,
    amountYocto: "1000000000000000000000000",
    context,
    fetchImpl,
    adapterRunner,
    policyAdapterRunner,
  });
}

async function assertPreflightRpcFailure(fetchImpl) {
  const walletCalls = {};
  const result = await runPreflight({ fetchImpl, walletCalls });
  assert.equal(result.status, "NEEDS_REVIEW", "RPC failure must not produce a success result");
  assert.equal(result.guard, null, "an incomplete preflight must not expose a final guard decision");
  assert.equal(result.preliminaryPolicy.allowed, true);
  assert.equal(result.recipientCodeCheck.status, "UNKNOWN");
  assert.equal(result.account, null);
  assert.equal(result.submitted, false);
  assertNoSigningOrSending(walletCalls);
  return result;
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

test("reads sender and recipient after policy-only allows, then matches the configured baseline", async () => {
  const walletCalls = {};
  const { calls: rpcCalls, fetchImpl } = rpcFetchStub();
  const guardRequests = [];
  const policyRequests = [];
  const result = await runPreflight({
    walletCalls,
    fetchImpl,
    policyAdapterRunner(serializedRequest) {
      policyRequests.push(JSON.parse(serializedRequest));
      return runWithTestPolicyOnly(serializedRequest);
    },
    adapterRunner(serializedRequest) {
      guardRequests.push(JSON.parse(serializedRequest));
      return runWithTestPolicy(serializedRequest);
    },
  });

  assert.equal(policyRequests.length, 1, "policy is evaluated before network access");
  assert.deepEqual(policyRequests[0].intent.transaction, {
    recipient: "alice.testnet",
    amount_yocto: "1000000000000000000000000",
    ...allowedContext,
  });
  assert.equal(Object.hasOwn(policyRequests[0].intent.transaction, "recipient_code_changed"), false);
  assert.equal(guardRequests.length, 1, "risk is evaluated once after verified account reads");
  assert.equal(guardRequests[0].intent.transaction.recipient_is_contract, false);
  assert.equal(guardRequests[0].intent.transaction.recipient_code_changed, false);
  assert.equal(result.mode, "TESTNET_PREFLIGHT_READ_ONLY");
  assert.equal(result.status, "PREPARED_NOT_SUBMITTED");
  assert.equal(result.guard.status, "COMPLETED");
  assert.equal(result.guard.decision, "ALLOW");
  assert.equal(result.account.accountId, "sender.testnet");
  assert.equal(result.account.network, "testnet");
  assert.equal(result.account.balanceYocto, "10000000000000000000000000");
  assert.deepEqual(result.recipientCodeCheck, {
    status: "MATCHED",
    network: "testnet",
    accountId: "alice.testnet",
    codeHash: EMPTY_CODE_HASH,
  });
  assert.equal(result.submitted, false);
  assert.deepEqual(rpcCalls.map(({ method }) => method), ["status", "query", "status", "query"]);
  assert.deepEqual(rpcCalls[1].params, {
    request_type: "view_account",
    finality: "final",
    account_id: "sender.testnet",
  });
  assert.deepEqual(rpcCalls[3].params, {
    request_type: "view_account",
    finality: "final",
    account_id: "alice.testnet",
  });
  assert.equal(walletCalls.connect || 0, 0);
  assertNoSigningOrSending(walletCalls);
});

test("derives contract and unchanged-code signals from the recipient's matching baseline", async () => {
  process.env[CODE_HASH_BASELINES_ENV_VAR] = baselineForAlice(CONTRACT_HASH_A);
  const { calls, fetchImpl } = rpcFetchStub({
    accountsById: { "alice.testnet": { code_hash: CONTRACT_HASH_A } },
  });
  const requests = [];
  const walletCalls = {};
  const result = await runPreflight({
    fetchImpl,
    walletCalls,
    adapterRunner(serializedRequest) {
      requests.push(JSON.parse(serializedRequest));
      return runWithTestPolicy(serializedRequest);
    },
  });

  assert.equal(result.status, "PREPARED_NOT_SUBMITTED");
  assert.equal(result.recipientCodeCheck.status, "MATCHED");
  assert.equal(requests[0].intent.transaction.recipient_is_contract, true);
  assert.equal(requests[0].intent.transaction.recipient_code_changed, false);
  assert.equal(result.guard.risk.risk_score, 5);
  assert.equal(calls[3].params.account_id, "alice.testnet");
  assertNoSigningOrSending(walletCalls);
});

for (const {
  label,
  baselineHash,
  currentHash,
  recipientIsContract,
  expectedScore,
} of [
  {
    label: "baseline empty-code -> current contract code",
    baselineHash: EMPTY_CODE_HASH,
    currentHash: CONTRACT_HASH_A,
    recipientIsContract: true,
    expectedScore: 55,
  },
  {
    label: "baseline contract code -> current empty-code",
    baselineHash: CONTRACT_HASH_A,
    currentHash: EMPTY_CODE_HASH,
    recipientIsContract: false,
    expectedScore: 50,
  },
  {
    label: "baseline contract code -> different contract code",
    baselineHash: CONTRACT_HASH_A,
    currentHash: CONTRACT_HASH_B,
    recipientIsContract: true,
    expectedScore: 55,
  },
]) {
  test(`a changed recipient code hash blocks fail-closed (${label})`, async () => {
    process.env[CODE_HASH_BASELINES_ENV_VAR] = baselineForAlice(baselineHash);
    const { calls, fetchImpl } = rpcFetchStub({
      accountsById: { "alice.testnet": { code_hash: currentHash } },
    });
    const requests = [];
    const policyRequests = [];
    const walletCalls = {};
    const result = await runPreflight({
      fetchImpl,
      walletCalls,
      policyAdapterRunner(serializedRequest) {
        policyRequests.push(JSON.parse(serializedRequest));
        return runWithTestPolicyOnly(serializedRequest);
      },
      adapterRunner(serializedRequest) {
        requests.push(JSON.parse(serializedRequest));
        return runWithTestPolicy(serializedRequest);
      },
    });

    assert.equal(result.status, "BLOCKED");
    assert.equal(result.guard.decision, "BLOCK");
    assert.equal(result.guard.risk.risk_score, expectedScore);
    assert.equal(result.guard.risk.reasons[0], "Recipient code hash changed");
    assert.equal(result.recipientCodeCheck.status, "CHANGED");
    assert.equal(result.recipientCodeCheck.codeHash, currentHash);
    assert.equal(Object.hasOwn(policyRequests[0].intent.transaction, "recipient_code_changed"), false);
    assert.equal(requests.length, 1);
    assert.equal(requests[0].intent.transaction.recipient_is_contract, recipientIsContract);
    assert.equal(requests[0].intent.transaction.recipient_code_changed, true);
    assert.equal(calls[3].params.account_id, "alice.testnet");
    assert.equal(result.submitted, false);
    assertNoSigningOrSending(walletCalls);
  });
}

test("known_malicious remains caller-supplied and is passed to final risk unchanged", async () => {
  const { calls, fetchImpl } = rpcFetchStub();
  const riskRequests = [];
  const walletCalls = {};
  const result = await runPreflight({
    context: { ...allowedContext, known_malicious: true },
    fetchImpl,
    walletCalls,
    adapterRunner(serializedRequest) {
      riskRequests.push(JSON.parse(serializedRequest));
      return runWithTestPolicy(serializedRequest);
    },
  });

  assert.equal(result.status, "BLOCKED");
  assert.equal(result.guard.risk.decision, "BLOCK");
  assert.equal(riskRequests[0].intent.transaction.known_malicious, true);
  assert.equal(result.guard.risk.reasons.includes("Recipient is marked as known malicious"), true);
  assert.deepEqual(calls.map(({ method }) => method), ["status", "query", "status", "query"]);
  assertNoSigningOrSending(walletCalls);
});

test("caller context cannot supply reserved recipient contract or code-change flags", () => {
  for (const field of ["recipient_is_contract", "recipient_code_changed"]) {
    assert.throws(() => makeTransferIntent({
      recipient: "alice.testnet",
      amountYocto: "1",
      context: { [field]: false },
    }), new RegExp(`reserved field ${field}`));
  }
  const intent = makeTransferIntent({
    recipient: "alice.testnet",
    amountYocto: "1",
    context: { known_malicious: true },
  });
  assert.equal(intent.transaction.known_malicious, true, "known_malicious remains caller-supplied");
});

test("missing operator baseline returns UNKNOWN/NEEDS_REVIEW before wallet or RPC access", async () => {
  delete process.env[CODE_HASH_BASELINES_ENV_VAR];
  let rpcCalls = 0;
  const walletCalls = {};
  const result = await runPreflight({
    walletCalls,
    fetchImpl: async () => { rpcCalls += 1; throw new Error("RPC must not run without a baseline"); },
  });
  assert.equal(result.status, "NEEDS_REVIEW");
  assert.equal(result.guard, null, "missing baseline must not expose a final ALLOW");
  assert.equal(result.preliminaryPolicy.allowed, true, "the policy-only result is separately labeled");
  assert.equal(result.recipientCodeCheck.status, "UNKNOWN");
  assert.match(result.recipientCodeCheck.reason, /No valid operator code-hash baseline/);
  assert.equal(result.account, null);
  assert.equal(result.submitted, false);
  assert.equal(rpcCalls, 0);
  assert.equal(walletCalls.wallet || 0, 0);
  assertNoSigningOrSending(walletCalls);
});

const validAliceBaselineEntry = {
  network: "testnet",
  account_id: "alice.testnet",
  code_hash: EMPTY_CODE_HASH,
};
const invalidBaselineCases = [
  ["malformed JSON", "["],
  ["malformed entry shape", JSON.stringify([{ network: "testnet", account_id: "alice.testnet" }])],
  ["duplicate entry for one account", JSON.stringify([validAliceBaselineEntry, validAliceBaselineEntry])],
  ["network mismatch", JSON.stringify([{ ...validAliceBaselineEntry, network: "mainnet" }])],
  ["recipient account mismatch", JSON.stringify([{ ...validAliceBaselineEntry, account_id: "bob.testnet" }])],
  ["invalid base58 character", JSON.stringify([{ ...validAliceBaselineEntry, code_hash: "0".repeat(32) }])],
  ["leading-zero byte count beyond 32 bytes", JSON.stringify([{ ...validAliceBaselineEntry, code_hash: "1".repeat(33) }])],
  ["44-character base58 value decoding beyond 32 bytes", JSON.stringify([{ ...validAliceBaselineEntry, code_hash: "z".repeat(44) }])],
];

for (const [label, rawBaseline] of invalidBaselineCases) {
  test(`rejects ${label} baseline before wallet or RPC access`, async () => {
    process.env[CODE_HASH_BASELINES_ENV_VAR] = rawBaseline;
    let rpcCalls = 0;
    let finalRiskCalls = 0;
    const walletCalls = {};
    const result = await runPreflight({
      walletCalls,
      fetchImpl: async () => { rpcCalls += 1; throw new Error("RPC must not run for an invalid baseline"); },
      adapterRunner(serializedRequest) {
        finalRiskCalls += 1;
        return runWithTestPolicy(serializedRequest);
      },
    });

    assert.equal(result.status, "NEEDS_REVIEW");
    assert.equal(result.guard, null, "an invalid baseline must not produce a final ALLOW");
    assert.equal(result.preliminaryPolicy.allowed, true, "the policy-only result remains separately labeled");
    assert.equal(result.recipientCodeCheck.status, "UNKNOWN");
    assert.match(result.recipientCodeCheck.reason, /No valid operator code-hash baseline/);
    assert.equal(result.account, null);
    assert.equal(result.submitted, false);
    assert.equal(rpcCalls, 0);
    assert.equal(finalRiskCalls, 0);
    assert.equal(walletCalls.wallet || 0, 0);
    assert.equal(walletCalls.getAccounts || 0, 0);
    assertNoSigningOrSending(walletCalls);
  });
}

test("does not read RPC or touch a wallet when the local policy denies the recipient", async () => {
  let rpcCalls = 0;
  const walletCalls = {};
  const result = await runPreflight({
    recipient: "mallory.testnet",
    walletCalls,
    fetchImpl: async () => { rpcCalls += 1; throw new Error("RPC should not run"); },
  });
  assert.equal(result.status, "BLOCKED");
  assert.equal(result.guard, null);
  assert.equal(result.policy.allowed, false);
  assert.equal(result.policy.reason, "recipient_not_allowed");
  assert.equal(result.account, null);
  assert.equal(rpcCalls, 0);
  assert.equal(walletCalls.wallet || 0, 0);
  assertNoSigningOrSending(walletCalls);
});

test("policy configuration error stops before wallet access and RPC", async () => {
  const walletCalls = {};
  let rpcCalls = 0;
  const result = await runPreflight({
    walletCalls,
    fetchImpl: async () => { rpcCalls += 1; throw new Error("RPC must not run"); },
    policyAdapterRunner: (serializedRequest) => runPythonPolicyAdapter(
      serializedRequest,
      undefined,
      null,
    ),
  });

  assert.equal(result.status, "NEEDS_REVIEW");
  assert.equal(result.guard, null);
  assert.equal(result.preliminaryPolicy.status, "ERROR");
  assert.equal(walletCalls.wallet || 0, 0);
  assert.equal(walletCalls.getAccounts || 0, 0);
  assert.equal(rpcCalls, 0);
  assertNoSigningOrSending(walletCalls);
});

test("invalid risk-context values stop during shape validation before wallet or RPC", async () => {
  const walletCalls = {};
  let rpcCalls = 0;
  const result = await runPreflight({
    context: { account_age_days: -1 },
    walletCalls,
    fetchImpl: async () => { rpcCalls += 1; throw new Error("RPC must not run"); },
  });

  assert.equal(result.status, "NEEDS_REVIEW");
  assert.equal(result.guard, null);
  assert.equal(result.preliminaryPolicy.status, "INVALID_INPUT");
  assert.equal(walletCalls.wallet || 0, 0);
  assert.equal(walletCalls.getAccounts || 0, 0);
  assert.equal(rpcCalls, 0);
});

test("policy ALLOW permits read-only checks, then missing history remains a final WARN without fabricated values", async () => {
  const { calls: rpcCalls, fetchImpl } = rpcFetchStub();
  const riskRequests = [];
  const policyRequests = [];
  const result = await runPreflight({
    context: {},
    fetchImpl,
    policyAdapterRunner(serializedRequest) {
      policyRequests.push(JSON.parse(serializedRequest));
      return runWithTestPolicyOnly(serializedRequest);
    },
    adapterRunner(serializedRequest) {
      riskRequests.push(JSON.parse(serializedRequest));
      return runWithTestPolicy(serializedRequest);
    },
  });
  assert.equal(result.status, "NEEDS_REVIEW");
  assert.equal(result.guard.decision, "WARN");
  assert.deepEqual(result.guard.risk.reasons, [
    "Account is less than 7 days old",
    "No previous interaction with recipient",
  ]);
  assert.equal(Object.hasOwn(policyRequests[0].intent.transaction, "account_age_days"), false);
  assert.equal(Object.hasOwn(policyRequests[0].intent.transaction, "previous_interactions"), false);
  assert.equal(Object.hasOwn(riskRequests[0].intent.transaction, "account_age_days"), false);
  assert.equal(Object.hasOwn(riskRequests[0].intent.transaction, "previous_interactions"), false);
  assert.equal(result.submitted, false);
  assert.deepEqual(rpcCalls.map(({ method }) => method), ["status", "query", "status", "query"]);
});

test("records policy allow, both read-only account checks, and final WARN in order", async () => {
  const sequence = [];
  const { calls: rpcCalls, fetchImpl: baseFetchImpl } = rpcFetchStub();
  const fetchImpl = async (url, options) => {
    const request = JSON.parse(options.body);
    sequence.push(request.method === "status" ? "rpc:status" : `rpc:query:${request.params.account_id}`);
    return baseFetchImpl(url, options);
  };
  const walletCalls = {};
  let policyResponse;
  const result = await runPreflight({
    context: {},
    fetchImpl,
    walletCalls,
    policyAdapterRunner(serializedRequest) {
      policyResponse = runWithTestPolicyOnly(serializedRequest);
      sequence.push(policyResponse.allowed === true ? "policy:allow" : "policy:not-allow");
      return policyResponse;
    },
    adapterRunner(serializedRequest) {
      sequence.push("risk:final");
      return runWithTestPolicy(serializedRequest);
    },
  });

  assert.equal(policyResponse.status, "POLICY_EVALUATED");
  assert.equal(policyResponse.allowed, true);
  assert.equal(result.status, "NEEDS_REVIEW");
  assert.equal(result.guard.decision, "WARN");
  assert.equal(result.submitted, false);
  assert.deepEqual(rpcCalls.map(({ method }) => method), ["status", "query", "status", "query"]);
  assert.deepEqual(sequence, [
    "policy:allow",
    "rpc:status",
    "rpc:query:sender.testnet",
    "rpc:status",
    "rpc:query:alice.testnet",
    "risk:final",
  ]);
  assertNoSigningOrSending(walletCalls);
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

test("fails closed when RPC chain_id changes between sender and recipient reads", async () => {
  const rpcCalls = [];
  let statusReads = 0;
  const fetchImpl = async (url, options) => {
    assert.equal(url, TESTNET_RPC_URL);
    const request = JSON.parse(options.body);
    rpcCalls.push(request);
    let result;
    if (request.method === "status") {
      statusReads += 1;
      result = { chain_id: statusReads === 1 ? "testnet" : "mainnet" };
    } else {
      result = {
        amount: "10000000000000000000000000",
        locked: "0",
        storage_usage: 182,
        code_hash: EMPTY_CODE_HASH,
      };
    }
    return {
      ok: true,
      status: 200,
      json: async () => ({ jsonrpc: "2.0", id: request.id, result }),
    };
  };
  let finalRiskCalls = 0;
  const walletCalls = {};
  const result = await runPreflight({
    fetchImpl,
    walletCalls,
    adapterRunner(serializedRequest) {
      finalRiskCalls += 1;
      return runWithTestPolicy(serializedRequest);
    },
  });

  assert.equal(result.status, "NEEDS_REVIEW");
  assert.equal(result.guard, null, "a network mismatch must prevent final risk evaluation");
  assert.equal(result.preliminaryPolicy.allowed, true);
  assert.equal(result.recipientCodeCheck.status, "UNKNOWN");
  assert.equal(result.account, null);
  assert.equal(result.submitted, false);
  assert.deepEqual(rpcCalls.map(({ method, params }) => [method, params?.account_id]), [
    ["status", undefined],
    ["query", "sender.testnet"],
    ["status", undefined],
  ]);
  assert.equal(finalRiskCalls, 0);
  assertNoSigningOrSending(walletCalls);
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
      policyAdapterRunner: runWithTestPolicyOnly,
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

test("returns NEEDS_REVIEW on an HTTP error without signing, submission, or false success", async () => {
  await assertPreflightRpcFailure(async (url) => {
    assert.equal(url, TESTNET_RPC_URL);
    return { ok: false, status: 503 };
  });
});

test("returns NEEDS_REVIEW on a JSON-RPC error without signing or submission", async () => {
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
  });
});

for (const [label, error] of [
  ["error: null", null],
  ["error: false", false],
  ["error and result together", { code: -32000, message: "account lookup unavailable" }],
]) {
  test(`returns NEEDS_REVIEW when a JSON-RPC envelope contains ${label}`, async () => {
    let rpcCalls = 0;
    const result = await assertPreflightRpcFailure(async (_url, options) => {
      const request = JSON.parse(options.body);
      rpcCalls += 1;
      return {
        ok: true,
        status: 200,
        json: async () => ({
          jsonrpc: "2.0",
          id: request.id,
          error,
          result: request.method === "status"
            ? { chain_id: "testnet" }
            : {
              amount: "10000000000000000000000000",
              locked: "0",
              storage_usage: 182,
              code_hash: EMPTY_CODE_HASH,
            },
        }),
      };
    });

    assert.equal(result.status, "NEEDS_REVIEW");
    assert.equal(rpcCalls, 1, "an error-bearing response must stop the preflight immediately");
  });
}

test("returns NEEDS_REVIEW on a malformed JSON-RPC envelope", async () => {
  await assertPreflightRpcFailure(async () => ({
    ok: true,
    status: 200,
    json: async () => ({ jsonrpc: "1.0", id: "wrong", result: { chain_id: "testnet" } }),
  }));
});

test("returns NEEDS_REVIEW when the RPC response body is malformed JSON", async () => {
  await assertPreflightRpcFailure(async () => ({
    ok: true,
    status: 200,
    json: async () => { throw new SyntaxError("malformed JSON body"); },
  }));
});

test("returns NEEDS_REVIEW when the recipient account does not exist", async () => {
  const { calls, fetchImpl } = rpcFetchStub({
    errorsByAccountId: { "alice.testnet": "UNKNOWN_ACCOUNT" },
  });
  const walletCalls = {};
  const result = await runPreflight({ fetchImpl, walletCalls });
  assert.equal(result.status, "NEEDS_REVIEW");
  assert.equal(result.recipientCodeCheck.status, "UNKNOWN");
  assert.equal(result.account, null);
  assert.deepEqual(calls.map(({ method }) => method), ["status", "query", "status", "query"]);
  assert.equal(calls[3].params.account_id, "alice.testnet");
  assertNoSigningOrSending(walletCalls);
});

test("returns NEEDS_REVIEW on a malformed account payload or code hash", async () => {
  let requestCount = 0;
  const result = await assertPreflightRpcFailure(async (_url, options) => {
    const request = JSON.parse(options.body);
    requestCount += 1;
    const payload = request.method === "status"
      ? { result: { chain_id: "testnet" } }
      : { result: { amount: "not-an-amount", locked: "0", storage_usage: 1, code_hash: "hash" } };
    return {
      ok: true,
      status: 200,
      json: async () => ({ jsonrpc: "2.0", id: request.id, ...payload }),
    };
  });
  assert.equal(requestCount, 2);
  assert.equal(result.recipientCodeCheck.status, "UNKNOWN");
});

test("returns NEEDS_REVIEW when the testnet RPC request is aborted at timeout", {
  timeout: RPC_TIMEOUT_MS + 2000,
}, async () => {
  let aborted = false;
  await assertPreflightRpcFailure((_url, options) => new Promise((_resolve, reject) => {
    options.signal.addEventListener("abort", () => {
      aborted = true;
      reject(Object.assign(new Error("RPC request aborted"), { name: "AbortError" }));
    }, { once: true });
  }));
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
