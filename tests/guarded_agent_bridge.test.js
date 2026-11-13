"use strict";

const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const path = require("node:path");
const test = require("node:test");
const {
  ADAPTER_TIMEOUT_MS,
  MAX_INPUT_BYTES,
  MAX_OUTPUT_BYTES,
  evaluateAndMockSign,
  evaluatePolicyIntent,
  runPythonAdapter,
  runPythonPolicyAdapter,
} = require("../examples/guarded_agent_bridge.js");

const EXAMPLE_POLICY = path.resolve(__dirname, "../examples/test_policy.json");

function runWithExamplePolicy(serialized) {
  return runPythonAdapter(serialized, undefined, EXAMPLE_POLICY);
}

function runWithExamplePolicyOnly(serialized) {
  return runPythonPolicyAdapter(serialized, undefined, EXAMPLE_POLICY);
}

function makeRequest(requestId = "node-test-1") {
  return {
    request_id: requestId,
    intent: {
      action: "transfer",
      resource: "alice.near",
      transaction: {
        recipient: "alice.near",
        amount_yocto: "1000000000000000000000000",
        previous_interactions: 3,
        account_age_days: 365,
      },
    },
  };
}

function intentHash(request) {
  function canonical(value) {
    if (value === null || typeof value !== "object") return JSON.stringify(value);
    if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  }
  return createHash("sha256").update(canonical(request.intent), "utf8").digest("hex");
}

function responseFor(request, overrides = {}) {
  const policy = {
    status: "EVALUATED",
    allowed: true,
    reason: "matched_allow_rule",
    matched_rule: "json-policy-recipient-allow-list",
    error: null,
    error_stage: null,
  };
  const risk = {
    status: "EVALUATED",
    decision: "ALLOW",
    risk_score: 0,
    reasons: [],
    error: null,
  };
  return {
    request_id: request.request_id,
    intent_hash: intentHash(request),
    status: "COMPLETED",
    decision: "ALLOW",
    policy,
    risk,
    reasons: [],
    ...overrides,
  };
}

function policyResponseFor(request, overrides = {}) {
  return {
    request_id: request.request_id,
    intent_hash: intentHash(request),
    status: "POLICY_EVALUATED",
    allowed: true,
    reason: "matched_allow_rule",
    matched_rule: "json-policy-recipient-allow-list",
    error: null,
    ...overrides,
  };
}

test("policy-only bridge returns a request-bound policy decision without risk fields", () => {
  const request = makeRequest("policy-only-real-adapter");
  const result = evaluatePolicyIntent(request, { adapterRunner: runWithExamplePolicyOnly });

  assert.equal(result.error, null);
  assert.equal(result.response.status, "POLICY_EVALUATED");
  assert.equal(result.response.request_id, request.request_id);
  assert.equal(result.response.intent_hash, intentHash(request));
  assert.equal(result.response.allowed, true);
  assert.equal(Object.hasOwn(result.response, "risk"), false);
});

test("policy-only bridge stops on a real policy denial", () => {
  const request = makeRequest("policy-only-deny");
  request.intent.resource = "mallory.near";
  request.intent.transaction.recipient = "mallory.near";
  const result = evaluatePolicyIntent(request, { adapterRunner: runWithExamplePolicyOnly });

  assert.equal(result.error, null);
  assert.equal(result.response.status, "POLICY_EVALUATED");
  assert.equal(result.response.allowed, false);
  assert.equal(result.response.reason, "recipient_not_allowed");
});

test("policy-only bridge rejects malformed or mismatched response identity", () => {
  const request = makeRequest("policy-only-response-binding");
  const mismatched = policyResponseFor(request, { request_id: "other-request" });
  const extraField = policyResponseFor(request, { decision: "ALLOW" });
  for (const response of [mismatched, extraField]) {
    const result = evaluatePolicyIntent(request, { adapterRunner: () => response });
    assert.equal(result.response, null);
    assert.match(result.error, /schema or request-identity/);
  }
});

test("policy-only subprocess uses the isolated fixed adapter invocation", () => {
  const request = makeRequest("policy-only-subprocess");
  const serialized = JSON.stringify(request);
  let observed;
  const valid = policyResponseFor(request);
  const response = runPythonPolicyAdapter(serialized, (...args) => {
    observed = args;
    return { status: 0, stdout: JSON.stringify(valid), stderr: "", error: null };
  }, EXAMPLE_POLICY);

  assert.equal(response.request_id, request.request_id);
  assert.deepEqual(observed[1].slice(0, 3), ["-I", "-S", "-B"]);
  assert.match(observed[1][3], /sentinel_guard\/json_adapter\.py$/);
  assert.deepEqual(observed[1][4], "--policy-only");
  assert.equal(observed[2].shell, false);
  assert.equal(observed[2].input, serialized);
  assert.equal(observed[2].timeout, ADAPTER_TIMEOUT_MS);
  assert.equal(observed[2].maxBuffer, MAX_OUTPUT_BYTES);
  assert.equal(observed[2].env.SENTINEL_GUARD_POLICY_FILE, EXAMPLE_POLICY);
});

function invokeWith(responseOrThrow, request = makeRequest()) {
  let signerCalls = 0;
  const adapterRunner = typeof responseOrThrow === "function"
    ? responseOrThrow
    : () => {
      if (responseOrThrow instanceof Error) throw responseOrThrow;
      return responseOrThrow;
    };
  const result = evaluateAndMockSign(request, () => {
    signerCalls += 1;
    return "MOCK-ONLY";
  }, {
    adapterRunner,
  });
  return { result, signerCalls };
}

const negativeResponses = [
  ["WARN", (response) => {
    response.decision = "WARN";
    response.risk.decision = "WARN";
    response.risk.risk_score = 30;
    response.risk.reasons = ["Transaction amount exceeds threshold"];
    response.reasons = ["Risk: Transaction amount exceeds threshold"];
  }],
  ["BLOCK", (response) => {
    response.decision = "BLOCK";
    response.risk.decision = "BLOCK";
    response.risk.risk_score = 100;
    response.risk.reasons = ["Recipient is marked as known malicious"];
    response.reasons = ["Risk: Recipient is marked as known malicious"];
  }],
  ["INVALID_INPUT", (response) => {
    response.status = "INVALID_INPUT";
    response.decision = "BLOCK";
    response.policy.status = "NOT_EVALUATED";
    response.policy.allowed = null;
    response.policy.reason = null;
    response.policy.matched_rule = null;
    response.policy.error = null;
    response.policy.error_stage = null;
    response.risk.status = "NOT_EVALUATED";
    response.risk.decision = null;
    response.risk.risk_score = null;
    response.risk.reasons = [];
    response.risk.error = null;
    response.reasons = ["unsupported action"];
  }],
  ["ERROR", (response) => {
    response.status = "ERROR";
    response.decision = "BLOCK";
    response.policy.status = "ERROR";
    response.policy.allowed = null;
    response.policy.reason = null;
    response.policy.matched_rule = null;
    response.policy.error = "RuntimeError: local evaluator failure";
    response.policy.error_stage = "CALL";
    response.reasons = ["Policy evaluation error"];
  }],
];

for (const [label, modify] of negativeResponses) {
  test(`mock signer is not called for ${label}`, () => {
    const request = makeRequest();
    const response = responseFor(request);
    modify(response);
    const { result, signerCalls } = invokeWith(response, request);

    assert.equal(result.error, null);
    const expectedStatus = label === "WARN" || label === "BLOCK" ? "COMPLETED" : label;
    const expectedDecision = label === "WARN" ? "WARN" : "BLOCK";
    assert.equal(result.response.status, expectedStatus);
    assert.equal(result.response.decision, expectedDecision);
    assert.equal(signerCalls, 0);
    assert.equal(result.mockSignature, null);
  });
}

test("mock signer is called exactly once for same-request COMPLETED ALLOW", () => {
  const request = makeRequest();
  const response = responseFor(request);
  const { result, signerCalls } = invokeWith(response, request);

  assert.equal(result.error, null);
  assert.equal(result.response.status, "COMPLETED");
  assert.equal(result.response.decision, "ALLOW");
  assert.equal(signerCalls, 1);
  assert.equal(result.mockSignature, "MOCK-ONLY");
});

test("mock signer accepts a consistent benign 15-point ALLOW exactly once", () => {
  const request = makeRequest();
  const response = responseFor(request);
  response.risk.risk_score = 15;
  response.risk.reasons = ["Account is less than 7 days old"];
  response.reasons = ["Risk: Account is less than 7 days old"];
  const { result, signerCalls } = invokeWith(response, request);

  assert.equal(result.error, null);
  assert.equal(result.response.status, "COMPLETED");
  assert.equal(result.response.decision, "ALLOW");
  assert.equal(result.response.risk.risk_score, 15);
  assert.equal(signerCalls, 1);
  assert.equal(result.mockSignature, "MOCK-ONLY");
});

test("mock signer rejects COMPLETED ALLOW when policy details deny", () => {
  const request = makeRequest();
  const response = responseFor(request);
  response.policy.allowed = false;
  response.policy.reason = "default_deny";
  response.policy.matched_rule = null;
  response.reasons = ["Policy denied: default_deny"];
  const { result, signerCalls } = invokeWith(response, request);

  assert.equal(result.response, null);
  assert.match(result.error, /schema or request-identity/);
  assert.equal(signerCalls, 0);
  assert.equal(result.mockSignature, null);
});

test("mock signer rejects COMPLETED ALLOW when risk details BLOCK", () => {
  const request = makeRequest();
  const response = responseFor(request);
  response.risk.decision = "BLOCK";
  response.risk.risk_score = 50;
  response.risk.reasons = ["Recipient is marked as known malicious"];
  response.reasons = ["Risk: Recipient is marked as known malicious"];
  const { result, signerCalls } = invokeWith(response, request);

  assert.equal(result.response, null);
  assert.match(result.error, /schema or request-identity/);
  assert.equal(signerCalls, 0);
  assert.equal(result.mockSignature, null);
});

test("mock signer is not called for malformed response schema", () => {
  const response = responseFor(makeRequest());
  delete response.risk.reasons;
  const { result, signerCalls } = invokeWith(response);

  assert.equal(result.response, null);
  assert.match(result.error, /schema or request-identity/);
  assert.equal(signerCalls, 0);
});

test("mock signer is not called when subprocess output is malformed JSON", () => {
  const { result, signerCalls } = invokeWith((serialized) => runPythonAdapter(serialized, () => ({
    status: 0,
    stdout: "{not-json",
    stderr: "",
    error: null,
  })));

  assert.equal(result.response, null);
  assert.match(result.error, /malformed JSON/);
  assert.equal(signerCalls, 0);
});

test("mock signer is not called for a different request id or intent hash", () => {
  const request = makeRequest();
  const mismatchedId = responseFor(request, { request_id: "other-request" });
  const mismatchedHash = responseFor(request, { intent_hash: "0".repeat(64) });

  for (const response of [mismatchedId, mismatchedHash]) {
    const { result, signerCalls } = invokeWith(response, request);
    assert.equal(result.response, null);
    assert.match(result.error, /request-identity/);
    assert.equal(signerCalls, 0);
  }
});

test("mock signer is not called after a subprocess timeout", () => {
  const timeout = Object.assign(new Error("spawnSync timed out"), { code: "ETIMEDOUT" });
  const { result, signerCalls } = invokeWith((serialized) => runPythonAdapter(serialized, () => ({
    error: timeout,
    status: null,
    stdout: "",
  })));

  assert.equal(result.response, null);
  assert.match(result.error, /timed out/);
  assert.equal(signerCalls, 0);
});

test("mock signer is not called after a subprocess launch/process error", () => {
  const processError = Object.assign(new Error("python executable missing"), { code: "ENOENT" });
  const { result, signerCalls } = invokeWith((serialized) => runPythonAdapter(serialized, () => ({
    error: processError,
    status: null,
    stdout: "",
  })));

  assert.equal(result.response, null);
  assert.match(result.error, /missing/);
  assert.equal(signerCalls, 0);
});

test("fixed subprocess invocation uses bounded input, output, and timeout without a shell", () => {
  const request = makeRequest();
  const serialized = JSON.stringify(request);
  let observed;
  const valid = responseFor(request);
  const response = runPythonAdapter(serialized, (...args) => {
    observed = args;
    return { status: 0, stdout: JSON.stringify(valid), stderr: "", error: null };
  });

  assert.equal(response.request_id, request.request_id);
  assert.equal(observed[1][0], "-I");
  assert.equal(observed[1][1], "-S");
  assert.equal(observed[1][2], "-B");
  assert.equal(observed[2].shell, false);
  assert.equal(observed[2].input, serialized);
  assert.equal(observed[2].timeout, ADAPTER_TIMEOUT_MS);
  assert.equal(observed[2].maxBuffer, MAX_OUTPUT_BYTES);
  assert.ok(Buffer.byteLength(serialized, "utf8") < MAX_INPUT_BYTES);
});

test("oversized request is rejected before adapter runner and mock signer", () => {
  const request = makeRequest();
  request.intent.padding = "💩".repeat(Math.ceil(MAX_INPUT_BYTES / 4));
  let adapterCalls = 0;
  let signerCalls = 0;
  let stringifyCalls = 0;
  const originalStringify = JSON.stringify;
  let result;
  JSON.stringify = () => {
    stringifyCalls += 1;
    throw new Error("oversized request must not be serialized");
  };
  try {
    result = evaluateAndMockSign(request, () => {
      signerCalls += 1;
      return "MUST-NOT-RUN";
    }, {
      adapterRunner: () => {
        adapterCalls += 1;
        return responseFor(request);
      },
    });
  } finally {
    JSON.stringify = originalStringify;
  }

  assert.equal(result.response, null);
  assert.match(result.error, /65536-byte input limit/);
  assert.equal(stringifyCalls, 0);
  assert.equal(adapterCalls, 0);
  assert.equal(signerCalls, 0);
});

test("size precheck handles deep input iteratively and rejects before serialization", () => {
  const request = makeRequest();
  let nested = {};
  for (let index = 0; index < 20_000; index += 1) nested = { child: nested };
  request.intent.deep = nested;
  let stringifyCalls = 0;
  let adapterCalls = 0;
  const originalStringify = JSON.stringify;
  let result;
  JSON.stringify = () => {
    stringifyCalls += 1;
    throw new Error("deep request must not be serialized");
  };
  try {
    result = evaluateAndMockSign(request, () => "MUST-NOT-RUN", {
      adapterRunner: () => {
        adapterCalls += 1;
        return responseFor(request);
      },
    });
  } finally {
    JSON.stringify = originalStringify;
  }
  assert.equal(result.response, null);
  assert.match(result.error, /nesting exceeds the 256-level bridge limit/);
  assert.equal(stringifyCalls, 0);
  assert.equal(adapterCalls, 0);
});

test("request exactly at the input-byte limit remains accepted", () => {
  const request = makeRequest();
  request.intent.padding = "";
  const emptyPaddingBytes = Buffer.byteLength(JSON.stringify(request), "utf8");
  const pattern = "💩\n\\\"\u0000\ud800";
  const patternBytes = Buffer.byteLength(JSON.stringify(pattern), "utf8") - 2;
  const remainingBytes = MAX_INPUT_BYTES - emptyPaddingBytes;
  request.intent.padding = pattern.repeat(Math.floor(remainingBytes / patternBytes))
    + "x".repeat(remainingBytes % patternBytes);
  const serializedBytes = Buffer.byteLength(JSON.stringify(request), "utf8");
  assert.equal(serializedBytes, MAX_INPUT_BYTES);
  let adapterCalls = 0;
  let receivedBytes = null;
  const result = evaluateAndMockSign(request, () => "MOCK-ONLY", {
    adapterRunner: (serialized) => {
      adapterCalls += 1;
      receivedBytes = Buffer.byteLength(serialized, "utf8");
      return responseFor(request);
    },
  });
  assert.equal(result.error, null);
  assert.equal(result.response.decision, "ALLOW");
  assert.equal(adapterCalls, 1);
  assert.equal(receivedBytes, MAX_INPUT_BYTES);
});

test("default bridge round-trips through the real local Python adapter", () => {
  const request = makeRequest("actual-adapter-test");
  let signerCalls = 0;
  const result = evaluateAndMockSign(request, () => {
    signerCalls += 1;
    return "MOCK-ONLY";
  }, { adapterRunner: runWithExamplePolicy });

  assert.equal(result.error, null);
  assert.equal(result.response.request_id, request.request_id);
  assert.equal(result.response.intent_hash, intentHash(request));
  assert.equal(result.response.status, "COMPLETED");
  assert.equal(result.response.decision, "ALLOW");
  assert.equal(signerCalls, 1);
});

test("real Python adapter ALLOW with a benign 15-point signal reaches mock signer once", () => {
  const request = makeRequest("actual-young-account-test");
  request.intent.transaction.account_age_days = 1;
  let signerCalls = 0;
  const result = evaluateAndMockSign(request, () => {
    signerCalls += 1;
    return "MOCK-ONLY";
  }, { adapterRunner: runWithExamplePolicy });

  assert.equal(result.error, null);
  assert.equal(result.response.status, "COMPLETED");
  assert.equal(result.response.decision, "ALLOW");
  assert.equal(result.response.risk.risk_score, 15);
  assert.deepEqual(result.response.risk.reasons, ["Account is less than 7 days old"]);
  assert.deepEqual(result.response.reasons, ["Risk: Account is less than 7 days old"]);
  assert.equal(signerCalls, 1);
});

test("real Python-adapter BLOCK result never invokes the mock signer", () => {
  const request = makeRequest("actual-block-test");
  request.intent.transaction.known_malicious = true;
  let signerCalls = 0;
  const result = evaluateAndMockSign(request, () => {
    signerCalls += 1;
    return "MUST-NOT-RUN";
  }, { adapterRunner: runWithExamplePolicy });

  assert.equal(result.error, null);
  assert.equal(result.response.status, "COMPLETED");
  assert.equal(result.response.decision, "BLOCK");
  assert.equal(signerCalls, 0);
  assert.equal(result.mockSignature, null);
});

test("real policy denies an unapproved recipient before the mock signer", () => {
  const request = makeRequest("actual-unapproved-recipient-test");
  request.intent.resource = "mallory.near";
  request.intent.transaction.recipient = "mallory.near";
  let signerCalls = 0;
  const result = evaluateAndMockSign(request, () => {
    signerCalls += 1;
    return "MUST-NOT-RUN";
  }, { adapterRunner: runWithExamplePolicy });

  assert.equal(result.error, null);
  assert.equal(result.response.status, "COMPLETED");
  assert.equal(result.response.decision, "BLOCK");
  assert.equal(result.response.policy.reason, "recipient_not_allowed");
  assert.equal(signerCalls, 0);
  assert.equal(result.mockSignature, null);
});

test("real policy denies an over-cap amount before the mock signer", () => {
  const request = makeRequest("actual-over-cap-test");
  request.intent.transaction.amount_yocto = "20000000000000000000000001";
  let signerCalls = 0;
  const result = evaluateAndMockSign(request, () => {
    signerCalls += 1;
    return "MUST-NOT-RUN";
  }, { adapterRunner: runWithExamplePolicy });

  assert.equal(result.error, null);
  assert.equal(result.response.status, "COMPLETED");
  assert.equal(result.response.decision, "BLOCK");
  assert.equal(result.response.policy.reason, "amount_limit_exceeded");
  assert.equal(signerCalls, 0);
  assert.equal(result.mockSignature, null);
});

test("local red-team demo allows only the mock callback and fails closed on attacks", () => {
  const { runDemo } = require("../examples/guarded_agent_red_team_demo.js");
  const results = runDemo();
  const byLabel = new Map(results.map((result) => [result.label, result]));

  assert.equal(results.length, 5);
  assert.ok(results.every((result) => result.passed));
  assert.equal(byLabel.get("fictional allowed transfer").mockCallbackCalls, 1);
  assert.match(
    byLabel.get("fictional allowed transfer").mockCallbackResult,
    /^MOCK-ONLY \(not a signature\): alice\.near$/,
  );
  for (const label of [
    "altered recipient",
    "amount above the policy cap",
    "malformed adapter JSON",
    "inconsistent adapter intent hash",
  ]) {
    assert.equal(byLabel.get(label).mockCallbackCalls, 0, `${label} must not reach callback`);
    assert.equal(byLabel.get(label).mockCallbackResult, null);
  }
  assert.equal(byLabel.get("altered recipient").policyReason, "recipient_not_allowed");
  assert.equal(byLabel.get("amount above the policy cap").policyReason, "amount_limit_exceeded");
});

test("missing policy configuration fails closed before the mock signer", () => {
  const request = makeRequest("actual-missing-policy-test");
  let signerCalls = 0;
  const result = evaluateAndMockSign(request, () => {
    signerCalls += 1;
    return "MUST-NOT-RUN";
  }, {
    adapterRunner: (serialized) => runPythonAdapter(serialized, undefined, null),
  });

  assert.equal(result.error, null);
  assert.equal(result.response.status, "ERROR");
  assert.equal(result.response.decision, "BLOCK");
  assert.equal(signerCalls, 0);
  assert.equal(result.mockSignature, null);
});
