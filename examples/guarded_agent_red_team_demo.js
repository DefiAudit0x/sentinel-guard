#!/usr/bin/env node
"use strict";

/**
 * Deterministic, local-only red-team demonstration of the Node/Python guard.
 * Uses fictional requests and the checked-in test policy; it never signs,
 * submits, connects to a wallet, or accesses a network.
 */
const path = require("node:path");
const {
  evaluateAndMockSign,
  makeRequest,
  runPythonAdapter,
} = require("./guarded_agent_bridge.js");

const PROJECT_ROOT = path.resolve(__dirname, "..");
const DEMO_POLICY = path.join(PROJECT_ROOT, "examples", "test_policy.json");
const YOCTO_PER_NEAR = 10n ** 24n;

function transferRequest(requestId, recipient, amountYocto) {
  return makeRequest(requestId, "transfer", {
    recipient,
    amount_yocto: String(amountYocto),
    previous_interactions: 3,
    account_age_days: 365,
  });
}

function runScenario(label, request, adapterRunner, expected) {
  let mockCallbackCalls = 0;
  const result = evaluateAndMockSign(request, (intent) => {
    mockCallbackCalls += 1;
    return `MOCK-ONLY (not a signature): ${intent.transaction.recipient}`;
  }, { adapterRunner });

  const response = result.response;
  const passed = mockCallbackCalls === expected.mockCallbackCalls
    && (expected.errorIncludes
      ? typeof result.error === "string" && result.error.includes(expected.errorIncludes)
      : result.error === null)
    && (expected.status === null ? response === null : response?.status === expected.status)
    && (expected.decision === null ? response === null : response?.decision === expected.decision)
    && (expected.policyReason === undefined
      || response?.policy?.reason === expected.policyReason);

  return {
    label,
    status: response?.status ?? "BRIDGE_ERROR",
    decision: response?.decision ?? "BLOCK",
    policyReason: response?.policy?.reason ?? null,
    mockCallbackCalls,
    mockCallbackResult: result.mockSignature,
    error: result.error,
    passed,
  };
}

function runDemo() {
  const realLocalAdapter = (serialized) =>
    runPythonAdapter(serialized, undefined, DEMO_POLICY);
  const allowedRequest = transferRequest(
    "red-team-allow",
    "alice.near",
    YOCTO_PER_NEAR,
  );
  const alteredRecipient = transferRequest(
    "red-team-altered-recipient",
    "mallory.near",
    YOCTO_PER_NEAR,
  );
  const overCapRequest = transferRequest(
    "red-team-over-cap",
    "alice.near",
    20n * YOCTO_PER_NEAR + 1n,
  );

  return [
    runScenario("fictional allowed transfer", allowedRequest, realLocalAdapter, {
      status: "COMPLETED",
      decision: "ALLOW",
      mockCallbackCalls: 1,
    }),
    runScenario("altered recipient", alteredRecipient, realLocalAdapter, {
      status: "COMPLETED",
      decision: "BLOCK",
      policyReason: "recipient_not_allowed",
      mockCallbackCalls: 0,
    }),
    runScenario("amount above the policy cap", overCapRequest, realLocalAdapter, {
      status: "COMPLETED",
      decision: "BLOCK",
      policyReason: "amount_limit_exceeded",
      mockCallbackCalls: 0,
    }),
    runScenario("malformed adapter JSON", allowedRequest, (serialized) =>
      runPythonAdapter(serialized, () => ({
        status: 0,
        stdout: "{not-json",
        stderr: "",
        error: null,
      }), DEMO_POLICY), {
      status: null,
      decision: null,
      errorIncludes: "malformed JSON",
      mockCallbackCalls: 0,
    }),
    runScenario("inconsistent adapter intent hash", allowedRequest, (serialized) => {
      const response = runPythonAdapter(serialized, undefined, DEMO_POLICY);
      return { ...response, intent_hash: "0".repeat(64) };
    }, {
      status: null,
      decision: null,
      errorIncludes: "request-identity",
      mockCallbackCalls: 0,
    }),
  ];
}

function main() {
  const results = runDemo();
  console.log("Sentinel Guard — local red-team bridge demo");
  console.log("Synthetic inputs only; no network, wallet, signing, or submission.\n");

  for (const result of results) {
    console.log(`${result.label}: status=${result.status}, decision=${result.decision}, mock callback calls=${result.mockCallbackCalls}`);
    if (result.policyReason) console.log(`  Policy reason: ${result.policyReason}`);
    if (result.mockCallbackResult) console.log(`  ${result.mockCallbackResult}`);
    if (result.error) console.log(`  Fail-closed reason: ${result.error}`);
    console.log(`  Expected-result check: ${result.passed ? "PASS" : "FAIL"}`);
  }

  const allPassed = results.every((result) => result.passed);
  console.log(`\nOverall: ${allPassed ? "PASS" : "FAIL"}`);
  return allPassed ? 0 : 1;
}

if (require.main === module) process.exitCode = main();

module.exports = { runDemo };
