#!/usr/bin/env node
"use strict";

/**
 * Local-only Node/Python bridge demo. No NEAR SDK, wallet, key, network, or
 * real signing is used. The only callback accepted here is explicitly named
 * mockSigner and is reachable only after a valid, request-bound ALLOW result.
 */
const { spawnSync } = require("node:child_process");
const { createHash } = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const PROJECT_ROOT = path.resolve(__dirname, "..");
const PYTHON = path.join(PROJECT_ROOT, ".venv", "bin", "python");
const ADAPTER = path.join(PROJECT_ROOT, "sentinel_guard", "json_adapter.py");
const POLICY_ENV_VAR = "SENTINEL_GUARD_POLICY_FILE";
const EXAMPLE_POLICY = path.join(PROJECT_ROOT, "examples", "test_policy.json");
const MAX_INPUT_BYTES = 64 * 1024;
const MAX_OUTPUT_BYTES = 64 * 1024;
const ADAPTER_TIMEOUT_MS = 2500;
const REQUEST_ID_MAX_LENGTH = 128;

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function canonicalJson(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("non-finite number in intent");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (isPlainObject(value)) {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  throw new TypeError("intent must contain only JSON values");
}

function freezeRecursively(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) freezeRecursively(child);
  }
  return value;
}

function exactKeys(value, expected) {
  return isPlainObject(value)
    && Object.keys(value).length === expected.length
    && expected.every((key) => Object.hasOwn(value, key));
}

function isStringOrNull(value) {
  return value === null || typeof value === "string";
}

function validateResponse(response, requestId, intentHash) {
  if (!exactKeys(response, ["request_id", "intent_hash", "status", "decision", "policy", "risk", "reasons"])) {
    return false;
  }
  if (response.request_id !== requestId || response.intent_hash !== intentHash) return false;
  if (!/^[0-9a-f]{64}$/.test(response.intent_hash)) return false;
  if (!["COMPLETED", "INVALID_INPUT", "ERROR"].includes(response.status)) return false;
  if (!["ALLOW", "WARN", "BLOCK"].includes(response.decision)) return false;
  if (!Array.isArray(response.reasons) || response.reasons.some((item) => typeof item !== "string")) return false;

  const policy = response.policy;
  if (!exactKeys(policy, ["status", "allowed", "reason", "matched_rule", "error", "error_stage"])) return false;
  if (!["EVALUATED", "ERROR", "NOT_EVALUATED"].includes(policy.status)) return false;
  if (policy.allowed !== null && typeof policy.allowed !== "boolean") return false;
  if (!isStringOrNull(policy.reason) || !isStringOrNull(policy.matched_rule) || !isStringOrNull(policy.error)) return false;
  if (policy.error_stage !== null && !["LOOKUP", "CONTRACT", "CALL"].includes(policy.error_stage)) return false;

  const risk = response.risk;
  if (!exactKeys(risk, ["status", "decision", "risk_score", "reasons", "error"])) return false;
  if (!["EVALUATED", "ERROR", "NOT_EVALUATED"].includes(risk.status)) return false;
  if (risk.decision !== null && !["ALLOW", "WARN", "BLOCK"].includes(risk.decision)) return false;
  if (risk.risk_score !== null && (!Number.isInteger(risk.risk_score) || risk.risk_score < 0 || risk.risk_score > 100)) return false;
  if (!Array.isArray(risk.reasons) || risk.reasons.some((item) => typeof item !== "string")) return false;
  if (!isStringOrNull(risk.error)) return false;

  if (policy.status === "EVALUATED") {
    if (typeof policy.allowed !== "boolean" || typeof policy.reason !== "string" || !policy.reason.trim()) return false;
    if (policy.error !== null || policy.error_stage !== null) return false;
    if (policy.allowed && policy.matched_rule !== "json-policy-recipient-allow-list") return false;
  } else if (policy.status === "ERROR") {
    if (policy.allowed !== null || policy.reason !== null || policy.matched_rule !== null) return false;
    if (typeof policy.error !== "string" || !policy.error.trim() || policy.error_stage === null) return false;
  } else if (policy.allowed !== null || policy.reason !== null || policy.matched_rule !== null
      || policy.error !== null || policy.error_stage !== null) {
    return false;
  }

  if (risk.status === "EVALUATED") {
    if (risk.decision === null || risk.risk_score === null || risk.error !== null) return false;
    const scoreMatchesDecision = risk.decision === "ALLOW" ? risk.risk_score < 20
      : risk.decision === "WARN" ? risk.risk_score >= 20 && risk.risk_score < 50
        : risk.risk_score >= 50;
    if (!scoreMatchesDecision) return false;
    if (risk.decision !== "ALLOW" && risk.reasons.length === 0) return false;
  } else if (risk.status === "ERROR") {
    if (risk.decision !== null || risk.risk_score !== null || risk.reasons.length !== 0) return false;
    if (typeof risk.error !== "string" || !risk.error.trim()) return false;
  } else if (risk.decision !== null || risk.risk_score !== null || risk.reasons.length !== 0
      || risk.error !== null) {
    return false;
  }

  if (response.status === "COMPLETED") {
    if (policy.status !== "EVALUATED" || risk.status !== "EVALUATED") return false;
    const expectedDecision = !policy.allowed || risk.decision === "BLOCK"
      ? "BLOCK"
      : risk.decision === "WARN" ? "WARN" : "ALLOW";
    const expectedReasons = [];
    if (!policy.allowed) expectedReasons.push(`Policy denied: ${policy.reason}`);
    expectedReasons.push(...risk.reasons.map((reason) => `Risk: ${reason}`));
    if (response.reasons.length !== expectedReasons.length
      || response.reasons.some((reason, index) => reason !== expectedReasons[index])) return false;
    return response.decision === expectedDecision;
  }
  if (response.decision !== "BLOCK" || response.reasons.length === 0) return false;
  if (response.status === "INVALID_INPUT") {
    return policy.status === "NOT_EVALUATED" && risk.status === "NOT_EVALUATED";
  }
  return policy.status === "ERROR" || risk.status === "ERROR"
    || (policy.status === "NOT_EVALUATED" && risk.status === "NOT_EVALUATED");
}

function runPythonAdapter(
  serializedRequest,
  spawn = spawnSync,
  policyPath = process.env[POLICY_ENV_VAR],
) {
  if (!fs.existsSync(PYTHON)) throw new Error("project .venv/bin/python was not found");
  const childEnv = {
    PATH: process.env.PATH || "",
    PYTHONIOENCODING: "utf-8",
    PYTHONDONTWRITEBYTECODE: "1",
    PYTHONHASHSEED: "0",
  };
  if (policyPath !== undefined && policyPath !== null) {
    if (typeof policyPath !== "string" || !policyPath.trim()) {
      throw new TypeError("policyPath must be a non-empty string when provided");
    }
    childEnv[POLICY_ENV_VAR] = policyPath;
  }
  const child = spawn(PYTHON, ["-I", "-S", "-B", ADAPTER], {
    cwd: PROJECT_ROOT,
    env: childEnv,
    input: serializedRequest,
    encoding: "utf8",
    timeout: ADAPTER_TIMEOUT_MS,
    maxBuffer: MAX_OUTPUT_BYTES,
    shell: false,
    windowsHide: true,
  });
  if (child.error) throw child.error;
  if (child.status !== 0) {
    throw new Error(`Python adapter exited with status ${String(child.status)}`);
  }
  if (typeof child.stdout !== "string" || Buffer.byteLength(child.stdout, "utf8") > MAX_OUTPUT_BYTES) {
    throw new Error("Python adapter output exceeded its limit");
  }
  let response;
  try {
    response = JSON.parse(child.stdout);
  } catch {
    throw new Error("Python adapter returned malformed JSON");
  }
  return response;
}

function evaluateRequest(request, adapterRunner) {
  if (typeof adapterRunner !== "function") throw new TypeError("adapterRunner must be a function");
  try {
    const serializedRequest = JSON.stringify(request);
    if (typeof serializedRequest !== "string") throw new TypeError("request is not JSON-serializable");
    if (Buffer.byteLength(serializedRequest, "utf8") > MAX_INPUT_BYTES) {
      throw new Error("request exceeds the 65536-byte input limit");
    }
    const safeRequest = JSON.parse(serializedRequest);
    if (!isPlainObject(safeRequest) || typeof safeRequest.request_id !== "string"
      || !safeRequest.request_id.trim() || safeRequest.request_id.length > REQUEST_ID_MAX_LENGTH
      || !isPlainObject(safeRequest.intent)) {
      throw new Error("request must include a valid request_id and intent object");
    }

    const intentHash = createHash("sha256").update(canonicalJson(safeRequest.intent), "utf8").digest("hex");
    freezeRecursively(safeRequest.intent);
    const response = adapterRunner(serializedRequest);
    if (!validateResponse(response, safeRequest.request_id, intentHash)) {
      throw new Error("Python adapter response failed schema or request-identity validation");
    }
    return { safeRequest, response, error: null };
  } catch (error) {
    return { safeRequest: null, response: null, error: error instanceof Error ? error.message : "bridge failure" };
  }
}

function evaluateIntent(request, { adapterRunner = runPythonAdapter } = {}) {
  const { response, error } = evaluateRequest(request, adapterRunner);
  return { response, error };
}

function evaluateAndMockSign(request, mockSigner, { adapterRunner = runPythonAdapter } = {}) {
  if (typeof mockSigner !== "function") throw new TypeError("mockSigner must be a function");
  const { safeRequest, response, error } = evaluateRequest(request, adapterRunner);
  if (error) return { response: null, mockSignature: null, error };
  if (response.status !== "COMPLETED" || response.decision !== "ALLOW") {
    return { response, mockSignature: null, error: null };
  }
  try {
    return { response, mockSignature: mockSigner(safeRequest.intent), error: null };
  } catch (signerError) {
    return {
      response: null,
      mockSignature: null,
      error: signerError instanceof Error ? signerError.message : "mock signer failure",
    };
  }
}

function makeRequest(requestId, action, transaction) {
  return {
    request_id: requestId,
    intent: {
      action,
      resource: transaction.recipient,
      transaction,
    },
  };
}

function dummySigner(intent) {
  return `MOCK-ONLY (not a signature): ${intent.transaction.recipient}`;
}

function main() {
  // The standalone demo uses an explicitly labeled example policy. Imported
  // bridge users must configure their own policy path or the adapter denies.
  if (!process.env[POLICY_ENV_VAR]) process.env[POLICY_ENV_VAR] = EXAMPLE_POLICY;
  const familiarTransfer = {
    recipient: "alice.near",
    amount_yocto: "1000000000000000000000000",
    previous_interactions: 3,
    account_age_days: 365,
  };
  const scenarios = [
    ["safe transfer", makeRequest("demo-allow", "transfer", familiarTransfer)],
    ["risk warning", makeRequest("demo-warn", "transfer", { ...familiarTransfer, amount_yocto: "11000000000000000000000000" })],
    ["risk block", makeRequest("demo-block", "transfer", { ...familiarTransfer, known_malicious: true })],
    ["unsupported contract call", makeRequest("demo-invalid", "function_call", familiarTransfer)],
  ];

  console.log("Sentinel Guard — local Node/Python guarded mock");
  console.log("Demo only: no NEAR integration, network, wallet, private key, signing, or broadcast.\n");
  let allPassed = true;
  for (const [label, request] of scenarios) {
    let signerCalls = 0;
    const result = evaluateAndMockSign(request, (intent) => {
      signerCalls += 1;
      return dummySigner(intent);
    });
    const expectedCalls = result.response?.status === "COMPLETED" && result.response?.decision === "ALLOW" ? 1 : 0;
    const passed = result.error === null && signerCalls === expectedCalls;
    console.log(`${label}: status=${result.response?.status ?? "BRIDGE_ERROR"}, decision=${result.response?.decision ?? "BLOCK"}, mock signer calls=${signerCalls}`);
    if (result.mockSignature) console.log(`  ${result.mockSignature}`);
    if (result.error) console.log(`  ${result.error}`);
    console.log(`  Gate check: ${passed ? "PASS" : "FAIL"}`);
    allPassed = allPassed && passed;
  }
  console.log(`\nOverall: ${allPassed ? "PASS" : "FAIL"}`);
  return allPassed ? 0 : 1;
}

if (require.main === module) process.exitCode = main();

module.exports = {
  ADAPTER_TIMEOUT_MS,
  MAX_INPUT_BYTES,
  MAX_OUTPUT_BYTES,
  evaluateAndMockSign,
  evaluateIntent,
  makeRequest,
  runPythonAdapter,
  validateResponse,
};
