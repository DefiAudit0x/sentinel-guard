#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { randomBytes, randomUUID } = require("node:crypto");
const {
  preflightTestnetNativeTransfer,
  TESTNET_RPC_URL,
} = require("../examples/near_testnet_preflight.js");
const {
  runPythonAdapter,
  runPythonPolicyAdapter,
} = require("../examples/guarded_agent_bridge.js");

const LOOPBACK_HOST = "127.0.0.1";
const DEFAULT_PORT = 4173;
const MAX_REQUEST_BYTES = 8192;
const FIXED_RECIPIENT = "defiaudit0x.testnet";
const MAX_AMOUNT_YOCTO = 100000000000000000000000n;
const CANONICAL_AMOUNT = /^(?:0|[1-9][0-9]{0,79})$/;
const ACCOUNT_ID = /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?![\s\S])/;
const CONTEXT_FIELDS = new Set(["previous_interactions", "account_age_days"]);
const PROJECT_ROOT = path.resolve(__dirname, "..");
const DEFAULT_STATIC_ROOT = path.join(PROJECT_ROOT, "dist");
const POLICY_ENV_VAR = "SENTINEL_GUARD_POLICY_FILE";
const CSP_CONNECT_ORIGINS = [new URL(TESTNET_RPC_URL).origin];
const CSP_IMAGE_SOURCES = ["'self'", "data:"];

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const SECURITY_HEADERS = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
  "cache-control": "no-store",
  "content-security-policy": [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    `connect-src 'self' ${CSP_CONNECT_ORIGINS.join(" ")}`,
    `img-src ${CSP_IMAGE_SOURCES.join(" ")}`,
    "frame-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
  ].join("; "),
};

function sendJson(response, status, value) {
  const body = Buffer.from(JSON.stringify(value));
  response.writeHead(status, {
    ...SECURITY_HEADERS,
    "content-type": "application/json; charset=utf-8",
    "content-length": body.length,
  });
  response.end(body);
}

function validateLocalRequest(request) {
  if (!request || Object.getPrototypeOf(request) !== Object.prototype
    || Object.keys(request).length !== 4
    || !Object.hasOwn(request, "accountId")
    || !Object.hasOwn(request, "recipient")
    || !Object.hasOwn(request, "amountYocto")
    || !Object.hasOwn(request, "context")) {
    throw new HttpError(400, "Request must contain only accountId, recipient, amountYocto, and context.");
  }
  if (typeof request.accountId !== "string" || request.accountId.length < 2
    || request.accountId.length > 64 || !ACCOUNT_ID.test(request.accountId)) {
    throw new HttpError(400, "A valid connected NEAR account is required.");
  }
  if (request.recipient !== FIXED_RECIPIENT) {
    throw new HttpError(403, "Only the configured testnet recipient is allowed.");
  }
  if (typeof request.amountYocto !== "string" || !CANONICAL_AMOUNT.test(request.amountYocto)) {
    throw new HttpError(400, "amountYocto must be a canonical decimal string.");
  }
  const amount = BigInt(request.amountYocto);
  if (amount <= 0n) throw new HttpError(400, "Amount must be greater than zero.");
  if (amount > MAX_AMOUNT_YOCTO) throw new HttpError(403, "Amount exceeds the local 0.1 NEAR cap.");
  if (!request.context || Object.getPrototypeOf(request.context) !== Object.prototype
    || Object.keys(request.context).some((key) => !CONTEXT_FIELDS.has(key))) {
    throw new HttpError(400, "context may contain only previous_interactions and account_age_days.");
  }
  for (const [key, value] of Object.entries(request.context)) {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new HttpError(400, `${key} must be a non-negative safe integer.`);
    }
  }
  return request;
}

async function readJsonBody(request) {
  const contentType = request.headers["content-type"] || "";
  if (!/^application\/json(?:\s*;|$)/i.test(contentType)) {
    throw new HttpError(415, "Content-Type must be application/json.");
  }
  const chunks = [];
  let total = 0;
  for await (const chunk of request) {
    total += chunk.length;
    if (total > MAX_REQUEST_BYTES) throw new HttpError(413, "Request body is too large.");
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new HttpError(400, "Request body must be valid JSON.");
  }
}

function assertLoopbackRequest(request) {
  const host = request.headers.host || "";
  if (!/^127\.0\.0\.1(?::[0-9]{1,5})?$/.test(host)) {
    throw new HttpError(403, "This local service accepts loopback requests only.");
  }
  const origin = request.headers.origin;
  if (origin !== undefined) {
    let parsed;
    try { parsed = new URL(origin); } catch { throw new HttpError(403, "Invalid request origin."); }
    if (parsed.protocol !== "http:" || parsed.host !== host || parsed.hostname !== LOOPBACK_HOST) {
      throw new HttpError(403, "Cross-origin requests are not accepted.");
    }
  }
}

function contentType(filePath) {
  const extension = path.extname(filePath).toLowerCase();
  return ({
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
  })[extension] || "application/octet-stream";
}

function resolveStaticFile(urlPath, staticRoot) {
  if (urlPath === "/" || urlPath === "/index.html") return path.join(staticRoot, "index.html");
  if (!urlPath.startsWith("/assets/")) return null;
  let decoded;
  try { decoded = decodeURIComponent(urlPath); } catch { return null; }
  if (decoded.includes("\\") || decoded.split("/").some((segment) => segment === ".." || segment.startsWith("."))) return null;
  const filePath = path.resolve(staticRoot, `.${decoded}`);
  const relative = path.relative(path.resolve(staticRoot), filePath);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) return null;
  return filePath;
}

function createLocalUiServer({
  preflight = preflightTestnetNativeTransfer,
  adapterRunner = (serializedRequest) => runPythonAdapter(serializedRequest),
  policyAdapterRunner = (serializedRequest) => runPythonPolicyAdapter(serializedRequest),
  fetchImpl = globalThis.fetch,
  staticRoot = DEFAULT_STATIC_ROOT,
  policyPath,
} = {}) {
  const root = path.resolve(staticRoot);
  if (policyPath !== undefined) assertPrivatePolicyPath(policyPath, root);
  return http.createServer(async (request, response) => {
    try {
      assertLoopbackRequest(request);
      const host = request.headers.host;
      const requestUrl = new URL(request.url || "/", `http://${host}`);
      if (request.method === "POST" && requestUrl.pathname === "/api/preflight") {
        const intent = validateLocalRequest(await readJsonBody(request));
        const connector = {
          network: "testnet",
          async wallet() {
            return {
              async getAccounts() { return [{ accountId: intent.accountId }]; },
            };
          },
        };
        const result = await preflight({
          connector,
          recipient: intent.recipient,
          amountYocto: intent.amountYocto,
          context: intent.context,
          accountId: intent.accountId,
          requestId: randomUUID(),
          fetchImpl,
          adapterRunner,
          policyAdapterRunner,
        });
        return sendJson(response, 200, result);
      }
      if (request.method !== "GET" && request.method !== "HEAD") {
        throw new HttpError(405, "Method not allowed.");
      }
      const filePath = resolveStaticFile(requestUrl.pathname, root);
      if (!filePath) throw new HttpError(404, "Not found.");
      let file;
      try {
        const [staticRootReal, fileStat] = await Promise.all([
          fs.promises.realpath(root),
          fs.promises.lstat(filePath),
        ]);
        if (!fileStat.isFile() || fileStat.isSymbolicLink()) throw new HttpError(404, "Not found.");
        const fileRealPath = await fs.promises.realpath(filePath);
        const realRelative = path.relative(staticRootReal, fileRealPath);
        if (!realRelative || realRelative.startsWith("..") || path.isAbsolute(realRelative)) {
          throw new HttpError(404, "Not found.");
        }
        file = await fs.promises.readFile(fileRealPath);
      }
      catch (error) {
        if (error && error.code === "ENOENT") throw new HttpError(404, "Not found.");
        throw error;
      }
      let responseBody = file;
      let responseHeaders = SECURITY_HEADERS;
      if (path.extname(filePath).toLowerCase() === ".html") {
        const nonce = randomBytes(18).toString("base64");
        const html = file.toString("utf8");
        const moduleScripts = [...html.matchAll(/<script\b(?=[^>]*\btype=(?:"module"|'module'|module)(?=\s|>))(?=[^>]*\bsrc\s*=)[^>]*>/gi)];
        if (moduleScripts.length !== 1) {
          throw new Error("Static HTML must contain exactly one external module script for a CSP nonce.");
        }
        const moduleScript = moduleScripts[0][0];
        if (/\snonce\s*=/.test(moduleScript)) {
          throw new Error("Static HTML module script must not define a static CSP nonce.");
        }
        responseBody = Buffer.from(html.replace(
          moduleScript,
          moduleScript.replace(/>$/, ` nonce="${nonce}">`),
        ));
        responseHeaders = {
          ...SECURITY_HEADERS,
          "content-security-policy": SECURITY_HEADERS["content-security-policy"].replace(
            "script-src 'self'",
            `script-src 'self' 'nonce-${nonce}'`,
          ),
        };
      }
      response.writeHead(200, {
        ...responseHeaders,
        "content-type": contentType(filePath),
        "content-length": responseBody.length,
      });
      response.end(request.method === "HEAD" ? undefined : responseBody);
    } catch (error) {
      const status = error instanceof HttpError ? error.status : 502;
      const message = error instanceof HttpError
        ? error.message
        : (error instanceof Error ? error.message : "Local preflight failed.");
      sendJson(response, status, { error: message, submitted: false });
    }
  });
}

function configuredPort(value = process.env.SENTINEL_GUARD_UI_PORT) {
  if (value === undefined || value === "") return DEFAULT_PORT;
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new TypeError("SENTINEL_GUARD_UI_PORT must be an integer from 1 through 65535.");
  }
  return port;
}

function assertPrivatePolicyPath(policyPath, staticRoot = DEFAULT_STATIC_ROOT) {
  if (typeof policyPath !== "string" || !path.isAbsolute(policyPath)) {
    throw new TypeError(`${POLICY_ENV_VAR} must name an absolute local policy path.`);
  }
  let staticRootReal;
  let policyPathReal;
  try {
    staticRootReal = fs.realpathSync.native(path.resolve(staticRoot));
    policyPathReal = fs.realpathSync.native(path.resolve(policyPath));
  } catch {
    throw new TypeError(`${POLICY_ENV_VAR} and the UI static directory must resolve to existing real paths.`);
  }
  const relative = path.relative(staticRootReal, policyPathReal);
  if (relative === "" || (relative !== ".."
    && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative))) {
    throw new TypeError("The local policy file must not be inside the UI static directory.");
  }
}

function main() {
  const policyPath = process.env[POLICY_ENV_VAR];
  try {
    assertPrivatePolicyPath(policyPath);
    const port = configuredPort();
    const server = createLocalUiServer({ policyPath });
    server.listen(port, LOOPBACK_HOST, () => {
      console.log(`Sentinel Guard local UI: http://${LOOPBACK_HOST}:${port}/`);
      console.log("Loopback only · NEAR testnet · application preflight has no signing or submission call");
    });
  } catch (error) {
    console.error(error instanceof Error ? error.message : "Unable to start local UI.");
    process.exitCode = 1;
  }
}

if (require.main === module) main();
module.exports = {
  FIXED_RECIPIENT,
  MAX_AMOUNT_YOCTO,
  assertPrivatePolicyPath,
  configuredPort,
  createLocalUiServer,
  readJsonBody,
  resolveStaticFile,
  validateLocalRequest,
};
