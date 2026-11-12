# Sentinel Guard

A local-first prototype for deterministic policy and risk evaluation in NEAR applications and autonomous AI agents. Sentinel Guard produces explainable ALLOW, WARN, or BLOCK results for supported local inputs; these results do not prove that a real transaction is safe or constrain downstream wallet or executor behavior.

## Problem

AI agents and automated applications operating on NEAR need to execute transfers and contract calls without exposing user treasuries to unauthorized actions, drained funds, or recently mutated smart contracts. Relying on probabilistic LLM prompts for spending security is brittle, while scattering ad-hoc checks across application code makes security decisions opaque, hard to audit, and impossible to reproduce deterministically.

## Links

- **Live Demo**: N/A (Local CLI evaluation tool)
- **Contracts**: N/A (Local client-side transaction simulation & policy guard)

## How to try it

1. **Verify the test suite**:
   Follow the complete command sequence in [Quick start](#quick-start-from-a-clean-clone) below. It creates the virtual environment, installs the Python and Node dependencies, then runs the local verification suite without live network access.

2. **Run local CLI demo**:
   Run `python3 examples/local_demo.py` — the CLI evaluates three deterministic NEAR transaction scenarios (safe transfer, above-threshold warning, and explicit policy/malicious recipient block) and prints the unified decision, status, policy evaluation, risk score, and reasons for each scenario.

3. **Integrate Sentinel Guard**:
   Import `simulate_transaction`, `PolicyEngine`, `PolicyRule`, and `simulation_result_to_json` from `sentinel_guard` — evaluate supported action/resource pairs and transaction context locally. Invalid wrappers and evaluator failures fail closed; the core itself does not sign or submit transactions, and an `ALLOW` is not a safety guarantee.

## Screenshots and video

- Screenshots: N/A
- Demo Video: N/A

## Architecture

```
                                +-----------------------------+
                                | Proposed Transaction Context |
                                +--------------+--------------+
                                               |
                                               v
                                +--------------+--------------+
                                |     simulate_transaction    |
                                +--------------+--------------+
                                               |
                       +-----------------------+-----------------------+
                       |                                               |
                       v                                               v
        +--------------+--------------+                 +--------------+--------------+
        |        PolicyEngine         |                 |        RiskAnalyzer         |
        |  (Exact-match DENY/ALLOW)   |                 | (Rule-based Risk Scoring)   |
        +--------------+--------------+                 +--------------+--------------+
                       |                                               |
                       v                                               v
        +--------------+--------------+                 +--------------+--------------+
        |        PolicyResult         |                 |          RiskResult         |
        |  (allowed, matched_rule)    |                 |   (decision, risk_score)    |
        +--------------+--------------+                 +--------------+--------------+
                       |                                               |
                       +-----------------------+-----------------------+
                                               |
                                               v
                                +--------------+--------------+
                                |      SimulationResult       |
                                |   ALLOW / WARN / BLOCK      |
                                +-----------------------------+
```

Sentinel Guard follows a dual-engine architecture:
- **PolicyEngine**: Evaluates exact-match rules (`ALLOW` or `DENY`) on `(action, resource)`. DENY rules take precedence over ALLOW rules, with a default-deny model.
- **RiskAnalyzer**: Evaluates numeric risk scoring based on transfer thresholds, contract state mutation checks, interaction history, and known malicious recipient flags.
- **TransactionSimulator**: Combines policy evaluation and risk analysis into a unified `SimulationDecision` (`ALLOW`, `WARN`, `BLOCK`).

## Threat Model

Sentinel Guard addresses key attack vectors facing automated agents and NEAR applications:
1. **Malicious Recipient Drain**: Direct transfers to known drainers or unauthorized accounts are blocked by explicit `DENY` policies or flagged by high risk scores.
2. **Contract Code Mutation**: Recent smart contract deployments/mutations raise risk scores to prevent interacting with unvetted contracts.
3. **Large Outflow Risk**: Single transactions exceeding pre-configured thresholds (e.g. 10 NEAR) trigger warnings or strict review requirements.
4. **Untrusted LLM Execution**: A caller can use deterministic local checks to avoid invoking its own signing step for denied requests, but this prototype does not control a wallet, signer, or third-party executor.

## Limitations

- **Local / In-Memory Evaluation**: The core simulator does not fetch RPC state. The separate testnet preflight reads account state only after local evaluation returns `ALLOW`; that read is not a guarantee of transaction safety.
- **Static Policy Rules**: Current policy rules require explicit configuration in code or local policy files. evaluate an action/resource pair against in-memory rules, give explicit deny rules precedence, and deny by default when no rule permits an action.

## Requirements

- Python 3.12 or newer
- Node.js 20.19 or newer, or 22.12 or newer, and npm
- No third-party Python packages are required to run the application; `pytest` is needed for the full test suite.

## Quick start from a clean clone

```bash
git clone https://github.com/DefiAudit0x/sentinel-guard.git
cd sentinel-guard
python3 -m venv .venv
.venv/bin/python -m pip install pytest
npm ci
./scripts/verify.sh
```

Use `python3` backed by Python 3.12 or newer and Node.js 20.19 or newer (or 22.12 or newer). `npm ci` installs the exact JavaScript dependencies from the lockfile. VS Code is configured to use `.venv/bin/python` and its built-in `unittest` support.

## Run the tests

After completing Quick start, you can run individual test suites:

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m unittest discover -s tests -v
node --test tests/guarded_agent_bridge.test.js tests/near_testnet_preflight.test.js
npm run test:ui
```

Run the complete local verification sequence from the project root:

```bash
./scripts/verify.sh
```

You can also invoke the script by its absolute path from outside the project directory:

```bash
/workspace/sentinel-guard/scripts/verify.sh
```

The script finds the project root from its own location, uses the existing `.venv/bin/python`, runs the Node tests, and builds the UI bundle. It does not install dependencies or connect to the internet; `pytest` and the dependencies installed by `npm ci` must already be available.

## Example

```python
from sentinel_guard.policy_engine import Effect, PolicyEngine, PolicyRule

engine = PolicyEngine([
    PolicyRule("approved-transfer", Effect.ALLOW, "transfer", "alice.near"),
])
decision = engine.evaluate("transfer", "alice.near")
print(decision.allowed, decision.reason, decision.matched_rule)
```

A rule without a `resource` applies to any resource for the exact action name. A rule with a resource matches that resource exactly. A matching deny rule overrides any matching allow rule, regardless of rule order.

## Risk analyzer amount units

The risk analyzer accepts transaction amounts in the integer field `amount_yocto`, measured in yoctoNEAR. One NEAR equals `10**24` yoctoNEAR; for example, 15 NEAR is represented as `15 * 10**24`. Floating-point values, booleans, and negative amounts are rejected.

An amount strictly greater than `10 * 10**24` yoctoNEAR (more than 10 NEAR) adds 30 risk points. Exactly 10 NEAR does not trigger this signal. This is an experimental threshold, not an established security standard.

## Caller-provided `known_malicious` signal

After input validation, `known_malicious: true` returns `BLOCK` with a risk score of 100. If the field is omitted, it defaults to `false` for this signal alone; the analyzer's other checks still apply. The caller is responsible for the value. The analyzer does not fetch malicious-address lists or independently verify the signal, so this result reflects the supplied input and does not by itself establish that the recipient is malicious.

## Local transaction simulator

`simulate_transaction(action, resource, transaction, policy_engine)` validates the request wrapper, then evaluates policy and transaction risk independently. A supplied resource must exactly match the transaction recipient; if `resource` is `None`, a valid recipient is used for policy matching so recipient-specific denies cannot be bypassed by a general allow. Its result preserves each engine's status, decision, and reasons. A policy denial, risk `BLOCK`, or engine error produces a final `BLOCK`; policy allow plus risk `WARN` remains `WARN`, never an automatic allow. Invalid wrappers are blocked with `INVALID_INPUT`, and neither engine is evaluated.

This is local decision orchestration only. It does not request human approval, connect to NEAR, sign or submit transactions, or modify files outside this project; it is not a production security boundary.

## Local Demo

From the project root, run the deterministic local demonstration:

```bash
.venv/bin/python examples/local_demo.py
```

With the included scenarios, the final decisions and risk scores are:

| Scenario | Final decision | Risk score |
| --- | --- | ---: |
| 1 NEAR transfer to a familiar, unflagged recipient | `ALLOW` | 0 |
| 11 NEAR transfer, above the 10 NEAR risk threshold | `WARN` | 30 |
| 1 NEAR transfer to a recipient explicitly marked as known malicious | `BLOCK` | 100 |

This is a deterministic, local simulation: it does not connect to the NEAR network, sign transactions, or submit transactions. It demonstrates prototype behavior only and is not evidence that real transactions are safe or protected.

### Guarded application mock

Run `.venv/bin/python examples/guarded_agent_mock.py` to see an application-shaped call site. Its placeholder callback is invoked only when the simulator returns `COMPLETED` and `ALLOW`; `WARN`, `BLOCK`, and invalid input do not reach it. The callback returns a labeled mock string, not a signature. This example uses no NEAR SDK, wallet, private key, network, or real transaction signer.

### Node/Python JSON bridge mock

Run `node examples/guarded_agent_bridge.js` for a small JavaScript-to-Python example. Node sends one bounded JSON request to the local adapter using fixed Python arguments, no shell, a 2.5-second timeout, and bounded output. The response includes the same request ID and a SHA-256 hash of the canonical intent; the mock callback runs only after both match and the policy, risk details, combined decision, and explanatory reasons agree on a structurally valid `COMPLETED` + `ALLOW`. A benign low risk score such as 15 may include an explanation and still allow; policy denial, risk `WARN`/`BLOCK`, or contradictory response fields fail closed.

This bridge accepts only a simple native `transfer` with a valid recipient and `amount_yocto` as a decimal string, plus the simulator's listed risk-context fields. An explicit `resource` must match that recipient; a missing or invalid recipient, mismatch, unsupported action, or extra transaction field is rejected before evaluation. It does not parse NEAR transaction payloads or support contract calls. It is a local demo only: no NEAR integration, network access, wallet, private key, real signing, or broadcast is used. The callback returns a `MOCK-ONLY` marker, not a signature.

#### Local red-team bridge demo

Run the deterministic, synthetic-input check from the project root:

```bash
node examples/guarded_agent_red_team_demo.js
```

Expected result: all five checks pass and the output ends with `Overall: PASS`. One fictional allowed transfer reaches the mock callback once, which returns a `MOCK-ONLY` marker. An altered recipient and an amount above the policy cap return `BLOCK`; malformed adapter JSON and an inconsistent adapter intent hash fail closed with `BRIDGE_ERROR`. None of those four cases reaches the mock callback. This local demonstration does not sign or submit transactions and does not establish that an actual signer or executor is constrained.

#### Local JSON spending policy

The JSON adapter requires an explicit local policy file selected by `SENTINEL_GUARD_POLICY_FILE`. Its strict version-1 schema is:

```json
{
  "version": 1,
  "default": "deny",
  "allowed_recipients": ["alice.near"],
  "max_amount_yocto": "20000000000000000000000000"
}
```

`allowed_recipients` is an exact, case-sensitive allow-list of valid lowercase NEAR account IDs (2–64 characters, using `[a-z0-9]+` segments separated only by `.`, `_`, or `-`); an empty list denies every recipient. `max_amount_yocto` is a canonical non-negative decimal string, compared as an exact integer in yoctoNEAR. The amount equal to the cap is permitted by policy; a greater amount is denied. The transaction `resource` must still be identical to its recipient. Unknown or duplicate policy fields, a non-`deny` default, malformed values, a missing file, or an unset policy path fail closed. To use a local policy with the bridge, set `SENTINEL_GUARD_POLICY_FILE=/absolute/path/to/policy.json` before running it. The standalone demo uses [`examples/test_policy.json`](examples/test_policy.json) only when no path is set; that file is fictional test data, not the user's spending policy. The JSON adapter does not infer or create real financial limits.

### Local NEAR testnet wallet UI

The local browser app uses the maintained [`@hot-labs/near-connect`](https://docs.near.org/web3-apps/tutorials/wallet-login) package and the existing read-only testnet preflight. After installing dependencies with `npm ci`, run from the repository root:

```bash
SENTINEL_GUARD_POLICY_FILE="$PWD/examples/ui_demo_policy.json" npm run ui
```

Open `http://127.0.0.1:4173/`. The server binds only to loopback; it serves the built `dist/` assets and does not expose the configured policy file. If the default port is occupied, set `SENTINEL_GUARD_UI_PORT` to another local port. The policy path is read only from `SENTINEL_GUARD_POLICY_FILE` and must be outside the static UI directory. [`examples/ui_demo_policy.json`](examples/ui_demo_policy.json) is a public demo policy for the server's fixed `defiaudit0x.testnet` recipient and 0.1 NEAR cap; it is not a user's spending policy. The separate [`examples/test_policy.json`](examples/test_policy.json) remains bridge-test fixture data.

The Connect button is enabled only for a locally constructed Meteor-only manifest. Its executor is pinned to immutable repository commit `6369ad789d2f3aaf8e6ccb065021723111027174`; the wallet icon is an image from the same GitHub repository's `main` path and is not executable code. Because `@hot-labs/near-connect` 0.12.0 can replace a same-ID manifest wallet when it receives `near-wallet-injected`, the app installs capture-phase guards for both the injected CustomEvent and the parent-frame message before constructing the connector, then accepts only a returned wallet whose manifest is the exact pinned object. It selects `meteor-wallet` directly, without a picker, and keeps `autoConnect` disabled. A detected injection or unexpected provider fails closed. Connector loading and construction occur only after the user clicks Connect.

Connecting may request account sign-in through Meteor Wallet. The application's own code contains no transaction-signing or submission call, but the pinned third-party executor receives NEAR Connect storage permission and access to the `meteorCom` and `meteorComV2` bridges, and may open only `https://wallet.meteorwallet.app` or `https://meteorwallet.app`. The executor has not been audited here, so the application cannot guarantee what its code does when a user connects; the page discloses this before the Connect button. After local policy returns `ALLOW`, the preflight sends the selected public account ID to `https://rpc.testnet.near.org` for a read-only lookup, as disclosed before the preflight button. CSP allows the exact `raw.githubusercontent.com` origin for the pinned executor and icon, plus the fixed testnet RPC origin; it no longer allows default manifest endpoints or any `https:` wildcard. No public deployment is created. The UI controller and server tests use mocked wallets, policy evaluation, and RPC responses; run them with `npm run test:ui` or include them in `./scripts/verify.sh`.

### NEAR testnet read-only preflight

`examples/near_testnet_preflight.js` adds a separate, read-only adapter for a simple native NEAR transfer intent. It requires a [NEAR Connect](https://docs.near.org/web3-apps/tutorials/wallet-login) connector configured with `network: "testnet"` and an already-connected wallet. The host application must handle any wallet connection through its own user-initiated flow; this adapter never calls `connect()`. It checks that the fixed RPC endpoint reports `chain_id: "testnet"`, reads the selected account with the read-only `status` and `query` RPC methods, and passes the exact `transfer` action, recipient/resource, amount, and supplied risk context through the local Sentinel Guard bridge.

```js
const { preflightTestnetNativeTransfer } = require("./near_testnet_preflight.js");

// `connector` is an existing NearConnector({ network: "testnet" }) instance.
// Call only after the host app has obtained the user's connection separately.
const result = await preflightTestnetNativeTransfer({
  connector,
  recipient: "alice.testnet",
  amountYocto: "1000000000000000000000000",
  context: { previous_interactions: 8, account_age_days: 400 },
});
console.log(result.status, result.guard.decision);
```

`PREPARED_NOT_SUBMITTED` means only that this local prototype returned `ALLOW` and an account snapshot was read. The adapter has no signing or submission path: it does not call `signAndSendTransaction`, sign any payload, hold a key, or broadcast. `WARN`/`BLOCK` stops before wallet and RPC access. The test suite mocks RPC responses and does not contact NEAR. This prototype's rules and caller-provided context are experimental; a preflight result is neither a safety guarantee nor authorization to transact. The official [NEAR Connect repository](https://github.com/azbang/near-connect) describes the connector API; a real wallet connection remains a separate user interaction.

An `ALLOW` from this prototype is not a policy approval or authorization for a real transfer. The example policy is only test data, and caller-provided risk context and the prototype's risk heuristics are experimental.

## Current limitations

The Python simulator expects the caller to provide a decoded transaction dictionary and an in-memory policy engine; the bounded JSON adapter separately loads the explicitly selected local policy described above. The testnet preflight supports only a native transfer intent and a read-only account snapshot; the system does not parse signed transaction payloads, perform human approvals, estimate transaction fees, or establish production security. These capabilities and their threat model should be specified and reviewed before extending or submitting the project.
