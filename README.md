# Sentinel Guard

A local-first prototype for deterministic policy and risk evaluation in NEAR applications and autonomous AI agents. Sentinel Guard produces explainable ALLOW, WARN, or BLOCK results for supported local inputs; these results do not prove that a real transaction is safe or constrain downstream wallet or executor behavior.

Prepared for **NEAR HACKATHON 2026** in the **AI Security & Defense (`security`)** track. The implemented NEAR Testnet path runs a local guard and read-only account/RPC preflight; an optional fixed 0.001 NEAR self-transfer demo can request a wallet action only after a separate review and click. These experimental client-side checks do not enforce policy on a real signer or wallet, and a live transfer has not been tested.

## Problem

AI agents and automated applications operating on NEAR need to execute transfers and contract calls without exposing user treasuries to unauthorized actions, drained funds, or recently mutated smart contracts. Relying on probabilistic LLM prompts for spending security is brittle, while scattering ad-hoc checks across application code makes security decisions opaque, hard to audit, and impossible to reproduce deterministically.

## Links

- **Live Demo**: N/A (no hosted demo; local CLI and browser UI only)
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
4. **Untrusted LLM Execution**: The optional local UI can request one fixed Testnet self-transfer only after a local `ALLOW`, an exact review, and a second click. This is a client-side demonstration, not enforcement for other applications, and it cannot guarantee the behavior of the third-party wallet executor.

## Limitations

- **Local / In-Memory Evaluation**: The core simulator does not fetch RPC state. The separate testnet preflight first checks policy only, then reads sender and recipient account state when policy allows and a configured baseline exists; it runs risk afterward without inventing missing history, so the final result may still be `WARN` / `NEEDS_REVIEW`. Those reads are not a guarantee of transaction safety.
- **Static Policy Rules**: Current policy rules require explicit configuration in code or local policy files. The engine evaluates an action/resource pair against in-memory rules, gives explicit deny rules precedence, and denies by default when no rule permits an action.

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

From outside the project directory, invoke the script using the path to your local clone (replace `/path/to/sentinel-guard` with that location):

```bash
/path/to/sentinel-guard/scripts/verify.sh
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

The local browser app uses the official [`@meteorwallet/sdk`](https://www.npmjs.com/package/@meteorwallet/sdk) for Meteor wallet connection, alongside the separate read-only preflight and optional fixed Testnet transfer demonstration. After installing dependencies with `npm ci`, run from the repository root:

```bash
SENTINEL_GUARD_POLICY_FILE="$PWD/examples/ui_demo_policy.json" npm run ui
```

Open `http://127.0.0.1:4173/`. The server binds only to loopback; it serves the built `dist/` assets and does not expose the configured policy file. If the default port is occupied, set `SENTINEL_GUARD_UI_PORT` to another local port. The policy path is read only from `SENTINEL_GUARD_POLICY_FILE` and must be outside the static UI directory. [`examples/ui_demo_policy.json`](examples/ui_demo_policy.json) is a public demo policy for the server's fixed `defiaudit0x.testnet` recipient and 0.1 NEAR cap; it is not a user's spending policy. The separate [`examples/test_policy.json`](examples/test_policy.json) remains bridge-test fixture data.

The Connect button lazily loads the SDK and requests only `near::sign_in` for `{ blockchain: "near", network: "testnet" }` after an explicit click. It does not request a function-call key, a message signature, or a transaction during sign-in. SDK initialization uses `webpage_local_storage`; the Meteor Mobile bridge and its account-transfer/new-key-transfer surfaces are disabled, and there is no auto-connect. For later gates, the UI re-reads the exact signed-in Testnet account from Meteor SDK storage; the SDK does not expose the previous connector's live wallet-account-list query.

The fixed-transfer path is separate from sign-in and accepts only one native self-transfer from `defiaudit0x.testnet` to itself for exactly `0.001` NEAR (`1000000000000000000000` yoctoNEAR). A local `ALLOW`, the exact result status/request ID/intent hash, a two-minute immutable review, and a separate second click are required; an untouched review closes automatically at its deadline. At the signing boundary, the UI rechecks the review binding and selected Testnet account, then sends one SDK `near::sign_transactions` action targeted to that account with `useFunctionCallKey: false`; the wallet must still show its own confirmation. After the request is handed to the wallet, the page cannot cancel an opened prompt and locks this fixed-transfer flow for the rest of the loaded page session. Check the wallet/Testnet outcome before reloading or trying again; reloading resets only this local UI state and does not establish what happened. The UI reads the exact Testnet account record saved by Meteor SDK, not a live wallet-account list; that record alone is not proof of current wallet ownership. The existing preflight remains read-only, and the local server's client-supplied account ID is not proof of ownership. This is a demonstration-only client-side gate, not production enforcement or a fee estimate. The SDK and wallet are third-party components and have not been audited here.

Only the unused `raw.githubusercontent.com` origin was removed from `connect-src` and `img-src`; `rpc.testnet.near.org` and every other security directive remain unchanged. No wildcard or new inline-script permission was added. UI tests mock the Meteor SDK, wallet action, policy results, and RPC responses. They do not contact Meteor or submit a transaction. **A live transfer has not been tested.** Run the UI tests with `npm run test:ui` or include them in `./scripts/verify.sh`. No public deployment is created.

### NEAR testnet read-only preflight

`examples/near_testnet_preflight.js` adds a separate, read-only adapter for a simple native NEAR transfer intent. It requires a [NEAR Connect](https://docs.near.org/web3-apps/tutorials/wallet-login) connector configured with `network: "testnet"` and an already-connected wallet. The host application must handle any wallet connection through its own user-initiated flow; this adapter never calls `connect()`. It first runs a policy-only gate; policy denial, policy error, or invalid input stops before wallet access and RPC. Only after policy allows and a matching operator baseline is available does it read the selected sender and recipient using the fixed Testnet RPC's read-only `status` and `query` (`view_account`) methods. Risk runs once afterward with the caller's context unchanged and the recipient contract/code-change signals derived from RPC. Missing account-age or interaction history is never filled in; it can leave the final result at `NEEDS_REVIEW` after the read-only checks.

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
console.log(result.status, result.guard?.decision ?? "no final guard", result.recipientCodeCheck?.status ?? "not checked");
```

The recipient code-hash baseline must be supplied out-of-band by the operator in the server-side `SENTINEL_GUARD_CODE_HASH_BASELINES` environment setting as JSON records with exactly `network`, `account_id`, and `code_hash` fields. The configuration is matched to both `testnet` and the exact recipient; it must not be embedded in browser code or public files. The adapter never learns a baseline from an RPC response. A missing/invalid baseline, missing account, malformed RPC response, timeout, or other RPC failure produces `NEEDS_REVIEW` with code-hash status `UNKNOWN`, not an unchanged-code signal or final `ALLOW`; these results have no final `guard`, and retain the earlier policy-only result as `preliminaryPolicy`. `recipient_is_contract` and `recipient_code_changed` are reserved in this preflight context and are computed from the recipient's current hash and the configured baseline; `known_malicious` remains caller-supplied and is not independently verified.

`PREPARED_NOT_SUBMITTED` means only that the policy-only gate allowed the request, both account reads succeeded, the recipient hash was compared to its configured baseline, and the final risk evaluation returned `ALLOW`. The adapter has no signing or submission path: it does not call `signAndSendTransaction`, sign any payload, hold a key, or broadcast. A final risk `WARN`/`BLOCK` prevents a prepared result, though the read-only account requests have already occurred. The test suite mocks RPC responses and does not contact NEAR. This prototype's rules and caller-provided context are experimental; a preflight result is neither a safety guarantee nor authorization to transact. The official [NEAR Connect repository](https://github.com/azbang/near-connect) describes the connector API; a real wallet connection remains a separate user interaction.

An `ALLOW` from this prototype is not a policy approval or authorization for a real transfer. The example policy is only test data, and caller-provided risk context and the prototype's risk heuristics are experimental.

## Current limitations

The Python simulator expects the caller to provide a decoded transaction dictionary and an in-memory policy engine; the bounded JSON adapter separately loads the explicitly selected local policy described above. The preflight adapter remains read-only and does not sign or submit. Only the separate browser demonstration can request the one fixed Testnet self-transfer after its review and second click. The system does not parse or independently verify the wallet's signed transaction, estimate transaction fees, audit the third-party executor, or establish production security. The demo's client-side checks are not a guarantee that the wallet executor follows them.
