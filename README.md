# Sentinel Guard

A local-first, deterministic transaction security and policy evaluation framework for NEAR applications and autonomous AI agents. Sentinel Guard combines exact-match policy enforcement with rule-based transaction risk analysis to produce explainable ALLOW, WARN, or BLOCK decisions before any NEAR transaction is signed.

## Problem

AI agents and automated applications operating on NEAR need to execute transfers and contract calls without exposing user treasuries to unauthorized actions, drained funds, or recently mutated smart contracts. Relying on probabilistic LLM prompts for spending security is brittle, while scattering ad-hoc checks across application code makes security decisions opaque, hard to audit, and impossible to reproduce deterministically.

## Links

- **Live Demo**: N/A (Local CLI evaluation tool)
- **Contracts**: N/A (Local client-side transaction simulation & policy guard)

## How to try it

1. **Verify the test suite**:
   Clone the repository and run `./scripts/verify.sh` — `pytest` and `unittest` execute the unit, boundary, integration, failure, and property test suites with zero network dependencies and report all checks passing.

2. **Run local CLI demo**:
   Run `python3 examples/local_demo.py` — the CLI evaluates three deterministic NEAR transaction scenarios (safe transfer, above-threshold warning, and explicit policy/malicious recipient block) and prints the unified decision, status, policy evaluation, risk score, and reasons for each scenario.

3. **Integrate Sentinel Guard**:
   Import `simulate_transaction`, `PolicyEngine`, `PolicyRule`, and `simulation_result_to_json` from `sentinel_guard` — evaluate proposed action/resource pairs and transaction context locally with fail-closed guarantees before signing.

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
4. **Untrusted LLM Execution**: Prevents AI agent hallucination-based asset loss by enforcing strict local, deterministic checks before key signing.

## Limitations

- **Local / In-Memory Evaluation**: Sentinel Guard operates locally before transaction submission and does not perform live RPC state fetching unless context is provided by the caller.
- **Static Policy Rules**: Current policy rules require explicit configuration in code or local policy files. evaluate an action/resource pair against in-memory rules, give explicit deny rules precedence, and deny by default when no rule permits an action.

## Requirements

- Python 3.12 or newer
- No third-party Python packages are required to run the application; `pytest` is needed for the full test suite.

## Set up

```bash
python3 -m venv .venv
source .venv/bin/activate
```

VS Code is configured to use `.venv/bin/python` and its built-in `unittest` support.

## Run the tests

Install pytest inside the virtual environment:

```bash
.venv/bin/python -m pip install pytest
```

Run all tests:

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m unittest discover -s tests -v
```

Run the complete local verification sequence from the project root:

```bash
./scripts/verify.sh
```

You can also invoke the script by its absolute path from outside the project directory:

```bash
/workspace/sentinel-guard/scripts/verify.sh
```

The script finds the project root from its own location and uses only the existing `.venv/bin/python`. It does not install dependencies or connect to the internet; pytest must already be available in the virtual environment.

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

## Current limitations

The simulator expects the caller to provide a decoded transaction dictionary and an in-memory policy engine. It does not parse transaction payloads, load policies from disk, perform human approvals, or establish production security. These capabilities and their threat model should be specified and reviewed before extending or submitting the project.
