# Sentinel Guard

Sentinel Guard is an early, local prototype for deterministic policy decisions in a NEAR hackathon project. The current scope is intentionally small: evaluate an action/resource pair against in-memory rules, give explicit deny rules precedence, and deny by default when no rule permits an action.

## Requirements

- Python 3.12 or newer
- No third-party Python packages are required

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

## Local transaction simulator

`simulate_transaction(action, resource, transaction, policy_engine)` validates the request wrapper, then evaluates policy and transaction risk independently. Its result preserves each engine's status, decision, and reasons. A policy denial, risk `BLOCK`, or engine error produces a final `BLOCK`; policy allow plus risk `WARN` remains `WARN`, never an automatic allow. Invalid wrappers are blocked with `INVALID_INPUT`, and neither engine is evaluated.

This is local decision orchestration only. It does not request human approval, connect to NEAR, sign or submit transactions, or modify files outside this project; it is not a production security boundary.

## Current limitations

The simulator expects the caller to provide a decoded transaction dictionary and an in-memory policy engine. It does not parse transaction payloads, load policies from disk, perform human approvals, or establish production security. These capabilities and their threat model should be specified and reviewed before extending or submitting the project.
