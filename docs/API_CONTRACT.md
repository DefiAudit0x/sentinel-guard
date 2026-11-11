# Sentinel Guard Local API Contract

This document describes the behavior implemented by the current local Python prototype. It is a deterministic input evaluator only: it does not connect to a NEAR network, inspect chain state, sign or submit transactions, or establish that a transaction is safe in production.

## Public entry point

```python
simulate_transaction(
    action: str,
    resource: str | None,
    transaction: dict[str, Any],
    policy_engine: Any,
) -> SimulationResult
```

The simulator first validates the request wrapper. For a valid wrapper, it evaluates policy and transaction risk independently, even if one evaluator errors. `resource` is passed directly to the policy engine; the transaction's `recipient` is passed to risk analysis. The simulator does not check that those two values agree.

### Request wrapper

| Argument | Requirement |
| --- | --- |
| `action` | A non-empty string after whitespace trimming. The original string is passed through and matched exactly; it is not normalized. |
| `resource` | `None` or a non-empty string after whitespace trimming. The original string is passed through and matched exactly. |
| `transaction` | A dictionary whose keys are all strings. Transaction-field validation is performed by the risk analyzer, not by wrapper validation. |
| `policy_engine` | An object with a callable `evaluate(action, resource)` method. Its result must be a `PolicyDecision` with a boolean `allowed`, a non-empty string `reason`, and `matched_rule` either a string or `None`. |

If wrapper validation fails, the simulator returns `decision=BLOCK`, `status=INVALID_INPUT`, both evaluator statuses `NOT_EVALUATED`, and the wrapper validation messages in `reasons`. Neither evaluator is called. A missing or malformed risk field is **not** a wrapper error: it is reported by the risk evaluator as an evaluated `BLOCK` result.

## Policy contract

The built-in policy API is `PolicyRule(name, effect, action, resource=None)` and `PolicyEngine(rules=())`. `effect` must be `Effect.ALLOW` or `Effect.DENY`; a rule's name and action must be non-empty strings, and a supplied resource must also be non-empty. A rule with `resource=None` applies to every resource for its action. Otherwise both `action` and `resource` must match exactly (case-sensitive string equality).

Policy evaluation uses **deny-overrides** and **default-deny**:

1. Any matching deny rule wins over matching allow rules, regardless of declaration order.
2. If there is no matching deny, the first matching allow rule allows the request.
3. If no rule matches, the result is denied by default.

The built-in `PolicyDecision` contains `allowed: bool`, `reason: str`, and `matched_rule: str | None`. Its `reason` is `explicit_deny`, `matched_allow_rule`, or `default_deny`. `matched_rule` is the name of the selected deny/allow rule, or `None` for default-deny. A policy denial is a normal security decision, not an evaluator error.

## Transaction fields and risk analysis

The `transaction` dictionary is the risk analyzer's input. `recipient` and `amount_yocto` are functionally required for a non-blocking risk evaluation: omitting either makes risk return `BLOCK` with score `100`. Unknown string-keyed fields are ignored by the current analyzer.

| Field | Required / default | Accepted value and behavior |
| --- | --- | --- |
| `recipient` | Required | Non-empty string after whitespace trimming. An absent, non-string, empty, or whitespace-only value returns `BLOCK` / `100` with `Missing or invalid recipient`. |
| `amount_yocto` | Required | Non-negative Python `int`, explicitly excluding `bool`. The unit is **yoctoNEAR** (`1 NEAR = 10**24 yoctoNEAR`). A missing, non-integer, float, or boolean returns `BLOCK` / `100` with `Invalid transaction amount`; a negative integer returns `BLOCK` / `100` with `Negative transaction amount`. |
| `recipient_is_contract` | Optional; `False` | Must be a boolean when supplied; otherwise returns `BLOCK` / `100` with `Invalid recipient_is_contract value`. `True` adds 5 points and the reason `Recipient is a smart contract`. |
| `recipient_code_changed` | Optional; `False` | Must be a boolean when supplied; otherwise returns `BLOCK` / `100` with `Invalid recipient_code_changed value`. It adds 50 points only when `recipient_is_contract` is also `True`, with reason `Recipient contract code changed`. |
| `known_malicious` | Optional; `False` | Must be a boolean when supplied; otherwise returns `BLOCK` / `100` with `Invalid known_malicious value`. After the other risk inputs have passed validation, `True` immediately returns `BLOCK` / `100` with `Recipient is marked as known malicious`. This is a caller-supplied flag, not a reputation lookup or a claim verified by Sentinel Guard. |
| `previous_interactions` | Optional; `0` | Non-negative Python `int`, excluding `bool`. `0` adds 10 points with reason `No previous interaction with recipient`. Invalid values return `BLOCK` / `100` with `Invalid previous interaction count`. |
| `account_age_days` | Optional; `0` | Non-negative Python `int`, excluding `bool`. A value below 7 adds 15 points with reason `Account is less than 7 days old`. Invalid values return `BLOCK` / `100` with `Invalid account age`. |

Because the two count/age fields default to zero, a transaction that supplies only the required `recipient` and `amount_yocto` receives both corresponding risk signals: at least 25 points before any other signals, so it is a `WARN` unless an earlier validation error or the `known_malicious` flag blocks it. Callers should supply these values explicitly when they have them; the defaults do not represent observed account history.

### Risk score and decision

For validated inputs, the analyzer adds the following deterministic signals:

| Condition | Points |
| --- | ---: |
| `recipient_code_changed` and `recipient_is_contract` are both `True` | 50 |
| `amount_yocto` is strictly greater than `10 * 10**24` (more than 10 NEAR) | 30 |
| `account_age_days < 7` | 15 |
| `previous_interactions == 0` | 10 |
| `recipient_is_contract` is `True` | 5 |

Exactly 10 NEAR does not trigger the amount signal. For the ordinary scoring path, the analyzer sums the applicable points and caps the returned score at 100. Scores of 50 or higher yield `RiskDecision.BLOCK`; scores from 20 through 49 yield `WARN`; lower scores yield `ALLOW`. All five point weights and these decision thresholds are experimental prototype heuristics, not validated or calibrated production rules or an established security standard. They do not establish that a transaction is safe or unsafe. `RiskResult` contains `decision`, `risk_score`, and a tuple of explanatory `reasons`.

`known_malicious=True` follows a separate immediate-block path after input validation: it returns `BLOCK` / `100` without calculating or adding the weighted risk signals. It is not a point in the score sum. Because validation runs first, an invalid recipient, amount, count, age, or supplied boolean is reported as an invalid-input risk `BLOCK` even if `known_malicious=True` is also present.

## Result fields and status meanings

The simulator returns a `SimulationResult` with:

| Field | Type | Meaning |
| --- | --- | --- |
| `decision` | `SimulationDecision` | The combined outcome: `ALLOW`, `WARN`, or `BLOCK`. |
| `status` | `SimulationStatus` | Overall processing outcome: `COMPLETED`, `ERROR`, or `INVALID_INPUT`. |
| `policy` | `PolicyEvaluation` | Policy evaluator status and, when available, allow/deny details or error information. |
| `risk` | `RiskEvaluation` | Risk evaluator status and, when available, risk decision, score, and reasons or error information. |
| `reasons` | `tuple[str, ...]` | Combined explanatory messages in policy-then-risk order. |

These enums describe different layers and are not interchangeable:

- **`SimulationDecision`** is the final combined decision (`ALLOW`, `WARN`, `BLOCK`).
- **`SimulationStatus`** says whether the wrapper was invalid, an evaluator failed technically, or processing completed (`INVALID_INPUT`, `ERROR`, `COMPLETED`).
- **`EvaluationStatus`**, held separately by `policy.status` and `risk.status`, says whether that evaluator ran and returned a valid result (`EVALUATED`, `ERROR`, `NOT_EVALUATED`).
- The risk engine's **`RiskDecision`** (`ALLOW`, `WARN`, `BLOCK`) is only its own assessment, not the final simulation decision.

## Combining policy and risk

After a valid wrapper, both evaluators are attempted independently. The final outcome is combined as follows:

| Policy result | Risk result | Final decision |
| --- | --- | --- |
| Allowed | `ALLOW` | `ALLOW` |
| Allowed | `WARN` | `WARN` (not upgraded to `ALLOW`) |
| Denied | Any valid risk decision | `BLOCK` |
| Allowed | `BLOCK` | `BLOCK` |
| Either evaluator has status `ERROR` | Any other result | `BLOCK` |

A normal policy denial, risk warning, or risk block is a completed evaluation: `SimulationStatus.COMPLETED`. A technically failing policy or risk evaluator produces `SimulationStatus.ERROR` and final `BLOCK`; the other evaluator is still attempted. A valid wrapper with risk-invalid transaction fields is also `COMPLETED` when both evaluators ran successfully—the risk evaluation itself returns `BLOCK` / `100`. Only invalid wrapper fields produce `SimulationStatus.INVALID_INPUT` and leave both evaluator statuses as `NOT_EVALUATED`.

Policy evaluator errors record `error_stage`: `LOOKUP` when accessing `evaluate` fails, `CONTRACT` when it is not callable or returns a malformed/incorrect decision object, and `CALL` when invoking it raises. Risk evaluator errors have an `error` string but no stage. `ERROR` is an operational result, distinct from a policy/risk security rejection represented by a completed `BLOCK`.

## Local example

Run this from the repository root. The example supplies all transaction fields explicitly and uses the in-memory policy engine; it does not make a network request or execute a transaction.

```python
from sentinel_guard.policy_engine import Effect, PolicyEngine, PolicyRule
from sentinel_guard.transaction_simulator import simulate_transaction

policy = PolicyEngine([
    PolicyRule(
        name="allow-transfer",
        effect=Effect.ALLOW,
        action="transfer",
        resource="alice.near",
    ),
])

transaction = {
    "recipient": "alice.near",
    "amount_yocto": 1 * 10**24,  # 1 NEAR, in integer yoctoNEAR
    "recipient_is_contract": False,
    "recipient_code_changed": False,
    "known_malicious": False,  # supplied by the caller; not verified by the analyzer
    "previous_interactions": 3,
    "account_age_days": 365,
}

result = simulate_transaction(
    action="transfer",
    resource="alice.near",
    transaction=transaction,
    policy_engine=policy,
)

print(result.status.value, result.decision.value)
print(result.policy.status.value, result.policy.allowed, result.policy.reason)
print(result.risk.status.value, result.risk.decision.value, result.risk.risk_score)
```

With these values the local result is `COMPLETED ALLOW`; policy allows the exact action/resource, and the risk score is 0. This is only an example of the implemented local contract, not evidence of network or production protection.
