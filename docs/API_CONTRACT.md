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

The simulator first validates the request wrapper. For a valid wrapper, it evaluates policy and transaction risk independently, even if one evaluator errors. A supplied `resource` requires `transaction["recipient"]` to be a valid non-empty string and must exactly match it; a missing, invalid, or mismatched recipient/resource pair is rejected as `INVALID_INPUT` before either evaluator runs. If `resource` is `None` and the transaction recipient is a valid non-empty string, that recipient is used for policy evaluation. This ensures recipient-specific `DENY` rules still override a general `ALLOW` rule when callers omit `resource`. The transaction's recipient is also passed to risk analysis.

### Request wrapper

| Argument | Requirement |
| --- | --- |
| `action` | A non-empty string after whitespace trimming. The original string is passed through and matched exactly; it is not normalized. |
| `resource` | `None` or a non-empty string after whitespace trimming. A supplied value requires a valid non-empty string recipient and must exactly equal it. If omitted and the recipient is valid, the recipient is used for policy matching. |
| `transaction` | A dictionary whose keys are all strings. Transaction-field validation is performed by the risk analyzer, not by wrapper validation. |
| `policy_engine` | An object with a callable `evaluate(action, resource)` method. Its result must be a `PolicyDecision` with a boolean `allowed`, a non-empty string `reason`, and `matched_rule` either a string or `None`. |

If wrapper validation fails, the simulator returns `decision=BLOCK`, `status=INVALID_INPUT`, both evaluator statuses `NOT_EVALUATED`, and the wrapper validation messages in `reasons`. Neither evaluator is called. A missing or malformed risk field is **not** a wrapper error: it is reported by the risk evaluator as an evaluated `BLOCK` result. When `resource=None` and the recipient is missing or invalid, policy receives `None` and the risk evaluator blocks the invalid transaction recipient. When an explicit resource is supplied with a missing, non-string, empty, or whitespace-only recipient, the wrapper instead returns `INVALID_INPUT` before either evaluator runs.

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


## NEAR testnet JavaScript preflight

`examples/near_testnet_preflight.js` is a separate integration layer; it does not change the Python simulator contract above. It accepts only a supported native transfer intent and requires a connected `NearConnector` configured as `new NearConnector({ network: "testnet" })`. The host application must have completed any wallet connection separately. The adapter calls the existing connector's `wallet()` and the returned wallet's `getAccounts()` only; it does not call `connect()`.

The adapter builds one immutable-by-copy intent with `action: "transfer"`, `resource` equal to the exact recipient, and transaction fields `recipient`, canonical decimal-string `amount_yocto`, and the caller's JSON context. Reserved context keys cannot override `recipient` or `amount_yocto`. The complete intent is submitted to the existing request-bound JavaScript/Python bridge, which evaluates it using the local Sentinel Guard policy and risk engines. Unsupported context fields and invalid amounts fail closed in that local adapter.

### JSON adapter local policy

`sentinel_guard/json_adapter.py` loads its policy path from `SENTINEL_GUARD_POLICY_FILE`; `evaluate_request(request, policy_path)` also accepts an explicit path for local callers and tests. There is no implicit allow policy. An unset path, unreadable file, malformed JSON, duplicate key, or invalid schema returns `ERROR` / `BLOCK`, marks policy evaluation as `ERROR`, and does not evaluate risk or continue to a callback.

The file must contain exactly these version-1 fields:

```json
{
  "version": 1,
  "default": "deny",
  "allowed_recipients": ["alice.near"],
  "max_amount_yocto": "20000000000000000000000000"
}
```

`allowed_recipients` contains unique valid lowercase NEAR account IDs of 2–64 characters, using `[a-z0-9]+` segments separated only by `.`, `_`, or `-`; no case folding or trimming is applied. The request's transaction recipient and any supplied `resource` use the same grammar, and `resource` must exactly match the transaction recipient. An empty allow-list is valid and denies every recipient. `max_amount_yocto` is a canonical non-negative decimal string of at most 80 digits, and policy compares it with the canonical transaction amount as an exact Python integer (yoctoNEAR), never a float. Equality with the cap is allowed by policy; larger amounts are denied. `examples/test_policy.json` is fictional test/demo data only and is not a recommended or inferred financial policy.

For a `COMPLETED` + `ALLOW` guard result, the adapter sends read-only JSON-RPC `status` and `query` (`request_type: "view_account"`, `finality: "final"`) requests to the fixed `https://rpc.testnet.near.org` endpoint. It requires `status.result.chain_id === "testnet"` before reading the account. It returns `status: "PREPARED_NOT_SUBMITTED"` with the local decision and account snapshot; `WARN` and `BLOCK` return before wallet or RPC access. Multiple connected accounts require an explicit account ID.

The module contains no transaction construction for wallet submission and never invokes `signTransaction`, `signAndSendTransaction`, or `signAndSendTransactions`. `PREPARED_NOT_SUBMITTED` is not signing authorization, fee estimation, a guarantee that a future transaction will succeed, or evidence that the heuristic policy is production-safe. Balance, account metadata, and caller-supplied risk context may be stale or incomplete. The unit tests use mocked RPC responses and do not contact the testnet.

The separate generic preflight example accepts a host-supplied `NearConnector`; its wallet integration guidance remains in [NEAR's Wallet Login documentation](https://docs.near.org/web3-apps/tutorials/wallet-login) and the [NEAR Connect repository](https://github.com/azbang/near-connect). The local Meteor browser UI described below uses the official [`@meteorwallet/sdk`](https://www.npmjs.com/package/@meteorwallet/sdk) instead.

### Local wallet UI boundary

`ui/main.mjs` dynamically imports `@meteorwallet/sdk` only after the user clicks Connect. It initializes the SDK with `webpage_local_storage`, local-origin partner metadata, the Meteor Mobile bridge disabled, and both account-transfer and new-key-transfer surfaces disabled. The only sign-in action is `near::sign_in` targeting `{ blockchain: "near", network: "testnet" }`; it omits `addFunctionCallKey`. Ordinary sign-in does not request a message signature or transaction, and there is no auto-connect. The UI retains only the returned Testnet account identifier and re-reads that exact identifier through `MeteorConnect.getAccount()` before later gates. This checks the Testnet account record saved by SDK, not a live wallet account list; that record alone is not proof of current wallet ownership.

The optional browser transfer path remains separate. It requires `defiaudit0x.testnet` as both sender and receiver, one native `Transfer` of exactly `1000000000000000000000` yoctoNEAR, a completed local ALLOW, the exact result status/request ID/intent hash, and sufficient Testnet balance before showing a two-minute immutable review. The binding includes the guard hash, network, sender, receiver, action, and amount. An untouched review closes automatically at its deadline. Only a separate second click can create the SDK's `near::sign_transactions` action; immediately beforehand the UI re-reads the exact stored Testnet account and validates the frozen review. The SDK request targets that account, contains exactly one native transfer, and sets `useFunctionCallKey: false`, so the SDK is instructed to require the wallet rather than use an access key. After handing the request to Meteor, the page cannot cancel an opened wallet prompt and locks another fixed-transfer attempt for the rest of the loaded page session. Reloading clears only that local UI state and does not establish the prior outcome. This is a client-side demonstration gate, not production enforcement; the wallet must still show its own confirmation. No live transfer has been tested, and no fee estimate is provided.

The Node server binds to `127.0.0.1` only. It accepts only the exact recipient `defiaudit0x.testnet`, a positive amount at or below `100000000000000000000000` yoctoNEAR, and the two documented optional context fields. It creates a synthetic connector exposing only `wallet()`/`getAccounts()` for the existing preflight adapter; it does not attest wallet ownership, and the account ID is treated as a client-supplied identifier for read-only lookup. The local policy remains server-side through `SENTINEL_GUARD_POLICY_FILE`, and startup rejects a policy path inside the generated static UI directory. Static routing is restricted to `/`, `/index.html`, and built `/assets/*` files.

An omitted account-age or interaction value remains omitted and may cause the existing risk engine to return `WARN` / `NEEDS_REVIEW`; the UI must not invent those facts. `WARN`, `BLOCK`, policy failure, and invalid input do not lead to account RPC reads or the wallet. `PREPARED_NOT_SUBMITTED` means only that local evaluation allowed the request and a read-only account snapshot succeeded; it is not authorization to transact. Before the preflight button, the page discloses that an `ALLOW` causes the selected public account ID to be sent to `https://rpc.testnet.near.org` for a read-only lookup. CSP removes only the unused `raw.githubusercontent.com` origin from `connect-src` and `img-src`; `rpc.testnet.near.org` and every other security directive remain unchanged. UI tests mock the Meteor SDK actions, wallet responses, and RPC. They verify no sign-in or transaction action on mount, ordinary Testnet sign-in without a function-call key, no transaction prompt from ALLOW/review, and the existing transfer hash/account/network/click gates. These tests do not contact Meteor, sign or send a transaction, or audit the SDK or wallet. A live transfer has not been tested.


**Policy boundary:** the JSON bridge applies only the explicitly configured local policy file. The bundled example is non-production test data; a preflight `ALLOW` is not authorization to transact, a guarantee of safety, or a claim that caller-provided risk context is verified. The risk heuristics remain experimental.
