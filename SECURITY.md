# Security

## Scope

Sentinel Guard is a local prototype that evaluates an action/resource pair against in-memory policy rules and evaluates a caller-supplied, already-decoded transaction dictionary. Policy matching is exact: a rule without a resource applies to any resource for its action; a resource-specific rule must match exactly. Any matching `DENY` overrides matching `ALLOW` rules, regardless of rule order. When no rule matches, policy evaluation returns `default_deny`.

The simulator only combines these local decisions. It does not read blockchain or network state, sign or submit transactions, execute them, or request human approval. It is not a production security boundary.

## Trust boundaries and inputs

The caller supplies the action, resource, transaction fields, in-memory policy rules, and descriptive signals such as `recipient_is_contract`, `recipient_code_changed`, `previous_interactions`, and `account_age_days`. The prototype does not independently establish that these values describe a real transaction or account, nor does it parse or authenticate raw transaction data.

`known_malicious` is a caller-provided Boolean signal, not a verified finding. After the analyzer's input checks, `true` produces `BLOCK` with score 100; when omitted, it defaults to `false` for this signal only. Sentinel Guard does not fetch or verify a malicious-address list, so this result alone does not establish that a recipient is malicious.

The analyzer rejects missing or invalid recipients, non-integer, Boolean, or negative amounts, invalid interaction counts or account ages, and non-Boolean values for the three Boolean signals. Its amount threshold and score rules are experimental heuristics, not established security standards or a trusted reputation service.

## Failure behavior

The simulator validates the request wrapper before calling either evaluator. An invalid wrapper produces `BLOCK` with `INVALID_INPUT`, and neither evaluator is run. For a valid wrapper, policy and risk evaluation are attempted independently. An evaluator exception or an invalid result contract is recorded as an error and makes the overall decision `BLOCK`; the other evaluator is still attempted. A policy denial or risk `BLOCK` also makes the final decision `BLOCK`. A risk `WARN` remains `WARN` when policy allows and is never converted to `ALLOW`.

These are implemented behaviors. The repository tests exercise policy deny-overrides and default-deny cases, selected risk inputs and thresholds, wrapper validation, evaluator failures, and decision combination. Passing tests establishes only those tested behaviors for the local implementation and fixtures; it does not establish production security or safety for real transactions.

## Current limitations

There is no transaction parser, trusted on-chain or reputation data source, policy loading or persistence, human approval flow, signing, submission, or execution. Authentication, authorization, deployment hardening, and a production threat model are also outside this prototype's implementation. Do not treat a local `ALLOW` or the current tests as evidence that a real transaction is safe.
