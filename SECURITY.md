# Security

## Scope

Sentinel Guard is a local prototype that evaluates an action/resource pair against in-memory policy rules and evaluates a caller-supplied, already-decoded transaction dictionary. For simulator calls, a supplied resource must exactly match a valid transaction recipient; when resource is omitted, the recipient is used for policy evaluation. Policy matching is exact: a rule without a resource applies to any resource for its action; a resource-specific rule must match exactly. Any matching `DENY` overrides matching `ALLOW` rules, regardless of rule order. When no rule matches, policy evaluation returns `default_deny`.

The simulator only combines these local decisions. It does not read blockchain or network state, sign or submit transactions, execute them, or request human approval. It is not a production security boundary.

## Trust boundaries and inputs

The caller supplies the action, resource, transaction fields, in-memory policy rules, and descriptive signals such as `recipient_is_contract`, `recipient_code_changed`, `previous_interactions`, and `account_age_days`. The simulator checks that an explicit resource agrees with a valid transaction recipient, but it does not independently establish that the supplied values describe a real transaction or account, nor does it parse or authenticate raw transaction data.

`known_malicious` is a caller-provided Boolean signal, not a verified finding. After the analyzer's input checks, `true` produces `BLOCK` with score 100; when omitted, it defaults to `false` for this signal only. Sentinel Guard does not fetch or verify a malicious-address list, so this result alone does not establish that a recipient is malicious.

The analyzer rejects missing or invalid recipients, non-integer, Boolean, or negative amounts, invalid interaction counts or account ages, and non-Boolean values for the three Boolean signals. Its amount threshold and score rules are experimental heuristics, not established security standards or a trusted reputation service.

## Failure behavior

The simulator validates the request wrapper before calling either evaluator. An invalid wrapper produces `BLOCK` with `INVALID_INPUT`, and neither evaluator is run. For a valid wrapper, policy and risk evaluation are attempted independently. An evaluator exception or an invalid result contract is recorded as an error and makes the overall decision `BLOCK`; the other evaluator is still attempted. A policy denial or risk `BLOCK` also makes the final decision `BLOCK`. A risk `WARN` remains `WARN` when policy allows and is never converted to `ALLOW`.

These are implemented behaviors. The repository tests exercise policy deny-overrides and default-deny cases, selected risk inputs and thresholds, wrapper validation, evaluator failures, and decision combination. Passing tests establishes only those tested behaviors for the local implementation and fixtures; it does not establish production security or safety for real transactions.

## Current limitations

The core simulator has no policy loader or persistence: callers supply its in-memory policy rules. Separately, the bounded JSON adapter loads an explicitly selected local policy file and fails closed on loading errors; it does not persist or modify that file. The core simulator, JSON adapter, and generic preflight have no transaction-signing or submission path. A separate optional browser demonstration can request one fixed Testnet self-transfer after a local `ALLOW`, a two-minute exact review, and a second user click; the wallet must still confirm it. This is not a control on other applications or an enforcement boundary. The local UI uses the third-party Meteor SDK and wallet; the application cannot guarantee their behavior. There is no transaction parser, trusted on-chain or reputation data source, or production enforcement. Authentication, authorization, deployment hardening, and a production threat model are also outside this prototype's implementation. Do not treat a local `ALLOW` or the current tests as evidence that a real transaction is safe. A live transfer has not been tested.

The local UI lazily imports `@meteorwallet/sdk` after an explicit Connect click. It initializes with `webpage_local_storage`, local-origin partner metadata, the Meteor Mobile bridge disabled, and both `transferAccounts` and `newKeyTransfer` disabled. The only sign-in request is `near::sign_in` with the NEAR Testnet target; it does not include `addFunctionCallKey` and does not request a message signature or transaction. There is no auto-connect. The UI re-reads only the exact signed-in Testnet identifier through `MeteorConnect.getAccount()` before later gates. This is the Testnet account record saved by SDK, not a live wallet account-list query, and that record alone is not proof of current wallet ownership.

The server CSP removes only the unused `raw.githubusercontent.com` origin from `connect-src` and `img-src`; `rpc.testnet.near.org` and every other security directive remain unchanged. No wildcard or new inline-script permission was added. The optional fixed-transfer path is distinct from sign-in: it validates the exact Testnet account, result status, request ID and intent hash, then displays an immutable two-minute review. A second click rechecks the review binding and exact SDK-stored Testnet account before making one `near::sign_transactions` request for one native transfer with `useFunctionCallKey: false`; the SDK is instructed to require wallet confirmation. This remains a client-side gate, not a guarantee that third-party code is safe or follows the UI's limits. Tests use a mocked Meteor SDK, wallet response, and RPC; they do not contact Meteor or sign or send any transaction.
