import unittest
from copy import deepcopy
from types import MappingProxyType
from unittest.mock import patch

from sentinel_guard.policy_engine import (
    Effect,
    PolicyDecision,
    PolicyEngine,
    PolicyRule,
)
from sentinel_guard.risk_analyzer import RiskDecision, RiskResult, analyze_transaction
from sentinel_guard.transaction_simulator import (
    EvaluationStatus,
    PolicyErrorStage,
    SimulationDecision,
    SimulationStatus,
    simulate_transaction,
)


class StubPolicyEngine:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.calls = 0

    def evaluate(self, action, resource=None):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.result


class RaisingLookupPolicyEngine:
    def __init__(self, error):
        self.error = error
        self.lookups = 0

    @property
    def evaluate(self):
        self.lookups += 1
        raise self.error


class TransactionSimulatorTests(unittest.TestCase):
    def setUp(self):
        self.allow_engine = PolicyEngine(
            [
                PolicyRule(
                    "allow-transfer",
                    Effect.ALLOW,
                    "transfer",
                    "alice.near",
                )
            ]
        )
        self.safe_transaction = {
            "recipient": "alice.near",
            "amount_yocto": 0,
            "previous_interactions": 5,
            "account_age_days": 100,
        }

    def simulate(self, engine=None, transaction=None):
        return simulate_transaction(
            "transfer",
            "alice.near",
            self.safe_transaction if transaction is None else transaction,
            self.allow_engine if engine is None else engine,
        )

    def test_policy_allow_and_risk_allow_produce_allow(self):
        result = self.simulate()

        self.assertEqual(result.decision, SimulationDecision.ALLOW)
        self.assertEqual(result.status, SimulationStatus.COMPLETED)
        self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
        self.assertTrue(result.policy.allowed)
        self.assertEqual(result.policy.reason, "matched_allow_rule")
        self.assertEqual(result.policy.matched_rule, "allow-transfer")
        self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)
        self.assertEqual(result.risk.decision, RiskDecision.ALLOW)
        self.assertEqual(result.risk.reasons, ())
        self.assertEqual(result.reasons, ())

    def test_policy_allow_and_risk_warn_produce_warn(self):
        transaction = dict(self.safe_transaction, amount_yocto=11 * 10**24)

        result = self.simulate(transaction=transaction)

        self.assertEqual(result.decision, SimulationDecision.WARN)
        self.assertEqual(result.status, SimulationStatus.COMPLETED)
        self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
        self.assertTrue(result.policy.allowed)
        self.assertEqual(result.policy.reason, "matched_allow_rule")
        self.assertEqual(result.policy.matched_rule, "allow-transfer")
        self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)
        self.assertEqual(result.risk.decision, RiskDecision.WARN)
        self.assertEqual(result.risk.reasons, ("Transaction amount exceeds threshold",))
        self.assertIn("Risk: Transaction amount exceeds threshold", result.reasons)

    def test_policy_allow_and_risk_block_produce_block(self):
        transaction = dict(self.safe_transaction, known_malicious=True)

        result = self.simulate(transaction=transaction)

        self.assertEqual(result.decision, SimulationDecision.BLOCK)
        self.assertEqual(result.status, SimulationStatus.COMPLETED)
        self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
        self.assertTrue(result.policy.allowed)
        self.assertEqual(result.policy.reason, "matched_allow_rule")
        self.assertEqual(result.policy.matched_rule, "allow-transfer")
        self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)
        self.assertEqual(result.risk.decision, RiskDecision.BLOCK)
        self.assertEqual(result.risk.risk_score, 100)
        self.assertEqual(
            result.risk.reasons,
            ("Recipient is marked as known malicious",),
        )
        self.assertEqual(
            result.reasons,
            ("Risk: Recipient is marked as known malicious",),
        )

    def test_missing_amount_is_blocked_by_real_risk_analyzer(self):
        transaction = dict(self.safe_transaction)
        del transaction["amount_yocto"]

        result = self.simulate(transaction=transaction)

        self.assertEqual(result.decision, SimulationDecision.BLOCK)
        self.assertEqual(result.status, SimulationStatus.COMPLETED)
        self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
        self.assertTrue(result.policy.allowed)
        self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)
        self.assertEqual(result.risk.decision, RiskDecision.BLOCK)
        self.assertEqual(result.risk.risk_score, 100)
        self.assertEqual(result.risk.reasons, ("Invalid transaction amount",))
        self.assertEqual(result.reasons, ("Risk: Invalid transaction amount",))

    def test_combined_risk_signals_saturate_score_at_100(self):
        transaction = {
            "recipient": "alice.near",
            "recipient_is_contract": True,
            "recipient_code_changed": True,
            "amount_yocto": 11 * 10**24,
            "account_age_days": 6,
            "previous_interactions": 0,
        }

        result = self.simulate(transaction=transaction)

        self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
        self.assertTrue(result.policy.allowed)
        self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)
        self.assertEqual(result.risk.risk_score, 100)
        self.assertEqual(result.risk.decision, RiskDecision.BLOCK)
        self.assertEqual(
            result.risk.reasons,
            (
                "Recipient contract code changed",
                "Transaction amount exceeds threshold",
                "Account is less than 7 days old",
                "No previous interaction with recipient",
                "Recipient is a smart contract",
            ),
        )
        self.assertEqual(result.decision, SimulationDecision.BLOCK)
        self.assertEqual(result.status, SimulationStatus.COMPLETED)

    def test_three_weak_risk_signals_accumulate_to_warn(self):
        transaction = {
            "recipient": "alice.near",
            "amount_yocto": 5 * 10**24,
            "account_age_days": 6,
            "previous_interactions": 0,
            "recipient_is_contract": True,
        }

        result = self.simulate(transaction=transaction)

        self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
        self.assertTrue(result.policy.allowed)
        self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)
        self.assertEqual(result.risk.decision, RiskDecision.WARN)
        self.assertEqual(result.risk.risk_score, 30)
        self.assertEqual(
            result.risk.reasons,
            (
                "Account is less than 7 days old",
                "No previous interaction with recipient",
                "Recipient is a smart contract",
            ),
        )
        self.assertEqual(result.decision, SimulationDecision.WARN)
        self.assertEqual(result.status, SimulationStatus.COMPLETED)

    def test_risk_threshold_at_50_blocks_after_contract_signal(self):
        base_transaction = {
            "recipient": "alice.near",
            "amount_yocto": 11 * 10**24,
            "account_age_days": 3,
            "previous_interactions": 1,
        }
        scenarios = (
            (
                "without_contract",
                dict(base_transaction, recipient_is_contract=False),
                45,
                RiskDecision.WARN,
                SimulationDecision.WARN,
                (
                    "Transaction amount exceeds threshold",
                    "Account is less than 7 days old",
                ),
            ),
            (
                "with_contract",
                dict(base_transaction, recipient_is_contract=True),
                50,
                RiskDecision.BLOCK,
                SimulationDecision.BLOCK,
                (
                    "Transaction amount exceeds threshold",
                    "Account is less than 7 days old",
                    "Recipient is a smart contract",
                ),
            ),
        )

        for name, transaction, score, risk_decision, decision, risk_reasons in scenarios:
            with self.subTest(scenario=name):
                result = self.simulate(transaction=transaction)

                self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
                self.assertTrue(result.policy.allowed)
                self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)
                self.assertEqual(result.risk.risk_score, score)
                self.assertEqual(result.risk.decision, risk_decision)
                self.assertEqual(result.risk.reasons, risk_reasons)
                self.assertEqual(result.status, SimulationStatus.COMPLETED)
                self.assertEqual(result.decision, decision)
                self.assertEqual(
                    result.reasons,
                    tuple(f"Risk: {reason}" for reason in risk_reasons),
                )

    def test_young_account_and_contract_signal_cross_allow_warn_boundary(self):
        young_account = {
            "recipient": "alice.near",
            "amount_yocto": 5 * 10**24,
            "account_age_days": 3,
            "previous_interactions": 4,
        }
        scenarios = (
            (
                "young_account_only",
                young_account,
                15,
                RiskDecision.ALLOW,
                ("Account is less than 7 days old",),
                SimulationDecision.ALLOW,
            ),
            (
                "young_account_and_contract",
                dict(young_account, recipient_is_contract=True),
                20,
                RiskDecision.WARN,
                (
                    "Account is less than 7 days old",
                    "Recipient is a smart contract",
                ),
                SimulationDecision.WARN,
            ),
        )

        for name, transaction, score, risk_decision, risk_reasons, decision in scenarios:
            with self.subTest(scenario=name):
                result = self.simulate(transaction=transaction)

                self.assertEqual(result.status, SimulationStatus.COMPLETED)
                self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
                self.assertTrue(result.policy.allowed)
                self.assertEqual(result.policy.reason, "matched_allow_rule")
                self.assertEqual(result.policy.matched_rule, "allow-transfer")
                self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)
                self.assertEqual(result.risk.risk_score, score)
                self.assertEqual(result.risk.decision, risk_decision)
                self.assertEqual(result.risk.reasons, risk_reasons)
                self.assertEqual(result.decision, decision)
                self.assertEqual(
                    result.reasons,
                    tuple(f"Risk: {reason}" for reason in risk_reasons),
                )

    def test_explicit_policy_deny_blocks_even_when_risk_allows(self):
        engine = PolicyEngine(
            [PolicyRule("deny-transfer", Effect.DENY, "transfer", "alice.near")]
        )

        result = self.simulate(engine=engine)

        self.assertEqual(result.decision, SimulationDecision.BLOCK)
        self.assertEqual(result.status, SimulationStatus.COMPLETED)
        self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
        self.assertFalse(result.policy.allowed)
        self.assertEqual(result.policy.reason, "explicit_deny")
        self.assertEqual(result.policy.matched_rule, "deny-transfer")
        self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)
        self.assertEqual(result.risk.decision, RiskDecision.ALLOW)
        self.assertEqual(result.risk.reasons, ())
        self.assertEqual(result.reasons, ("Policy denied: explicit_deny",))

    def test_explicit_policy_deny_and_risk_warn_produce_block(self):
        engine = PolicyEngine(
            [PolicyRule("deny-transfer", Effect.DENY, "transfer", "alice.near")]
        )
        transaction = dict(self.safe_transaction, amount_yocto=11 * 10**24)

        result = self.simulate(engine=engine, transaction=transaction)

        self.assertEqual(result.decision, SimulationDecision.BLOCK)
        self.assertEqual(result.status, SimulationStatus.COMPLETED)
        self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
        self.assertFalse(result.policy.allowed)
        self.assertEqual(result.policy.reason, "explicit_deny")
        self.assertEqual(result.policy.matched_rule, "deny-transfer")
        self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)
        self.assertEqual(result.risk.decision, RiskDecision.WARN)
        self.assertEqual(result.risk.risk_score, 30)
        self.assertEqual(
            result.risk.reasons,
            ("Transaction amount exceeds threshold",),
        )
        self.assertEqual(
            result.reasons,
            (
                "Policy denied: explicit_deny",
                "Risk: Transaction amount exceeds threshold",
            ),
        )

    def test_explicit_policy_deny_and_known_malicious_recipient_produce_block(self):
        engine = PolicyEngine(
            [PolicyRule("deny-transfer", Effect.DENY, "transfer", "alice.near")]
        )
        transaction = dict(self.safe_transaction, known_malicious=True)

        result = self.simulate(engine=engine, transaction=transaction)

        self.assertEqual(result.decision, SimulationDecision.BLOCK)
        self.assertEqual(result.status, SimulationStatus.COMPLETED)
        self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
        self.assertFalse(result.policy.allowed)
        self.assertEqual(result.policy.reason, "explicit_deny")
        self.assertEqual(result.policy.matched_rule, "deny-transfer")
        self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)
        self.assertEqual(result.risk.decision, RiskDecision.BLOCK)
        self.assertEqual(result.risk.risk_score, 100)
        self.assertEqual(
            result.risk.reasons,
            ("Recipient is marked as known malicious",),
        )
        self.assertEqual(
            result.reasons,
            (
                "Policy denied: explicit_deny",
                "Risk: Recipient is marked as known malicious",
            ),
        )

    def test_matching_deny_overrides_allow_regardless_of_rule_order(self):
        deny_rule = PolicyRule("deny-transfer", Effect.DENY, "transfer", "alice.near")
        allow_rule = PolicyRule("allow-transfer", Effect.ALLOW, "transfer", "alice.near")
        results = []

        for order, rules in (
            ("deny_before_allow", (deny_rule, allow_rule)),
            ("allow_before_deny", (allow_rule, deny_rule)),
        ):
            with self.subTest(order=order):
                result = self.simulate(engine=PolicyEngine(rules))

                self.assertEqual(result.decision, SimulationDecision.BLOCK)
                self.assertEqual(result.status, SimulationStatus.COMPLETED)
                self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
                self.assertFalse(result.policy.allowed)
                self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)
                self.assertEqual(result.risk.decision, RiskDecision.ALLOW)
                results.append(result)

        self.assertEqual(results[0], results[1])

    def test_default_deny_blocks_even_when_risk_allows(self):
        result = self.simulate(engine=PolicyEngine())

        self.assertEqual(result.decision, SimulationDecision.BLOCK)
        self.assertEqual(result.policy.reason, "default_deny")
        self.assertEqual(result.risk.decision, RiskDecision.ALLOW)

    def test_invalid_wrapper_blocks_without_evaluating_either_engine(self):
        engine = StubPolicyEngine(PolicyDecision(True, "matched_allow_rule"))

        result = simulate_transaction(" ", "alice.near", self.safe_transaction, engine)

        self.assertEqual(result.decision, SimulationDecision.BLOCK)
        self.assertEqual(result.status, SimulationStatus.INVALID_INPUT)
        self.assertEqual(result.policy.status, EvaluationStatus.NOT_EVALUATED)
        self.assertEqual(result.risk.status, EvaluationStatus.NOT_EVALUATED)
        self.assertEqual(engine.calls, 0)
        self.assertIn("action must be a non-empty string", result.reasons)

    def test_policy_engine_without_evaluate_is_engine_error(self):
        result = simulate_transaction(
            "transfer", "alice.near", self.safe_transaction, object()
        )

        self.assertEqual(result.decision, SimulationDecision.BLOCK)
        self.assertEqual(result.status, SimulationStatus.ERROR)
        self.assertEqual(result.policy.status, EvaluationStatus.ERROR)
        self.assertEqual(result.policy.error_stage, PolicyErrorStage.LOOKUP)
        self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)

    def test_policy_property_lookup_value_and_runtime_errors_are_lookup_errors(self):
        for error in (ValueError("bad descriptor"), RuntimeError("lookup failed")):
            with self.subTest(error=type(error).__name__):
                engine = RaisingLookupPolicyEngine(error)

                result = self.simulate(engine=engine)

                self.assertEqual(result.status, SimulationStatus.ERROR)
                self.assertEqual(result.decision, SimulationDecision.BLOCK)
                self.assertEqual(result.policy.status, EvaluationStatus.ERROR)
                self.assertEqual(result.policy.error_stage, PolicyErrorStage.LOOKUP)
                self.assertIn(str(error), result.policy.error)
                self.assertEqual(engine.lookups, 1)
                self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)

    def test_non_callable_evaluate_is_a_contract_error(self):
        class NonCallablePolicyEngine:
            evaluate = 7

        result = self.simulate(engine=NonCallablePolicyEngine())

        self.assertEqual(result.status, SimulationStatus.ERROR)
        self.assertEqual(result.decision, SimulationDecision.BLOCK)
        self.assertEqual(result.policy.status, EvaluationStatus.ERROR)
        self.assertEqual(result.policy.error_stage, PolicyErrorStage.CONTRACT)
        self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)

    def test_policy_evaluate_value_and_runtime_errors_are_call_errors(self):
        for error in (ValueError("bad policy input"), RuntimeError("call failed")):
            with self.subTest(error=type(error).__name__):
                engine = StubPolicyEngine(error=error)

                result = self.simulate(engine=engine)

                self.assertEqual(result.status, SimulationStatus.ERROR)
                self.assertEqual(result.decision, SimulationDecision.BLOCK)
                self.assertEqual(result.policy.status, EvaluationStatus.ERROR)
                self.assertEqual(result.policy.error_stage, PolicyErrorStage.CALL)
                self.assertIn(str(error), result.policy.error)
                self.assertEqual(engine.calls, 1)
                self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)

    def test_evaluate_property_is_read_once_and_called_once(self):
        class CountingPropertyPolicyEngine:
            def __init__(self):
                self.reads = 0
                self.calls = 0

            @property
            def evaluate(self):
                self.reads += 1

                def evaluate_once(action, resource):
                    self.calls += 1
                    return PolicyDecision(True, "matched_allow_rule")

                return evaluate_once

        engine = CountingPropertyPolicyEngine()

        result = self.simulate(engine=engine)

        self.assertEqual(result.status, SimulationStatus.COMPLETED)
        self.assertEqual(result.decision, SimulationDecision.ALLOW)
        self.assertEqual(engine.reads, 1)
        self.assertEqual(engine.calls, 1)

    def test_policy_error_is_recorded_and_risk_is_still_evaluated(self):
        engine = StubPolicyEngine(error=RuntimeError("policy unavailable"))

        result = self.simulate(engine=engine)

        self.assertEqual(result.decision, SimulationDecision.BLOCK)
        self.assertEqual(result.status, SimulationStatus.ERROR)
        self.assertEqual(result.policy.status, EvaluationStatus.ERROR)
        self.assertIn("policy unavailable", result.policy.error)
        self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)
        self.assertEqual(result.risk.decision, RiskDecision.ALLOW)
        self.assertEqual(engine.calls, 1)

    def test_risk_error_is_recorded_and_policy_is_still_evaluated(self):
        with patch(
            "sentinel_guard.transaction_simulator.analyze_transaction",
            side_effect=RuntimeError("risk unavailable"),
        ):
            result = self.simulate()

        self.assertEqual(result.decision, SimulationDecision.BLOCK)
        self.assertEqual(result.status, SimulationStatus.ERROR)
        self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
        self.assertTrue(result.policy.allowed)
        self.assertEqual(result.risk.status, EvaluationStatus.ERROR)
        self.assertIn("risk unavailable", result.risk.error)

    def test_both_engine_errors_are_recorded(self):
        engine = StubPolicyEngine(error=RuntimeError("policy unavailable"))
        with patch(
            "sentinel_guard.transaction_simulator.analyze_transaction",
            side_effect=RuntimeError("risk unavailable"),
        ):
            result = self.simulate(engine=engine)

        self.assertEqual(result.decision, SimulationDecision.BLOCK)
        self.assertEqual(result.status, SimulationStatus.ERROR)
        self.assertEqual(result.policy.status, EvaluationStatus.ERROR)
        self.assertEqual(result.risk.status, EvaluationStatus.ERROR)
        self.assertIn("policy unavailable", result.policy.error)
        self.assertIn("risk unavailable", result.risk.error)

    def test_warn_is_never_upgraded_to_allow(self):
        transaction = dict(self.safe_transaction, amount_yocto=11 * 10**24)

        result = self.simulate(transaction=transaction)

        self.assertIs(result.decision, SimulationDecision.WARN)
        self.assertIsNot(result.decision, SimulationDecision.ALLOW)

    def test_simulation_is_deterministic_for_identical_inputs(self):
        first = self.simulate()
        second = self.simulate()

        self.assertEqual(first, second)

    def test_invalid_transaction_type_is_rejected_before_evaluation(self):
        engine = StubPolicyEngine(PolicyDecision(True, "matched_allow_rule"))

        result = simulate_transaction("transfer", "alice.near", [], engine)

        self.assertEqual(result.status, SimulationStatus.INVALID_INPUT)
        self.assertEqual(result.decision, SimulationDecision.BLOCK)
        self.assertEqual(result.policy.status, EvaluationStatus.NOT_EVALUATED)
        self.assertEqual(result.risk.status, EvaluationStatus.NOT_EVALUATED)
        self.assertEqual(engine.calls, 0)

    def test_malformed_policy_result_is_an_error_not_an_allow(self):
        engine = StubPolicyEngine(result={"allowed": True})

        result = self.simulate(engine=engine)

        self.assertEqual(result.decision, SimulationDecision.BLOCK)
        self.assertEqual(result.policy.status, EvaluationStatus.ERROR)
        self.assertEqual(result.policy.error_stage, PolicyErrorStage.CONTRACT)
        self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)

    def test_malformed_risk_result_is_an_error_not_an_allow(self):
        with patch(
            "sentinel_guard.transaction_simulator.analyze_transaction",
            return_value=RiskResult("ALLOW", 0, ()),
        ):
            result = self.simulate()

        self.assertEqual(result.decision, SimulationDecision.BLOCK)
        self.assertEqual(result.risk.status, EvaluationStatus.ERROR)
        self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)

    def test_policy_allow_deny_and_risk_allow_warn_block_matrix(self):
        policies = (
            (True, self.allow_engine),
            (
                False,
                PolicyEngine(
                    [PolicyRule("deny-transfer", Effect.DENY, "transfer", "alice.near")]
                ),
            ),
        )
        risks = (
            (RiskDecision.ALLOW, 0, (), SimulationDecision.ALLOW),
            (RiskDecision.WARN, 50, ("warning reason",), SimulationDecision.WARN),
            (RiskDecision.BLOCK, 90, ("blocking reason",), SimulationDecision.BLOCK),
        )

        for policy_allows, engine in policies:
            for risk_decision, score, reasons, allowed_decision in risks:
                with self.subTest(policy_allows=policy_allows, risk=risk_decision):
                    with patch(
                        "sentinel_guard.transaction_simulator.analyze_transaction",
                        return_value=RiskResult(risk_decision, score, reasons),
                    ):
                        result = self.simulate(engine=engine)

                    expected = (
                        SimulationDecision.BLOCK
                        if not policy_allows
                        else allowed_decision
                    )
                    self.assertEqual(result.status, SimulationStatus.COMPLETED)
                    self.assertEqual(result.decision, expected)
                    self.assertEqual(result.policy.allowed, policy_allows)
                    self.assertEqual(result.risk.decision, risk_decision)
                    self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)

    def test_warn_and_block_without_valid_reasons_are_risk_errors(self):
        for decision in (RiskDecision.WARN, RiskDecision.BLOCK):
            for reasons in ((), ("",), (" \t ",)):
                with self.subTest(decision=decision, reasons=reasons):
                    with patch(
                        "sentinel_guard.transaction_simulator.analyze_transaction",
                        return_value=RiskResult(decision, 50, reasons),
                    ):
                        result = self.simulate()

                    self.assertEqual(result.status, SimulationStatus.ERROR)
                    self.assertEqual(result.decision, SimulationDecision.BLOCK)
                    self.assertEqual(result.risk.status, EvaluationStatus.ERROR)
                    self.assertIn("reason", result.risk.error.lower())
                    self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)

    def test_warn_and_block_with_missing_reasons_attribute_are_risk_errors(self):
        for decision in (RiskDecision.WARN, RiskDecision.BLOCK):
            with self.subTest(decision=decision):
                incomplete_result = object.__new__(RiskResult)
                object.__setattr__(incomplete_result, "decision", decision)
                object.__setattr__(incomplete_result, "risk_score", 50)
                with patch(
                    "sentinel_guard.transaction_simulator.analyze_transaction",
                    return_value=incomplete_result,
                ):
                    result = self.simulate()

                self.assertEqual(result.status, SimulationStatus.ERROR)
                self.assertEqual(result.decision, SimulationDecision.BLOCK)
                self.assertEqual(result.risk.status, EvaluationStatus.ERROR)
                self.assertIn("reasons", result.risk.error.lower())
                self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)

    def test_simulation_does_not_mutate_caller_transaction(self):
        scenarios = (
            ("allow", dict(self.safe_transaction), SimulationDecision.ALLOW),
            (
                "warn",
                dict(self.safe_transaction, amount_yocto=11 * 10**24),
                SimulationDecision.WARN,
            ),
            (
                "block",
                dict(self.safe_transaction, known_malicious=True),
                SimulationDecision.BLOCK,
            ),
        )
        for name, transaction, expected_decision in scenarios:
            with self.subTest(scenario=name):
                original_copy = deepcopy(transaction)

                result = self.simulate(transaction=transaction)

                self.assertEqual(result.decision, expected_decision)
                self.assertEqual(transaction, original_copy)


    def test_risk_uses_read_only_snapshot_before_mutating_policy_engine(self):
        transaction = dict(self.safe_transaction)
        expected_snapshot = deepcopy(transaction)
        policy_resources = []

        class MutatingPolicyEngine:
            def evaluate(_self, action, resource=None):
                policy_resources.append(resource)
                transaction["recipient"] = "mallory.testnet"
                transaction["amount_yocto"] = 11 * 10**24
                transaction["known_malicious"] = True
                return PolicyDecision(True, "matched_allow_rule")

        engine = MutatingPolicyEngine()
        with patch(
            "sentinel_guard.transaction_simulator.analyze_transaction",
            wraps=analyze_transaction,
        ) as risk_analyzer:
            result = simulate_transaction("transfer", None, transaction, engine)

        self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
        self.assertTrue(result.policy.allowed)
        self.assertEqual(policy_resources, ["alice.near"])
        self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)
        self.assertEqual(result.risk.decision, RiskDecision.ALLOW)
        self.assertEqual(result.risk.risk_score, 0)
        risk_snapshot = risk_analyzer.call_args.args[0]
        self.assertIsInstance(risk_snapshot, MappingProxyType)
        self.assertEqual(dict(risk_snapshot), expected_snapshot)
        with self.assertRaises(TypeError):
            risk_snapshot["recipient"] = "mallory.testnet"



    def test_action_mismatch_is_denied_while_real_risk_allows(self):
        result = simulate_transaction(
            "withdraw",
            "alice.near",
            self.safe_transaction,
            self.allow_engine,
        )

        self.assertEqual(result.decision, SimulationDecision.BLOCK)
        self.assertEqual(result.status, SimulationStatus.COMPLETED)
        self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
        self.assertFalse(result.policy.allowed)

    def test_amount_at_ten_near_threshold_is_allowed(self):
        transaction = dict(
            self.safe_transaction,
            amount_yocto=10 * 10**24,
        )

        result = self.simulate(transaction=transaction)

        self.assertEqual(result.decision, SimulationDecision.ALLOW)
        self.assertEqual(result.status, SimulationStatus.COMPLETED)
        self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
        self.assertTrue(result.policy.allowed)
        self.assertEqual(result.policy.matched_rule, "allow-transfer")
        self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)
        self.assertEqual(result.risk.decision, RiskDecision.ALLOW)
        self.assertEqual(result.risk.risk_score, 0)
        self.assertEqual(result.risk.reasons, ())
        self.assertEqual(result.reasons, ())

    def test_amount_one_yocto_above_ten_near_warns(self):
        transaction = dict(
            self.safe_transaction,
            amount_yocto=10 * 10**24 + 1,
        )

        result = self.simulate(transaction=transaction)

        self.assertEqual(result.decision, SimulationDecision.WARN)
        self.assertEqual(result.status, SimulationStatus.COMPLETED)
        self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
        self.assertTrue(result.policy.allowed)
        self.assertEqual(result.policy.matched_rule, "allow-transfer")
        self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)
        self.assertEqual(result.risk.decision, RiskDecision.WARN)
        self.assertEqual(result.risk.risk_score, 30)
        self.assertEqual(
            result.risk.reasons,
            ("Transaction amount exceeds threshold",),
        )
        self.assertEqual(
            result.reasons,
            ("Risk: Transaction amount exceeds threshold",),
        )

    def test_amount_one_yocto_below_ten_near_is_allowed(self):
        transaction = dict(
            self.safe_transaction,
            amount_yocto=10 * 10**24 - 1,
        )

        result = self.simulate(transaction=transaction)

        self.assertEqual(result.decision, SimulationDecision.ALLOW)
        self.assertEqual(result.status, SimulationStatus.COMPLETED)
        self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
        self.assertTrue(result.policy.allowed)
        self.assertEqual(result.policy.matched_rule, "allow-transfer")
        self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)
        self.assertEqual(result.risk.decision, RiskDecision.ALLOW)
        self.assertEqual(result.risk.risk_score, 0)
        self.assertEqual(result.risk.reasons, ())
        self.assertEqual(result.reasons, ())

    def test_boolean_account_age_is_blocked_by_real_risk_analyzer(self):
        transaction = dict(self.safe_transaction, account_age_days=True)

        result = self.simulate(transaction=transaction)

        self.assertEqual(result.decision, SimulationDecision.BLOCK)
        self.assertEqual(result.status, SimulationStatus.COMPLETED)
        self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
        self.assertTrue(result.policy.allowed)
        self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)
        self.assertEqual(result.risk.decision, RiskDecision.BLOCK)
        self.assertEqual(result.risk.risk_score, 100)
        self.assertEqual(result.risk.reasons, ("Invalid account age",))
        self.assertEqual(result.reasons, ("Risk: Invalid account age",))

    def test_boolean_risk_score_is_rejected_as_error(self):
        with patch(
            "sentinel_guard.transaction_simulator.analyze_transaction",
            return_value=RiskResult(RiskDecision.ALLOW, True, ()),
        ):
            result = self.simulate()

        self.assertEqual(result.decision, SimulationDecision.BLOCK)
        self.assertEqual(result.status, SimulationStatus.ERROR)
        self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
        self.assertTrue(result.policy.allowed)
        self.assertEqual(result.risk.status, EvaluationStatus.ERROR)
        self.assertIn("risk_score", result.risk.error)
        self.assertIn("integer from 0 to 100", result.risk.error)

    def test_contract_code_change_and_contract_signal_score_55(self):
        transaction = dict(
            self.safe_transaction,
            recipient_is_contract=True,
            recipient_code_changed=True,
        )

        result = self.simulate(transaction=transaction)

        self.assertEqual(result.decision, SimulationDecision.BLOCK)
        self.assertEqual(result.status, SimulationStatus.COMPLETED)
        self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
        self.assertTrue(result.policy.allowed)
        self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)
        self.assertEqual(result.risk.decision, RiskDecision.BLOCK)
        self.assertEqual(result.risk.risk_score, 55)
        self.assertEqual(
            result.risk.reasons,
            (
                "Recipient contract code changed",
                "Recipient is a smart contract",
            ),
        )
        self.assertEqual(
            result.reasons,
            (
                "Risk: Recipient contract code changed",
                "Risk: Recipient is a smart contract",
            ),
        )

    def test_default_deny_blocks_and_preserves_known_malicious_reason(self):
        transaction = dict(self.safe_transaction, known_malicious=True)

        result = self.simulate(engine=PolicyEngine(), transaction=transaction)

        self.assertEqual(result.decision, SimulationDecision.BLOCK)
        self.assertEqual(result.status, SimulationStatus.COMPLETED)
        self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
        self.assertFalse(result.policy.allowed)
        self.assertEqual(result.policy.reason, "default_deny")
        self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)
        self.assertEqual(result.risk.decision, RiskDecision.BLOCK)
        self.assertEqual(result.risk.risk_score, 100)
        self.assertEqual(
            result.risk.reasons,
            ("Recipient is marked as known malicious",),
        )
        self.assertEqual(
            result.reasons,
            (
                "Policy denied: default_deny",
                "Risk: Recipient is marked as known malicious",
            ),
        )

    def test_default_deny_blocks_and_preserves_real_risk_warning(self):
        transaction = dict(self.safe_transaction, amount_yocto=11 * 10**24)

        result = self.simulate(engine=PolicyEngine(), transaction=transaction)

        self.assertEqual(result.decision, SimulationDecision.BLOCK)
        self.assertEqual(result.status, SimulationStatus.COMPLETED)
        self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
        self.assertFalse(result.policy.allowed)
        self.assertEqual(result.policy.reason, "default_deny")
        self.assertIsNone(result.policy.matched_rule)
        self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)
        self.assertEqual(result.risk.decision, RiskDecision.WARN)
        self.assertEqual(result.risk.risk_score, 30)
        self.assertEqual(
            result.risk.reasons,
            ("Transaction amount exceeds threshold",),
        )
        self.assertEqual(
            result.reasons,
            (
                "Policy denied: default_deny",
                "Risk: Transaction amount exceeds threshold",
            ),
        )

    def test_general_allow_rule_accepts_specific_resource(self):
        engine = PolicyEngine([
            PolicyRule(
                "allow-all-transfers",
                Effect.ALLOW,
                "transfer",
                resource=None,
            ),
        ])

        result = simulate_transaction(
            "transfer", "alice.near", self.safe_transaction, engine
        )

        self.assertEqual(result.decision, SimulationDecision.ALLOW)
        self.assertEqual(result.status, SimulationStatus.COMPLETED)
        self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
        self.assertTrue(result.policy.allowed)
        self.assertEqual(result.policy.matched_rule, "allow-all-transfers")
        self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)
        self.assertEqual(result.risk.decision, RiskDecision.ALLOW)
        self.assertEqual(result.risk.risk_score, 0)
        self.assertEqual(result.reasons, ())

    def test_general_deny_overrides_specific_allow_regardless_of_rule_order(self):
        deny_rule = PolicyRule(
            "deny-all-transfers",
            Effect.DENY,
            "transfer",
            resource=None,
        )
        allow_rule = PolicyRule(
            "allow-alice-transfer",
            Effect.ALLOW,
            "transfer",
            "alice.near",
        )
        results = []

        for order, rules in (
            ("deny_before_allow", (deny_rule, allow_rule)),
            ("allow_before_deny", (allow_rule, deny_rule)),
        ):
            with self.subTest(order=order):
                result = self.simulate(engine=PolicyEngine(rules))

                self.assertEqual(result.decision, SimulationDecision.BLOCK)
                self.assertEqual(result.status, SimulationStatus.COMPLETED)
                self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
                self.assertFalse(result.policy.allowed)
                self.assertEqual(result.policy.reason, "explicit_deny")
                self.assertEqual(result.policy.matched_rule, "deny-all-transfers")
                self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)
                self.assertEqual(result.risk.decision, RiskDecision.ALLOW)
                self.assertEqual(result.risk.risk_score, 0)
                results.append(result)

        self.assertEqual(results[0], results[1])

    def test_general_deny_rule_rejects_specific_resource(self):
        engine = PolicyEngine([
            PolicyRule(
                "deny-all-transfers",
                Effect.DENY,
                "transfer",
                resource=None,
            ),
        ])

        result = simulate_transaction(
            "transfer", "alice.near", self.safe_transaction, engine
        )

        self.assertEqual(result.decision, SimulationDecision.BLOCK)
        self.assertEqual(result.status, SimulationStatus.COMPLETED)
        self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
        self.assertFalse(result.policy.allowed)
        self.assertEqual(result.policy.reason, "explicit_deny")
        self.assertEqual(result.policy.matched_rule, "deny-all-transfers")
        self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)
        self.assertEqual(result.risk.decision, RiskDecision.ALLOW)
        self.assertEqual(result.risk.risk_score, 0)
        self.assertEqual(result.reasons, ("Policy denied: explicit_deny",))

    def test_missing_recipient_is_blocked_by_real_risk_analyzer(self):
        transaction = dict(self.safe_transaction)
        del transaction["recipient"]

        result = simulate_transaction(
            "transfer", None, transaction, self.allow_engine
        )

        self.assertEqual(result.decision, SimulationDecision.BLOCK)
        self.assertEqual(result.status, SimulationStatus.COMPLETED)
        self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
        self.assertFalse(result.policy.allowed)
        self.assertEqual(result.policy.reason, "default_deny")
        self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)
        self.assertEqual(result.risk.decision, RiskDecision.BLOCK)
        self.assertEqual(result.risk.risk_score, 100)
        self.assertEqual(
            result.risk.reasons,
            ("Missing or invalid recipient",),
        )
        self.assertEqual(
            result.reasons,
            (
                "Policy denied: default_deny",
                "Risk: Missing or invalid recipient",
            ),
        )

    def test_explicit_resource_requires_valid_recipient_before_either_evaluator(self):
        transactions = []
        missing_recipient = dict(self.safe_transaction)
        del missing_recipient["recipient"]
        transactions.append(("missing", missing_recipient))
        for label, recipient in (("null", None), ("non-string", 123), ("empty", ""), ("whitespace", " \t ")):
            transactions.append((label, dict(self.safe_transaction, recipient=recipient)))

        for label, transaction in transactions:
            with self.subTest(recipient=label):
                engine = StubPolicyEngine(PolicyDecision(True, "matched_allow_rule"))
                with patch("sentinel_guard.transaction_simulator.analyze_transaction") as analyze:
                    result = simulate_transaction(
                        "transfer", "alice.near", transaction, engine
                    )

                self.assertEqual(result.decision, SimulationDecision.BLOCK)
                self.assertEqual(result.status, SimulationStatus.INVALID_INPUT)
                self.assertEqual(
                    result.policy.status, EvaluationStatus.NOT_EVALUATED
                )
                self.assertEqual(
                    result.risk.status, EvaluationStatus.NOT_EVALUATED
                )
                self.assertEqual(
                    result.reasons,
                    ("explicit resource requires a valid transaction recipient",),
                )
                self.assertEqual(engine.calls, 0)
                analyze.assert_not_called()

    def test_multiple_wrapper_errors_are_reported_in_stable_order(self):
        engine = StubPolicyEngine(PolicyDecision(True, "matched_allow_rule"))

        result = simulate_transaction(" \t ", " \t ", None, engine)

        self.assertEqual(result.decision, SimulationDecision.BLOCK)
        self.assertEqual(result.status, SimulationStatus.INVALID_INPUT)
        self.assertEqual(result.policy.status, EvaluationStatus.NOT_EVALUATED)
        self.assertEqual(result.risk.status, EvaluationStatus.NOT_EVALUATED)
        self.assertEqual(
            result.reasons,
            (
                "action must be a non-empty string",
                "resource must be None or a non-empty string",
                "transaction must be a dictionary",
            ),
        )
        self.assertEqual(engine.calls, 0)

    def test_non_dictionary_transaction_is_rejected_before_evaluation(self):
        for transaction in (None, []):
            with self.subTest(transaction=transaction):
                result = simulate_transaction(
                    "transfer",
                    "alice.near",
                    transaction,
                    self.allow_engine,
                )

                self.assertEqual(result.decision, SimulationDecision.BLOCK)
                self.assertEqual(result.status, SimulationStatus.INVALID_INPUT)
                self.assertEqual(
                    result.policy.status, EvaluationStatus.NOT_EVALUATED
                )
                self.assertEqual(
                    result.risk.status, EvaluationStatus.NOT_EVALUATED
                )
                self.assertEqual(
                    result.reasons,
                    ("transaction must be a dictionary",),
                )

    def test_non_string_action_is_rejected_before_evaluation(self):
        for action in (None, 123):
            with self.subTest(action=action):
                result = simulate_transaction(
                    action, "alice.near", self.safe_transaction, self.allow_engine
                )

                self.assertEqual(result.decision, SimulationDecision.BLOCK)
                self.assertEqual(result.status, SimulationStatus.INVALID_INPUT)
                self.assertEqual(
                    result.policy.status, EvaluationStatus.NOT_EVALUATED
                )
                self.assertEqual(
                    result.risk.status, EvaluationStatus.NOT_EVALUATED
                )
                self.assertEqual(
                    result.reasons,
                    ("action must be a non-empty string",),
                )

    def test_non_string_resource_is_rejected_before_evaluation(self):
        for resource in (123, True):
            with self.subTest(resource=resource):
                result = simulate_transaction(
                    "transfer",
                    resource,
                    self.safe_transaction,
                    self.allow_engine,
                )

                self.assertEqual(result.decision, SimulationDecision.BLOCK)
                self.assertEqual(result.status, SimulationStatus.INVALID_INPUT)
                self.assertEqual(
                    result.policy.status, EvaluationStatus.NOT_EVALUATED
                )
                self.assertEqual(
                    result.risk.status, EvaluationStatus.NOT_EVALUATED
                )
                self.assertEqual(
                    result.reasons,
                    ("resource must be None or a non-empty string",),
                )

    def test_non_string_transaction_key_is_rejected_before_evaluation(self):
        transaction = dict(self.safe_transaction)
        transaction[1] = "invalid"

        result = self.simulate(transaction=transaction)

        self.assertEqual(result.decision, SimulationDecision.BLOCK)
        self.assertEqual(result.status, SimulationStatus.INVALID_INPUT)
        self.assertEqual(result.policy.status, EvaluationStatus.NOT_EVALUATED)
        self.assertEqual(result.risk.status, EvaluationStatus.NOT_EVALUATED)
        self.assertEqual(result.reasons, ("transaction keys must be strings",))

    def test_nonmatching_deny_action_does_not_block_general_allow(self):
        engine = PolicyEngine(
            [
                PolicyRule(
                    "allow-all-transfers",
                    Effect.ALLOW,
                    "transfer",
                    resource=None,
                ),
                PolicyRule(
                    "deny-all-withdrawals",
                    Effect.DENY,
                    "withdraw",
                    resource=None,
                ),
            ]
        )

        result = simulate_transaction(
            "transfer", "alice.near", self.safe_transaction, engine
        )

        self.assertEqual(result.decision, SimulationDecision.ALLOW)
        self.assertEqual(result.status, SimulationStatus.COMPLETED)
        self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
        self.assertTrue(result.policy.allowed)
        self.assertEqual(result.policy.reason, "matched_allow_rule")
        self.assertEqual(result.policy.matched_rule, "allow-all-transfers")
        self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)
        self.assertEqual(result.risk.decision, RiskDecision.ALLOW)
        self.assertEqual(result.risk.risk_score, 0)
        self.assertEqual(result.risk.reasons, ())
        self.assertEqual(result.reasons, ())

    def test_nonmatching_deny_resource_does_not_block_matching_allow(self):
        engine = PolicyEngine(
            [
                PolicyRule(
                    "deny-alice-transfer",
                    Effect.DENY,
                    "transfer",
                    "alice.near",
                ),
                PolicyRule(
                    "allow-bob-transfer",
                    Effect.ALLOW,
                    "transfer",
                    "bob.near",
                ),
            ]
        )
        transaction = dict(self.safe_transaction, recipient="bob.near")

        result = simulate_transaction(
            "transfer", "bob.near", transaction, engine
        )

        self.assertEqual(result.decision, SimulationDecision.ALLOW)
        self.assertEqual(result.status, SimulationStatus.COMPLETED)
        self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
        self.assertTrue(result.policy.allowed)
        self.assertEqual(result.policy.reason, "matched_allow_rule")
        self.assertEqual(result.policy.matched_rule, "allow-bob-transfer")
        self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)
        self.assertEqual(result.risk.decision, RiskDecision.ALLOW)
        self.assertEqual(result.risk.risk_score, 0)
        self.assertEqual(result.risk.reasons, ())
        self.assertEqual(result.reasons, ())

    def test_out_of_range_risk_scores_are_rejected_as_errors(self):
        for risk_score in (-1, 101):
            with self.subTest(risk_score=risk_score):
                with patch(
                    "sentinel_guard.transaction_simulator.analyze_transaction",
                    return_value=RiskResult(RiskDecision.ALLOW, risk_score, ()),
                ):
                    result = self.simulate()

                self.assertEqual(result.decision, SimulationDecision.BLOCK)
                self.assertEqual(result.status, SimulationStatus.ERROR)
                self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
                self.assertTrue(result.policy.allowed)
                self.assertEqual(result.risk.status, EvaluationStatus.ERROR)
                self.assertIn("risk_score", result.risk.error)
                self.assertIn("integer from 0 to 100", result.risk.error)

    def test_mismatched_resource_is_rejected_before_evaluation(self):
        engine = StubPolicyEngine(PolicyDecision(True, "matched_allow_rule"))
        transaction = dict(self.safe_transaction, recipient="bob.near")

        result = simulate_transaction(
            "transfer", "alice.near", transaction, engine
        )

        self.assertEqual(result.decision, SimulationDecision.BLOCK)
        self.assertEqual(result.status, SimulationStatus.INVALID_INPUT)
        self.assertEqual(result.policy.status, EvaluationStatus.NOT_EVALUATED)
        self.assertEqual(result.risk.status, EvaluationStatus.NOT_EVALUATED)
        self.assertEqual(
            result.reasons,
            ("resource must match transaction recipient",),
        )
        self.assertEqual(engine.calls, 0)

    def test_resource_none_uses_transaction_recipient_for_specific_allow(self):
        result = simulate_transaction(
            "transfer", None, self.safe_transaction, self.allow_engine
        )

        self.assertEqual(result.decision, SimulationDecision.ALLOW)
        self.assertEqual(result.status, SimulationStatus.COMPLETED)
        self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
        self.assertTrue(result.policy.allowed)
        self.assertEqual(result.policy.reason, "matched_allow_rule")
        self.assertEqual(result.policy.matched_rule, "allow-transfer")
        self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)
        self.assertEqual(result.risk.decision, RiskDecision.ALLOW)
        self.assertEqual(result.risk.risk_score, 0)
        self.assertEqual(result.reasons, ())

    def test_resource_none_is_allowed_by_general_policy(self):
        engine = PolicyEngine([
            PolicyRule(
                "allow-all-transfers",
                Effect.ALLOW,
                "transfer",
                resource=None,
            ),
        ])

        result = simulate_transaction(
            "transfer", None, self.safe_transaction, engine
        )

        self.assertEqual(result.decision, SimulationDecision.ALLOW)
        self.assertEqual(result.status, SimulationStatus.COMPLETED)
        self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
        self.assertTrue(result.policy.allowed)
        self.assertEqual(result.policy.matched_rule, "allow-all-transfers")
        self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)
        self.assertEqual(result.risk.decision, RiskDecision.ALLOW)
        self.assertEqual(result.risk.risk_score, 0)
        self.assertEqual(result.reasons, ())

    def test_resource_none_applies_specific_deny_over_general_allow(self):
        engine = PolicyEngine(
            [
                PolicyRule(
                    "allow-all-transfers",
                    Effect.ALLOW,
                    "transfer",
                    resource=None,
                ),
                PolicyRule(
                    "deny-alice-transfer",
                    Effect.DENY,
                    "transfer",
                    "alice.near",
                ),
            ]
        )

        result = simulate_transaction(
            "transfer", None, self.safe_transaction, engine
        )

        self.assertEqual(result.decision, SimulationDecision.BLOCK)
        self.assertEqual(result.status, SimulationStatus.COMPLETED)
        self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
        self.assertFalse(result.policy.allowed)
        self.assertEqual(result.policy.reason, "explicit_deny")
        self.assertEqual(result.policy.matched_rule, "deny-alice-transfer")
        self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)
        self.assertEqual(result.risk.decision, RiskDecision.ALLOW)
        self.assertEqual(result.risk.risk_score, 0)
        self.assertEqual(result.reasons, ("Policy denied: explicit_deny",))

    def test_specific_deny_overrides_general_allow_regardless_of_rule_order(self):
        allow_rule = PolicyRule(
            "allow-all-transfers",
            Effect.ALLOW,
            "transfer",
            resource=None,
        )
        deny_rule = PolicyRule(
            "deny-alice-transfer",
            Effect.DENY,
            "transfer",
            "alice.near",
        )
        results = []

        for order, rules in (
            ("allow_before_deny", (allow_rule, deny_rule)),
            ("deny_before_allow", (deny_rule, allow_rule)),
        ):
            with self.subTest(order=order):
                result = simulate_transaction(
                    "transfer",
                    "alice.near",
                    self.safe_transaction,
                    PolicyEngine(rules),
                )

                self.assertEqual(result.decision, SimulationDecision.BLOCK)
                self.assertEqual(result.status, SimulationStatus.COMPLETED)
                self.assertEqual(
                    result.policy.status, EvaluationStatus.EVALUATED
                )
                self.assertFalse(result.policy.allowed)
                self.assertEqual(result.policy.reason, "explicit_deny")
                self.assertEqual(
                    result.policy.matched_rule, "deny-alice-transfer"
                )
                self.assertEqual(
                    result.risk.status, EvaluationStatus.EVALUATED
                )
                self.assertEqual(result.risk.decision, RiskDecision.ALLOW)
                self.assertEqual(result.risk.risk_score, 0)
                self.assertEqual(
                    result.reasons, ("Policy denied: explicit_deny",)
                )
                results.append(result)

        self.assertEqual(results[0], results[1])

    def test_unmatched_resource_is_denied_while_real_risk_allows(self):
        transaction = dict(self.safe_transaction, recipient="bob.near")
        result = simulate_transaction(
            "transfer",
            "bob.near",
            transaction,
            self.allow_engine,
        )

        self.assertEqual(result.decision, SimulationDecision.BLOCK)
        self.assertEqual(result.status, SimulationStatus.COMPLETED)
        self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
        self.assertFalse(result.policy.allowed)
        self.assertEqual(result.policy.reason, "default_deny")
        self.assertIsNone(result.policy.matched_rule)
        self.assertEqual(result.risk.status, EvaluationStatus.EVALUATED)
        self.assertEqual(result.risk.decision, RiskDecision.ALLOW)
        self.assertEqual(result.risk.risk_score, 0)
        self.assertEqual(result.reasons, ("Policy denied: default_deny",))

    def test_whitespace_resource_is_rejected_before_evaluation(self):
        result = simulate_transaction(
            "transfer", " \t ", self.safe_transaction, self.allow_engine
        )

        self.assertEqual(result.decision, SimulationDecision.BLOCK)
        self.assertEqual(result.status, SimulationStatus.INVALID_INPUT)
        self.assertEqual(result.policy.status, EvaluationStatus.NOT_EVALUATED)
        self.assertEqual(result.risk.status, EvaluationStatus.NOT_EVALUATED)
        self.assertEqual(
            result.reasons,
            ("resource must be None or a non-empty string",),
        )

    def test_non_string_risk_reason_is_rejected_as_error(self):
        with patch(
            "sentinel_guard.transaction_simulator.analyze_transaction",
            return_value=RiskResult(
                RiskDecision.WARN, 30, ("Transaction warning", 123)
            ),
        ):
            result = self.simulate()

        self.assertEqual(result.decision, SimulationDecision.BLOCK)
        self.assertEqual(result.status, SimulationStatus.ERROR)
        self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
        self.assertTrue(result.policy.allowed)
        self.assertEqual(result.risk.status, EvaluationStatus.ERROR)
        self.assertIn("risk reasons must be a tuple of strings", result.risk.error)

    def test_list_risk_reasons_are_rejected_as_error(self):
        with patch(
            "sentinel_guard.transaction_simulator.analyze_transaction",
            return_value=RiskResult(
                RiskDecision.WARN, 30, ["Transaction warning"]
            ),
        ):
            result = self.simulate()

        self.assertEqual(result.decision, SimulationDecision.BLOCK)
        self.assertEqual(result.status, SimulationStatus.ERROR)
        self.assertEqual(result.policy.status, EvaluationStatus.EVALUATED)
        self.assertTrue(result.policy.allowed)
        self.assertEqual(result.risk.status, EvaluationStatus.ERROR)
        self.assertIn("risk reasons must be a tuple of strings", result.risk.error)

if __name__ == "__main__":
    unittest.main()
