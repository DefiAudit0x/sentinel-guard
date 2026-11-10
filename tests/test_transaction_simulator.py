import unittest
from unittest.mock import patch

from sentinel_guard.policy_engine import (
    Effect,
    PolicyDecision,
    PolicyEngine,
    PolicyRule,
)
from sentinel_guard.risk_analyzer import RiskDecision, RiskResult
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
        self.assertEqual(
            result.risk.reasons,
            ("Recipient is marked as known malicious",),
        )
        self.assertEqual(
            result.reasons,
            ("Risk: Recipient is marked as known malicious",),
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


if __name__ == "__main__":
    unittest.main()
