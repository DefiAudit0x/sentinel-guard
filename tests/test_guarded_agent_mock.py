import unittest
from unittest.mock import Mock

from examples.guarded_agent_mock import evaluate_then_mock_sign
from sentinel_guard.policy_engine import Effect, PolicyDecision, PolicyEngine, PolicyRule
from sentinel_guard.transaction_simulator import SimulationDecision, SimulationStatus


class GuardedAgentMockTests(unittest.TestCase):
    def setUp(self):
        self.allow_engine = PolicyEngine(
            [PolicyRule("allow-transfers", Effect.ALLOW, "transfer")]
        )
        self.transaction = {
            "recipient": "alice.near",
            "amount_yocto": 1 * 10**24,
            "previous_interactions": 3,
            "account_age_days": 365,
        }

    def run_guard(self, *, action="transfer", transaction=None, engine=None, signer=None):
        return evaluate_then_mock_sign(
            action=action,
            resource="alice.near",
            transaction=self.transaction if transaction is None else transaction,
            policy_engine=self.allow_engine if engine is None else engine,
            mock_signer=Mock(return_value="mock-only") if signer is None else signer,
        )

    def test_completed_allow_invokes_placeholder_signer_once(self):
        signer = Mock(return_value="mock-only:alice.near")

        result, mock_signature = self.run_guard(signer=signer)

        self.assertIs(result.status, SimulationStatus.COMPLETED)
        self.assertIs(result.decision, SimulationDecision.ALLOW)
        signer.assert_called_once_with(self.transaction)
        self.assertEqual(mock_signature, "mock-only:alice.near")

    def test_signer_receives_immutable_pre_evaluation_snapshot_after_source_mutation(self):
        source_transaction = dict(
            self.transaction,
            labels=["original"],
            metadata={"labels": ["original"]},
        )

        class MutatingPolicy:
            def evaluate(inner_self, action, resource):
                source_transaction["recipient"] = "mallory.near"
                source_transaction["amount_yocto"] = 11 * 10**24
                source_transaction["metadata"]["labels"][0] = "changed"
                return PolicyDecision(allowed=True, reason="test_allow")

        signer = Mock(return_value="mock-only:alice.near")
        result, mock_signature = evaluate_then_mock_sign(
            action="transfer",
            resource="alice.near",
            transaction=source_transaction,
            policy_engine=MutatingPolicy(),
            mock_signer=signer,
        )

        self.assertIs(result.status, SimulationStatus.COMPLETED)
        self.assertIs(result.decision, SimulationDecision.ALLOW)
        self.assertEqual(source_transaction["recipient"], "mallory.near")
        self.assertEqual(source_transaction["amount_yocto"], 11 * 10**24)
        signer.assert_called_once()
        callback_intent = signer.call_args.args[0]
        self.assertEqual(callback_intent["recipient"], "alice.near")
        self.assertEqual(callback_intent["amount_yocto"], 1 * 10**24)
        self.assertEqual(callback_intent["labels"], ("original",))
        self.assertEqual(callback_intent["metadata"]["labels"], ("original",))
        with self.assertRaises(TypeError):
            callback_intent["recipient"] = "mallory.near"
        with self.assertRaises(TypeError):
            callback_intent["metadata"]["labels"] = ("changed",)
        with self.assertRaises(TypeError):
            callback_intent["metadata"]["labels"][0] = "changed"
        self.assertEqual(mock_signature, "mock-only:alice.near")

    def test_non_allow_and_invalid_results_never_invoke_signer(self):
        denied_engine = PolicyEngine(
            [PolicyRule("deny-alice", Effect.DENY, "transfer", "alice.near")]
        )
        scenarios = (
            (
                "policy block",
                "transfer",
                self.transaction,
                denied_engine,
                SimulationDecision.BLOCK,
                SimulationStatus.COMPLETED,
            ),
            (
                "risk block",
                "transfer",
                dict(self.transaction, known_malicious=True),
                self.allow_engine,
                SimulationDecision.BLOCK,
                SimulationStatus.COMPLETED,
            ),
            (
                "warning",
                "transfer",
                dict(self.transaction, amount_yocto=11 * 10**24),
                self.allow_engine,
                SimulationDecision.WARN,
                SimulationStatus.COMPLETED,
            ),
            (
                "invalid wrapper",
                "",
                self.transaction,
                self.allow_engine,
                SimulationDecision.BLOCK,
                SimulationStatus.INVALID_INPUT,
            ),
        )

        for name, action, transaction, engine, decision, status in scenarios:
            with self.subTest(scenario=name):
                signer = Mock(return_value="must-not-be-returned")
                result, mock_signature = self.run_guard(
                    action=action,
                    transaction=transaction,
                    engine=engine,
                    signer=signer,
                )

                self.assertIs(result.decision, decision)
                self.assertIs(result.status, status)
                signer.assert_not_called()
                self.assertIsNone(mock_signature)


if __name__ == "__main__":
    unittest.main()
