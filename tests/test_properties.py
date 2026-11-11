"""Property-based, whitespace contract, and reporting tests for Sentinel Guard."""

import itertools
import json
import unittest
from copy import deepcopy

from sentinel_guard.policy_engine import Effect, PolicyEngine, PolicyRule
from sentinel_guard.reporting import (
    simulation_result_to_dict,
    simulation_result_to_json,
)
from sentinel_guard.transaction_simulator import (
    SimulationDecision,
    SimulationStatus,
    simulate_transaction,
)

YOCTO = 10**24


class SecurityPropertyTests(unittest.TestCase):
    def test_whitespace_contract_preserves_padded_values_and_matches_literally(
        self,
    ) -> None:
        rule = PolicyRule(
            name=" padded-rule ",
            effect=Effect.ALLOW,
            action=" transfer ",
            resource=" alice.near ",
        )
        self.assertEqual(rule.name, " padded-rule ")
        self.assertEqual(rule.action, " transfer ")
        self.assertEqual(rule.resource, " alice.near ")

        engine = PolicyEngine([rule])
        unpadded = engine.evaluate("transfer", "alice.near")
        self.assertFalse(unpadded.allowed)
        self.assertEqual(unpadded.reason, "default_deny")

        exact = engine.evaluate(" transfer ", " alice.near ")
        self.assertTrue(exact.allowed)
        self.assertEqual(exact.reason, "matched_allow_rule")
        self.assertEqual(exact.matched_rule, " padded-rule ")

    def test_property_a_decision_determinism_and_input_immutability(self) -> None:
        rules = [
            PolicyRule("allow-transfers", Effect.ALLOW, "transfer"),
            PolicyRule("deny-drainer", Effect.DENY, "transfer", "drainer.near"),
        ]
        engine = PolicyEngine(rules)
        tx = {
            "recipient": "alice.near",
            "amount_yocto": 12 * YOCTO,
            "recipient_is_contract": True,
            "recipient_code_changed": False,
            "previous_interactions": 2,
            "account_age_days": 90,
            "known_malicious": False,
        }
        snapshot = deepcopy(tx)
        baseline = simulate_transaction(engine, "transfer", "alice.near", tx)
        baseline_json = simulation_result_to_json(baseline)

        for _ in range(20):
            current = simulate_transaction(engine, "transfer", "alice.near", tx)
            self.assertEqual(current, baseline)
            self.assertEqual(simulation_result_to_json(current), baseline_json)
            self.assertEqual(tx, snapshot)

    def test_property_b_deny_precedence_across_all_rule_permutations(self) -> None:
        rule_set = (
            PolicyRule("general-allow", Effect.ALLOW, "transfer"),
            PolicyRule("specific-allow", Effect.ALLOW, "transfer", "vault.near"),
            PolicyRule("specific-deny", Effect.DENY, "transfer", "vault.near"),
        )
        tx = {
            "recipient": "vault.near",
            "amount_yocto": 1 * YOCTO,
            "recipient_is_contract": False,
            "recipient_code_changed": False,
            "previous_interactions": 5,
            "account_age_days": 365,
            "known_malicious": False,
        }
        for permutation in itertools.permutations(rule_set):
            engine = PolicyEngine(permutation)
            sim = simulate_transaction(engine, "transfer", "vault.near", tx)
            self.assertIs(sim.status, SimulationStatus.COMPLETED)
            self.assertIs(sim.decision, SimulationDecision.BLOCK)
            self.assertFalse(sim.policy.allowed)
            self.assertEqual(sim.policy.reason, "explicit_deny")

    def test_property_c_engine_independence(self) -> None:
        allow_engine = PolicyEngine(
            [PolicyRule("allow-transfer", Effect.ALLOW, "transfer", "target.near")]
        )
        deny_engine = PolicyEngine(
            [PolicyRule("deny-transfer", Effect.DENY, "transfer", "target.near")]
        )
        safe_tx = {
            "recipient": "target.near",
            "amount_yocto": 1 * YOCTO,
            "recipient_is_contract": False,
            "recipient_code_changed": False,
            "previous_interactions": 5,
            "account_age_days": 365,
            "known_malicious": False,
        }
        risky_tx = {
            **safe_tx,
            "amount_yocto": 50 * YOCTO,
            "known_malicious": True,
        }
        self.assertEqual(
            simulate_transaction(allow_engine, "transfer", "target.near", safe_tx).policy,
            simulate_transaction(allow_engine, "transfer", "target.near", risky_tx).policy,
        )
        self.assertEqual(
            simulate_transaction(allow_engine, "transfer", "target.near", risky_tx).risk,
            simulate_transaction(deny_engine, "transfer", "target.near", risky_tx).risk,
        )

    def test_structured_reporting_output(self) -> None:
        engine = PolicyEngine(
            [PolicyRule("deny-alice", Effect.DENY, "transfer", "alice.near")]
        )
        tx = {
            "recipient": "alice.near",
            "amount_yocto": 1 * YOCTO,
            "previous_interactions": 5,
            "account_age_days": 365,
        }
        result = simulate_transaction(engine, "transfer", "alice.near", tx)
        report = simulation_result_to_dict(result)
        self.assertEqual(report["decision"], "BLOCK")
        self.assertEqual(report["status"], "COMPLETED")
        self.assertEqual(json.loads(simulation_result_to_json(result)), report)


if __name__ == "__main__":
    unittest.main()
