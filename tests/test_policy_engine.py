import unittest
from enum import Enum

from sentinel_guard.policy_engine import Effect, PolicyEngine, PolicyRule


class PolicyEngineTests(unittest.TestCase):
    def test_allows_matching_action_and_resource(self) -> None:
        engine = PolicyEngine(
            [PolicyRule("approved-transfer", Effect.ALLOW, "transfer", "alice.near")]
        )

        decision = engine.evaluate("transfer", "alice.near")

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, "matched_allow_rule")
        self.assertEqual(decision.matched_rule, "approved-transfer")

    def test_denies_when_no_rule_matches(self) -> None:
        engine = PolicyEngine(
            [PolicyRule("approved-transfer", Effect.ALLOW, "transfer", "alice.near")]
        )

        decision = engine.evaluate("transfer", "mallory.near")

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "default_deny")
        self.assertIsNone(decision.matched_rule)

    def test_explicit_deny_overrides_allow_independent_of_order(self) -> None:
        engine = PolicyEngine(
            [
                PolicyRule("allow-transfers", Effect.ALLOW, "transfer"),
                PolicyRule("block-risky-target", Effect.DENY, "transfer", "risky.near"),
            ]
        )

        decision = engine.evaluate("transfer", "risky.near")

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "explicit_deny")
        self.assertEqual(decision.matched_rule, "block-risky-target")

    def test_action_mismatch_is_denied_by_default(self) -> None:
        engine = PolicyEngine(
            [PolicyRule("approved-transfer", Effect.ALLOW, "transfer", "alice.near")]
        )

        decision = engine.evaluate("stake", "alice.near")

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "default_deny")

    def test_empty_action_is_rejected(self) -> None:
        engine = PolicyEngine()

        with self.assertRaisesRegex(ValueError, "action must not be empty"):
            engine.evaluate(" ")

    def test_non_string_rule_name_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "rule name must be a string"):
            PolicyRule(7, Effect.ALLOW, "transfer")

    def test_non_string_rule_action_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "rule action must be a string"):
            PolicyRule("approved-transfer", Effect.ALLOW, 7)

    def test_non_string_rule_resource_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "rule resource must be a string or None"):
            PolicyRule("approved-transfer", Effect.ALLOW, "transfer", 7)

    def test_non_effect_rule_effect_is_rejected(self) -> None:
        for effect in ("ALLOW", "DENY"):
            with self.subTest(effect=effect):
                with self.assertRaisesRegex(
                    ValueError,
                    r"effect must be an Effect\.ALLOW or Effect\.DENY value",
                ):
                    PolicyRule("approved-transfer", effect, "transfer")

    def test_foreign_effect_enum_is_rejected(self) -> None:
        class OtherEffect(str, Enum):
            ALLOW = "allow"
            DENY = "deny"

        for effect in (OtherEffect.ALLOW, OtherEffect.DENY):
            with self.subTest(effect=effect):
                with self.assertRaisesRegex(
                    ValueError,
                    r"effect must be an Effect\.ALLOW or Effect\.DENY value",
                ):
                    PolicyRule("approved-transfer", effect, "transfer")


if __name__ == "__main__":
    unittest.main()
