"""A small, deterministic policy decision engine for Sentinel Guard."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable


class Effect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True, slots=True)
class PolicyRule:
    """A rule matching one action and, optionally, one exact resource."""

    name: str
    effect: Effect
    action: str
    resource: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.name, str):
            raise ValueError("rule name must be a string")
        if not self.name.strip():
            raise ValueError("rule name must not be empty")
        if not isinstance(self.action, str):
            raise ValueError("rule action must be a string")
        if not self.action.strip():
            raise ValueError("rule action must not be empty")
        if self.resource is not None and not isinstance(self.resource, str):
            raise ValueError("rule resource must be a string or None")
        if self.resource is not None and not self.resource.strip():
            raise ValueError("rule resource must not be empty when provided")
        if not isinstance(self.effect, Effect):
            raise ValueError("effect must be an Effect.ALLOW or Effect.DENY value")


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """The outcome of evaluating one action against the configured rules."""

    allowed: bool
    reason: str
    matched_rule: str | None = None


class PolicyEngine:
    """Evaluate actions with deny-overrides and a deny-by-default fallback.

    A rule with no resource applies to every resource for its action. A resource
    specified on a rule must match exactly. Any matching deny rule takes
    precedence over all matching allow rules, regardless of declaration order.
    """

    def __init__(self, rules: Iterable[PolicyRule] = ()) -> None:
        self._rules = tuple(rules)

    @property
    def rules(self) -> tuple[PolicyRule, ...]:
        return self._rules

    @staticmethod
    def _matches(rule: PolicyRule, action: str, resource: str | None) -> bool:
        return rule.action == action and (
            rule.resource is None or rule.resource == resource
        )

    def evaluate(self, action: str, resource: str | None = None) -> PolicyDecision:
        """Return an auditable decision for an action/resource pair."""
        if not action or not action.strip():
            raise ValueError("action must not be empty")
        if resource is not None and not resource.strip():
            raise ValueError("resource must not be empty when provided")

        matching_denies = (
            rule
            for rule in self._rules
            if rule.effect is Effect.DENY
            and self._matches(rule, action, resource)
        )
        denied_by = next(matching_denies, None)
        if denied_by is not None:
            return PolicyDecision(
                allowed=False,
                reason="explicit_deny",
                matched_rule=denied_by.name,
            )

        matching_allows = (
            rule
            for rule in self._rules
            if rule.effect is Effect.ALLOW
            and self._matches(rule, action, resource)
        )
        allowed_by = next(matching_allows, None)
        if allowed_by is not None:
            return PolicyDecision(
                allowed=True,
                reason="matched_allow_rule",
                matched_rule=allowed_by.name,
            )

        return PolicyDecision(allowed=False, reason="default_deny")
