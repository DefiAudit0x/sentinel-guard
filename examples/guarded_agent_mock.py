#!/usr/bin/env python3
"""Demonstrate a local application gate with a placeholder signer callback.

This is not a NEAR integration. It uses no wallet, key, network, or real
transaction signer; the callback only returns a clearly marked mock string.
"""

from __future__ import annotations

import math
import sys
from copy import deepcopy
from collections.abc import Callable, Mapping
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sentinel_guard.policy_engine import PolicyEngine
    from sentinel_guard.transaction_simulator import SimulationResult


MockSigner = Callable[[Mapping[str, Any]], str]


class _FrozenDict(dict[str, Any]):
    """A dict-compatible immutable snapshot accepted by the simulator."""

    def __init__(self, values: dict[str, Any]) -> None:
        dict.__init__(self, values)

    def _deny_mutation(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError("the evaluated transaction snapshot is immutable")

    __setitem__ = _deny_mutation
    __delitem__ = _deny_mutation
    clear = _deny_mutation
    pop = _deny_mutation
    popitem = _deny_mutation
    setdefault = _deny_mutation
    update = _deny_mutation
    __ior__ = _deny_mutation

    def __deepcopy__(self, memo: dict[int, Any]) -> dict[str, Any]:
        snapshot: dict[str, Any] = {}
        memo[id(self)] = snapshot
        for key, value in self.items():
            snapshot[deepcopy(key, memo)] = deepcopy(value, memo)
        return snapshot


def _immutable_intent_value(value: Any) -> Any:
    """Copy JSON-compatible intent data into recursively immutable values."""
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise TypeError("transaction numbers must be finite")
        return value
    if type(value) is list:
        return tuple(_immutable_intent_value(item) for item in value)
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise TypeError("transaction keys must be strings")
        return _FrozenDict({
            key: _immutable_intent_value(item)
            for key, item in value.items()
        })
    raise TypeError("transaction must contain only JSON-compatible values")


def _read_only_intent_view(value: Any) -> Any:
    if isinstance(value, _FrozenDict):
        return MappingProxyType({
            key: _read_only_intent_view(item)
            for key, item in value.items()
        })
    if type(value) is tuple:
        return tuple(_read_only_intent_view(item) for item in value)
    return value


def evaluate_then_mock_sign(
    action: str,
    resource: str | None,
    transaction: dict[str, Any],
    policy_engine: PolicyEngine,
    mock_signer: MockSigner,
) -> tuple[SimulationResult, str | None]:
    """Call the placeholder callback only for a completed ALLOW decision."""
    from sentinel_guard.transaction_simulator import (
        SimulationDecision,
        SimulationStatus,
        simulate_transaction,
    )

    transaction_snapshot = _immutable_intent_value(transaction)
    if not isinstance(transaction_snapshot, _FrozenDict):
        raise TypeError("transaction must be a dictionary")
    result = simulate_transaction(
        action, resource, transaction_snapshot, policy_engine
    )
    if (
        result.status is not SimulationStatus.COMPLETED
        or result.decision is not SimulationDecision.ALLOW
    ):
        return result, None

    return result, mock_signer(_read_only_intent_view(transaction_snapshot))


def _dummy_signer(transaction: Mapping[str, Any]) -> str:
    """Return a stable marker; this function performs no cryptographic signing."""
    return f"MOCK-ONLY (not a signature): {transaction['recipient']}"


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    from sentinel_guard.policy_engine import Effect, PolicyEngine, PolicyRule

    policy_engine = PolicyEngine(
        [PolicyRule("allow-transfers", Effect.ALLOW, "transfer")]
    )
    safe_transaction = {
        "recipient": "alice.near",
        "amount_yocto": 1 * 10**24,
        "previous_interactions": 3,
        "account_age_days": 365,
    }
    scenarios = (
        (
            "safe transfer",
            "transfer",
            safe_transaction,
            "ALLOW",
            "COMPLETED",
            True,
        ),
        (
            "warning",
            "transfer",
            dict(safe_transaction, amount_yocto=11 * 10**24),
            "WARN",
            "COMPLETED",
            False,
        ),
        (
            "risk block",
            "transfer",
            dict(safe_transaction, known_malicious=True),
            "BLOCK",
            "COMPLETED",
            False,
        ),
        (
            "invalid wrapper",
            "",
            safe_transaction,
            "BLOCK",
            "INVALID_INPUT",
            False,
        ),
    )

    print("Sentinel Guard — guarded application mock")
    print("Offline demo only; no NEAR connection or real signing occurs.\n")

    all_passed = True
    for (
        title,
        action,
        transaction,
        expected_decision,
        expected_status,
        expected_callback,
    ) in scenarios:
        result, mock_signature = evaluate_then_mock_sign(
            action=action,
            resource=transaction["recipient"],
            transaction=transaction,
            policy_engine=policy_engine,
            mock_signer=_dummy_signer,
        )
        callback_invoked = mock_signature is not None
        passed = (
            result.decision.value == expected_decision
            and result.status.value == expected_status
            and callback_invoked is expected_callback
        )
        print(
            f"{title}: status={result.status.value}, "
            f"decision={result.decision.value}, "
            f"dummy callback={'INVOKED' if callback_invoked else 'not invoked'}"
        )
        if mock_signature is not None:
            print(f"    {mock_signature}")
        print(f"    Expected-result check: {'PASS' if passed else 'FAIL'}")
        all_passed = all_passed and passed

    print(f"\nOverall: {'PASS' if all_passed else 'FAIL'}")
    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
