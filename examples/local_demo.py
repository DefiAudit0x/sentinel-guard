#!/usr/bin/env python3
"""Run three deterministic, local Sentinel Guard transaction examples."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Make direct invocation from the repository root work without installation.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sentinel_guard.policy_engine import Effect, PolicyEngine, PolicyRule
from sentinel_guard.risk_analyzer import YOCTO_PER_NEAR
from sentinel_guard.transaction_simulator import (
    EvaluationStatus,
    SimulationDecision,
    SimulationStatus,
    simulate_transaction,
)


@dataclass(frozen=True)
class DemoScenario:
    title: str
    description: str
    amount_near: int
    transaction: dict[str, Any]
    expected: SimulationDecision


SCENARIOS = (
    DemoScenario(
        title="Small transfer to a known recipient",
        description="1 NEAR; recipient has prior interactions and is not flagged.",
        amount_near=1,
        transaction={
            "recipient": "alice.near",
            "amount_yocto": YOCTO_PER_NEAR,
            "previous_interactions": 3,
            "account_age_days": 365,
        },
        expected=SimulationDecision.ALLOW,
    ),
    DemoScenario(
        title="Transfer above the 10 NEAR risk threshold",
        description="11 NEAR; recipient is otherwise familiar and not flagged.",
        amount_near=11,
        transaction={
            "recipient": "alice.near",
            "amount_yocto": 11 * YOCTO_PER_NEAR,
            "previous_interactions": 3,
            "account_age_days": 365,
        },
        expected=SimulationDecision.WARN,
    ),
    DemoScenario(
        title="Transfer to a known malicious recipient",
        description="1 NEAR; the recipient is explicitly marked as malicious.",
        amount_near=1,
        transaction={
            "recipient": "mallory.near",
            "amount_yocto": YOCTO_PER_NEAR,
            "known_malicious": True,
            "previous_interactions": 3,
            "account_age_days": 365,
        },
        expected=SimulationDecision.BLOCK,
    ),
)


def _show_reasons(reasons: tuple[str, ...]) -> str:
    return "; ".join(reasons) if reasons else "none"


def main() -> int:
    policy_engine = PolicyEngine(
        [
            PolicyRule(
                name="allow-transfers",
                effect=Effect.ALLOW,
                action="transfer",
            )
        ]
    )

    print("Sentinel Guard — local transaction demo")
    print("Offline simulation only; no transaction is signed or sent.\n")

    all_passed = True
    for index, scenario in enumerate(SCENARIOS, start=1):
        print(f"[{index}] {scenario.title}")
        print(f"    Scenario: {scenario.description}")
        print(f"    Expected final decision: {scenario.expected.value}")

        result = simulate_transaction(
            action="transfer",
            resource=scenario.transaction["recipient"],
            transaction=scenario.transaction,
            policy_engine=policy_engine,
        )

        print(
            "    Policy engine: "
            f"status={result.policy.status.value}, "
            f"allowed={result.policy.allowed}, "
            f"reason={result.policy.reason}, "
            f"matched_rule={result.policy.matched_rule}"
        )
        print(
            "    Risk engine: "
            f"status={result.risk.status.value}, "
            f"decision={result.risk.decision.value if result.risk.decision else None}, "
            f"risk_score={result.risk.risk_score}, "
            f"reasons={_show_reasons(result.risk.reasons)}"
        )
        print(
            "    Simulation: "
            f"status={result.status.value}, decision={result.decision.value}, "
            f"reasons={_show_reasons(result.reasons)}"
        )

        passed = (
            result.status is SimulationStatus.COMPLETED
            and result.decision is scenario.expected
            and result.policy.status is EvaluationStatus.EVALUATED
            and result.policy.allowed is True
            and result.risk.status is EvaluationStatus.EVALUATED
        )
        print(f"    Expected-result check: {'PASS' if passed else 'FAIL'}\n")
        all_passed = all_passed and passed

    print(f"Overall: {'PASS' if all_passed else 'FAIL'}")
    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
