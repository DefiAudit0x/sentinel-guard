"""Structured reporting helpers for Sentinel Guard simulation results."""

from __future__ import annotations

import json
from typing import Any

from .transaction_simulator import SimulationResult


def simulation_result_to_dict(result: SimulationResult) -> dict[str, Any]:
    """Convert a SimulationResult into a deterministic, JSON-serializable dictionary."""
    if not isinstance(result, SimulationResult):
        raise TypeError("result must be a SimulationResult instance")

    return {
        "decision": result.decision.value,
        "status": result.status.value,
        "policy": {
            "status": result.policy.status.value,
            "allowed": result.policy.allowed,
            "reason": result.policy.reason,
            "matched_rule": result.policy.matched_rule,
            "error": result.policy.error,
            "error_stage": (
                result.policy.error_stage.value
                if result.policy.error_stage is not None
                else None
            ),
        },
        "risk": {
            "status": result.risk.status.value,
            "decision": (
                result.risk.decision.value.upper()
                if result.risk.decision is not None
                else None
            ),
            "risk_score": result.risk.risk_score,
            "reasons": list(result.risk.reasons),
            "error": result.risk.error,
        },
        "reasons": list(result.reasons),
    }


def simulation_result_to_json(result: SimulationResult, *, indent: int = 2) -> str:
    """Serialize a SimulationResult to a formatted JSON string."""
    return json.dumps(simulation_result_to_dict(result), indent=indent)
