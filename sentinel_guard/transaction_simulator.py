"""Local, deterministic orchestration of policy and transaction-risk decisions.

This module only evaluates inputs. It never signs, submits, or otherwise executes
transactions.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any

from .policy_engine import PolicyDecision
from .risk_analyzer import RiskDecision, RiskResult, analyze_transaction


class SimulationDecision(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"


class EvaluationStatus(str, Enum):
    EVALUATED = "EVALUATED"
    ERROR = "ERROR"
    NOT_EVALUATED = "NOT_EVALUATED"


class SimulationStatus(str, Enum):
    COMPLETED = "COMPLETED"
    ERROR = "ERROR"
    INVALID_INPUT = "INVALID_INPUT"


class PolicyErrorStage(str, Enum):
    LOOKUP = "LOOKUP"
    CONTRACT = "CONTRACT"
    CALL = "CALL"


@dataclass(frozen=True, slots=True)
class PolicyEvaluation:
    status: EvaluationStatus
    allowed: bool | None = None
    reason: str | None = None
    matched_rule: str | None = None
    error: str | None = None
    error_stage: PolicyErrorStage | None = None


@dataclass(frozen=True, slots=True)
class RiskEvaluation:
    status: EvaluationStatus
    decision: RiskDecision | None = None
    risk_score: int | None = None
    reasons: tuple[str, ...] = ()
    error: str | None = None


@dataclass(frozen=True, slots=True)
class SimulationResult:
    decision: SimulationDecision
    status: SimulationStatus
    policy: PolicyEvaluation
    risk: RiskEvaluation
    reasons: tuple[str, ...] = ()


def _error_text(error: Exception) -> str:
    """Return a stable, useful description without allowing formatting to fail."""
    try:
        detail = str(error)
    except Exception:
        detail = "<unprintable error>"
    return f"{type(error).__name__}: {detail}" if detail else type(error).__name__


def _validate_wrapper(
    action: object,
    resource: object,
    transaction: object,
) -> tuple[str, ...]:
    errors: list[str] = []
    if not isinstance(action, str) or not action.strip():
        errors.append("action must be a non-empty string")
    if resource is not None and (
        not isinstance(resource, str) or not resource.strip()
    ):
        errors.append("resource must be None or a non-empty string")
    if not isinstance(transaction, dict):
        errors.append("transaction must be a dictionary")
    elif any(not isinstance(key, str) for key in transaction):
        errors.append("transaction keys must be strings")

    if (
        isinstance(transaction, dict)
        and isinstance(resource, str)
        and resource.strip()
    ):
        recipient = transaction.get("recipient")
        if not isinstance(recipient, str) or not recipient.strip():
            errors.append("explicit resource requires a valid transaction recipient")
        elif resource != recipient:
            errors.append("resource must match transaction recipient")

    return tuple(errors)


def _evaluate_policy(
    policy_engine: Any, action: str, resource: str | None
) -> PolicyEvaluation:
    try:
        evaluate = getattr(policy_engine, "evaluate")
    except Exception as error:
        return PolicyEvaluation(
            status=EvaluationStatus.ERROR,
            error=_error_text(error),
            error_stage=PolicyErrorStage.LOOKUP,
        )

    if not callable(evaluate):
        error = TypeError("policy_engine evaluate must be callable")
        return PolicyEvaluation(
            status=EvaluationStatus.ERROR,
            error=_error_text(error),
            error_stage=PolicyErrorStage.CONTRACT,
        )

    try:
        result = evaluate(action, resource)
    except Exception as error:
        return PolicyEvaluation(
            status=EvaluationStatus.ERROR,
            error=_error_text(error),
            error_stage=PolicyErrorStage.CALL,
        )

    try:
        if not isinstance(result, PolicyDecision):
            raise TypeError("policy engine returned an invalid decision object")
        if not isinstance(result.allowed, bool):
            raise TypeError("policy decision allowed must be a bool")
        if not isinstance(result.reason, str) or not result.reason:
            raise TypeError("policy decision reason must be a non-empty string")
        if result.matched_rule is not None and not isinstance(result.matched_rule, str):
            raise TypeError("policy decision matched_rule must be a string or None")
        return PolicyEvaluation(
            status=EvaluationStatus.EVALUATED,
            allowed=result.allowed,
            reason=result.reason,
            matched_rule=result.matched_rule,
        )
    except Exception as error:
        return PolicyEvaluation(
            status=EvaluationStatus.ERROR,
            error=_error_text(error),
            error_stage=PolicyErrorStage.CONTRACT,
        )


def _evaluate_risk(transaction: Mapping[str, Any]) -> RiskEvaluation:
    try:
        result = analyze_transaction(transaction)
        if not isinstance(result, RiskResult):
            raise TypeError("risk analyzer returned an invalid result object")
        if not isinstance(result.decision, RiskDecision):
            raise TypeError("risk decision must be a RiskDecision")
        if (
            not isinstance(result.risk_score, int)
            or isinstance(result.risk_score, bool)
            or not 0 <= result.risk_score <= 100
        ):
            raise TypeError("risk_score must be an integer from 0 to 100")
        if not isinstance(result.reasons, tuple) or any(
            not isinstance(reason, str) for reason in result.reasons
        ):
            raise TypeError("risk reasons must be a tuple of strings")
        if any(not reason.strip() for reason in result.reasons):
            raise TypeError("risk reasons must not be empty or whitespace-only")
        if result.decision in (RiskDecision.WARN, RiskDecision.BLOCK) and not result.reasons:
            raise TypeError("WARN and BLOCK risk decisions require at least one reason")
        return RiskEvaluation(
            status=EvaluationStatus.EVALUATED,
            decision=result.decision,
            risk_score=result.risk_score,
            reasons=result.reasons,
        )
    except Exception as error:
        return RiskEvaluation(
            status=EvaluationStatus.ERROR,
            error=_error_text(error),
        )


def simulate_transaction(
    action: str,
    resource: str | None,
    transaction: dict[str, Any],
    policy_engine: Any,
) -> SimulationResult:
    """Evaluate policy and risk independently, then combine them fail-closed.

    The request wrapper is validated before either engine runs. After valid input,
    a failure in either engine is recorded and does not prevent the other from
    being evaluated. A policy denial or risk BLOCK always blocks; risk WARN is
    preserved as WARN and is never upgraded to ALLOW. An omitted resource uses
    a valid transaction recipient for policy evaluation. An explicit resource
    requires a valid transaction recipient and must match it; either violation
    is rejected during wrapper validation before either evaluator runs.
    """
    validation_errors = _validate_wrapper(action, resource, transaction)
    if validation_errors:
        return SimulationResult(
            decision=SimulationDecision.BLOCK,
            status=SimulationStatus.INVALID_INPUT,
            policy=PolicyEvaluation(status=EvaluationStatus.NOT_EVALUATED),
            risk=RiskEvaluation(status=EvaluationStatus.NOT_EVALUATED),
            reasons=validation_errors,
        )

    # Both evaluations use one detached, read-only view. A caller-supplied policy
    # engine may hold a reference to the original request and mutate it.
    try:
        transaction_snapshot = MappingProxyType(deepcopy(transaction))
    except Exception as error:
        snapshot_error = _error_text(error)
        return SimulationResult(
            decision=SimulationDecision.BLOCK,
            status=SimulationStatus.ERROR,
            policy=PolicyEvaluation(status=EvaluationStatus.NOT_EVALUATED),
            risk=RiskEvaluation(
                status=EvaluationStatus.ERROR,
                error=snapshot_error,
            ),
            reasons=(f"Transaction snapshot error: {snapshot_error}",),
        )

    # Engines remain isolated so one engine's exception cannot suppress the other's evaluation.
    policy_resource = resource
    if policy_resource is None:
        recipient = transaction_snapshot.get("recipient")
        if isinstance(recipient, str) and recipient.strip():
            policy_resource = recipient

    policy_result = _evaluate_policy(
        policy_engine, action, policy_resource  # type: ignore[arg-type]
    )
    risk_result = _evaluate_risk(transaction_snapshot)

    if (
        policy_result.status is not EvaluationStatus.EVALUATED
        or risk_result.status is not EvaluationStatus.EVALUATED
        or policy_result.allowed is not True
        or risk_result.decision is RiskDecision.BLOCK
    ):
        decision = SimulationDecision.BLOCK
    elif risk_result.decision is RiskDecision.WARN:
        decision = SimulationDecision.WARN
    else:
        decision = SimulationDecision.ALLOW

    reasons: list[str] = []
    if policy_result.status is EvaluationStatus.ERROR:
        reasons.append(f"Policy evaluation error: {policy_result.error}")
    elif policy_result.allowed is False:
        reasons.append(f"Policy denied: {policy_result.reason}")
    if risk_result.status is EvaluationStatus.ERROR:
        reasons.append(f"Risk evaluation error: {risk_result.error}")
    else:
        reasons.extend(f"Risk: {reason}" for reason in risk_result.reasons)

    has_error = (
        policy_result.status is EvaluationStatus.ERROR
        or risk_result.status is EvaluationStatus.ERROR
    )
    return SimulationResult(
        decision=decision,
        status=SimulationStatus.ERROR if has_error else SimulationStatus.COMPLETED,
        policy=policy_result,
        risk=risk_result,
        reasons=tuple(reasons),
    )
