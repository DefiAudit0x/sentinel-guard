"""Bounded JSON adapter for the local, simulation-only Sentinel Guard demo.

This module accepts only a simple native transfer intent. It performs no NEAR
integration, network access, signing, or transaction submission.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_INPUT_BYTES = 64 * 1024
MAX_REQUEST_ID_LENGTH = 128
MAX_AMOUNT_DIGITS = 80
MAX_POLICY_BYTES = 64 * 1024
POLICY_ENV_VAR = "SENTINEL_GUARD_POLICY_FILE"
_SUPPORTED_ACTION = "transfer"
_TRANSACTION_FIELDS = {
    "recipient",
    "amount_yocto",
    "recipient_is_contract",
    "recipient_code_changed",
    "known_malicious",
    "previous_interactions",
    "account_age_days",
}
_AMOUNT_PATTERN = re.compile(rf"(?:0|[1-9][0-9]{{0,{MAX_AMOUNT_DIGITS - 1}}})\Z")
_ACCOUNT_ID_PATTERN = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*\Z")
_POLICY_FIELDS = {
    "version",
    "default",
    "allowed_recipients",
    "max_amount_yocto",
}


def _is_valid_account_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and 2 <= len(value) <= 64
        and _ACCOUNT_ID_PATTERN.fullmatch(value) is not None
    )

# The Node bridge executes this file in isolated mode. Add only this project
# root so the local package can be imported without relying on PYTHONPATH.
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from sentinel_guard.policy_engine import PolicyDecision  # noqa: E402
from sentinel_guard.reporting import simulation_result_to_dict  # noqa: E402
from sentinel_guard.transaction_simulator import (  # noqa: E402
    EvaluationStatus,
    SimulationDecision,
    SimulationStatus,
    simulate_transaction,
)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _intent_hash(intent: object) -> str:
    return hashlib.sha256(_canonical_json(intent)).hexdigest()


def _empty_response(
    request_id: str,
    intent_hash: str,
    status: str,
    reason: str,
) -> dict[str, Any]:
    """Return the complete wire schema for an unevaluated fail-closed result."""
    return {
        "request_id": request_id,
        "intent_hash": intent_hash,
        "status": status,
        "decision": SimulationDecision.BLOCK.value,
        "policy": {
            "status": EvaluationStatus.NOT_EVALUATED.value,
            "allowed": None,
            "reason": None,
            "matched_rule": None,
            "error": None,
            "error_stage": None,
        },
        "risk": {
            "status": EvaluationStatus.NOT_EVALUATED.value,
            "decision": None,
            "risk_score": None,
            "reasons": [],
            "error": None,
        },
        "reasons": [reason],
    }


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate policy key")
        result[key] = value
    return result


@dataclass(frozen=True, slots=True)
class _LocalPolicy:
    allowed_recipients: frozenset[str]
    max_amount_yocto: int


class _IntentPolicy:
    """Apply the loaded allow-list and cap to one validated transfer intent."""

    def __init__(
        self,
        policy: _LocalPolicy,
        amount_yocto: int,
    ) -> None:
        self._policy = policy
        self._amount_yocto = amount_yocto

    def evaluate(self, action: str, resource: str | None) -> PolicyDecision:
        if action != _SUPPORTED_ACTION:
            return PolicyDecision(allowed=False, reason="default_deny")
        if self._amount_yocto > self._policy.max_amount_yocto:
            return PolicyDecision(allowed=False, reason="amount_limit_exceeded")
        if resource not in self._policy.allowed_recipients:
            return PolicyDecision(allowed=False, reason="recipient_not_allowed")
        return PolicyDecision(
            allowed=True,
            reason="matched_allow_rule",
            matched_rule="json-policy-recipient-allow-list",
        )


def _load_policy(policy_path: str | Path | None) -> _LocalPolicy:
    if policy_path is None or not str(policy_path).strip():
        raise FileNotFoundError("no local policy path configured")
    with Path(policy_path).open("rb") as policy_file:
        raw = policy_file.read(MAX_POLICY_BYTES + 1)
    if len(raw) > MAX_POLICY_BYTES:
        raise ValueError("policy file exceeds the 65536-byte limit")
    policy = json.loads(
        raw.decode("utf-8"),
        parse_constant=_reject_json_constant,
        object_pairs_hook=_reject_duplicate_keys,
    )
    if not isinstance(policy, dict) or set(policy) != _POLICY_FIELDS:
        raise ValueError("policy must contain exactly the documented fields")
    if type(policy["version"]) is not int or policy["version"] != 1:
        raise ValueError("policy version must be integer 1")
    if policy["default"] != "deny":
        raise ValueError("policy default must be deny")
    recipients = policy["allowed_recipients"]
    if not isinstance(recipients, list):
        raise ValueError("allowed_recipients must be a JSON array")
    if any(
        not isinstance(recipient, str)
        or not _is_valid_account_id(recipient)
        for recipient in recipients
    ):
        raise ValueError(
            "allowed_recipients entries must be valid lowercase NEAR account IDs"
        )
    if len(set(recipients)) != len(recipients):
        raise ValueError("allowed_recipients entries must be unique")
    maximum = policy["max_amount_yocto"]
    if not isinstance(maximum, str) or not _AMOUNT_PATTERN.fullmatch(maximum):
        raise ValueError("max_amount_yocto must be a canonical non-negative decimal string")
    return _LocalPolicy(frozenset(recipients), int(maximum))


def _policy_error_response(
    request_id: str, intent_hash: str, error: Exception
) -> dict[str, Any]:
    error_stage = "LOOKUP" if isinstance(error, OSError) else "CONTRACT"
    response = _empty_response(
        request_id,
        intent_hash,
        SimulationStatus.ERROR.value,
        f"local policy configuration error: {type(error).__name__}",
    )
    response["policy"] = {
        "status": EvaluationStatus.ERROR.value,
        "allowed": None,
        "reason": None,
        "matched_rule": None,
        "error": f"policy configuration could not be loaded: {type(error).__name__}",
        "error_stage": error_stage,
    }
    return response


def _request_identity(request: object) -> tuple[str, str]:
    request_id = ""
    intent_hash = ""
    if isinstance(request, dict):
        candidate_id = request.get("request_id")
        if isinstance(candidate_id, str):
            request_id = candidate_id
        intent = request.get("intent")
        if isinstance(intent, dict):
            try:
                intent_hash = _intent_hash(intent)
            except (TypeError, ValueError, UnicodeError):
                pass
    return request_id, intent_hash


def evaluate_request(
    request: object, policy_path: str | Path | None = None
) -> dict[str, Any]:
    """Evaluate one JSON-compatible request and return the bounded wire schema."""
    request_id, intent_hash = _request_identity(request)

    if not isinstance(request, dict) or set(request) != {"request_id", "intent"}:
        return _empty_response(
            request_id, intent_hash, SimulationStatus.INVALID_INPUT.value,
            "request must contain only request_id and intent",
        )
    if (
        not isinstance(request_id, str)
        or not request_id.strip()
        or len(request_id) > MAX_REQUEST_ID_LENGTH
    ):
        return _empty_response(
            "", intent_hash, SimulationStatus.INVALID_INPUT.value,
            "request_id must be a non-empty string of at most 128 characters",
        )
    intent = request.get("intent")
    if not isinstance(intent, dict) or set(intent) != {
        "action", "resource", "transaction"
    }:
        return _empty_response(
            request_id, intent_hash, SimulationStatus.INVALID_INPUT.value,
            "intent must contain only action, resource, and transaction",
        )
    if intent.get("action") != _SUPPORTED_ACTION:
        return _empty_response(
            request_id, intent_hash, SimulationStatus.INVALID_INPUT.value,
            "only the simple native transfer action is supported",
        )

    resource = intent.get("resource")
    if resource is not None and not _is_valid_account_id(resource):
        return _empty_response(
            request_id, intent_hash, SimulationStatus.INVALID_INPUT.value,
            "resource must be null or a valid lowercase NEAR account ID",
        )

    transaction = intent.get("transaction")
    if not isinstance(transaction, dict) or any(
        not isinstance(key, str) for key in transaction
    ):
        return _empty_response(
            request_id, intent_hash, SimulationStatus.INVALID_INPUT.value,
            "transaction must be an object with string keys",
        )
    if set(transaction) - _TRANSACTION_FIELDS:
        return _empty_response(
            request_id, intent_hash, SimulationStatus.INVALID_INPUT.value,
            "unsupported transaction fields; contract calls and payload parsing are not supported",
        )
    recipient = transaction.get("recipient")
    if not _is_valid_account_id(recipient):
        return _empty_response(
            request_id, intent_hash, SimulationStatus.INVALID_INPUT.value,
            "a simple transfer requires a valid lowercase NEAR account ID recipient",
        )
    amount_text = transaction.get("amount_yocto")
    if not isinstance(amount_text, str) or not _AMOUNT_PATTERN.fullmatch(amount_text):
        return _empty_response(
            request_id, intent_hash, SimulationStatus.INVALID_INPUT.value,
            f"amount_yocto must be a canonical non-negative decimal string of at most {MAX_AMOUNT_DIGITS} digits",
        )

    try:
        local_policy = _load_policy(policy_path)
    except (OSError, UnicodeDecodeError, TypeError, ValueError) as error:
        return _policy_error_response(request_id, intent_hash, error)

    parsed_transaction = dict(transaction)
    parsed_transaction["amount_yocto"] = int(amount_text)
    policy = _IntentPolicy(local_policy, int(amount_text))
    result = simulate_transaction(
        _SUPPORTED_ACTION,
        resource,
        parsed_transaction,
        policy,
    )
    return {
        "request_id": request_id,
        "intent_hash": intent_hash,
        **simulation_result_to_dict(result),
    }


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant {value} is not accepted")


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r} is not accepted")
        result[key] = value
    return result


def main() -> int:
    """Read one bounded JSON request from stdin and write one JSON response."""
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        response = _empty_response(
            "", "", SimulationStatus.INVALID_INPUT.value,
            "request exceeds the 65536-byte input limit",
        )
    else:
        try:
            request = json.loads(
                raw,
                parse_constant=_reject_json_constant,
                object_pairs_hook=_reject_duplicate_json_keys,
            )
            response = evaluate_request(request, os.environ.get(POLICY_ENV_VAR))
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError, ValueError) as error:
            response = _empty_response(
                "", "", SimulationStatus.ERROR.value,
                f"invalid JSON request: {type(error).__name__}",
            )
        except Exception as error:  # Fail closed across the process boundary.
            response = _empty_response(
                "", "", SimulationStatus.ERROR.value,
                f"adapter error: {type(error).__name__}",
            )

    sys.stdout.write(json.dumps(response, separators=(",", ":"), ensure_ascii=False))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
