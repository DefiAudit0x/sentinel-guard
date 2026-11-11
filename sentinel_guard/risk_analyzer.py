from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any


YOCTO_PER_NEAR = 10**24
# Experimental risk signal; this threshold is not an established security standard.
AMOUNT_RISK_THRESHOLD_YOCTO = 10 * YOCTO_PER_NEAR


class RiskDecision(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"


@dataclass(frozen=True)
class RiskResult:
    decision: RiskDecision
    risk_score: int
    reasons: tuple[str, ...]


def analyze_transaction(transaction: Mapping[str, Any]) -> RiskResult:
    """
    Deterministic transaction risk analyzer.

    Required for a non-blocking evaluation:
      - recipient: non-empty str
      - amount_yocto: non-negative int (yoctoNEAR; 1 NEAR = 10**24 yoctoNEAR)

    Optional fields and defaults:
      - recipient_is_contract: bool (False)
      - recipient_code_changed: bool (False)
      - known_malicious: bool (False)
      - previous_interactions: non-negative int (0)
      - account_age_days: non-negative int (0)
    """

    score = 0
    reasons = []

    recipient = transaction.get("recipient")
    amount_yocto = transaction.get("amount_yocto")
    recipient_is_contract = transaction.get(
        "recipient_is_contract", False
    )
    recipient_code_changed = transaction.get(
        "recipient_code_changed", False
    )
    known_malicious = transaction.get("known_malicious", False)
    previous_interactions = transaction.get(
        "previous_interactions", 0
    )
    account_age_days = transaction.get("account_age_days", 0)

    # Validate input types and values.
    if not isinstance(recipient, str) or not recipient.strip():
        return RiskResult(
            RiskDecision.BLOCK,
            100,
            ("Missing or invalid recipient",),
        )

    if isinstance(amount_yocto, bool) or not isinstance(amount_yocto, int):
        return RiskResult(
            RiskDecision.BLOCK,
            100,
            ("Invalid transaction amount",),
        )

    if amount_yocto < 0:
        return RiskResult(
            RiskDecision.BLOCK,
            100,
            ("Negative transaction amount",),
        )

    if not isinstance(previous_interactions, int) or isinstance(
        previous_interactions, bool
    ) or previous_interactions < 0:
        return RiskResult(
            RiskDecision.BLOCK,
            100,
            ("Invalid previous interaction count",),
        )

    if not isinstance(account_age_days, int) or isinstance(
        account_age_days, bool
    ) or account_age_days < 0:
        return RiskResult(
            RiskDecision.BLOCK,
            100,
            ("Invalid account age",),
        )

    for field in (
        "recipient_is_contract",
        "recipient_code_changed",
        "known_malicious",
    ):
        if field in transaction and not isinstance(transaction[field], bool):
            return RiskResult(
                RiskDecision.BLOCK,
                100,
                (f"Invalid {field} value",),
            )

    # High-confidence blocking signal.
    if known_malicious:
        return RiskResult(
            RiskDecision.BLOCK,
            100,
            ("Recipient is marked as known malicious",),
        )

    # Suspicious signals.
    if recipient_code_changed and recipient_is_contract:
        score += 50
        reasons.append("Recipient contract code changed")

    if amount_yocto > AMOUNT_RISK_THRESHOLD_YOCTO:
        score += 30
        reasons.append("Transaction amount exceeds threshold")

    if account_age_days < 7:
        score += 15
        reasons.append("Account is less than 7 days old")

    if previous_interactions == 0:
        score += 10
        reasons.append("No previous interaction with recipient")

    if recipient_is_contract:
        score += 5
        reasons.append("Recipient is a smart contract")

    # Deterministic decision thresholds.
    if score >= 50:
        decision = RiskDecision.BLOCK
    elif score >= 20:
        decision = RiskDecision.WARN
    else:
        decision = RiskDecision.ALLOW

    return RiskResult(
        decision=decision,
        risk_score=min(score, 100),
        reasons=tuple(reasons),
    )
