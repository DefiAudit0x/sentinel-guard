import pytest

from sentinel_guard.risk_analyzer import (
    RiskDecision,
    analyze_transaction,
)


YOCTO_PER_NEAR = 10**24


def _analyze_with_amount(amount_yocto):
    return analyze_transaction({
        "recipient": "alice.near",
        "amount_yocto": amount_yocto,
        "recipient_is_contract": False,
        "previous_interactions": 5,
        "account_age_days": 100,
    })


def test_zero_near_is_allowed():
    result = _analyze_with_amount(0)

    assert result.decision == RiskDecision.ALLOW
    assert result.risk_score == 0


def test_exactly_10_near_does_not_add_amount_risk():
    result = _analyze_with_amount(10 * YOCTO_PER_NEAR)

    assert result.decision == RiskDecision.ALLOW
    assert result.risk_score == 0


def test_one_yocto_above_10_near_adds_30_risk_points():
    result = _analyze_with_amount(10 * YOCTO_PER_NEAR + 1)

    assert result.decision == RiskDecision.WARN
    assert result.risk_score == 30
    assert "Transaction amount exceeds threshold" in result.reasons


def test_known_malicious_recipient_is_blocked():
    result = analyze_transaction({
        "recipient": "malicious.near",
        "amount_yocto": 1,
        "known_malicious": True,
    })

    assert result.decision == RiskDecision.BLOCK
    assert result.risk_score == 100


def test_recent_contract_code_change_is_blocked():
    result = analyze_transaction({
        "recipient": "contract.near",
        "amount_yocto": 1,
        "recipient_is_contract": True,
        "recipient_code_changed": True,
        "previous_interactions": 5,
        "account_age_days": 100,
    })

    assert result.decision == RiskDecision.BLOCK
    assert result.risk_score == 55


def test_invalid_recipient_is_blocked():
    result = analyze_transaction({
        "recipient": "",
        "amount_yocto": 1,
    })

    assert result.decision == RiskDecision.BLOCK


def test_missing_amount_is_blocked():
    result = analyze_transaction({
        "recipient": "alice.near",
        "previous_interactions": 5,
        "account_age_days": 100,
    })

    assert result.decision == RiskDecision.BLOCK
    assert result.risk_score == 100
    assert result.reasons == ("Invalid transaction amount",)


def test_negative_amount_is_blocked():
    result = _analyze_with_amount(-1)

    assert result.decision == RiskDecision.BLOCK
    assert result.reasons == ("Negative transaction amount",)


@pytest.mark.parametrize("amount_yocto", [0.0, 1.5, float("inf"), float("nan")])
def test_float_amount_is_blocked(amount_yocto):
    result = _analyze_with_amount(amount_yocto)

    assert result.decision == RiskDecision.BLOCK
    assert result.reasons == ("Invalid transaction amount",)


@pytest.mark.parametrize("amount_yocto", [False, True])
def test_bool_amount_is_blocked(amount_yocto):
    result = _analyze_with_amount(amount_yocto)

    assert result.decision == RiskDecision.BLOCK
    assert result.reasons == ("Invalid transaction amount",)
