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


@pytest.mark.parametrize(
    ("field", "value"),
    [("account_age_days", 7), ("previous_interactions", 1)],
)
def test_safe_numeric_signal_boundaries_do_not_add_risk(field, value):
    transaction = {
        "recipient": "alice.near",
        "amount_yocto": 5 * YOCTO_PER_NEAR,
        "recipient_is_contract": False,
        "recipient_code_changed": False,
        "known_malicious": False,
        "previous_interactions": 5,
        "account_age_days": 100,
    }
    transaction[field] = value

    result = analyze_transaction(transaction)

    assert result.decision == RiskDecision.ALLOW
    assert result.risk_score == 0
    assert "Account is less than 7 days old" not in result.reasons
    assert "No previous interaction with recipient" not in result.reasons


def test_missing_optional_context_fields_use_documented_defaults():
    result = analyze_transaction({
        "recipient": "alice.near",
        "amount_yocto": 5 * YOCTO_PER_NEAR,
    })

    assert result.decision == RiskDecision.WARN
    assert result.risk_score == 25
    assert result.reasons == (
        "Account is less than 7 days old",
        "No previous interaction with recipient",
    )


def test_missing_context_fields_match_explicit_zero_values():
    missing_context = {
        "recipient": "alice.near",
        "amount_yocto": 5 * YOCTO_PER_NEAR,
        "recipient_is_contract": False,
        "recipient_code_changed": False,
        "known_malicious": False,
    }
    explicit_zero_context = {
        **missing_context,
        "account_age_days": 0,
        "previous_interactions": 0,
    }

    missing_result = analyze_transaction(missing_context)
    explicit_zero_result = analyze_transaction(explicit_zero_context)

    expected_reasons = (
        "Account is less than 7 days old",
        "No previous interaction with recipient",
    )
    assert missing_result.decision == explicit_zero_result.decision == RiskDecision.WARN
    assert missing_result.risk_score == explicit_zero_result.risk_score == 25
    assert missing_result.reasons == explicit_zero_result.reasons == expected_reasons
    assert missing_result == explicit_zero_result


def test_zero_previous_interactions_adds_only_ten_risk_points():
    result = analyze_transaction({
        "recipient": "alice.near",
        "amount_yocto": 5 * YOCTO_PER_NEAR,
        "recipient_is_contract": False,
        "recipient_code_changed": False,
        "known_malicious": False,
        "previous_interactions": 0,
        "account_age_days": 100,
    })

    assert result.decision == RiskDecision.ALLOW
    assert result.risk_score == 10
    assert result.reasons == ("No previous interaction with recipient",)


def test_known_malicious_recipient_is_blocked():
    result = analyze_transaction({
        "recipient": "malicious.near",
        "amount_yocto": 1,
        "known_malicious": True,
    })

    assert result.decision == RiskDecision.BLOCK
    assert result.risk_score == 100


def test_known_malicious_blocks_before_other_risk_signals_are_accumulated():
    result = analyze_transaction({
        "recipient": "malicious.near",
        "amount_yocto": 11 * 10**24,
        "account_age_days": 6,
        "previous_interactions": 0,
        "recipient_is_contract": True,
        "recipient_code_changed": True,
        "known_malicious": True,
    })

    assert result.decision == RiskDecision.BLOCK
    assert result.risk_score == 100
    assert result.reasons == ("Recipient is marked as known malicious",)


def test_invalid_amount_is_reported_before_known_malicious_signal():
    result = analyze_transaction({
        "recipient": "alice.near",
        "amount_yocto": None,
        "recipient_is_contract": False,
        "recipient_code_changed": False,
        "known_malicious": True,
        "previous_interactions": 5,
        "account_age_days": 100,
    })

    assert result.decision == RiskDecision.BLOCK
    assert result.risk_score == 100
    assert result.reasons == ("Invalid transaction amount",)
    assert "Recipient is marked as known malicious" not in result.reasons


def test_invalid_contract_flag_is_reported_before_known_malicious_signal():
    result = analyze_transaction({
        "recipient": "alice.near",
        "amount_yocto": 5 * 10**24,
        "recipient_is_contract": 1,
        "recipient_code_changed": False,
        "known_malicious": True,
        "previous_interactions": 5,
        "account_age_days": 100,
    })

    assert result.decision == RiskDecision.BLOCK
    assert result.risk_score == 100
    assert result.reasons == ("Invalid recipient_is_contract value",)
    assert "Recipient is marked as known malicious" not in result.reasons


@pytest.mark.parametrize(
    "field",
    ["recipient_is_contract", "recipient_code_changed", "known_malicious"],
)
def test_integer_one_is_rejected_for_boolean_signals(field):
    transaction = {
        "recipient": "alice.near",
        "amount_yocto": 0,
        "recipient_is_contract": False,
        "recipient_code_changed": False,
        "known_malicious": False,
        "previous_interactions": 5,
        "account_age_days": 100,
    }
    transaction[field] = 1

    result = analyze_transaction(transaction)

    assert result.decision == RiskDecision.BLOCK
    assert result.risk_score == 100
    assert result.reasons == (f"Invalid {field} value",)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("recipient_is_contract", None),
        ("recipient_is_contract", "true"),
        ("recipient_code_changed", None),
        ("recipient_code_changed", "true"),
        ("known_malicious", None),
        ("known_malicious", "true"),
    ],
)
def test_none_and_string_values_are_rejected_for_boolean_signals(field, value):
    transaction = {
        "recipient": "alice.near",
        "amount_yocto": 0,
        "recipient_is_contract": False,
        "recipient_code_changed": False,
        "known_malicious": False,
        "previous_interactions": 5,
        "account_age_days": 100,
    }
    transaction[field] = value

    result = analyze_transaction(transaction)

    assert result.decision == RiskDecision.BLOCK
    assert result.risk_score == 100
    assert result.reasons == (f"Invalid {field} value",)


@pytest.mark.parametrize(
    ("field", "value", "expected_reason"),
    [
        ("account_age_days", True, "Invalid account age"),
        ("account_age_days", False, "Invalid account age"),
        (
            "previous_interactions",
            True,
            "Invalid previous interaction count",
        ),
        (
            "previous_interactions",
            False,
            "Invalid previous interaction count",
        ),
    ],
)
def test_boolean_values_are_rejected_for_numeric_signals(
    field, value, expected_reason
):
    transaction = {
        "recipient": "alice.near",
        "amount_yocto": 0,
        "recipient_is_contract": False,
        "recipient_code_changed": False,
        "known_malicious": False,
        "previous_interactions": 5,
        "account_age_days": 100,
    }
    transaction[field] = value

    result = analyze_transaction(transaction)

    assert result.decision == RiskDecision.BLOCK
    assert result.risk_score == 100
    assert result.reasons == (expected_reason,)


@pytest.mark.parametrize(
    ("field", "value", "expected_reason"),
    [
        ("account_age_days", 1.5, "Invalid account age"),
        ("account_age_days", "1", "Invalid account age"),
        ("account_age_days", None, "Invalid account age"),
        (
            "previous_interactions",
            1.5,
            "Invalid previous interaction count",
        ),
        (
            "previous_interactions",
            "1",
            "Invalid previous interaction count",
        ),
        (
            "previous_interactions",
            None,
            "Invalid previous interaction count",
        ),
    ],
)
def test_invalid_types_are_rejected_for_numeric_signals(
    field, value, expected_reason
):
    transaction = {
        "recipient": "alice.near",
        "amount_yocto": 0,
        "recipient_is_contract": False,
        "recipient_code_changed": False,
        "known_malicious": False,
        "previous_interactions": 5,
        "account_age_days": 100,
    }
    transaction[field] = value

    result = analyze_transaction(transaction)

    assert result.decision == RiskDecision.BLOCK
    assert result.risk_score == 100
    assert result.reasons == (expected_reason,)


@pytest.mark.parametrize(
    ("field", "expected_reason"),
    [
        ("account_age_days", "Invalid account age"),
        ("previous_interactions", "Invalid previous interaction count"),
    ],
)
def test_negative_values_are_rejected_for_numeric_signals(field, expected_reason):
    transaction = {
        "recipient": "alice.near",
        "amount_yocto": 0,
        "recipient_is_contract": False,
        "recipient_code_changed": False,
        "known_malicious": False,
        "previous_interactions": 5,
        "account_age_days": 100,
    }
    transaction[field] = -1

    result = analyze_transaction(transaction)

    assert result.decision == RiskDecision.BLOCK
    assert result.risk_score == 100
    assert result.reasons == (expected_reason,)


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


def test_code_change_does_not_add_risk_when_recipient_is_not_contract():
    result = analyze_transaction({
        "recipient": "alice.near",
        "amount_yocto": 5 * YOCTO_PER_NEAR,
        "recipient_is_contract": False,
        "recipient_code_changed": True,
        "known_malicious": False,
        "previous_interactions": 1,
        "account_age_days": 100,
    })

    assert result.decision == RiskDecision.ALLOW
    assert result.risk_score == 0
    assert "Recipient contract code changed" not in result.reasons


def test_contract_signal_adds_only_five_risk_points_without_code_change():
    result = analyze_transaction({
        "recipient": "contract.near",
        "amount_yocto": 5 * YOCTO_PER_NEAR,
        "recipient_is_contract": True,
        "recipient_code_changed": False,
        "known_malicious": False,
        "previous_interactions": 1,
        "account_age_days": 100,
    })

    assert result.decision == RiskDecision.ALLOW
    assert result.risk_score == 5
    assert result.reasons == ("Recipient is a smart contract",)
    assert "Recipient contract code changed" not in result.reasons


def test_invalid_recipient_is_blocked():
    result = analyze_transaction({
        "recipient": "",
        "amount_yocto": 1,
    })

    assert result.decision == RiskDecision.BLOCK


@pytest.mark.parametrize("recipient", [None, 123, " \t "])
def test_invalid_recipient_values_are_blocked(recipient):
    result = analyze_transaction({
        "recipient": recipient,
        "amount_yocto": 0,
        "recipient_is_contract": False,
        "recipient_code_changed": False,
        "known_malicious": False,
        "previous_interactions": 5,
        "account_age_days": 100,
    })

    assert result.decision == RiskDecision.BLOCK
    assert result.risk_score == 100
    assert result.reasons == ("Missing or invalid recipient",)


def test_missing_recipient_key_is_blocked():
    result = analyze_transaction({
        "amount_yocto": 0,
        "recipient_is_contract": False,
        "previous_interactions": 5,
        "account_age_days": 100,
    })

    assert result.decision == RiskDecision.BLOCK
    assert result.risk_score == 100
    assert "Missing or invalid recipient" in result.reasons


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


@pytest.mark.parametrize("amount_yocto", [None, "1"])
def test_none_and_string_amounts_are_blocked(amount_yocto):
    result = _analyze_with_amount(amount_yocto)

    assert result.decision == RiskDecision.BLOCK
    assert result.risk_score == 100
    assert result.reasons == ("Invalid transaction amount",)


@pytest.mark.parametrize("amount_yocto", [False, True])
def test_bool_amount_is_blocked(amount_yocto):
    result = _analyze_with_amount(amount_yocto)

    assert result.decision == RiskDecision.BLOCK
    assert result.reasons == ("Invalid transaction amount",)
