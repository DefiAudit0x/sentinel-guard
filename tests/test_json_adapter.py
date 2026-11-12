import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from sentinel_guard.json_adapter import evaluate_request

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PYTHON = PROJECT_ROOT / ".venv" / "bin" / "python"
DEMO_POLICY_PATH = PROJECT_ROOT / "examples" / "test_policy.json"
POLICY_ENV_VAR = "SENTINEL_GUARD_POLICY_FILE"


def make_request(**updates):
    transaction = {
        "recipient": "alice.near",
        "amount_yocto": "1000000000000000000000000",
        "previous_interactions": 3,
        "account_age_days": 365,
    }
    intent = {
        "action": "transfer",
        "resource": "alice.near",
        "transaction": transaction,
    }
    request = {"request_id": "test-1", "intent": intent}
    for key, value in updates.items():
        request[key] = value
    return request


class JsonAdapterTests(unittest.TestCase):
    def evaluate(self, request, policy_path=DEMO_POLICY_PATH):
        return evaluate_request(request, policy_path)

    @staticmethod
    def write_policy(path, recipients):
        path.write_text(
            json.dumps({
                "version": 1,
                "default": "deny",
                "allowed_recipients": recipients,
                "max_amount_yocto": "20000000000000000000000000",
            }),
            encoding="utf-8",
        )

    def test_valid_transfer_returns_completed_allow_bound_to_request_and_intent(self):
        request = make_request()

        response = self.evaluate(request)

        canonical = json.dumps(
            request["intent"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        self.assertEqual(response["request_id"], "test-1")
        self.assertEqual(response["intent_hash"], hashlib.sha256(canonical).hexdigest())
        self.assertEqual(response["status"], "COMPLETED")
        self.assertEqual(response["decision"], "ALLOW")
        self.assertTrue(response["policy"]["allowed"])
        self.assertEqual(
            response["policy"]["matched_rule"],
            "json-policy-recipient-allow-list",
        )
        self.assertEqual(response["risk"]["decision"], "ALLOW")
        self.assertEqual(response["risk"]["risk_score"], 0)

    def test_explicit_recipient_is_allowed_at_the_exact_amount_cap(self):
        request = make_request()
        request["intent"]["transaction"]["amount_yocto"] = "20000000000000000000000000"

        response = self.evaluate(request)

        self.assertEqual((response["status"], response["decision"]), ("COMPLETED", "WARN"))
        self.assertTrue(response["policy"]["allowed"])

    def test_accepts_defiaudit_testnet_account_in_request_and_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            policy_path = Path(directory) / "policy.json"
            self.write_policy(policy_path, ["defiaudit0x.testnet"])
            request = make_request()
            request["intent"]["resource"] = "defiaudit0x.testnet"
            request["intent"]["transaction"]["recipient"] = "defiaudit0x.testnet"

            response = self.evaluate(request, policy_path=policy_path)

        self.assertEqual((response["status"], response["decision"]), ("COMPLETED", "ALLOW"))
        self.assertTrue(response["policy"]["allowed"])

    def test_rejects_malformed_account_ids_in_request_recipient_and_resource(self):
        invalid_ids = (
            "a",
            "Alice.testnet",
            ".alice",
            "alice.",
            "alice..testnet",
            "alice--testnet",
            "alice/testnet",
            "alice testnet",
            "é.testnet",
            "a" * 65,
        )
        for account_id in invalid_ids:
            with self.subTest(field="recipient", account_id=account_id):
                request = make_request()
                request["intent"]["transaction"]["recipient"] = account_id
                response = self.evaluate(request)
                self.assertEqual(response["status"], "INVALID_INPUT")
                self.assertEqual(response["decision"], "BLOCK")
                self.assertEqual(response["policy"]["status"], "NOT_EVALUATED")
                self.assertEqual(response["risk"]["status"], "NOT_EVALUATED")

            with self.subTest(field="resource", account_id=account_id):
                request = make_request()
                request["intent"]["resource"] = account_id
                response = self.evaluate(request)
                self.assertEqual(response["status"], "INVALID_INPUT")
                self.assertEqual(response["decision"], "BLOCK")
                self.assertEqual(response["policy"]["status"], "NOT_EVALUATED")
                self.assertEqual(response["risk"]["status"], "NOT_EVALUATED")

    def test_rejects_malformed_account_ids_in_local_policy(self):
        invalid_ids = (
            "a", "Alice.testnet", ".alice", "alice.", "alice..testnet",
            "alice/testnet", "a" * 65,
        )
        for account_id in invalid_ids:
            with self.subTest(account_id=account_id), tempfile.TemporaryDirectory() as directory:
                policy_path = Path(directory) / "policy.json"
                self.write_policy(policy_path, [account_id])
                response = self.evaluate(make_request(), policy_path=policy_path)
                self.assertEqual((response["status"], response["decision"]), ("ERROR", "BLOCK"))
                self.assertEqual(response["policy"]["status"], "ERROR")
                self.assertEqual(response["policy"]["error_stage"], "CONTRACT")

    def test_unapproved_recipient_is_denied_by_the_allow_list(self):
        request = make_request()
        request["intent"]["resource"] = "mallory.near"
        request["intent"]["transaction"]["recipient"] = "mallory.near"

        response = self.evaluate(request)

        self.assertEqual((response["status"], response["decision"]), ("COMPLETED", "BLOCK"))
        self.assertFalse(response["policy"]["allowed"])
        self.assertEqual(response["policy"]["reason"], "recipient_not_allowed")

    def test_amount_over_exact_decimal_cap_is_denied(self):
        request = make_request()
        request["intent"]["transaction"]["amount_yocto"] = "20000000000000000000000001"

        response = self.evaluate(request)

        self.assertEqual((response["status"], response["decision"]), ("COMPLETED", "BLOCK"))
        self.assertFalse(response["policy"]["allowed"])
        self.assertEqual(response["policy"]["reason"], "amount_limit_exceeded")

    def test_missing_policy_path_fails_closed(self):
        response = self.evaluate(make_request(), policy_path=None)

        self.assertEqual((response["status"], response["decision"]), ("ERROR", "BLOCK"))
        self.assertEqual(response["policy"]["status"], "ERROR")
        self.assertEqual(response["policy"]["error_stage"], "LOOKUP")
        self.assertEqual(response["risk"]["status"], "NOT_EVALUATED")

    def test_malformed_policy_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            policy_path = Path(directory) / "policy.json"
            policy_path.write_text('{"version":', encoding="utf-8")

            response = self.evaluate(make_request(), policy_path=policy_path)

        self.assertEqual((response["status"], response["decision"]), ("ERROR", "BLOCK"))
        self.assertEqual(response["policy"]["status"], "ERROR")
        self.assertEqual(response["policy"]["error_stage"], "CONTRACT")

    def test_invalid_policy_schema_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            policy_path = Path(directory) / "policy.json"
            policy_path.write_text('{"version": 1, "default": "allow"}', encoding="utf-8")

            response = self.evaluate(make_request(), policy_path=policy_path)

        self.assertEqual((response["status"], response["decision"]), ("ERROR", "BLOCK"))
        self.assertEqual(response["policy"]["status"], "ERROR")
        self.assertEqual(response["policy"]["error_stage"], "CONTRACT")

    def test_rejects_unsupported_action_and_extra_transaction_fields(self):
        call_request = make_request()
        call_request["intent"]["action"] = "function_call"
        extra_field_request = make_request()
        extra_field_request["intent"]["transaction"]["method_name"] = "transfer"

        for request in (call_request, extra_field_request):
            with self.subTest(request=request):
                response = self.evaluate(request)
                self.assertEqual(response["status"], "INVALID_INPUT")
                self.assertEqual(response["decision"], "BLOCK")
                self.assertEqual(response["policy"]["status"], "NOT_EVALUATED")

    def test_rejects_noncanonical_or_non_string_amount(self):
        for amount in (1, "01", "-1", "1.0", "x" * 81):
            with self.subTest(amount=amount):
                request = make_request()
                request["intent"]["transaction"]["amount_yocto"] = amount
                response = self.evaluate(request)
                self.assertEqual(response["status"], "INVALID_INPUT")
                self.assertEqual(response["decision"], "BLOCK")

    def test_risk_warning_and_block_are_returned_as_completed_not_allow(self):
        warning = make_request()
        warning["intent"]["transaction"]["amount_yocto"] = "11000000000000000000000000"
        blocked = make_request()
        blocked["intent"]["transaction"]["known_malicious"] = True

        warning_response = self.evaluate(warning)
        blocked_response = self.evaluate(blocked)

        self.assertEqual((warning_response["status"], warning_response["decision"]), ("COMPLETED", "WARN"))
        self.assertEqual((blocked_response["status"], blocked_response["decision"]), ("COMPLETED", "BLOCK"))

    def test_benign_risk_reason_can_coexist_with_completed_allow(self):
        request = make_request()
        request["intent"]["transaction"]["account_age_days"] = 1

        response = self.evaluate(request)

        self.assertEqual((response["status"], response["decision"]), ("COMPLETED", "ALLOW"))
        self.assertEqual(response["risk"]["risk_score"], 15)
        self.assertEqual(
            response["risk"]["reasons"], ["Account is less than 7 days old"]
        )
        self.assertEqual(
            response["reasons"], ["Risk: Account is less than 7 days old"]
        )

    def test_resource_mismatch_is_invalid_input(self):
        request = make_request()
        request["intent"]["resource"] = "mallory.near"

        response = self.evaluate(request)

        self.assertEqual(response["status"], "INVALID_INPUT")
        self.assertEqual(response["decision"], "BLOCK")

    def test_explicit_resource_rejects_missing_or_invalid_recipient(self):
        requests = []
        missing_recipient = make_request()
        del missing_recipient["intent"]["transaction"]["recipient"]
        requests.append(("missing", missing_recipient))
        for label, recipient in (("null", None), ("non-string", 123), ("empty", ""), ("whitespace", " \t ")):
            request = make_request()
            request["intent"]["transaction"]["recipient"] = recipient
            requests.append((label, request))

        for label, request in requests:
            with self.subTest(recipient=label):
                response = self.evaluate(request)
                self.assertEqual(response["status"], "INVALID_INPUT")
                self.assertEqual(response["decision"], "BLOCK")
                self.assertEqual(response["policy"]["status"], "NOT_EVALUATED")
                self.assertEqual(response["risk"]["status"], "NOT_EVALUATED")

    def test_cli_reads_one_json_request_and_writes_one_response(self):
        request = make_request()
        completed = subprocess.run(
            [str(PYTHON), "-I", "-S", str(PROJECT_ROOT / "sentinel_guard" / "json_adapter.py")],
            input=json.dumps(request),
            capture_output=True,
            text=True,
            env={**os.environ, POLICY_ENV_VAR: str(DEMO_POLICY_PATH)},
            cwd=PROJECT_ROOT,
            check=False,
            timeout=5,
        )

        self.assertEqual(completed.returncode, 0, msg=completed.stderr)
        self.assertEqual(completed.stderr, "")
        response = json.loads(completed.stdout)
        self.assertEqual(response["request_id"], request["request_id"])
        self.assertEqual(response["status"], "COMPLETED")
        self.assertEqual(response["decision"], "ALLOW")

    def test_cli_fails_closed_when_policy_is_unset(self):
        completed = subprocess.run(
            [str(PYTHON), "-I", "-S", str(PROJECT_ROOT / "sentinel_guard" / "json_adapter.py")],
            input=json.dumps(make_request()),
            capture_output=True,
            text=True,
            env={key: value for key, value in os.environ.items() if key != POLICY_ENV_VAR},
            cwd=PROJECT_ROOT,
            check=False,
            timeout=5,
        )

        self.assertEqual(completed.returncode, 0, msg=completed.stderr)
        response = json.loads(completed.stdout)
        self.assertEqual((response["status"], response["decision"]), ("ERROR", "BLOCK"))
        self.assertEqual(response["policy"]["error_stage"], "LOOKUP")

    def test_cli_fails_closed_on_malformed_json(self):
        completed = subprocess.run(
            [str(PYTHON), "-I", "-S", str(PROJECT_ROOT / "sentinel_guard" / "json_adapter.py")],
            input="{not json",
            capture_output=True,
            text=True,
            cwd=PROJECT_ROOT,
            check=False,
            timeout=5,
        )

        self.assertEqual(completed.returncode, 0, msg=completed.stderr)
        response = json.loads(completed.stdout)
        self.assertEqual(response["status"], "ERROR")
        self.assertEqual(response["decision"], "BLOCK")
        self.assertEqual(response["policy"]["status"], "NOT_EVALUATED")

    def test_cli_rejects_duplicate_keys_in_raw_json_request(self):
        request = make_request()
        raw_request = '{"request_id":"first",' + json.dumps(request)[1:]
        completed = subprocess.run(
            [str(PYTHON), "-I", "-S", str(PROJECT_ROOT / "sentinel_guard" / "json_adapter.py")],
            input=raw_request,
            capture_output=True,
            text=True,
            env={**os.environ, POLICY_ENV_VAR: str(DEMO_POLICY_PATH)},
            cwd=PROJECT_ROOT,
            check=False,
            timeout=5,
        )

        self.assertEqual(completed.returncode, 0, msg=completed.stderr)
        response = json.loads(completed.stdout)
        self.assertEqual(response["status"], "ERROR")
        self.assertEqual(response["decision"], "BLOCK")
        self.assertEqual(response["policy"]["status"], "NOT_EVALUATED")


if __name__ == "__main__":
    unittest.main()
