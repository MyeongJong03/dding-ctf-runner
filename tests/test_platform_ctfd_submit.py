import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path

from ctf_runner.platform_base import action_to_dict
from ctf_runner.platform_ctfd import CTFdPlatform


class FakeResponse:
    def __init__(self, payload: dict, status: int = 200):
        self.payload = json.dumps(payload).encode("utf-8")
        self.status = status

    def read(self, size: int = -1) -> bytes:
        return self.payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def make_flag(body: str = "unit_verified_value") -> str:
    return "FLAG" + "{" + body + "}"


class PlatformCTFdSubmitTests(unittest.TestCase):
    def _config(self, root: Path, *, allow_submission: bool = True) -> dict:
        secret_path = root / "token.txt"
        secret_path.write_text("token-value", encoding="utf-8")
        return {
            "platform": "ctfd",
            "name": "example",
            "base_url": "https://ctf.example.com",
            "auth": {"method": "api_token_file", "path": str(secret_path)},
            "policy": {
                "allow_live_discovery": False,
                "allow_live_download": False,
                "allow_submission": allow_submission,
                "allow_instance_start": False,
            },
        }

    def test_live_false_no_network_planned(self):
        with tempfile.TemporaryDirectory() as tmp:
            called = []

            def fake_open(request, timeout=0):
                called.append(request.full_url)
                raise AssertionError("network should not be called")

            platform = CTFdPlatform(config=self._config(Path(tmp)), urlopen=fake_open)
            action = platform.submit_flag("7", make_flag(), live=False)

            self.assertEqual(action.status, "planned")
            self.assertFalse(action.network)
            self.assertEqual(called, [])

    def test_live_true_policy_false_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            platform = CTFdPlatform(config=self._config(Path(tmp), allow_submission=False), urlopen=lambda request, timeout=0: None)
            action = platform.submit_flag("7", make_flag(), live=True, confirm=True)

            self.assertEqual(action.status, "blocked")
            self.assertEqual(action.details["reason"], "submission_not_allowed_by_policy")

    def test_live_true_no_confirm_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            called = []

            def fake_open(request, timeout=0):
                called.append(request.full_url)
                raise AssertionError("network should not be called")

            platform = CTFdPlatform(config=self._config(Path(tmp)), urlopen=fake_open)
            action = platform.submit_flag("7", make_flag(), live=True, confirm=False)

            self.assertEqual(action.status, "blocked")
            self.assertEqual(action.details["reason"], "live_submit_requires_confirm")
            self.assertEqual(called, [])

    def test_fake_http_accepted_response(self):
        with tempfile.TemporaryDirectory() as tmp:
            requests = []

            def fake_open(request, timeout=0):
                requests.append(request)
                return FakeResponse({"data": {"status": "correct", "message": "Correct"}})

            platform = CTFdPlatform(config=self._config(Path(tmp)), urlopen=fake_open)
            action = platform.submit_flag("7", make_flag(), live=True, confirm=True)

            self.assertEqual(action.status, "accepted")
            self.assertTrue(action.network)
            self.assertEqual(requests[0].full_url, "https://ctf.example.com/api/v1/challenges/attempt")

    def test_fake_http_rejected_response(self):
        with tempfile.TemporaryDirectory() as tmp:
            platform = CTFdPlatform(
                config=self._config(Path(tmp)),
                urlopen=lambda request, timeout=0: FakeResponse({"data": {"status": "incorrect", "message": "Incorrect"}}),
            )
            action = platform.submit_flag("7", make_flag("wrong_value"), live=True, confirm=True)

            self.assertEqual(action.status, "rejected")

    def test_fake_http_rate_limit_response(self):
        with tempfile.TemporaryDirectory() as tmp:
            def fake_open(request, timeout=0):
                raise urllib.error.HTTPError(
                    request.full_url,
                    429,
                    "Too Many Requests",
                    hdrs=None,
                    fp=io.BytesIO(b'{"message":"rate limit"}'),
                )

            platform = CTFdPlatform(config=self._config(Path(tmp)), urlopen=fake_open)
            action = platform.submit_flag("7", make_flag(), live=True, confirm=True)

            self.assertEqual(action.status, "rate_limited")
            self.assertEqual(action.details["result_summary_redacted"]["http_status"], 429)

    def test_raw_flag_not_logged(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = make_flag("secret_submission_value")
            platform = CTFdPlatform(
                config=self._config(Path(tmp)),
                urlopen=lambda request, timeout=0: FakeResponse({"data": {"status": "correct", "message": "Correct"}}),
            )
            action = platform.submit_flag("7", candidate, live=True, confirm=True)
            rendered = json.dumps(action_to_dict(action), sort_keys=True)

            self.assertNotIn(candidate, rendered)
            self.assertIn("flag_hash", rendered)


if __name__ == "__main__":
    unittest.main()
