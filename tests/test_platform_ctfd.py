import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from ctf_runner.platform_ctfd import CTFdPlatform


class FakeResponse:
    def __init__(self, payload: bytes):
        self.payload = payload
        self.offset = 0

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = len(self.payload) - self.offset
        chunk = self.payload[self.offset : self.offset + size]
        self.offset += len(chunk)
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class PlatformCTFdTests(unittest.TestCase):
    def _config(self, root: Path) -> dict:
        secret_path = root / "token.txt"
        secret_path.write_text("token-value", encoding="utf-8")
        return {
            "platform": "ctfd",
            "name": "example",
            "base_url": "https://ctf.example.com",
            "auth": {"method": "api_token_file", "path": str(secret_path)},
            "policy": {
                "allow_live_discovery": True,
                "allow_live_download": True,
                "allow_submission": False,
                "allow_instance_start": False,
            },
            "downloads": {"root": str(root / "contests")},
        }

    def test_live_false_does_not_touch_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            called = []

            def fake_open(request, timeout=0):
                called.append(request.full_url)
                raise AssertionError("network should not be called")

            platform = CTFdPlatform(config=self._config(Path(tmp)), urlopen=fake_open)

            action = platform.discover_challenges(live=False)

            self.assertEqual(action.status, "planned")
            self.assertEqual(called, [])

    def test_policy_gate_blocks_live_discovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self._config(Path(tmp))
            config["policy"]["allow_live_discovery"] = False
            platform = CTFdPlatform(config=config, urlopen=lambda request, timeout=0: None)

            action = platform.discover_challenges(live=True)

            self.assertEqual(action.status, "blocked")
            self.assertEqual(action.details["reason"], "live_discovery_not_allowed_by_policy")

    def test_discover_and_get_parse_ctfd_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            def fake_open(request, timeout=0):
                if request.full_url.endswith("/api/v1/challenges"):
                    return FakeResponse(
                        json.dumps(
                            {
                                "data": [
                                    {
                                        "id": 7,
                                        "name": "Warmup",
                                        "category": "web",
                                        "value": 100,
                                        "solves": 12,
                                        "tags": [{"value": "intro"}],
                                        "files": ["/files/warmup.zip?token=secret"],
                                        "connection_info": "nc host 31337",
                                    }
                                ]
                            }
                        ).encode("utf-8")
                    )
                return FakeResponse(
                    json.dumps(
                        {
                            "data": {
                                "id": 7,
                                "name": "Warmup",
                                "category": "web",
                                "value": 100,
                                "solves": 12,
                                "files": [{"url": "/files/warmup.zip?token=secret", "name": "warmup.zip"}],
                            }
                        }
                    ).encode("utf-8")
                )

            platform = CTFdPlatform(config=self._config(Path(tmp)), urlopen=fake_open)

            discover = platform.discover_challenges(live=True)
            detail = platform.get_challenge("7", live=True)

            self.assertEqual(discover.status, "ok")
            self.assertEqual(discover.details["challenge_count"], 1)
            self.assertTrue(discover.details["challenges"][0]["has_files"])
            self.assertEqual(detail.details["attachment_count"], 1)
            self.assertNotIn("token=secret", json.dumps(detail.details))

    def test_download_sanitizes_filename_and_redacts_signed_url(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)

            def fake_open(request, timeout=0):
                if request.full_url.endswith("/api/v1/challenges/9"):
                    return FakeResponse(
                        json.dumps(
                            {
                                "data": {
                                    "id": 9,
                                    "name": "Download",
                                    "category": "misc",
                                    "files": [
                                        {
                                            "url": "https://ctf.example.com/files/download?token=secret&id=1",
                                            "name": "../evil name?.txt",
                                        }
                                    ],
                                }
                            }
                        ).encode("utf-8")
                    )
                if request.full_url.startswith("https://ctf.example.com/files/download"):
                    return FakeResponse(b"hello attachment")
                raise AssertionError(f"unexpected url {request.full_url}")

            platform = CTFdPlatform(config=self._config(tmp_path), urlopen=fake_open)
            action = platform.download_attachments("9", live=True)

            self.assertEqual(action.status, "ok")
            self.assertEqual(action.details["download_count"], 1)
            download = action.details["downloads"][0]
            self.assertEqual(download["filename"], "evil_name_.txt")
            self.assertTrue(Path(download["fs_path"]).exists())
            self.assertEqual(download["sha256"], hashlib.sha256(b"hello attachment").hexdigest())
            self.assertNotIn("token=secret", json.dumps(action.details))

    def test_submit_policy_gate_blocks_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            called = []

            def fake_open(request, timeout=0):
                called.append(request.full_url)
                raise AssertionError("submit should not perform network")

            platform = CTFdPlatform(config=self._config(Path(tmp)), urlopen=fake_open)
            action = platform.submit_flag("1", "FLAG" + "{unit_value}", live=True, confirm=True)

            self.assertEqual(action.status, "blocked")
            self.assertEqual(action.details["reason"], "submission_not_allowed_by_policy")
            self.assertEqual(called, [])


if __name__ == "__main__":
    unittest.main()
