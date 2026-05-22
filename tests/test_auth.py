import json
import tempfile
import unittest
from pathlib import Path

from ctf_runner.auth import load_auth_metadata, load_auth_secret


class AuthTests(unittest.TestCase):
    def test_metadata_reads_only_path_information(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            secret_path = tmp_path / "example.token"
            secret_path.write_text("super-secret-token\n", encoding="utf-8")
            config_path = tmp_path / "platform.yaml"
            config_path.write_text(
                "\n".join(
                    [
                        "platform: ctfd",
                        "name: example",
                        "base_url: https://ctf.example.com",
                        "auth:",
                        "  method: api_token_file",
                        f"  path: {secret_path}",
                    ]
                ),
                encoding="utf-8",
            )

            metadata = load_auth_metadata(config_path)

            self.assertTrue(metadata["config_exists"])
            self.assertEqual(metadata["method"], "api_token_file")
            self.assertTrue(metadata["path_exists"])
            self.assertNotIn("super-secret-token", json.dumps(metadata))

    def test_secret_repr_is_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            secret_path = tmp_path / "cookie.txt"
            secret_path.write_text("session=abc123", encoding="utf-8")
            config = {
                "platform": "ctfd",
                "base_url": "https://ctf.example.com",
                "auth": {"method": "cookie_header_file", "path": str(secret_path)},
            }

            secret = load_auth_secret(config, live=True)

            self.assertEqual(secret.method, "cookie_header_file")
            self.assertIn("cookie_header_file", repr(secret))
            self.assertNotIn("abc123", repr(secret))
            self.assertEqual(secret.build_headers()["Cookie"], "session=abc123")

    def test_cookie_header_file_normalizes_multiline_headers(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            secret_path = tmp_path / "cookie.txt"
            secret_path.write_text("Cookie: session=abc123\ncsrf-token.0 : base64-value", encoding="utf-8")
            config = {
                "platform": "generic",
                "base_url": "https://ctf.example.com",
                "auth": {"method": "cookie_header_file", "path": str(secret_path)},
            }

            secret = load_auth_secret(config, live=True)
            cookie_header = secret.build_headers()["Cookie"]

            self.assertEqual(cookie_header, "session=abc123; csrf-token.0=base64-value")

    def test_storage_state_cookie_header_filters_by_host(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            state_path = tmp_path / "storage_state.json"
            state_path.write_text(
                json.dumps(
                    {
                        "cookies": [
                            {"name": "session", "value": "keepme", "domain": ".ctf.example.com"},
                            {"name": "other", "value": "skipme", "domain": ".other.example.com"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            config = {
                "platform": "ctfd",
                "base_url": "https://ctf.example.com",
                "auth": {"method": "storage_state_file", "path": str(state_path)},
            }

            secret = load_auth_secret(config, live=True)
            headers = secret.build_headers(base_url="https://ctf.example.com")

            self.assertIn("session=keepme", headers["Cookie"])
            self.assertNotIn("skipme", headers["Cookie"])
            self.assertNotIn("keepme", repr(secret))

    def test_secret_loading_requires_live(self):
        with tempfile.TemporaryDirectory() as tmp:
            secret_path = Path(tmp) / "token.txt"
            secret_path.write_text("top-secret", encoding="utf-8")
            config = {"auth": {"method": "api_token_file", "path": str(secret_path)}}

            with self.assertRaises(ValueError):
                load_auth_secret(config, live=False)


if __name__ == "__main__":
    unittest.main()
