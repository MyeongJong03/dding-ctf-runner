import unittest

from ctf_runner.redact import redact_text


class RedactTests(unittest.TestCase):
    def test_redacts_flag_cookie_bearer_and_query_secret(self):
        dummy_flag = "DH" + "{dummy_test_value}"
        bearer_value = "abcdef" + "ghijklmnop"
        session_value = "abc" + "def"
        text = (
            f"Authorization: Bearer {bearer_value}\n"
            f"Cookie: sessionid={session_value}; theme=dark\n"
            f"url=https://example.invalid/path?token={session_value}&safe=1\n"
            f"candidate={dummy_flag}\n"
        )
        redacted = redact_text(text)
        self.assertNotIn(bearer_value, redacted)
        self.assertNotIn(f"sessionid={session_value}", redacted)
        self.assertNotIn(f"token={session_value}", redacted)
        self.assertNotIn(dummy_flag, redacted)
        self.assertIn("[REDACTED]", redacted)

    def test_redacts_cookie_like_keys_with_dots_and_hyphens(self):
        text = "Invalid header value b'auth-token.0 : base64-secret-cookie-fragment'"
        redacted = redact_text(text)

        self.assertNotIn("base64-secret-cookie-fragment", redacted)
        self.assertIn("[REDACTED]", redacted)


if __name__ == "__main__":
    unittest.main()
