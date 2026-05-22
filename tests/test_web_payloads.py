from __future__ import annotations

import json

from ctf_runner.web_payloads import generate_callback_payloads


def test_payload_snippets_generated_for_callback_url():
    data = generate_callback_payloads("https://example.trycloudflare.com/base")
    snippets = data["snippets"]

    assert data["status"] == "ok"
    assert set(snippets) == {"plain_url", "img_src", "script_src", "fetch", "css_url", "ssrf_url"}
    assert "{TOKEN_PLACEHOLDER}" in snippets["plain_url"]
    assert 'credentials: "omit"' in snippets["fetch"]


def test_payload_generation_does_not_leak_callback_query_secret():
    secret = "abc" + "def" + "ghi"
    data = generate_callback_payloads(f"https://example.trycloudflare.com/cb?token={secret}")
    rendered = json.dumps(data, sort_keys=True)

    assert secret not in rendered
    assert "token=" not in rendered
    assert "document.cookie" not in rendered
    assert data["callback_url"] == "https://example.trycloudflare.com/cb"
