import json
from pathlib import Path

from ctf_runner.platform_base import action_to_dict
from ctf_runner.platform_generic import (
    GenericPlatform,
    browser_network_summary,
    cookie_header_to_browser_cookies,
    should_block_browser_request,
)


def test_browser_network_summary_redacts_query():
    summary = browser_network_summary(
        "https://ctf.example.com/api/challenges?token=secret-value&id=1",
        "GET",
        200,
        "application/json; charset=utf-8",
    )
    rendered = json.dumps(summary, sort_keys=True)

    assert summary["path"] == "/api/challenges"
    assert summary["method"] == "GET"
    assert summary["content_type"] == "application/json"
    assert "secret-value" not in rendered
    assert "?token=" not in rendered


def test_browser_request_policy_blocks_post_and_destructive_paths():
    assert should_block_browser_request("POST", "https://ctf.example.com/api/challenges")[0] is True
    assert should_block_browser_request("GET", "https://ctf.example.com/api/challenges/attempt")[0] is True
    assert should_block_browser_request("GET", "https://ctf.example.com/login")[0] is False
    assert should_block_browser_request("GET", "https://ctf.example.com/contests/demo")[0] is False


def test_cookie_header_conversion_is_internal_only():
    cookies = cookie_header_to_browser_cookies("session=raw-cookie-value; csrf=raw-csrf-value", "https://ctf.example.com")
    names = {item["name"] for item in cookies}

    assert names == {"session", "csrf"}
    assert all(item["domain"] == "ctf.example.com" for item in cookies)


def test_browser_discover_dry_run_does_not_emit_cookie(tmp_path: Path):
    secret_path = tmp_path / "cookie.txt"
    secret_path.write_text("session=raw-cookie-value", encoding="utf-8")
    platform = GenericPlatform(
        config={
            "platform": "generic",
            "name": "unit",
            "base_url": "https://ctf.example.com",
            "contest_url": "https://ctf.example.com/contests/demo",
            "auth": {"method": "cookie_header_file", "path": str(secret_path)},
            "policy": {
                "allow_live_discovery": True,
                "allow_live_download": False,
                "allow_submission": False,
                "allow_instance_start": False,
            },
        }
    )

    action = platform.browser_discover(live=False)
    rendered = json.dumps(action_to_dict(action), sort_keys=True)

    assert action.status == "planned"
    assert "raw-cookie-value" not in rendered
    assert "session=" not in rendered
