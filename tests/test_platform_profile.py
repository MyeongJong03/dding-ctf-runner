import json
from pathlib import Path

from ctf_runner.platform_profile import create_platform_profile, validate_platform_profile


def test_profile_create_and_check_defaults_to_readonly_destructive_false(tmp_path: Path):
    secret_path = tmp_path / "ctfd.token"
    secret_path.write_text("raw-secret-token-value", encoding="utf-8")
    profile_path = tmp_path / "platform.local.yaml"

    created = create_platform_profile(
        contest_id="unit contest",
        base_url="https://ctf.example.com",
        auth_method="api_token_file",
        auth_path=str(secret_path),
        output_path=profile_path,
    )
    checked = validate_platform_profile(profile_path)

    assert created["status"] == "ok"
    assert checked["status"] == "ok"
    assert checked["policy"]["allow_live_discovery"] is True
    assert checked["policy"]["allow_live_download"] is True
    assert checked["policy"]["allow_submission"] is False
    assert checked["policy"]["allow_instance_start"] is False


def test_profile_check_reports_auth_path_metadata_only(tmp_path: Path):
    secret_path = tmp_path / "ctfd.cookie"
    secret_path.write_text("session=raw-cookie-value", encoding="utf-8")
    profile_path = tmp_path / "platform.local.yaml"
    profile_path.write_text(
        "\n".join(
            [
                "platform: ctfd",
                "name: unit",
                "base_url: https://ctf.example.com",
                "auth:",
                "  method: cookie_header_file",
                f"  path: {secret_path}",
                "policy:",
                "  allow_live_discovery: true",
                "  allow_live_download: true",
                "  allow_submission: false",
                "  allow_instance_start: false",
            ]
        ),
        encoding="utf-8",
    )

    checked = validate_platform_profile(profile_path)
    rendered = json.dumps(checked, sort_keys=True)

    assert checked["auth"]["path_exists"] is True
    assert "raw-cookie-value" not in rendered
    assert "session=" not in rendered


def test_profile_check_embedded_credentials_warning_and_redaction(tmp_path: Path):
    profile_path = tmp_path / "platform.local.yaml"
    profile_path.write_text(
        "\n".join(
            [
                "platform: ctfd",
                "name: unit",
                "base_url: https://user:pass@ctf.example.com/path?token=query-value",
                "auth:",
                "  method: manual",
                "policy:",
                "  allow_live_discovery: true",
                "  allow_live_download: true",
                "  allow_submission: false",
                "  allow_instance_start: false",
            ]
        ),
        encoding="utf-8",
    )

    checked = validate_platform_profile(profile_path)
    rendered = json.dumps(checked, sort_keys=True)

    assert checked["status"] == "invalid"
    assert "base_url_embedded_credentials" in checked["warnings"]
    assert "user:pass" not in rendered
    assert "query-value" not in rendered


def test_profile_check_missing_policy_defaults_submission_false(tmp_path: Path):
    profile_path = tmp_path / "platform.local.yaml"
    profile_path.write_text(
        "\n".join(
            [
                "platform: ctfd",
                "name: unit",
                "base_url: https://ctf.example.com",
                "auth:",
                "  method: manual",
            ]
        ),
        encoding="utf-8",
    )

    checked = validate_platform_profile(profile_path)

    assert checked["status"] == "ok"
    assert checked["policy"]["allow_submission"] is False
    assert checked["policy"]["allow_instance_start"] is False


def test_profile_check_accepts_generic_with_contest_url(tmp_path: Path):
    secret_path = tmp_path / "ctfd.cookie"
    secret_path.write_text("session=raw-cookie-value", encoding="utf-8")
    profile_path = tmp_path / "generic.local.yaml"
    profile_path.write_text(
        "\n".join(
            [
                "platform: generic",
                "name: unit",
                "base_url: https://ctf.example.com",
                "contest_url: https://ctf.example.com/contests/demo?token=query-secret",
                "auth:",
                "  method: cookie_header_file",
                f"  path: {secret_path}",
                "policy:",
                "  allow_live_discovery: true",
                "  allow_live_download: true",
                "  allow_submission: false",
                "  allow_instance_start: false",
            ]
        ),
        encoding="utf-8",
    )

    checked = validate_platform_profile(profile_path)
    rendered = json.dumps(checked, sort_keys=True)

    assert checked["status"] == "ok"
    assert "contest_url_query_string_present" in checked["warnings"]
    assert checked["profile"]["contest_url"] == "https://ctf.example.com/contests/demo"
    assert "raw-cookie-value" not in rendered
    assert "query-secret" not in rendered
