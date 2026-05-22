import json
from pathlib import Path

from ctf_runner.auth import load_auth_metadata, load_auth_secret
from ctf_runner.platform_profile import add_platform_profile_auth_fallback, set_platform_profile_auth, validate_platform_profile


def test_auth_metadata_reports_primary_and_fallback_without_raw_values(tmp_path: Path):
    cookie_path = tmp_path / "ctfd.cookie"
    cookie_path.write_text("session=raw-cookie-value", encoding="utf-8")
    profile_path = tmp_path / "platform.yaml"
    profile_path.write_text(
        "\n".join(
            [
                "platform: generic",
                "name: unit",
                "base_url: https://ctf.example.com",
                "contest_url: https://ctf.example.com/contests/demo",
                "auth:",
                "  method: storage_state_file",
                f"  path: {tmp_path / 'missing.storage_state.json'}",
                "  fallback:",
                "    - method: cookie_header_file",
                f"      path: {cookie_path}",
            ]
        ),
        encoding="utf-8",
    )

    metadata = load_auth_metadata(profile_path)
    rendered = json.dumps(metadata, sort_keys=True)

    assert metadata["method"] == "storage_state_file"
    assert metadata["path_exists"] is False
    assert metadata["fallback"][0]["method"] == "cookie_header_file"
    assert metadata["fallback"][0]["path_exists"] is True
    assert metadata["effective_method"] == "cookie_header_file"
    assert "raw-cookie-value" not in rendered
    assert "session=" not in rendered


def test_auth_secret_uses_first_available_fallback(tmp_path: Path):
    cookie_path = tmp_path / "ctfd.cookie"
    cookie_path.write_text("session=raw-cookie-value", encoding="utf-8")
    config = {
        "auth": {
            "method": "storage_state_file",
            "path": str(tmp_path / "missing.storage_state.json"),
            "fallback": [{"method": "cookie_header_file", "path": str(cookie_path)}],
        }
    }

    secret = load_auth_secret(config, live=True)

    assert secret.method == "cookie_header_file"
    assert secret.source_role == "fallback"
    assert secret.build_headers()["Cookie"] == "session=raw-cookie-value"
    assert "raw-cookie-value" not in repr(secret)


def test_profile_check_backward_compatible_single_auth(tmp_path: Path):
    cookie_path = tmp_path / "ctfd.cookie"
    cookie_path.write_text("session=raw-cookie-value", encoding="utf-8")
    profile_path = tmp_path / "platform.yaml"
    profile_path.write_text(
        "\n".join(
            [
                "platform: ctfd",
                "name: unit",
                "base_url: https://ctf.example.com",
                "auth:",
                "  method: cookie_header_file",
                f"  path: {cookie_path}",
            ]
        ),
        encoding="utf-8",
    )

    checked = validate_platform_profile(profile_path)

    assert checked["status"] == "ok"
    assert checked["auth"]["method"] == "cookie_header_file"
    assert checked["auth"]["fallback"] == []


def test_profile_auth_helpers_preserve_fallback_metadata_only(tmp_path: Path):
    cookie_path = tmp_path / "ctfd.cookie"
    cookie_path.write_text("session=raw-cookie-value", encoding="utf-8")
    profile_path = tmp_path / "platform.yaml"
    profile_path.write_text(
        "\n".join(
            [
                "platform: generic",
                "name: unit",
                "base_url: https://ctf.example.com",
                "contest_url: https://ctf.example.com/contests/demo",
                "auth:",
                "  method: manual",
                "policy:",
                "  allow_live_discovery: true",
                "  allow_live_download: false",
                "  allow_submission: false",
                "  allow_instance_start: false",
            ]
        ),
        encoding="utf-8",
    )

    set_platform_profile_auth(profile_path, "storage_state_file", str(tmp_path / "missing.storage_state.json"))
    checked = add_platform_profile_auth_fallback(profile_path, "cookie_header_file", str(cookie_path))
    rendered = json.dumps(checked, sort_keys=True)

    assert checked["auth"]["method"] == "storage_state_file"
    assert checked["auth"]["fallback"][0]["method"] == "cookie_header_file"
    assert "auth_path_missing" in checked["warnings"]
    assert "raw-cookie-value" not in rendered
    assert "session=" not in rendered
