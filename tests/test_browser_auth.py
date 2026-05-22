import json
from pathlib import Path

from ctf_runner.browser_auth import capture_storage_state, storage_state_summary


def test_storage_state_summary_redacts_cookie_and_storage_values(tmp_path: Path):
    state_path = tmp_path / "state.json"
    state_path.write_text(
        json.dumps(
            {
                "cookies": [
                    {"name": "session", "value": "raw-cookie-value", "domain": ".ctf.example.com"},
                    {"name": "csrf", "value": "raw-csrf-value", "domain": "ctf.example.com"},
                ],
                "origins": [
                    {
                        "origin": "https://ctf.example.com",
                        "localStorage": [{"name": "authToken", "value": "raw-local-storage-value"}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    summary = storage_state_summary(state_path)
    rendered = json.dumps(summary, sort_keys=True)

    assert summary["status"] == "ok"
    assert summary["cookie_count"] == 2
    assert summary["origin_count"] == 1
    assert summary["domains"] == ["ctf.example.com"]
    assert summary["origins"][0]["local_storage_keys"] == ["authToken"]
    assert "raw-cookie-value" not in rendered
    assert "raw-csrf-value" not in rendered
    assert "raw-local-storage-value" not in rendered


def test_capture_storage_planned_mode_does_not_create_output(tmp_path: Path):
    profile_path = tmp_path / "platform.yaml"
    output_path = tmp_path / "state.json"
    profile_path.write_text(
        "\n".join(
            [
                "platform: generic",
                "name: unit",
                "base_url: https://ctf.example.com",
                "contest_url: https://ctf.example.com/contests/demo?token=query-secret",
                "auth:",
                "  method: manual",
            ]
        ),
        encoding="utf-8",
    )

    result = capture_storage_state(profile_path, output_path, live=False, headed=True, timeout_sec=1)
    rendered = json.dumps(result, sort_keys=True)

    assert result["status"] == "planned"
    assert result["live_required"] is True
    assert not output_path.exists()
    assert "query-secret" not in rendered
    assert "?token=" not in rendered


def test_storage_check_missing_is_graceful(tmp_path: Path):
    summary = storage_state_summary(tmp_path / "missing.storage_state.json")

    assert summary["status"] == "missing"
    assert summary["path_exists"] is False
    assert summary["warning"] == "storage_state_path_missing"
