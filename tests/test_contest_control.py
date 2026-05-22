import contextlib
import io
import json
from pathlib import Path
from typing import Any

from ctf_runner.cli import main


def test_prestart_no_network_and_storage_summary(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CTF_RUNNER_STATE_ROOT", str(tmp_path / "runner-state"))
    monkeypatch.setattr("ctf_runner.cli.collect_preflight", lambda deep=False, **kwargs: _preflight_stub())

    def fail_live_load(config):
        raise AssertionError("prestart must not load a live platform unless requested")

    monkeypatch.setattr("ctf_runner.cli._load_platform", fail_live_load)
    storage = tmp_path / "storage_state.json"
    storage.write_text(
        json.dumps(
            {
                "cookies": [{"name": "session", "value": "supersecret-cookie-value", "domain": "ctf.example.com"}],
                "origins": [
                    {
                        "origin": "https://ctf.example.com",
                        "localStorage": [{"name": "auth-key", "value": "supersecret-local-value"}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    profile = _write_profile(tmp_path, storage)

    result, code, raw = _run_json(
        [
            "contest",
            "prestart",
            "--contest-id",
            "example",
            "--profile",
            str(profile),
            "--json",
        ]
    )

    assert code == 0
    assert result["status"] == "ok"
    assert result["live_readonly_check"]["attempted"] is False
    assert result["profile_path"]
    assert result["armed"] is False
    assert result["storage_checks"][0]["summary"]["status"] == "ok"
    assert result["storage_checks"][0]["summary"]["cookie_count"] == 1
    assert "supersecret" not in raw


def test_arm_requires_confirm(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CTF_RUNNER_STATE_ROOT", str(tmp_path / "runner-state"))
    profile = _write_profile(tmp_path)

    result, code, _ = _run_json(
        [
            "contest",
            "arm",
            "--contest-id",
            "example",
            "--profile",
            str(profile),
            "--json",
        ]
    )

    assert code == 1
    assert result["status"] == "blocked"
    assert result["reason"] == "confirm_competition_required"


def test_arm_defaults_allow_live_submit_true(monkeypatch, tmp_path: Path):
    state_root = tmp_path / "runner-state"
    monkeypatch.setenv("CTF_RUNNER_STATE_ROOT", str(state_root))
    profile = _write_profile(tmp_path)

    result, code, _ = _run_json(
        [
            "contest",
            "arm",
            "--contest-id",
            "example",
            "--profile",
            str(profile),
            "--confirm-competition",
            "--max-workers",
            "3",
            "--max-parallel-codex",
            "2",
            "--json",
        ]
    )

    assert code == 0
    assert result["status"] == "armed"
    control_path = state_root / "contests" / "example" / "control.json"
    lock_path = state_root / "contests" / "example" / "arm.lock"
    assert control_path.exists()
    assert lock_path.exists()
    control = json.loads(control_path.read_text(encoding="utf-8"))
    assert control["armed"] is True
    assert control["run_mode"] == "competition"
    assert control["allow_live_submit"] is True
    assert control["max_workers"] == 3


def test_arm_no_live_submit_sets_false(monkeypatch, tmp_path: Path):
    state_root = tmp_path / "runner-state"
    monkeypatch.setenv("CTF_RUNNER_STATE_ROOT", str(state_root))
    profile = _write_profile(tmp_path)

    result, code, _ = _run_json(
        [
            "contest",
            "arm",
            "--contest-id",
            "example",
            "--profile",
            str(profile),
            "--confirm-competition",
            "--no-live-submit",
            "--json",
        ]
    )

    assert code == 0
    assert result["status"] == "armed"
    assert result["control"]["allow_live_submit"] is False


def test_arm_allow_live_submit_still_works(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CTF_RUNNER_STATE_ROOT", str(tmp_path / "runner-state"))
    profile = _write_profile(tmp_path)

    result, code, _ = _run_json(
        [
            "contest",
            "arm",
            "--contest-id",
            "example",
            "--profile",
            str(profile),
            "--confirm-competition",
            "--allow-live-submit",
            "--json",
        ]
    )

    assert code == 0
    assert result["status"] == "armed"
    assert result["control"]["allow_live_submit"] is True


def test_disarm_clears_armed(monkeypatch, tmp_path: Path):
    state_root = tmp_path / "runner-state"
    monkeypatch.setenv("CTF_RUNNER_STATE_ROOT", str(state_root))
    profile = _write_profile(tmp_path)
    _run_json(
        [
            "contest",
            "arm",
            "--contest-id",
            "example",
            "--profile",
            str(profile),
            "--confirm-competition",
            "--json",
        ]
    )

    result, code, _ = _run_json(["contest", "disarm", "--contest-id", "example", "--json"])

    assert code == 0
    assert result["status"] == "disarmed"
    assert result["control"]["armed"] is False
    assert result["control"]["run_mode"] == "rehearsal"
    assert not (state_root / "contests" / "example" / "arm.lock").exists()


def test_status_and_worker_commands_are_redacted_and_arm_sensitive(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CTF_RUNNER_STATE_ROOT", str(tmp_path / "runner-state"))
    profile = _write_profile(tmp_path)

    before, code, before_raw = _run_json(["contest", "worker-commands", "--contest-id", "example", "--json"])
    assert code == 0
    assert before["armed"] is False
    assert "CTF_RUN_MODE=competition" not in before_raw

    _run_json(
        [
            "contest",
            "arm",
            "--contest-id",
            "example",
            "--profile",
            str(profile),
            "--confirm-competition",
            "--max-workers",
            "2",
            "--json",
        ]
    )
    status, code, raw_status = _run_json(["contest", "status", "--contest-id", "example", "--json"])
    commands, _, raw_commands = _run_json(["contest", "worker-commands", "--contest-id", "example", "--json"])

    assert code == 0
    assert status["armed"] is True
    assert status["profile_path"]
    assert "supersecret" not in raw_status
    assert commands["armed"] is True
    assert commands["max_workers"] == 2
    assert all("./scripts/ctf-worker-" in item for item in commands["commands"])
    assert "CTF_RUN_MODE=competition" in raw_commands


def _write_profile(tmp_path: Path, storage: Path | None = None) -> Path:
    profile = tmp_path / "platform.yaml"
    auth_lines = ["auth:"]
    if storage:
        auth_lines.extend(["  method: storage_state_file", f"  path: {storage}"])
    else:
        auth_lines.extend(["  method: manual"])
    profile.write_text(
        "\n".join(
            [
                "platform: generic",
                "name: example",
                "base_url: https://ctf.example.com",
                "contest_url: https://ctf.example.com/contest",
                *auth_lines,
                "policy:",
                "  allow_live_discovery: true",
                "  allow_live_download: false",
                "  allow_submission: false",
                "  allow_instance_start: false",
                "downloads:",
                f"  root: {tmp_path / 'contests'}",
            ]
        ),
        encoding="utf-8",
    )
    return profile


def _preflight_stub() -> dict[str, Any]:
    return {
        "risk": {"High": [], "Medium": [], "Low": [], "Info": []},
        "paths": {"repo_under_mnt_c": False, "warnings": []},
        "browser_smoke": {"ok": True, "reason": "ok"},
        "callback_smoke": {"ok": True, "reason": "ok"},
        "docker": {"found": True, "reachable": True},
        "ctf_pwn_image": {"exists": True},
        "codex_worker_isolation": {
            "worker_homes": {
                "worker-1": {
                    "exists": True,
                    "auth_linked": True,
                    "auth_json": {"exists": True, "is_symlink": True},
                }
            }
        },
    }


def _run_json(argv: list[str]) -> tuple[dict[str, Any], int, str]:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = main(argv)
    output = buffer.getvalue()
    return json.loads(output), code, output
