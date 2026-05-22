from __future__ import annotations

import contextlib
import io
import json
import sys
import time
from pathlib import Path

from ctf_runner.cli import main
from ctf_runner.contest_control import record_prestart
from ctf_runner.worker_supervisor import start_worker_process, worker_status, workers_root


def test_start_workers_dry_run_does_not_start(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CTF_RUNNER_STATE_ROOT", str(tmp_path / "state"))
    result, code = _run_json(
        [
            "--db",
            str(tmp_path / "queue.sqlite3"),
            "contest",
            "start-workers",
            "--contest-id",
            "local-fake",
            "--dry-run",
            "--workers",
            "2",
            "--json",
        ]
    )

    assert code == 0
    assert result["status"] == "dry_run"
    assert result["launched"] is False
    assert not list(workers_root("local-fake", state_root=tmp_path / "state").glob("*.pid"))


def test_start_workers_apply_starts_fake_worker(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CTF_RUNNER_STATE_ROOT", str(tmp_path / "state"))
    result, code = _run_json(
        [
            "--db",
            str(tmp_path / "queue.sqlite3"),
            "contest",
            "start-workers",
            "--contest-id",
            "local-fake",
            "--apply",
            "--workers",
            "1",
            "--solver",
            "mock",
            "--max-iterations",
            "1",
            "--stop-when-empty",
            "--json",
        ]
    )
    assert code == 0
    assert result["status"] == "started"
    assert result["launched"] is True
    assert result["workers"][0]["pid"]

    deadline = time.monotonic() + 5
    status = worker_status("local-fake", state_root=tmp_path / "state")
    while status["running_worker_count"] and time.monotonic() < deadline:
        time.sleep(0.05)
        status = worker_status("local-fake", state_root=tmp_path / "state")
    assert status["running_worker_count"] == 0


def test_real_platform_unarmed_start_blocked(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CTF_RUNNER_STATE_ROOT", str(tmp_path / "state"))

    result, code = _run_json(
        [
            "contest",
            "start-workers",
            "--contest-id",
            "real-platform",
            "--apply",
            "--workers",
            "1",
            "--json",
        ]
    )

    assert code == 1
    assert result["status"] == "blocked"
    assert result["reason"] == "contest_not_armed"


def test_armed_competition_defaults_live_submit_worker_command(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CTF_RUNNER_STATE_ROOT", str(tmp_path / "state"))
    profile = _write_profile(tmp_path, allow_submission=True)
    armed, arm_code = _run_json(
        [
            "contest",
            "arm",
            "--contest-id",
            "real-platform",
            "--profile",
            str(profile),
            "--confirm-competition",
            "--json",
        ]
    )
    assert arm_code == 0
    assert armed["control"]["allow_live_submit"] is True

    result, code = _run_json(
        [
            "--db",
            str(tmp_path / "queue.sqlite3"),
            "contest",
            "start-workers",
            "--contest-id",
            "real-platform",
            "--dry-run",
            "--workers",
            "1",
            "--json",
        ]
    )

    assert code == 0
    assert result["run_mode"] == "competition"
    assert result["live_submit_default"] is True
    assert result["live_submit_effective"] is True
    assert result["confirm_submit_effective"] is True
    command = result["workers"][0]["command_redacted"]
    assert "--live-submit" in command
    assert "--confirm-submit" in command


def test_no_live_submit_arm_disables_worker_live_submit(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CTF_RUNNER_STATE_ROOT", str(tmp_path / "state"))
    profile = _write_profile(tmp_path, allow_submission=True)
    armed, arm_code = _run_json(
        [
            "contest",
            "arm",
            "--contest-id",
            "real-platform",
            "--profile",
            str(profile),
            "--confirm-competition",
            "--no-live-submit",
            "--json",
        ]
    )
    assert arm_code == 0
    assert armed["control"]["allow_live_submit"] is False

    result, code = _run_json(
        [
            "--db",
            str(tmp_path / "queue.sqlite3"),
            "contest",
            "start-workers",
            "--contest-id",
            "real-platform",
            "--dry-run",
            "--workers",
            "1",
            "--json",
        ]
    )

    assert code == 0
    assert result["run_mode"] == "competition"
    assert result["live_submit_default"] is False
    assert result["live_submit_effective"] is False
    command = result["workers"][0]["command_redacted"]
    assert "--live-submit" not in command
    assert "--confirm-submit" not in command


def test_setup_and_rehearsal_worker_commands_do_not_live_submit(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CTF_RUNNER_STATE_ROOT", str(tmp_path / "state"))
    profile = _write_profile(tmp_path, allow_submission=True)

    setup, setup_code = _run_json(
        [
            "contest",
            "start-workers",
            "--contest-id",
            "real-platform",
            "--dry-run",
            "--workers",
            "1",
            "--json",
        ]
    )
    assert setup_code == 0
    assert setup["run_mode"] == "setup"
    assert setup["live_submit_default"] is False
    assert "--live-submit" not in setup["workers"][0]["command_redacted"]

    record_prestart("real-platform", profile_path=profile, run_mode="rehearsal", state_root=tmp_path / "state")
    rehearsal, rehearsal_code = _run_json(
        [
            "contest",
            "start-workers",
            "--contest-id",
            "real-platform",
            "--dry-run",
            "--workers",
            "1",
            "--json",
        ]
    )

    assert rehearsal_code == 0
    assert rehearsal["run_mode"] == "rehearsal"
    assert rehearsal["live_submit_default"] is False
    assert "--live-submit" not in rehearsal["workers"][0]["command_redacted"]


def test_disarm_stop_workers_stops_process(monkeypatch, tmp_path: Path):
    state_root = tmp_path / "state"
    monkeypatch.setenv("CTF_RUNNER_STATE_ROOT", str(state_root))
    start_worker_process(
        "example",
        "worker-1",
        [sys.executable, "-c", "import time; time.sleep(30)"],
        env={"CTF_RUN_MODE": "setup", "CTF_CONTEST_ID": "example"},
        metadata={"mode": "setup", "solver": "mock"},
        state_root=state_root,
    )

    result, code = _run_json(["contest", "disarm", "--contest-id", "example", "--stop-workers", "--json"])

    assert code == 0
    assert result["status"] == "disarmed"
    assert result["worker_stop"]["status"] == "ok"
    assert worker_status("example", state_root=state_root)["running_worker_count"] == 0


def _run_json(argv: list[str]) -> tuple[dict, int]:
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        code = main(argv)
    raw = stdout.getvalue()
    return json.loads(raw), code


def _write_profile(tmp_path: Path, *, allow_submission: bool) -> Path:
    profile = tmp_path / "platform.yaml"
    profile.write_text(
        "\n".join(
            [
                "platform: generic",
                "name: example",
                "base_url: https://ctf.example.com",
                "contest_url: https://ctf.example.com/contest",
                "auth:",
                "  method: manual",
                "policy:",
                "  allow_live_discovery: true",
                "  allow_live_download: true",
                f"  allow_submission: {str(allow_submission).lower()}",
                "  allow_instance_start: false",
                "downloads:",
                f"  root: {tmp_path / 'contests'}",
            ]
        ),
        encoding="utf-8",
    )
    return profile
