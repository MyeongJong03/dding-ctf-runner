import contextlib
import io
import json
from pathlib import Path
from typing import Any

from ctf_runner.cli import main
from ctf_runner.contest_control import arm_contest


class FakeRealPlatform:
    platform_name = "example-real"
    base_url = "https://ctf.example.com"
    downloads_root: Path

    def __init__(self, root: Path, *, allow_submission: bool = False) -> None:
        self.downloads_root = root / "contests"
        self.policy = {
            "allow_live_discovery": True,
            "allow_live_download": True,
            "allow_submission": allow_submission,
            "allow_instance_start": False,
        }
        self.submit_called = False

    def text_ingest_candidates(self, live: bool = False, *, max_challenges: int = 20, max_detail_fetch: int = 20) -> dict[str, Any]:
        assert live is True
        return {
            "status": "ok",
            "warnings": [],
            "challenges": [
                {
                    "challenge_id": "real-sync",
                    "name": "Real Sync",
                    "category": "misc",
                    "points": 100,
                    "statement": "Read-only rehearsal statement",
                }
            ],
            "public_challenges": [{"challenge_id": "real-sync", "name": "Real Sync", "category": "misc", "points": 100}],
        }

    def submit_flag(self, *args, **kwargs):
        self.submit_called = True
        raise AssertionError("live submit should be blocked before platform call")


def test_setup_profile_check_allowed(tmp_path: Path):
    config = _write_profile(tmp_path)
    result = _run_json(["platform", "profile-check", "--mode", "setup", "--config", str(config), "--json"])

    assert result["status"] == "ok"


def test_setup_sync_challenges_without_allow_real_readonly_blocked(monkeypatch, tmp_path: Path):
    fake = FakeRealPlatform(tmp_path)
    monkeypatch.setattr("ctf_runner.cli._load_platform", lambda config: fake)

    result = _run_json(
        [
            "--db",
            str(tmp_path / "queue.sqlite3"),
            "platform",
            "sync-challenges",
            "--mode",
            "setup",
            "--config",
            str(tmp_path / "platform.yaml"),
            "--live",
            "--save-state",
            "--ingest-text",
            "--json",
        ]
    )

    assert result["status"] == "blocked"
    assert result["decision"]["reason"] == "setup_requires_allow_real_readonly"


def test_rehearsal_sync_challenges_allowed(monkeypatch, tmp_path: Path):
    fake = FakeRealPlatform(tmp_path)
    monkeypatch.setattr("ctf_runner.cli._load_platform", lambda config: fake)

    result = _run_json(
        [
            "--db",
            str(tmp_path / "queue.sqlite3"),
            "platform",
            "sync-challenges",
            "--mode",
            "rehearsal",
            "--config",
            str(tmp_path / "platform.yaml"),
            "--live",
            "--save-state",
            "--ingest-text",
            "--json",
        ]
    )

    assert result["status"] == "ok"
    assert result["challenge_count"] == 1
    assert result["ingest_ready_count"] == 1


def test_submit_blocked_in_setup_and_rehearsal(monkeypatch, tmp_path: Path):
    for mode in ("setup", "rehearsal"):
        fake = FakeRealPlatform(tmp_path, allow_submission=True)
        monkeypatch.setattr("ctf_runner.cli._load_platform", lambda config, fake=fake: fake)
        result = _run_json(
            [
                "--db",
                str(tmp_path / f"{mode}.sqlite3"),
                "platform",
                "submit",
                "--mode",
                mode,
                "--config",
                str(tmp_path / "platform.yaml"),
                "--challenge-id",
                "real-sync",
                "--flag",
                _flag_like("FLAG", "unit_value"),
                "--live",
                "--confirm",
                "--json",
            ]
        )

        assert result["status"] == "blocked"
        assert result["platform_action"]["network"] is False
        assert fake.submit_called is False


def test_competition_submit_requires_policy_and_confirm(monkeypatch, tmp_path: Path):
    state_root = tmp_path / "runner-state"
    monkeypatch.setenv("CTF_RUNNER_STATE_ROOT", str(state_root))
    profile = tmp_path / "platform.yaml"
    profile.write_text("platform: generic\nname: example-real\nbase_url: https://ctf.example.com\n", encoding="utf-8")
    arm_contest(
        "example-real",
        profile_path=profile,
        confirm_competition=True,
        allow_live_submit=True,
        state_root=state_root,
    )

    no_policy = FakeRealPlatform(tmp_path, allow_submission=False)
    monkeypatch.setattr("ctf_runner.cli._load_platform", lambda config: no_policy)
    blocked_policy = _run_json(
        [
            "--db",
            str(tmp_path / "policy.sqlite3"),
            "platform",
            "submit",
            "--mode",
            "competition",
            "--confirm-competition",
            "--config",
            str(tmp_path / "platform.yaml"),
            "--challenge-id",
            "real-sync",
            "--flag",
            _flag_like("FLAG", "unit_value"),
            "--live",
            "--confirm",
            "--json",
        ]
    )

    assert blocked_policy["status"] == "blocked"
    assert blocked_policy["platform_action"]["details"]["reason"] == "live_submit_not_allowed_by_policy"
    assert no_policy.submit_called is False

    needs_confirm = FakeRealPlatform(tmp_path, allow_submission=True)
    monkeypatch.setattr("ctf_runner.cli._load_platform", lambda config: needs_confirm)
    blocked_confirm = _run_json(
        [
            "--db",
            str(tmp_path / "confirm.sqlite3"),
            "platform",
            "submit",
            "--mode",
            "competition",
            "--confirm-competition",
            "--config",
            str(tmp_path / "platform.yaml"),
            "--challenge-id",
            "real-sync",
            "--flag",
            _flag_like("FLAG", "unit_value"),
            "--live",
            "--json",
        ]
    )

    assert blocked_confirm["status"] == "blocked"
    assert blocked_confirm["platform_action"]["details"]["reason"] == "live_submit_requires_confirm"
    assert needs_confirm.submit_called is False


def _write_profile(tmp_path: Path) -> Path:
    config = tmp_path / "platform.yaml"
    config.write_text(
        "\n".join(
            [
                "platform: generic",
                "name: example-real",
                "base_url: https://ctf.example.com",
                "contest_url: https://ctf.example.com/contest",
                "auth:",
                "  method: manual",
                "policy:",
                "  allow_live_discovery: true",
                "  allow_live_download: true",
                "  allow_submission: false",
                "  allow_instance_start: false",
                "downloads:",
                f"  root: {tmp_path / 'contests'}",
            ]
        ),
        encoding="utf-8",
    )
    return config


def _run_json(argv: list[str]) -> dict[str, Any]:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = main(argv)
    output = buffer.getvalue()
    assert code == 0, output
    return json.loads(output)


def _flag_like(prefix: str, body: str) -> str:
    return prefix + "{" + body + "}"
