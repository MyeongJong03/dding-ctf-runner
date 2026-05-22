from pathlib import Path

from ctf_runner.contest_control import arm_contest
from ctf_runner.state import add_manual_challenge, get_challenge_state, init_db, upsert_platform_challenges
from ctf_runner.worker_loop import MOCK_SOLVED_MARKER, run_worker_once


def _brief(root: Path, contest_id: str, challenge_id: str, text: str) -> Path:
    path = root / contest_id / challenge_id / "brief.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _real_platform_challenge(db: Path, contests: Path, challenge_id: str = "real-platform-1") -> None:
    init_db(db)
    upsert_platform_challenges(
        [{"challenge_id": challenge_id, "name": "Real Challenge", "category": "misc", "points": 100}],
        contest_id="example-real",
        db_path=db,
    )
    _brief(contests, "example-real", challenge_id, f"# Brief\n{MOCK_SOLVED_MARKER}\n")


def _write_profile(tmp_path: Path, contests: Path) -> Path:
    profile = tmp_path / "platform.yaml"
    profile.write_text(
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
                "  allow_live_download: false",
                "  allow_submission: false",
                "  allow_instance_start: false",
                "downloads:",
                f"  root: {contests}",
            ]
        ),
        encoding="utf-8",
    )
    return profile


def test_real_platform_challenge_in_setup_blocks_before_solver(monkeypatch, tmp_path: Path):
    db = tmp_path / "queue.sqlite3"
    contests = tmp_path / "contests"
    _real_platform_challenge(db, contests)

    def fail_solver(*args, **kwargs):
        raise AssertionError("solver must not run")

    monkeypatch.setattr("ctf_runner.worker_loop._run_solver", fail_solver)

    result = run_worker_once(
        "worker-test",
        solver="mock",
        run_mode="setup",
        db_path=db,
        contests_root=contests,
        state_root=tmp_path / "state",
    )

    assert result["status"] == "blocked_by_mode"
    assert result["reason"] == "setup_blocks_real_challenge_solve"
    assert result["flag_candidate_count"] == 0
    assert result["submit_plan_status"] == "none"
    assert get_challenge_state("real-platform-1", db)["status"] == "blocked_by_mode"


def test_real_platform_challenge_in_rehearsal_without_allow_blocks(monkeypatch, tmp_path: Path):
    db = tmp_path / "queue.sqlite3"
    contests = tmp_path / "contests"
    _real_platform_challenge(db, contests)

    def fail_solver(*args, **kwargs):
        raise AssertionError("solver must not run")

    monkeypatch.setattr("ctf_runner.worker_loop._run_solver", fail_solver)

    result = run_worker_once(
        "worker-test",
        solver="mock",
        run_mode="rehearsal",
        db_path=db,
        contests_root=contests,
        state_root=tmp_path / "state",
    )

    assert result["status"] == "blocked_by_mode"
    assert result["reason"] == "rehearsal_requires_allow_real_solve_dry_run"


def test_rehearsal_allow_real_solve_dry_run_runs_solver_without_live_submit(tmp_path: Path):
    db = tmp_path / "queue.sqlite3"
    contests = tmp_path / "contests"
    _real_platform_challenge(db, contests)

    result = run_worker_once(
        "worker-test",
        solver="mock",
        live_submit=True,
        run_mode="rehearsal",
        allow_real_solve_dry_run=True,
        db_path=db,
        contests_root=contests,
        state_root=tmp_path / "state",
    )

    assert result["status"] == "submit_planned"
    assert result["live_submit_called"] is False
    assert result["live_submit_mode_decision"]["reason"] == "rehearsal_blocks_live_submit"
    assert get_challenge_state("real-platform-1", db)["status"] == "submit_planned"


def test_competition_with_confirm_allows_real_platform_solver(tmp_path: Path):
    db = tmp_path / "queue.sqlite3"
    contests = tmp_path / "contests"
    state_root = tmp_path / "state"
    profile = _write_profile(tmp_path, contests)
    _real_platform_challenge(db, contests)
    arm_contest("example-real", profile_path=profile, confirm_competition=True, state_root=state_root)

    result = run_worker_once(
        "worker-test",
        solver="mock",
        run_mode="competition",
        confirm_competition=True,
        db_path=db,
        state_root=state_root,
    )

    assert result["status"] == "submit_planned"
    assert result["run_mode"] == "competition"
    assert result["target_kind"] == "real_platform"
    assert result["contest_armed"] is True


def test_fake_local_challenge_in_setup_is_allowed(tmp_path: Path):
    db = tmp_path / "queue.sqlite3"
    contests = tmp_path / "contests"
    init_db(db)
    add_manual_challenge("local-unit", "Local Unit", "misc", db_path=db)
    _brief(contests, "manual", "local-unit", f"# Brief\n{MOCK_SOLVED_MARKER}\n")

    result = run_worker_once(
        "worker-test",
        solver="mock",
        run_mode="setup",
        db_path=db,
        contests_root=contests,
        state_root=tmp_path / "state",
    )

    assert result["status"] == "submit_planned"
    assert result["target_kind"] == "local"
