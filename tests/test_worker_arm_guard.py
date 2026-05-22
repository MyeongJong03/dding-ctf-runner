import json
from pathlib import Path

from ctf_runner.contest_control import arm_contest
from ctf_runner.fake_ctfd import CHALLENGE_ID, FakeCTFdServer, platform_config
from ctf_runner.state import add_manual_challenge, get_challenge_state, init_db, upsert_platform_challenges
from ctf_runner.worker_loop import MOCK_SOLVED_MARKER, run_worker_once


def test_real_challenge_competition_without_arm_blocks_before_solver(monkeypatch, tmp_path: Path):
    db = tmp_path / "queue.sqlite3"
    contests = tmp_path / "contests"
    _real_platform_challenge(db, contests)

    def fail_solver(*args, **kwargs):
        raise AssertionError("solver must not run")

    monkeypatch.setattr("ctf_runner.worker_loop._run_solver", fail_solver)

    result = run_worker_once(
        "worker-test",
        solver="mock",
        run_mode="competition",
        confirm_competition=True,
        db_path=db,
        contests_root=contests,
        state_root=tmp_path / "runner-state",
    )

    assert result["status"] == "blocked_by_mode"
    assert result["reason"] == "competition_not_armed"
    assert result["contest_armed"] is False
    assert get_challenge_state("real-guard", db)["status"] == "blocked_by_mode"


def test_armed_without_allow_live_submit_never_posts(tmp_path: Path):
    db = tmp_path / "queue.sqlite3"
    contests = tmp_path / "contests"
    state_root = tmp_path / "runner-state"
    profile = tmp_path / "platform.json"
    candidate = "DDING" + "{" + "mock_solver_verified_value" + "}"

    with FakeCTFdServer(correct_flag=candidate) as server:
        profile.write_text(json.dumps(platform_config(server.base_url, contests)), encoding="utf-8")
        _real_platform_challenge(db, contests, CHALLENGE_ID)
        arm_contest("real-contest", profile_path=profile, confirm_competition=True, state_root=state_root)

        result = run_worker_once(
            "worker-test",
            solver="mock",
            live_submit=True,
            confirm_submit=True,
            run_mode="competition",
            confirm_competition=True,
            db_path=db,
            state_root=state_root,
        )

        assert result["status"] == "submit_planned"
        assert result["live_submit_called"] is False
        assert result["live_submit_mode_decision"]["reason"] == "contest_live_submit_not_allowed"
        assert not any("/api/v1/challenges/attempt" in item for item in server.request_log)


def test_armed_allow_live_submit_with_confirm_posts_to_fake_mock_only(tmp_path: Path):
    db = tmp_path / "queue.sqlite3"
    contests = tmp_path / "contests"
    state_root = tmp_path / "runner-state"
    profile = tmp_path / "platform.json"
    candidate = "DDING" + "{" + "mock_solver_verified_value" + "}"

    with FakeCTFdServer(correct_flag=candidate) as server:
        profile.write_text(json.dumps(platform_config(server.base_url, contests)), encoding="utf-8")
        _real_platform_challenge(db, contests, CHALLENGE_ID)
        arm_contest(
            "real-contest",
            profile_path=profile,
            confirm_competition=True,
            allow_live_submit=True,
            state_root=state_root,
        )

        result = run_worker_once(
            "worker-test",
            solver="mock",
            live_submit=True,
            confirm_submit=True,
            run_mode="competition",
            confirm_competition=True,
            db_path=db,
            state_root=state_root,
        )

        assert result["status"] == "solved"
        assert result["live_submit_called"] is True
        assert result["submit_plan_status"] == "accepted"
        assert any("/api/v1/challenges/attempt" in item for item in server.request_log)
        assert candidate not in json.dumps(result, sort_keys=True)


def test_setup_and_rehearsal_guards_unchanged(tmp_path: Path):
    db = tmp_path / "queue.sqlite3"
    contests = tmp_path / "contests"
    _real_platform_challenge(db, contests)

    setup = run_worker_once(
        "worker-setup",
        solver="mock",
        run_mode="setup",
        db_path=db,
        contests_root=contests,
        state_root=tmp_path / "runner-state",
    )

    assert setup["status"] == "blocked_by_mode"
    assert setup["reason"] == "setup_blocks_real_challenge_solve"


def test_fake_local_setup_still_allowed(tmp_path: Path):
    db = tmp_path / "queue.sqlite3"
    contests = tmp_path / "contests"
    init_db(db)
    add_manual_challenge(CHALLENGE_ID, "Local Fake", "misc", contest_id="fake_ctfd", db_path=db)
    _brief(contests, "fake_ctfd", CHALLENGE_ID, f"# Brief\n{MOCK_SOLVED_MARKER}\n")

    result = run_worker_once(
        "worker-test",
        solver="mock",
        run_mode="setup",
        db_path=db,
        contests_root=contests,
        state_root=tmp_path / "runner-state",
    )

    assert result["status"] == "submit_planned"
    assert result["target_kind"] == "fake"


def _real_platform_challenge(db: Path, contests: Path, challenge_id: str = "real-guard") -> None:
    init_db(db)
    upsert_platform_challenges(
        [{"challenge_id": challenge_id, "name": "Real Guard", "category": "misc", "points": 100}],
        contest_id="real-contest",
        db_path=db,
    )
    _brief(contests, "real-contest", challenge_id, f"# Brief\n{MOCK_SOLVED_MARKER}\n")


def _brief(root: Path, contest_id: str, challenge_id: str, text: str) -> Path:
    path = root / contest_id / challenge_id / "brief.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path
