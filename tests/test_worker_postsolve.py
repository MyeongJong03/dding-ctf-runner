import json
from pathlib import Path

from ctf_runner.fake_ctfd import CHALLENGE_ID, FakeCTFdServer, platform_config
from ctf_runner.state import add_manual_challenge, init_db, upsert_platform_challenges
from ctf_runner.worker_loop import MOCK_SOLVED_MARKER, run_worker_once


def test_fake_local_solved_worker_generates_postsolve(tmp_path: Path):
    candidate = "DDING" + "{" + "mock_solver_verified_value" + "}"
    db = tmp_path / "queue.sqlite3"
    contests = tmp_path / "contests"
    config_path = tmp_path / "platform.json"

    with FakeCTFdServer(correct_flag=candidate) as server:
        config_path.write_text(json.dumps(platform_config(server.base_url, contests)), encoding="utf-8")
        init_db(db)
        add_manual_challenge(CHALLENGE_ID, "Local Postsolve", "misc", contest_id="fake_ctfd", db_path=db)
        _brief(contests, "fake_ctfd", CHALLENGE_ID, f"# Brief\n{MOCK_SOLVED_MARKER}\n")

        result = run_worker_once(
            "worker-test",
            solver="mock",
            live_submit=True,
            confirm_submit=True,
            platform_config=config_path,
            db_path=db,
            state_root=tmp_path / "runner-state",
            telemetry_path=tmp_path / "events.jsonl",
        )

    postsolve = result["postsolve_summary"]
    assert result["status"] == "solved"
    assert postsolve["status"] == "ok"
    postsolve_dir = Path(str(postsolve["postsolve_dir"]).replace("~/", str(Path.home()) + "/", 1))
    assert (postsolve_dir / "solve_summary.md").exists()
    assert candidate not in (postsolve_dir / "solve_summary.md").read_text(encoding="utf-8")


def test_real_unarmed_challenge_does_not_generate_postsolve(tmp_path: Path):
    db = tmp_path / "queue.sqlite3"
    contests = tmp_path / "contests"
    init_db(db)
    upsert_platform_challenges(
        [{"challenge_id": "real-postsolve", "name": "Real Postsolve", "category": "misc", "points": 100}],
        contest_id="real-contest",
        db_path=db,
    )
    _brief(contests, "real-contest", "real-postsolve", f"# Brief\n{MOCK_SOLVED_MARKER}\n")

    result = run_worker_once(
        "worker-test",
        solver="mock",
        run_mode="competition",
        confirm_competition=True,
        postsolve=True,
        db_path=db,
        contests_root=contests,
        state_root=tmp_path / "runner-state",
    )

    assert result["status"] == "blocked_by_mode"
    assert result["reason"] == "competition_not_armed"
    assert "postsolve_summary" not in result
    assert not (contests / "real-contest" / "real-postsolve" / "postsolve").exists()


def _brief(root: Path, contest_id: str, challenge_id: str, text: str) -> Path:
    path = root / contest_id / challenge_id / "brief.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path
