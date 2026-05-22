from pathlib import Path

from ctf_runner.contest_control import contest_status
from ctf_runner.postsolve import archive_postsolve, generate_postsolve
from ctf_runner.state import add_manual_challenge, init_db, update_challenge_solved
from ctf_runner.submit import hash_flag


def test_contest_status_includes_postsolve_counts(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))
    db = tmp_path / "queue.sqlite3"
    init_db(db)
    add_manual_challenge("count-1", "Count One", "misc", contest_id="local-fake", db_path=db)
    update_challenge_solved(
        "count-1",
        worker_id="worker-test",
        flag_hash=hash_flag("FLAG" + "{" + "count_one_local" + "}"),
        confidence="high",
        db_path=db,
    )

    generated = generate_postsolve("local-fake", "count-1", db_path=db)
    archived = archive_postsolve("local-fake", "count-1", db_path=db)
    status = contest_status("local-fake", db_path=db, state_root=tmp_path / "runner-state")

    assert generated["status"] == "ok"
    assert archived["status"] == "ok"
    assert status["solved_count"] == 1
    assert status["postsolve_generated_count"] == 1
    assert status["skill_candidate_count"] == 1
    assert status["archive_count"] == 1
