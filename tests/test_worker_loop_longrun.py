from __future__ import annotations

from pathlib import Path

from ctf_runner.state import add_manual_challenge, connect, init_db, list_status
from ctf_runner.worker_loop import run_worker_forever


def test_worker_loop_respects_max_iterations_on_empty_queue(tmp_path: Path):
    db = tmp_path / "queue.sqlite3"
    init_db(db)

    result = run_worker_forever(
        "worker-1",
        solver="mock",
        max_iterations=2,
        sleep_seconds=0,
        stop_when_empty=False,
        db_path=db,
    )

    assert result["status"] == "ok"
    assert result["iterations"] == 2
    assert result["empty_count"] == 2


def test_worker_loop_stop_when_empty_preserves_previous_default(tmp_path: Path):
    db = tmp_path / "queue.sqlite3"
    init_db(db)

    result = run_worker_forever(
        "worker-1",
        solver="mock",
        max_iterations=5,
        sleep_seconds=0,
        stop_when_empty=True,
        db_path=db,
    )

    assert result["iterations"] == 1
    assert result["empty_count"] == 1


def test_worker_loop_claims_without_duplicates(tmp_path: Path):
    db = tmp_path / "queue.sqlite3"
    add_manual_challenge("local-1", "local-1", "misc", contest_id="local-fake", db_path=db)
    add_manual_challenge("local-2", "local-2", "misc", contest_id="local-fake", db_path=db)

    result = run_worker_forever(
        "worker-1",
        solver="mock",
        max_iterations=2,
        sleep_seconds=0,
        stop_when_empty=True,
        db_path=db,
        contest_id="local-fake",
    )

    assert result["iterations"] == 2
    status = list_status(db)
    assert status["challenge_counts"]["stalled"] == 2
    with connect(db) as conn:
        duplicate_rows = conn.execute(
            """
            SELECT challenge_id, COUNT(*) AS count
            FROM events
            WHERE event_type='challenge_claim' AND status='ok'
            GROUP BY challenge_id
            HAVING COUNT(*) > 1
            """
        ).fetchall()
    assert duplicate_rows == []
