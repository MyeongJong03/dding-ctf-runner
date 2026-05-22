from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ctf_runner.state import add_manual_challenge, claim_next_challenge, connect, get_challenge_state, init_db, list_status


def test_concurrent_claim_next_challenge_returns_unique_claims(tmp_path: Path):
    db = tmp_path / "queue.sqlite3"
    init_db(db)
    for index in range(10):
        add_manual_challenge(f"chal-{index}", f"Challenge {index}", "misc", priority=index, db_path=db)

    def claim(index: int):
        return claim_next_challenge(f"worker-{index}", db, stale_after_sec=60)

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(claim, range(10)))

    challenge_ids = [item["id"] for item in results if item is not None]
    assert len(challenge_ids) == 10
    assert len(set(challenge_ids)) == 10
    status = list_status(db)
    assert len(status["active_claims"]) == 10


def test_stale_claim_can_be_reclaimed_once(tmp_path: Path):
    db = tmp_path / "queue.sqlite3"
    init_db(db)
    add_manual_challenge("stale-chal", "Stale Challenge", "misc", db_path=db)
    first = claim_next_challenge("worker-a", db, stale_after_sec=60)
    assert first is not None
    assert first["id"] == "stale-chal"

    with connect(db) as conn:
        conn.execute(
            "UPDATE claims SET heartbeat_at='2000-01-01T00:00:00+00:00' WHERE challenge_id='stale-chal'"
        )
        conn.execute("UPDATE challenges SET status='solving' WHERE id='stale-chal'")

    second = claim_next_challenge("worker-b", db, stale_after_sec=1)
    assert second is not None
    assert second["id"] == "stale-chal"
    assert get_challenge_state("stale-chal", db)["status"] == "claimed"

    status = list_status(db)
    assert len(status["active_claims"]) == 1
    assert status["active_claims"][0]["challenge_id"] == "stale-chal"
    assert status["active_claims"][0]["worker_id"] == "worker-b"
    assert status["active_claims"][0]["heartbeat_at"]
    assert status["claim_history_counts"]["stale"] == 1
