import sqlite3
from pathlib import Path

import pytest

from ctf_runner.state import add_manual_challenge, connect, get_challenge_state, init_db, update_challenge_status


def test_connect_context_manager_closes_connection(tmp_path: Path):
    db = tmp_path / "state.sqlite3"
    init_db(db)

    with connect(db) as conn:
        conn.execute("SELECT 1").fetchone()

    with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
        conn.execute("SELECT 1").fetchone()


def test_repeated_state_operations_do_not_keep_context_connections_open(tmp_path: Path):
    db = tmp_path / "state.sqlite3"
    init_db(db)
    add_manual_challenge("fd-check", "FD Check", "misc", db_path=db)

    for index in range(50):
        update_challenge_status("fd-check", "queued", details={"iteration": index}, db_path=db)
        state = get_challenge_state("fd-check", db)
        assert state["status"] == "queued"


def test_connect_direct_use_still_works_until_explicit_close(tmp_path: Path):
    db = tmp_path / "state.sqlite3"
    conn = connect(db)
    try:
        assert conn.execute("SELECT 1").fetchone()[0] == 1
    finally:
        conn.close()
