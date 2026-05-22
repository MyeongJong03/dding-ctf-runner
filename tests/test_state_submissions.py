import sqlite3
import tempfile
import unittest
from pathlib import Path

from ctf_runner.state import (
    add_manual_challenge,
    count_wrong_submissions,
    get_challenge_state,
    has_duplicate_submission,
    init_db,
    list_submissions,
    record_submission_attempt,
    update_challenge_solved,
)
from ctf_runner.submit import hash_flag


def make_flag() -> str:
    return "FLAG" + "{" + "state_secret_value" + "}"


class StateSubmissionTests(unittest.TestCase):
    def test_record_submission_hash_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "state.sqlite3"
            candidate = make_flag()
            digest = hash_flag(candidate)
            init_db(db)
            record_submission_attempt(
                challenge_id="chal-state",
                flag_hash=digest,
                status="planned",
                confidence="high",
                result_summary_redacted="planned",
                db_path=db,
            )

            rows = list_submissions("chal-state", db)
            self.assertEqual(rows[0]["flag_hash"], digest)
            self.assertNotIn(candidate, repr(rows))
            with sqlite3.connect(db) as conn:
                rendered = "\n".join(str(row) for row in conn.execute("SELECT * FROM submissions").fetchall())
            self.assertNotIn(candidate, rendered)

    def test_wrong_count_and_duplicate(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "state.sqlite3"
            digest = hash_flag(make_flag())
            init_db(db)
            record_submission_attempt(challenge_id="chal-state", flag_hash="wrong-1", status="rejected", db_path=db)
            record_submission_attempt(challenge_id="chal-state", flag_hash=digest, status="accepted", db_path=db)

            self.assertEqual(count_wrong_submissions("chal-state", db), 1)
            self.assertTrue(has_duplicate_submission("chal-state", digest, db))

    def test_solved_update(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "state.sqlite3"
            digest = hash_flag(make_flag())
            init_db(db)
            add_manual_challenge("chal-state", "State Challenge", "misc", db_path=db)
            update_challenge_solved("chal-state", flag_hash=digest, confidence="high", db_path=db)

            state = get_challenge_state("chal-state", db)
            rows = list_submissions("chal-state", db)
            self.assertTrue(state["solved"])
            self.assertEqual(rows[0]["status"], "accepted")
            self.assertEqual(rows[0]["flag_hash"], digest)


if __name__ == "__main__":
    unittest.main()
