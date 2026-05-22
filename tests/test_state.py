import tempfile
import unittest
from pathlib import Path

from ctf_runner.state import add_manual_challenge, claim_next_challenge, init_db, list_status, register_worker, release_claim


class StateTests(unittest.TestCase):
    def test_queue_claim_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "queue.sqlite3"
            init_db(db)
            register_worker("worker-test", "primary", db)
            add_manual_challenge("chal-test", "Challenge Test", "misc", db_path=db)
            claimed = claim_next_challenge("worker-test", db)
            self.assertIsNotNone(claimed)
            self.assertEqual(claimed["id"], "chal-test")
            release_claim("worker-test", "chal-test", "stalled", "unit test", db)
            status = list_status(db)
            self.assertEqual(status["challenge_counts"].get("stalled"), 1)


if __name__ == "__main__":
    unittest.main()
