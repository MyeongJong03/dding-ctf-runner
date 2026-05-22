import json
import tempfile
import unittest
from pathlib import Path

from ctf_runner.state import connect, init_db, upsert_platform_challenges


class PlatformStateTests(unittest.TestCase):
    def test_discover_result_upserts_into_sqlite(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "queue.sqlite3"
            init_db(db)

            result = upsert_platform_challenges(
                [
                    {
                        "challenge_id": "chal-1",
                        "name": "Challenge One",
                        "category": "web",
                        "points": 100,
                        "solves": 5,
                        "tags": ["intro"],
                        "has_files": True,
                    }
                ],
                contest_id="example",
                db_path=db,
            )

            self.assertEqual(result["count"], 1)
            with connect(db) as conn:
                row = conn.execute(
                    "SELECT id, contest_id, name, category, points, solves, status, source, metadata FROM challenges WHERE id=?",
                    ("chal-1",),
                ).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["contest_id"], "example")
            self.assertEqual(row["status"], "new")
            self.assertEqual(row["source"], "platform")
            metadata = json.loads(row["metadata"])
            self.assertEqual(metadata["name"], "Challenge One")
            self.assertTrue(metadata["has_files"])


if __name__ == "__main__":
    unittest.main()
