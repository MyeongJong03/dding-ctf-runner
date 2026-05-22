import time
import unittest

from ctf_runner.solve_result import parse_solver_output
from ctf_runner.submit import classify_flag_confidence, detect_flag_candidates, hash_flag, redact_flag, should_submit


def flag(prefix: str = "DH", body: str = "unit_real_value") -> str:
    return prefix + "{" + body + "}"


class SubmitPolicyTests(unittest.TestCase):
    def test_regex_flag_candidate_detect(self):
        candidate = flag("tjctf", "unit_real_value")
        self.assertEqual(detect_flag_candidates(f"found {candidate}"), [candidate])
        custom = "TEAM-FLAG-12345"
        self.assertEqual(detect_flag_candidates(f"got {custom}", flag_regex=r"TEAM-FLAG-\d+"), [custom])

    def test_fake_test_example_flag_reject(self):
        candidate = flag("tjctf", "dummy_test_value")
        decision = should_submit(candidate, {"auto_submit_default": True, "reject_fake_like": True}, [])
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["reason"], "fake_likely")
        self.assertEqual(decision["confidence"], "low")

    def test_duplicate_hash_blocks(self):
        candidate = flag()
        previous = [{"flag_hash": hash_flag(candidate), "status": "accepted"}]
        decision = should_submit(
            candidate,
            {"auto_submit_default": True, "require_high_confidence": True, "duplicate_detection": "sha256"},
            previous,
            context={"source": "exploit_output"},
        )
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["reason"], "duplicate")

    def test_wrong_limit_blocks(self):
        candidate = flag("DH", "another_real_value")
        previous = [
            {"flag_hash": "x1", "status": "rejected", "submitted_at_epoch": time.time() - 100},
            {"flag_hash": "x2", "status": "incorrect", "submitted_at_epoch": time.time() - 90},
        ]
        policy = {
            "auto_submit_default": True,
            "require_high_confidence": True,
            "max_wrong_per_challenge": 2,
            "cooldown_seconds": 0,
        }
        decision = should_submit(candidate, policy, previous, context={"source": "exploit_output"})
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["reason"], "wrong_submission_limit")

    def test_cooldown_blocks(self):
        candidate = flag("DH", "cooldown_real_value")
        previous = [{"flag_hash": "x", "status": "rejected", "submitted_at_epoch": time.time()}]
        policy = {
            "auto_submit_default": True,
            "require_high_confidence": True,
            "max_wrong_per_challenge": 2,
            "cooldown_seconds": 999,
        }
        decision = should_submit(candidate, policy, previous, context={"source": "exploit_output"})
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["reason"], "cooldown_active")

    def test_high_confidence_allows(self):
        candidate = flag("tjctf", "verified_real_value")
        decision = should_submit(
            candidate,
            {"auto_submit_default": True, "require_high_confidence": True},
            [],
            context={"source": "exploit_output"},
        )
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["confidence"], "high")

    def test_evidence_source_and_derivation_are_high_confidence(self):
        candidate = flag("tjctf", "file_evidence_value")
        decision = should_submit(
            candidate,
            {"auto_submit_default": True, "require_high_confidence": True},
            [],
            context={
                "source": "file_read",
                "evidence_source": "raw/note.txt",
                "derivation": "read candidate from raw/note.txt",
            },
        )

        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["confidence"], "high")

    def test_rejected_candidates_are_not_submitted(self):
        candidate = flag("tjctf", "real_evidence_value")
        decoy = flag("FLAG", "example_dummy_flag")
        parsed = parse_solver_output(
            "\n".join(
                [
                    "STATUS: solved",
                    "CONFIDENCE: high",
                    "EVIDENCE_SOURCE: raw/note.txt",
                    "DERIVATION: read direct evidence",
                    f"FLAG_CANDIDATE: {candidate}",
                    "REJECTED_CANDIDATES:",
                    f"- {decoy} reason=example decoy",
                ]
            )
        )

        self.assertEqual([item["candidate"] for item in parsed["flag_candidates"]], [candidate])
        self.assertEqual([item["candidate"] for item in parsed["rejected_candidates"]], [decoy])
        decision = should_submit(
            parsed["flag_candidates"][0]["candidate"],
            {"auto_submit_default": True, "require_high_confidence": True},
            [],
            context={
                "source": "file_read",
                "evidence_source": "raw/note.txt",
                "derivation": "read direct evidence",
            },
        )
        self.assertTrue(decision["allowed"])

    def test_medium_confidence_blocked_by_default(self):
        candidate = flag("tjctf", "uncertain_real_value")
        decision = should_submit(candidate, {"auto_submit_default": True, "require_high_confidence": True}, [])
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["reason"], "confidence_too_low")
        self.assertEqual(decision["confidence"], "medium")

    def test_raw_flag_not_in_result_repr_or_preview(self):
        candidate = flag("tjctf", "very_secret_value")
        result = classify_flag_confidence(candidate, context={"source": "exploit_output"})
        self.assertNotIn(candidate, repr(result))
        self.assertNotIn(candidate, redact_flag(candidate))
        self.assertIn(hash_flag(candidate), repr(result))


if __name__ == "__main__":
    unittest.main()
