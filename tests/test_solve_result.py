from ctf_runner.solve_result import parse_solver_output, public_solver_result
from ctf_runner.submit import hash_flag


def test_parse_flag_candidate_and_public_redaction():
    candidate = "TJCTF" + "{" + "verified_real_value" + "}"
    parsed = parse_solver_output(
        "\n".join(
            [
                "STATUS: solved",
                "SUMMARY: exploit output produced the candidate",
                "SOURCE: exploit_output",
                "LOCAL_VERIFIED: true",
                "FAKE_LIKE: false",
                f"FLAG_CANDIDATE: {candidate}",
            ]
        )
    )
    public = public_solver_result(parsed)

    assert parsed["status"] == "solved"
    assert parsed["flag_candidates"][0]["candidate"] == candidate
    assert public["flag_candidates"][0]["flag_hash"] == hash_flag(candidate)
    assert candidate not in repr(public)


def test_stalled_parse_sections():
    parsed = parse_solver_output(
        "\n".join(
            [
                "STATUS: stalled",
                "SUMMARY: no candidate yet",
                "FACTS:",
                "- service exposes a parser",
                "ATTEMPTS:",
                "- tried local sample",
                "NEXT_IDEAS:",
                "- inspect grammar",
            ]
        )
    )

    assert parsed["status"] == "stalled"
    assert parsed["flag_candidates"] == []
    assert parsed["facts"] == ["service exposes a parser"]
    assert parsed["attempts"] == ["tried local sample"]
    assert parsed["next_ideas"] == ["inspect grammar"]


def test_fake_decoy_candidate_context():
    candidate = "TJCTF" + "{" + "dummy_test_value" + "}"
    parsed = parse_solver_output(
        "\n".join(
            [
                "STATUS: solved",
                "SUMMARY: found a decoy sample flag",
                "SOURCE: file_read",
                "LOCAL_VERIFIED: false",
                "FAKE_LIKE: true",
                f"FLAG_CANDIDATE: {candidate}",
            ]
        )
    )
    public = public_solver_result(parsed)

    assert public["confidence_context"]["fake_like"] is True
    assert public["flag_candidates"][0]["fake_like"] is True
    assert candidate not in repr(public)
