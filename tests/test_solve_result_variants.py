from ctf_runner.solve_result import parse_solver_output, public_solver_result


def test_natural_language_flag_candidate_is_detected_and_redacted():
    candidate = "TJCTF" + "{" + "aurora_cipher_74291" + "}"
    parsed = parse_solver_output(f"I found {candidate} by reading note.txt locally.")
    public = public_solver_result(parsed)

    assert parsed["status"] == "solved"
    assert parsed["confidence_context"]["source"] == "file_read"
    assert parsed["confidence_context"]["local_verified"] is True
    assert parsed["flag_candidates"][0]["candidate"] == candidate
    assert candidate not in repr(public)


def test_json_like_flag_candidate_is_detected():
    candidate = "TJCTF" + "{" + "json_alpha_74291" + "}"
    parsed = parse_solver_output(
        '{"status":"solved","source":"file_read","local_verified":true,'
        f'"summary":"read from local file","flag_candidate":"{candidate}"}}'
    )

    assert parsed["status"] == "solved"
    assert parsed["confidence_context"]["source"] == "file_read"
    assert parsed["confidence_context"]["local_verified"] is True
    assert parsed["flag_candidates"][0]["candidate"] == candidate


def test_markdown_fenced_schema_output_is_detected():
    candidate = "TJCTF" + "{" + "fenced_alpha_74291" + "}"
    parsed = parse_solver_output(
        "\n".join(
            [
                "```text",
                "STATUS: solved",
                "SUMMARY: read from note.txt",
                "SOURCE: file_read",
                "LOCAL_VERIFIED: true",
                "FAKE_LIKE: false",
                f"FLAG_CANDIDATE: {candidate}",
                "```",
            ]
        )
    )

    assert parsed["status"] == "solved"
    assert parsed["summary"] == "read from note.txt"
    assert parsed["flag_candidates"][0]["candidate"] == candidate


def test_structured_block_extracts_evidence_derivation_and_rejections():
    candidate = "TJCTF" + "{" + "structured_alpha_74291" + "}"
    decoy = "FLAG" + "{" + "example_dummy_flag" + "}"

    parsed = parse_solver_output(
        "\n".join(
            [
                "STATUS: solved",
                "CONFIDENCE: high",
                "EVIDENCE_SOURCE: /tmp/chal/note.txt",
                "DERIVATION: read note.txt directly",
                f"FLAG_CANDIDATE: {candidate}",
                "REJECTED_CANDIDATES:",
                f"- {decoy} reason=example decoy",
                "NEXT_IDEAS:",
                "- none",
            ]
        )
    )
    public = public_solver_result(parsed)

    assert parsed["status"] == "solved"
    assert parsed["confidence_context"]["confidence"] == "high"
    assert parsed["confidence_context"]["evidence_source"].endswith("note.txt")
    assert parsed["confidence_context"]["derivation"] == "read note.txt directly"
    assert [item["candidate"] for item in parsed["flag_candidates"]] == [candidate]
    assert [item["candidate"] for item in parsed["rejected_candidates"]] == [decoy]
    assert decoy not in repr(public)
    assert candidate not in repr(public)


def test_markdown_table_schema_is_detected():
    candidate = "TJCTF" + "{" + "table_alpha_74291" + "}"
    parsed = parse_solver_output(
        "\n".join(
            [
                "| Field | Value |",
                "| --- | --- |",
                "| STATUS | solved |",
                "| CONFIDENCE | high |",
                "| EVIDENCE_SOURCE | raw/note.txt |",
                "| DERIVATION | decoded base64 with python |",
                f"| FLAG_CANDIDATE | {candidate} |",
            ]
        )
    )

    assert parsed["status"] == "solved"
    assert parsed["confidence_context"]["evidence_source"] == "raw/note.txt"
    assert parsed["flag_candidates"][0]["candidate"] == candidate


def test_json_rejected_candidates_are_not_submittable_candidates():
    candidate = "TJCTF" + "{" + "json_real_74291" + "}"
    decoy = "FLAG" + "{" + "example_dummy_flag" + "}"

    parsed = parse_solver_output(
        "{"
        '"status":"solved",'
        '"confidence":"high",'
        '"evidence_source":"raw/app.py",'
        '"derivation":"read ROUTE_SECRET",'
        f'"flag_candidate":"{candidate}",'
        f'"rejected_candidates":[{{"candidate":"{decoy}","reason":"decoy"}}]'
        "}"
    )

    assert [item["candidate"] for item in parsed["flag_candidates"]] == [candidate]
    assert [item["candidate"] for item in parsed["rejected_candidates"]] == [decoy]


def test_no_flag_output_stalls():
    parsed = parse_solver_output("I inspected the file but did not find a candidate yet.")

    assert parsed["status"] == "stalled"
    assert parsed["flag_candidates"] == []
