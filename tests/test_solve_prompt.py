from pathlib import Path

from ctf_runner.solve_prompt import MAX_PROMPT_BYTES, build_solve_prompt


def test_build_solve_prompt_from_brief_redacts_and_bounds(tmp_path: Path):
    raw_flag = "TJCTF" + "{" + "prompt_secret_value" + "}"
    raw_token = "tok_" + "abcdef123456"
    brief = tmp_path / "brief.md"
    brief.write_text(("notes " + raw_flag + f"\ntoken={raw_token}\n") * 400, encoding="utf-8")
    challenge = {
        "id": "prompt-test",
        "name": "Prompt Test",
        "category": "misc",
        "status": "queued",
        "metadata": '{"api_token": "tok_abcdef123456"}',
    }

    prompt = build_solve_prompt(challenge, brief)

    assert "STATUS: solved|stalled" in prompt
    assert "CONFIDENCE: high|medium|low" in prompt
    assert "EVIDENCE_SOURCE:" in prompt
    assert "DERIVATION:" in prompt
    assert "FLAG_CANDIDATE: <flag>" in prompt
    assert "REJECTED_CANDIDATES:" in prompt
    assert "Prompt Test" in prompt
    assert raw_flag not in prompt
    assert raw_token not in prompt
    assert len(prompt.encode("utf-8")) <= MAX_PROMPT_BYTES


def test_selected_sensitive_file_content_is_skipped(tmp_path: Path):
    brief = tmp_path / "brief.md"
    brief.write_text("brief\n", encoding="utf-8")
    token_file = tmp_path / "auth_token.txt"
    token_value = "secret_" + "abcdef"
    token_file.write_text(token_value, encoding="utf-8")

    prompt = build_solve_prompt({"id": "selected-test"}, brief, selected_files=[token_file])

    assert token_value not in prompt
    assert "content skipped" in prompt


def test_selected_local_file_evidence_is_included_within_limit(tmp_path: Path):
    brief = tmp_path / "brief.md"
    brief.write_text("brief\n", encoding="utf-8")
    candidate = "TJCTF" + "{" + "selected_evidence_74291" + "}"
    note = tmp_path / "note.txt"
    note.write_text(f"verified candidate: {candidate}\n", encoding="utf-8")

    prompt = build_solve_prompt({"id": "selected-evidence"}, brief, selected_files=[note])

    assert "Selected local file evidence" in prompt
    assert str(note) in prompt
    assert candidate in prompt
    assert len(prompt.encode("utf-8")) <= MAX_PROMPT_BYTES


def test_pwn_rev_prompt_includes_docker_pool_hint(tmp_path: Path):
    brief = tmp_path / "brief.md"
    brief.write_text("brief\n", encoding="utf-8")
    challenge = {
        "id": "pwn-test",
        "category": "pwn",
        "metadata": {
            "docker_pool_hint": {
                "available": True,
                "container_name": "ctf-runner-local-worker-1",
                "workspace": "~/CTF/workspaces/local/worker-1",
                "safe_command": "ctfctl docker pool-exec --contest-id local --worker-id worker-1 --command '<local command>' --json",
            }
        },
    }

    prompt = build_solve_prompt(challenge, brief)

    assert "Docker pool available via `ctfctl docker pool-exec`" in prompt
    assert "ctf-runner-local-worker-1" in prompt
