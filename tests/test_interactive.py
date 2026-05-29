import contextlib
import io
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from ctf_runner.cli import main
from ctf_runner.platform_base import PlatformAction
from ctf_runner.public_check import run_public_check


def test_interactive_init_creates_files_idempotently(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))

    first = _run_json(["interactive", "init", "--contest-id", "demo", "--agents", "4", "--json"])
    second = _run_json(["interactive", "init", "--contest-id", "demo", "--agents", "4", "--json"])

    root = tmp_path / "contests" / "demo" / "operator"
    assert first["status"] == "ok"
    assert second["status"] == "ok"
    for name in ["BOARD.md", "board.json", "solved.jsonl", "external_solved.txt", "stalled.jsonl"]:
        assert (root / name).exists()
    assert (root / "claims").is_dir()
    assert (root / "memos").is_dir()
    assert (root / "metrics" / "events.jsonl").exists()
    assert (root / "metrics" / "summary.json").exists()


def test_interactive_prompt_allows_local_flag_output_and_bans_public_upload(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))

    result = _run_json(["interactive", "prompt", "--contest-id", "demo", "--agent", "a1", "--json"])
    prompt = result["prompt"]

    assert "Local terminal output may include flags, solver output, and exploit output" in prompt
    assert "Do not print raw secrets" not in prompt
    assert "raw flag 출력 금지" not in prompt
    assert "Do not publish or upload flags, writeups, exploits, tokens, cookies" in prompt
    assert "public repositories" in prompt
    assert "public pastes" in prompt
    assert "Writeups are local-only during the contest and accepted-only" in prompt
    assert "ctfctl interactive next" in prompt
    assert "ctfctl interactive prepare-target" in prompt
    assert "triage_summary_path" in prompt
    assert "starter_path" in prompt
    assert "target_pack_path" in prompt
    assert "ctfctl interactive target-pack" in prompt
    assert "prepare-target --contest-id demo --agent a1 --json" in prompt
    assert "completion_status is all_solved or all_solved_or_stalled" in prompt
    assert "Never stop after one problem" in prompt


def test_interactive_init_lock_idempotent(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))
    root = tmp_path / "contests" / "demo" / "operator"
    root.mkdir(parents=True)
    (root / ".init.lock").write_text("{}", encoding="utf-8")

    result = _run_json(["interactive", "init", "--contest-id", "demo", "--json"])

    assert result["status"] == "ok"
    assert (root / "board.json").exists()
    assert (root / ".init.lock").exists()


def test_claim_prevents_and_allows_duplicate(tmp_path: Path, monkeypatch):
    _seed_board(tmp_path, monkeypatch)

    first = _run_json(["interactive", "claim", "--contest-id", "demo", "--agent", "a1", "--json"])
    duplicate = _run_json_fail(["interactive", "claim", "--contest-id", "demo", "--agent", "a2", "--challenge", "Birdhouse", "--json"])
    allowed = _run_json(["interactive", "claim", "--contest-id", "demo", "--agent", "a2", "--challenge", "Birdhouse", "--allow-duplicate", "--json"])

    assert first["status"] == "claimed"
    assert duplicate["status"] == "blocked"
    assert duplicate["reason"] == "already_claimed_on_this_machine"
    assert allowed["status"] == "claimed"


def test_external_solved_prevents_future_claim(tmp_path: Path, monkeypatch):
    _seed_board(tmp_path, monkeypatch)

    marked = _run_json(["interactive", "external-solved", "--contest-id", "demo", "--challenge", "Birdhouse", "--json"])
    claim = _run_json(["interactive", "claim", "--contest-id", "demo", "--agent", "a1", "--json"])

    assert marked["status"] == "ok"
    assert claim["status"] == "empty"


def test_interactive_sync_marks_static_aliases_not_default_targets(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))
    profile = tmp_path / "profile.yaml"
    profile.write_text("name: demo\n", encoding="utf-8")
    monkeypatch.setattr("ctf_runner.interactive.load_platform_adapter", lambda profile: FakeSyncPlatform())

    result = _run_json(["interactive", "sync", "--contest-id", "demo", "--profile", str(profile), "--live", "--json"])
    claim = _run_json(["interactive", "claim", "--contest-id", "demo", "--agent", "a1", "--json"])

    assert result["status"] == "ok"
    assert result["target_count"] == 1
    assert result["alias_count"] == 1
    assert result["canonical_map"]["birdhouse-static"] == "birdhouse"
    assert claim["challenge_id"] == "birdhouse"


def test_interactive_sync_defcon_fixture_canonicalizes_aliases(tmp_path: Path, monkeypatch):
    _sync_defcon_fixture(tmp_path, monkeypatch)
    root = tmp_path / "contests" / "defcon" / "operator"
    board = json.loads((root / "board.json").read_text(encoding="utf-8"))
    status = _run_json(["interactive", "board", "--contest-id", "defcon", "--json"])

    ids = {item["challenge_id"] for item in board["challenges"]}
    mfi = next(item for item in board["challenges"] if item["challenge_id"] == "my-favorite-instructions")

    assert board["canonical_counts"]["canonical_count"] == 6
    assert board["canonical_counts"]["alias_count"] == 9
    assert board["canonical_map"]["birdhouse-static"] == "birdhouse"
    assert board["canonical_map"]["FavoriteInstructions"] == "my-favorite-instructions"
    assert board["canonical_map"]["favorite-static"] == "my-favorite-instructions"
    assert board["canonical_map"]["twobirdtwocan"] == "2bird2can"
    assert board["canonical_map"]["waybird-machine"] == "waybird-machine-main"
    assert board["canonical_map"]["livectf-phase1"] == "LiveCTF"
    assert "favorite-static" in mfi["artifact_sources"]
    assert "my-favorite-instructions-static" in mfi["artifact_sources"]
    assert "FavoriteInstructions" in mfi["aliases"]
    assert "favorite-static" not in ids
    assert "FavoriteInstructions" not in ids
    assert status["canonical_count"] == 6
    assert status["alias_count"] == 9
    assert status["claimable_count"] == 6
    assert status["challenges"]["todo"][0]["aliases"]
    assert "artifact_sources" in status["challenges"]["todo"][0]


def test_claim_specific_alias_returns_canonical_and_duplicate_override_works(tmp_path: Path, monkeypatch):
    _sync_defcon_fixture(tmp_path, monkeypatch)

    first = _run_json(["interactive", "claim", "--contest-id", "defcon", "--agent", "a1", "--challenge", "FavoriteInstructions", "--json"])
    duplicate = _run_json_fail(["interactive", "claim", "--contest-id", "defcon", "--agent", "a2", "--challenge", "my-favorite-instructions", "--json"])
    allowed = _run_json(
        [
            "interactive",
            "claim",
            "--contest-id",
            "defcon",
            "--agent",
            "a2",
            "--challenge",
            "favorite-static",
            "--allow-duplicate",
            "--json",
        ]
    )

    assert first["status"] == "claimed"
    assert first["challenge_id"] == "my-favorite-instructions"
    assert first["name"] == "My Favorite Instructions"
    assert "FavoriteInstructions" not in first["path"]
    assert duplicate["status"] == "blocked"
    assert allowed["status"] == "claimed"
    assert allowed["challenge_id"] == "my-favorite-instructions"


def test_interactive_next_selects_canonical_not_alias_or_static(tmp_path: Path, monkeypatch):
    _seed_target_planning_board(tmp_path, monkeypatch)

    result = _run_json(["interactive", "next", "--contest-id", "planning", "--agent", "a1", "--json"])

    assert result["status"] == "claimed"
    assert result["challenge_id"] == "real-target"
    assert result["name"] == "Real Target"
    assert "alias-target" not in result["target_pack_path"]
    assert Path(result["target_pack_path"].replace("~", str(Path.home()), 1)).exists()


def test_interactive_next_prefers_attachment_target_over_static_shell(tmp_path: Path, monkeypatch):
    _seed_target_planning_board(tmp_path, monkeypatch)

    result = _run_json(["interactive", "next", "--contest-id", "planning", "--agent", "a1", "--dry-run", "--json"])

    assert result["status"] == "planned"
    assert result["challenge_id"] == "real-target"
    assert "has_files_or_artifacts" in result["score_reasons"]


def test_target_pack_includes_aliases_artifact_sources_and_memory(tmp_path: Path, monkeypatch):
    _seed_target_planning_board(tmp_path, monkeypatch)
    _run_json(
        [
            "interactive",
            "memo",
            "--contest-id",
            "planning",
            "--challenge-id",
            "real-target",
            "--kind",
            "memory",
            "--append",
            "parsed config points at /api/check",
            "--json",
        ]
    )
    _run_json(
        [
            "interactive",
            "memo",
            "--contest-id",
            "planning",
            "--challenge-id",
            "real-target",
            "--kind",
            "next_steps",
            "--append",
            "inspect app.py route validation",
            "--json",
        ]
    )

    result = _run_json(["interactive", "target-pack", "--contest-id", "planning", "--challenge-id", "alias-target", "--agent", "a1", "--json"])
    text = Path(result["target_pack_path"].replace("~", str(Path.home()), 1)).read_text(encoding="utf-8")

    assert result["status"] == "ok"
    assert "canonical_name: Real Target" in text
    assert "aliases: alias-target, Real Target Alias" in text
    assert "artifact_sources: real-target-static" in text
    assert "memory.md" in text
    assert "parsed config points at /api/check" in text
    assert "inspect app.py route validation" in text


def test_target_pack_includes_category_specific_first_commands(tmp_path: Path, monkeypatch):
    _seed_pwn_target_board(tmp_path, monkeypatch)

    result = _run_json(["interactive", "target-pack", "--contest-id", "pwn-plan", "--challenge-id", "overflow", "--agent", "a1", "--json"])
    text = Path(result["target_pack_path"].replace("~", str(Path.home()), 1)).read_text(encoding="utf-8")

    assert result["status"] == "ok"
    assert "- category: pwn" in text
    assert "checksec" in text
    assert "pwntools ok" in text


def test_target_pack_redacts_synthetic_token_session_markers(tmp_path: Path, monkeypatch):
    _seed_target_planning_board(tmp_path, monkeypatch)
    marker = "TOKEN_SYNTHETIC_SESSION_MARKER"
    _run_json(
        [
            "interactive",
            "memo",
            "--contest-id",
            "planning",
            "--challenge-id",
            "real-target",
            "--kind",
            "operator_notes",
            "--append",
            f"debug note {marker} session=raw-session cookie=raw-cookie",
            "--json",
        ]
    )

    result = _run_json(["interactive", "target-pack", "--contest-id", "planning", "--challenge-id", "real-target", "--json"])
    text = Path(result["target_pack_path"].replace("~", str(Path.home()), 1)).read_text(encoding="utf-8")

    assert marker not in text
    assert "raw-session" not in text
    assert "raw-cookie" not in text
    assert "[REDACTED]" in text


def test_interactive_brief_outputs_compact_target_state(tmp_path: Path, monkeypatch):
    _seed_target_planning_board(tmp_path, monkeypatch)

    result = _run_json(["interactive", "brief", "--contest-id", "planning", "--challenge-id", "real-target", "--json"])

    assert result["status"] == "ok"
    assert "# Brief: Real Target" in result["brief"]
    assert "artifact_sources:" in result["brief"]
    assert "top_files:" in result["brief"]


def test_interactive_triage_creates_summary_updates_memos_and_metrics_for_fake_rev(tmp_path: Path, monkeypatch):
    _seed_rev_triage_board(tmp_path, monkeypatch)

    result = _run_json(["interactive", "triage", "--contest-id", "rev-triage", "--challenge-id", "crackme", "--agent", "a1", "--json"])

    root = tmp_path / "contests" / "rev-triage"
    challenge = root / "rev" / "Crackme"
    summary = Path(result["triage_summary_path"].replace("~", str(Path.home()), 1))
    events = (root / "operator" / "metrics" / "events.jsonl").read_text(encoding="utf-8")

    assert result["status"] == "ok"
    assert result["category"] == "rev"
    assert summary.exists()
    assert "# Auto Triage: Crackme" in summary.read_text(encoding="utf-8")
    assert (challenge / "triage" / "files.json").exists()
    assert (challenge / "triage" / "commands.jsonl").exists()
    assert (challenge / "triage" / "findings.jsonl").exists()
    assert "Auto Triage" in (challenge / "evidence.md").read_text(encoding="utf-8")
    assert "Auto Triage Next Steps" in (challenge / "next_steps.md").read_text(encoding="utf-8")
    assert "auto_triage" in (challenge / "memory.md").read_text(encoding="utf-8")
    assert "triage_started" in events
    assert "triage_completed" in events
    assert not list((root / "operator" / "writeups").glob("*Writeup.*.md"))


def test_interactive_starter_creates_solve_rev_with_full_path_references(tmp_path: Path, monkeypatch):
    _seed_rev_triage_board(tmp_path, monkeypatch)

    result = _run_json(["interactive", "starter", "--contest-id", "rev-triage", "--challenge-id", "crackme", "--category", "rev", "--json"])

    root = tmp_path / "contests" / "rev-triage"
    challenge = root / "rev" / "Crackme"
    starter = Path(result["starter_path"].replace("~", str(Path.home()), 1))
    operator = json.loads((root / "operator" / "operator.json").read_text(encoding="utf-8"))
    board = json.loads((root / "operator" / "board.json").read_text(encoding="utf-8"))
    text = starter.read_text(encoding="utf-8")

    assert result["status"] == "ok"
    assert starter.name == "solve_rev.py"
    assert str(challenge) in text
    assert "subprocess.run" in text
    assert "z3" in text
    assert operator["challenge_solver_metadata"]["crackme"]["starter_path"] == str(starter)
    assert board["solver_metadata"]["crackme"]["starter_path"] == str(starter)
    assert not list((root / "operator" / "writeups").glob("*Writeup.*.md"))


def test_interactive_prepare_target_returns_target_pack_triage_and_starter(tmp_path: Path, monkeypatch):
    _seed_rev_triage_board(tmp_path, monkeypatch)

    result = _run_json(["interactive", "prepare-target", "--contest-id", "rev-triage", "--agent", "a1", "--challenge-id", "crackme", "--json"])

    assert result["status"] == "ok"
    assert Path(result["target_pack_path"].replace("~", str(Path.home()), 1)).exists()
    assert Path(result["triage_summary_path"].replace("~", str(Path.home()), 1)).exists()
    assert Path(result["starter_path"].replace("~", str(Path.home()), 1)).exists()
    assert result["top_files"]
    assert result["first_commands"]
    assert result["next_steps"]


def test_interactive_prepare_target_without_challenge_claims_next(tmp_path: Path, monkeypatch):
    _seed_rev_triage_board(tmp_path, monkeypatch)

    result = _run_json(["interactive", "prepare-target", "--contest-id", "rev-triage", "--agent", "a1", "--json"])

    assert result["status"] == "ok"
    assert result["challenge_id"] == "crackme"
    assert result["selection"]["status"] == "claimed"
    assert Path(result["starter_path"].replace("~", str(Path.home()), 1)).exists()


def test_run_attempt_records_stdout_stderr_returncode_and_candidate(tmp_path: Path, monkeypatch):
    _seed_solve_harness_board(tmp_path, monkeypatch, contest_id="attempt-demo")
    challenge = tmp_path / "contests" / "attempt-demo" / "misc" / "Auto"
    raw_candidate = "FLAG{unit_attempt_candidate}"
    solver = challenge / "solver.py"
    solver.write_text(
        "import sys\n"
        f"print({raw_candidate!r})\n"
        "print('debug stderr', file=sys.stderr)\n",
        encoding="utf-8",
    )

    result, output = _run_json_with_output(
        [
            "interactive",
            "run-attempt",
            "--contest-id",
            "attempt-demo",
            "--challenge-id",
            "auto",
            "--script",
            "solver.py",
            "--timeout",
            "10",
            "--json",
        ]
    )

    root = tmp_path / "contests" / "attempt-demo" / "operator"
    attempt_path = Path(result["attempt_path"])
    attempt = json.loads(attempt_path.read_text(encoding="utf-8"))
    candidate_store = (challenge / "candidates.jsonl").read_text(encoding="utf-8")
    events = (root / "metrics" / "events.jsonl").read_text(encoding="utf-8")

    assert result["status"] == "ok"
    assert result["returncode"] == 0
    assert raw_candidate in result["stdout"]
    assert "debug stderr" in result["stderr"]
    assert raw_candidate in output
    assert attempt["stdout"].strip() == raw_candidate
    assert attempt["stderr"].strip() == "debug stderr"
    assert attempt["returncode"] == 0
    assert raw_candidate in candidate_store
    assert "attempt_started" in events
    assert "attempt_completed" in events
    assert "Attempt" in (challenge / "attempts.md").read_text(encoding="utf-8")


def test_candidates_lists_local_raw_and_verify_marks_high_confidence(tmp_path: Path, monkeypatch):
    _seed_solve_harness_board(tmp_path, monkeypatch, contest_id="candidate-demo")
    challenge = tmp_path / "contests" / "candidate-demo" / "misc" / "Auto"
    raw_candidate = "FLAG{unit_verified_candidate}"
    (challenge / "solver.py").write_text(f"print({raw_candidate!r})\n", encoding="utf-8")

    _run_json(
        [
            "interactive",
            "run-attempt",
            "--contest-id",
            "candidate-demo",
            "--challenge-id",
            "auto",
            "--script",
            "solver.py",
            "--json",
        ]
    )
    listed = _run_json(["interactive", "candidates", "--contest-id", "candidate-demo", "--challenge-id", "auto", "--json"])
    verified = _run_json(["interactive", "verify-candidate", "--contest-id", "candidate-demo", "--challenge-id", "auto", "--json"])

    assert listed["count"] == 1
    assert listed["candidates"][0]["value"] == raw_candidate
    assert verified["candidate"] == raw_candidate
    assert verified["confidence"] == "high"
    assert verified["verification_status"] == "verified_high"
    assert verified["submit_allowed"] is True


def test_public_snapshot_excludes_raw_local_candidate(tmp_path: Path, monkeypatch):
    _seed_solve_harness_board(tmp_path, monkeypatch, contest_id="public-candidate-demo")
    challenge = tmp_path / "contests" / "public-candidate-demo" / "misc" / "Auto"
    raw_candidate = "FLAG{unit_public_snapshot_candidate}"
    (challenge / "solver.py").write_text(f"print({raw_candidate!r})\n", encoding="utf-8")

    _run_json(["interactive", "run-attempt", "--contest-id", "public-candidate-demo", "--challenge-id", "auto", "--script", "solver.py", "--json"])
    assert raw_candidate in (challenge / "candidates.jsonl").read_text(encoding="utf-8")

    snapshot_root = tmp_path / "public" / "candidate-demo"
    snapshot = _run_json(
        [
            "interactive",
            "metrics",
            "publish-snapshot",
            "--contest-id",
            "public-candidate-demo",
            "--output-root",
            str(snapshot_root),
            "--contest-ended",
            "--json",
        ]
    )
    combined = "\n".join(path.read_text(encoding="utf-8") for path in snapshot_root.glob("*.public.*"))

    assert snapshot["public_safe"] is True
    assert raw_candidate not in combined
    assert "unit_public_snapshot_candidate" not in combined
    assert "flag_hash" in combined
    assert "attempt_stdout" in combined


def test_solve_loop_fake_accepted_creates_writeups_cleanup_and_metrics(tmp_path: Path, monkeypatch):
    profile = tmp_path / "profile.yaml"
    _seed_solve_harness_board(tmp_path, monkeypatch, contest_id="solve-loop-demo", profile=profile)
    monkeypatch.setattr("ctf_runner.interactive.load_platform_adapter", lambda profile: FakeAcceptedPlatform())
    challenge = tmp_path / "contests" / "solve-loop-demo" / "misc" / "Auto"
    raw_candidate = "FLAG{unit_solve_loop_value}"
    (challenge / "solve_misc.py").write_text(f"print({raw_candidate!r})\n", encoding="utf-8")

    result = _run_json(
        [
            "interactive",
            "solve-loop",
            "--contest-id",
            "solve-loop-demo",
            "--agent",
            "a1",
            "--challenge-id",
            "auto",
            "--max-attempts",
            "1",
            "--json",
        ]
    )

    assert result["status"] == "solved"
    assert result["submit"]["status"] == "accepted"
    assert result["metrics_summary"]["attempt_count"] == 1
    assert result["metrics_summary"]["accepted_count"] == 1
    assert result["metrics_summary"]["writeup_ko_count"] == 1
    assert result["metrics_summary"]["writeup_en_count"] == 1
    assert result["metrics_summary"]["cleanup_count"] == 1
    assert Path(result["writeup"]["files"]["ko"]).exists()
    assert Path(result["writeup"]["files"]["en"]).exists()
    assert (challenge / "solve_summary.md").exists()
    assert (challenge / "skill_candidate.md").exists()
    assert raw_candidate in (challenge / "candidates.jsonl").read_text(encoding="utf-8")


def test_solve_loop_failing_fixture_stalls_without_writeup(tmp_path: Path, monkeypatch):
    _seed_solve_harness_board(tmp_path, monkeypatch, contest_id="solve-loop-fail")
    challenge = tmp_path / "contests" / "solve-loop-fail" / "misc" / "Auto"
    (challenge / "solve_misc.py").write_text("print('no candidate yet')\nraise SystemExit(1)\n", encoding="utf-8")

    result = _run_json(
        [
            "interactive",
            "solve-loop",
            "--contest-id",
            "solve-loop-fail",
            "--agent",
            "a1",
            "--challenge-id",
            "auto",
            "--max-attempts",
            "1",
            "--json",
        ]
    )

    assert result["status"] == "stalled"
    assert result["metrics_summary"]["attempt_count"] == 1
    assert result["metrics_summary"]["stalled_count"] == 1
    assert not list((tmp_path / "contests" / "solve-loop-fail" / "operator" / "writeups").glob("*Writeup.*.md"))


def test_interactive_starter_generation_smoke_web_pwn_crypto(tmp_path: Path, monkeypatch):
    for category, expected in [("web", "solve_web.py"), ("pwn", "exploit.py"), ("crypto", "solve_crypto.py")]:
        contest_id = f"starter-{category}"
        _seed_category_starter_board(tmp_path, monkeypatch, contest_id=contest_id, category=category)

        result = _run_json(["interactive", "starter", "--contest-id", contest_id, "--challenge-id", "demo", "--category", category, "--json"])

        starter = Path(result["starter_path"].replace("~", str(Path.home()), 1))
        assert result["status"] == "ok"
        assert starter.name == expected
        assert starter.exists()
        text = starter.read_text(encoding="utf-8")
        assert str(tmp_path / "contests" / contest_id / category / "Demo") in text
        if category == "web":
            assert "requests.Session" in text
        elif category == "pwn":
            assert "from pwn import" in text
        elif category == "crypto":
            assert "parse_ints" in text
        assert not list((tmp_path / "contests" / contest_id / "operator" / "writeups").glob("*Writeup.*.md"))


def test_interactive_next_reports_all_solved_or_stalled_when_only_stalled_remains(tmp_path: Path, monkeypatch):
    _seed_board(tmp_path, monkeypatch)
    _run_json(["interactive", "claim", "--contest-id", "demo", "--agent", "a1", "--json"])
    _run_json(
        [
            "interactive",
            "memo",
            "--contest-id",
            "demo",
            "--challenge-id",
            "Birdhouse",
            "--kind",
            "next_steps",
            "--append",
            "test the extracted hint parser",
            "--json",
        ]
    )
    _run_json(
        [
            "interactive",
            "stalled",
            "--contest-id",
            "demo",
            "--agent",
            "a1",
            "--challenge",
            "Birdhouse",
            "--reason",
            "need to test extracted hint parser",
            "--json",
        ]
    )

    result = _run_json(["interactive", "next", "--contest-id", "demo", "--agent", "a2", "--json"])

    assert result["status"] == "empty"
    assert result["completion_status"] == "all_solved_or_stalled"
    assert result["no_useful_work"] is True


def test_external_solved_alias_marks_canonical_and_releases_alias_locks(tmp_path: Path, monkeypatch):
    _sync_defcon_fixture(tmp_path, monkeypatch)
    root = tmp_path / "contests" / "defcon" / "operator"
    _run_json(["interactive", "claim", "--contest-id", "defcon", "--agent", "a1", "--challenge", "Birdhouse", "--json"])

    marked = _run_json(["interactive", "external-solved", "--contest-id", "defcon", "--challenge", "birdhouse-static", "--json"])
    board = _run_json(["interactive", "board", "--contest-id", "defcon", "--json"])
    birdhouse = next(item for item in board["challenges"]["solved"] if item["challenge_id"] == "birdhouse")
    external_text = (root / "external_solved.txt").read_text(encoding="utf-8")

    assert marked["status"] == "ok"
    assert marked["challenge_id"] == "birdhouse"
    assert marked["canonical_name"] == "Birdhouse"
    assert marked["released_count"] >= 1
    assert not list((root / "claims").glob("*.lock"))
    assert birdhouse["status"] == "external_solved"
    assert birdhouse["solved_by_external"] is True
    assert "birdhouse-static" in external_text
    assert "Birdhouse" in external_text


def test_sync_platform_solved_status_excludes_team_solved_without_raw_submission(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))
    profile = tmp_path / "profile.yaml"
    profile.write_text("name: demo\n", encoding="utf-8")
    monkeypatch.setattr("ctf_runner.interactive.load_platform_adapter", lambda profile: FakeSolvedSyncPlatform())
    raw_marker = "TOKEN_SYNTHETIC_SUBMISSION_MARKER"

    result, output = _run_json_with_output(["interactive", "sync", "--contest-id", "solved-sync", "--profile", str(profile), "--live", "--json"])
    claim = _run_json(["interactive", "claim", "--contest-id", "solved-sync", "--agent", "a1", "--json"])
    root = tmp_path / "contests" / "solved-sync" / "operator"
    board_text = (root / "board.json").read_text(encoding="utf-8")
    board = json.loads(board_text)

    assert result["status"] == "ok"
    assert result["claimable_count"] == 0
    assert claim["status"] == "empty"
    assert board["challenges"][0]["status"] == "external_solved"
    assert board["challenges"][0]["solved_by_external"] is True
    assert board["challenges"][0]["platform_submission"]["status"] == "correct"
    assert raw_marker not in output
    assert raw_marker not in board_text


def test_interactive_status_reports_active_with_todo_challenges(tmp_path: Path, monkeypatch):
    _seed_board(tmp_path, monkeypatch)

    status = _run_json(["interactive", "status", "--contest-id", "demo", "--json"])

    assert status["status"] == "ok"
    assert status["completion_status"] == "active"
    assert status["canonical_count"] == 1
    assert status["claimable_count"] == 1
    assert status["todo"] == 1
    assert status["no_useful_work"] is False


def test_interactive_status_reports_all_solved_when_all_canonical_solved(tmp_path: Path, monkeypatch):
    _seed_board(tmp_path, monkeypatch)
    operator = tmp_path / "contests" / "demo" / "operator"
    _append_jsonl(operator / "solved.jsonl", {"challenge_id": "birdhouse", "status": "accepted", "flag_hash": "abc", "timestamp": "now"})

    status = _run_json(["interactive", "status", "--contest-id", "demo", "--json"])

    assert status["completion_status"] == "all_solved"
    assert status["solved"] == 1
    assert status["external_solved"] == 0
    assert status["no_useful_work"] is True


def test_interactive_status_reports_all_solved_or_stalled(tmp_path: Path, monkeypatch):
    _seed_board(tmp_path, monkeypatch)
    _run_json(["interactive", "stalled", "--contest-id", "demo", "--agent", "a1", "--challenge", "Birdhouse", "--reason", "documented blocker and next action", "--json"])

    status = _run_json(["interactive", "status", "--contest-id", "demo", "--json"])

    assert status["completion_status"] == "all_solved_or_stalled"
    assert status["stalled"] == 1
    assert status["no_useful_work"] is True


def test_interactive_next_refresh_syncs_new_challenge_and_records_metrics(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))
    profile = tmp_path / "profile.yaml"
    profile.write_text("name: demo\n", encoding="utf-8")
    platform = FakeRefreshSyncPlatform(
        [
            {
                "challenge_id": "fresh-web",
                "name": "Fresh Web",
                "category": "web",
                "statement": "New challenge with a real statement and useful signal.",
                "file_count": 1,
            }
        ]
    )
    monkeypatch.setattr("ctf_runner.interactive.load_platform_adapter", lambda profile: platform)
    _run_json(["interactive", "init", "--contest-id", "refresh-demo", "--profile", str(profile), "--json"])

    result = _run_json(["interactive", "next", "--contest-id", "refresh-demo", "--agent", "a1", "--refresh", "--profile", str(profile), "--json"])

    root = tmp_path / "contests" / "refresh-demo" / "operator"
    events = (root / "metrics" / "events.jsonl").read_text(encoding="utf-8")
    status = _run_json(["interactive", "status", "--contest-id", "refresh-demo", "--json"])

    assert platform.calls == 1
    assert platform.live_values == [True]
    assert result["status"] == "claimed"
    assert result["challenge_id"] == "fresh-web"
    assert result["refresh"]["new_count"] == 1
    assert status["claimed"] == 1
    assert "sync_completed" in events
    assert "new_challenges_detected" in events


def test_interactive_prepare_target_refresh_returns_no_useful_work_when_no_target_remains(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))
    profile = tmp_path / "profile.yaml"
    profile.write_text("name: demo\n", encoding="utf-8")
    monkeypatch.setattr("ctf_runner.interactive.load_platform_adapter", lambda profile: FakeSolvedSyncPlatform())

    result = _run_json(["interactive", "prepare-target", "--contest-id", "solved-refresh", "--agent", "a1", "--refresh", "--profile", str(profile), "--json"])

    assert result["status"] == "empty"
    assert result["completion_status"] == "all_solved"
    assert result["no_useful_work"] is True
    assert result["selection"]["refresh"]["claimable_count"] == 0


def test_interactive_next_skips_solved_and_external_solved_challenges(tmp_path: Path, monkeypatch):
    _seed_board(tmp_path, monkeypatch)
    root = tmp_path / "contests" / "demo" / "operator"
    board_path = root / "board.json"
    board = json.loads(board_path.read_text(encoding="utf-8"))
    board["challenges"].extend(
        [
            {
                "challenge_id": "team-solved",
                "name": "Team Solved",
                "category": "misc",
                "status": "todo",
                "priority": 1,
            },
            {
                "challenge_id": "fresh-target",
                "name": "Fresh Target",
                "category": "misc",
                "status": "todo",
                "priority": 100,
            },
        ]
    )
    board_path.write_text(json.dumps(board), encoding="utf-8")
    _append_jsonl(root / "solved.jsonl", {"challenge_id": "birdhouse", "status": "accepted", "flag_hash": "abc", "timestamp": "now"})
    _run_json(["interactive", "external-solved", "--contest-id", "demo", "--challenge", "team-solved", "--json"])

    result = _run_json(["interactive", "next", "--contest-id", "demo", "--agent", "a1", "--json"])

    assert result["status"] == "claimed"
    assert result["challenge_id"] == "fresh-target"


def test_stalled_records_note_and_releases_claim(tmp_path: Path, monkeypatch):
    _seed_board(tmp_path, monkeypatch)
    _run_json(["interactive", "claim", "--contest-id", "demo", "--agent", "a1", "--json"])

    stalled = _run_json(
        ["interactive", "stalled", "--contest-id", "demo", "--agent", "a1", "--challenge", "Birdhouse", "--reason", "need new idea", "--json"]
    )
    root = tmp_path / "contests" / "demo" / "operator"

    assert stalled["status"] == "stalled"
    assert not list((root / "claims").glob("*.lock"))
    assert "need new idea" in (tmp_path / "contests" / "demo" / "misc" / "Birdhouse" / "operator_notes.md").read_text(encoding="utf-8")


def test_submit_accepted_updates_solved_without_raw_flag(tmp_path: Path, monkeypatch):
    _seed_board(tmp_path, monkeypatch, profile=tmp_path / "profile.yaml")
    monkeypatch.setattr("ctf_runner.interactive.load_platform_adapter", lambda profile: FakeAcceptedPlatform())
    flag_path = tmp_path / "flag.txt"
    raw_flag = "FLAG{unit_verified_value}"
    flag_path.write_text(raw_flag, encoding="utf-8")

    result, output = _run_json_with_output(
        ["interactive", "submit", "--contest-id", "demo", "--challenge-id", "birdhouse", "--flag-file", str(flag_path), "--confirm", "--json"]
    )

    assert result["status"] == "accepted"
    assert result["flag_hash"]
    assert raw_flag not in output
    solved = (tmp_path / "contests" / "demo" / "operator" / "solved.jsonl").read_text(encoding="utf-8")
    assert "accepted" in solved
    assert raw_flag not in solved


def test_upload_submit_blocks_without_endpoint_or_config_and_records_safely(tmp_path: Path, monkeypatch):
    _seed_board(tmp_path, monkeypatch)
    artifact = tmp_path / "solution.wasm"
    raw_marker = "TOKEN_SYNTHETIC_ARTIFACT_MARKER"
    artifact.write_bytes(b"\x00asm" + raw_marker.encode("ascii"))

    result = _run_json_fail(
        [
            "interactive",
            "upload-submit",
            "--contest-id",
            "demo",
            "--challenge-id",
            "birdhouse",
            "--artifact",
            str(artifact),
            "--confirm",
            "--json",
        ]
    )

    root = tmp_path / "contests" / "demo" / "operator"
    submissions = (root / "submissions.jsonl").read_text(encoding="utf-8")
    events = (root / "metrics" / "events.jsonl").read_text(encoding="utf-8")

    assert result["status"] == "blocked"
    assert result["reason"] == "official_upload_endpoint_metadata_missing"
    assert result["artifact"]["sha256"]
    assert raw_marker not in submissions
    assert "artifact_submit_planned" in events
    assert "artifact_submit_blocked" in events


def test_submit_config_saves_artifact_upload_metadata(tmp_path: Path, monkeypatch):
    _seed_board(tmp_path, monkeypatch)

    result = _run_json(
        [
            "interactive",
            "submit-config",
            "--contest-id",
            "demo",
            "--challenge-id",
            "birdhouse",
            "--submit-type",
            "artifact_upload",
            "--endpoint",
            "https://example.invalid/submit",
            "--field-name",
            "file",
            "--status-url",
            "https://example.invalid/status/birdhouse",
            "--json",
        ]
    )

    root = tmp_path / "contests" / "demo" / "operator"
    operator = json.loads((root / "operator.json").read_text(encoding="utf-8"))
    board = json.loads((root / "board.json").read_text(encoding="utf-8"))
    metadata = operator["challenge_submit_metadata"]["birdhouse"]

    assert result["status"] == "ok"
    assert metadata["submit_type"] == "artifact_upload"
    assert metadata["endpoint"] == "https://example.invalid/submit"
    assert metadata["field_name"] == "file"
    assert board["submit_metadata"]["birdhouse"]["submit_type"] == "artifact_upload"
    assert board["challenges"][0]["submit_metadata"]["endpoint"] == "https://example.invalid/submit"


def test_upload_submit_fake_local_endpoint_records_acceptance_and_public_safe_snapshot(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))
    raw_secret_marker = "TOKEN_SYNTHETIC_RESPONSE_MARKER"
    with ArtifactUploadServer(raw_secret_marker=raw_secret_marker) as server:
        profile = tmp_path / "profile.json"
        profile.write_text(
            json.dumps(
                {
                    "platform": "ctfd",
                    "name": "artifact-local",
                    "base_url": server.base_url,
                    "auth": {"method": "manual"},
                    "policy": {
                        "allow_live_discovery": False,
                        "allow_live_download": False,
                        "allow_submission": True,
                        "allow_instance_start": False,
                    },
                }
            ),
            encoding="utf-8",
        )
        _run_json(["interactive", "init", "--contest-id", "demo", "--profile", str(profile), "--json"])
        root = tmp_path / "contests" / "demo" / "operator"
        (root / "board.json").write_text(
            json.dumps(
                {
                    "contest_id": "demo",
                    "challenges": [
                        {
                            "challenge_id": "rfc1149b",
                            "name": "rfc1149b",
                            "category": "rev",
                            "status": "todo",
                            "priority": 100,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        artifact = tmp_path / "rfc1149b.wasm"
        artifact.write_bytes(b"\x00asm\x01\x02\x03")
        expected_sha = "4fc449952b7b752dd0cdde23a6442e288b4e10a8d220df4fcbe3db4baa893a8e"

        _run_json(
            [
                "interactive",
                "submit-config",
                "--contest-id",
                "demo",
                "--challenge-id",
                "rfc1149b",
                "--submit-type",
                "artifact_upload",
                "--endpoint",
                f"{server.base_url}/submit",
                "--status-url",
                f"{server.base_url}/status/rfc1149b",
                "--json",
            ]
        )
        result, output = _run_json_with_output(
            [
                "interactive",
                "upload-submit",
                "--contest-id",
                "demo",
                "--challenge-id",
                "rfc1149b",
                "--artifact",
                str(artifact),
                "--confirm",
                "--json",
            ]
        )

        submissions = (root / "submissions.jsonl").read_text(encoding="utf-8")
        events = (root / "metrics" / "events.jsonl").read_text(encoding="utf-8")
        summary = _run_json(["interactive", "metrics", "summary", "--contest-id", "demo", "--json"])
        writeup = _run_json(
            [
                "interactive",
                "writeup",
                "--contest-id",
                "demo",
                "--challenge-id",
                "rfc1149b",
                "--category",
                "rev",
                "--json",
            ]
        )
        snapshot_root = tmp_path / "public" / "demo"
        snapshot = _run_json(
            [
                "interactive",
                "metrics",
                "publish-snapshot",
                "--contest-id",
                "demo",
                "--output-root",
                str(snapshot_root),
                "--contest-ended",
                "--json",
            ]
        )
        combined_snapshot = "\n".join(path.read_text(encoding="utf-8") for path in snapshot_root.glob("*.public.*"))

        assert result["status"] == "accepted"
        assert result["record"]["artifact_sha256"] == expected_sha
        assert result["record"]["artifact_size"] == 7
        assert result["record"]["active_status"] == "active"
        assert server.upload_count == 1
        assert expected_sha in submissions
        assert '"artifact_size": 7' in submissions
        assert "artifact_submit_attempted" in events
        assert "artifact_submit_accepted" in events
        assert summary["artifact_submitted_count"] == 1
        assert summary["artifact_accepted_count"] == 1
        assert writeup["status"] == "ok"
        assert snapshot["public_safe"] is True
        assert expected_sha in combined_snapshot
        assert raw_secret_marker not in output
        assert raw_secret_marker not in submissions
        assert raw_secret_marker not in events
        assert raw_secret_marker not in combined_snapshot


def test_writeup_refuses_unsolved_and_creates_ko_en_with_code_for_accepted(tmp_path: Path, monkeypatch):
    _seed_board(tmp_path, monkeypatch)
    blocked = _run_json_fail(["interactive", "writeup", "--contest-id", "demo", "--challenge-id", "birdhouse", "--category", "misc", "--json"])
    assert blocked["reason"] == "accepted_solve_required"

    root = tmp_path / "contests" / "demo"
    operator = root / "operator"
    _append_jsonl(operator / "solved.jsonl", {"challenge_id": "birdhouse", "status": "accepted", "flag_hash": "abc", "timestamp": "now"})
    solver = root / "misc" / "Birdhouse" / "solver.py"
    solver.parent.mkdir(parents=True, exist_ok=True)
    solver.write_text("print('solved')\n", encoding="utf-8")

    result = _run_json(["interactive", "writeup", "--contest-id", "demo", "--challenge-id", "birdhouse", "--category", "misc", "--include-code", "--json"])

    assert result["status"] == "ok"
    ko = Path(result["files"]["ko"].replace("~", str(Path.home()), 1))
    en = Path(result["files"]["en"].replace("~", str(Path.home()), 1))
    assert ko.exists()
    assert en.exists()
    assert "```python\nprint('solved')\n```" in ko.read_text(encoding="utf-8")
    assert "```python\nprint('solved')\n```" in en.read_text(encoding="utf-8")


def test_cleanup_keeps_final_artifacts_and_removes_safe_temp(tmp_path: Path, monkeypatch):
    _seed_board(tmp_path, monkeypatch)
    challenge = tmp_path / "contests" / "demo" / "misc" / "Birdhouse"
    challenge.mkdir(parents=True, exist_ok=True)
    (challenge / "solver.py").write_text("print('keep')\n", encoding="utf-8")
    (challenge / "run.log").write_text("remove\n", encoding="utf-8")
    cache = challenge / "__pycache__"
    cache.mkdir()
    (cache / "x.pyc").write_bytes(b"x")

    result = _run_json(["interactive", "cleanup", "--contest-id", "demo", "--challenge-id", "birdhouse", "--safe", "--json"])

    assert result["status"] == "ok"
    assert (challenge / "solver.py").exists()
    assert not (challenge / "run.log").exists()
    assert not cache.exists()


def test_public_check_ignores_untracked_operator_runtime_files(tmp_path: Path):
    from tests.test_public_check import _required_tracked_files, _write_required_public_files

    _write_required_public_files(tmp_path)
    result = run_public_check(
        repo=tmp_path,
        include_preflight=False,
        tracked_files=_required_tracked_files(),
        untracked_files=["contests/demo/operator/board.json"],
    )

    assert result["status"] == "ok"
    assert result["untracked_runtime_paths"] == []


def test_interactive_e2e_smoke_full_fake_loop(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))
    writeup_root = tmp_path / "writeups"

    result = _run_json(
        [
            "interactive",
            "e2e-smoke",
            "--contest-id",
            "fake-interactive-demo",
            "--agents",
            "2",
            "--writeup-root",
            str(writeup_root),
            "--keep-runtime",
            "--json",
        ]
    )

    assert result["status"] == "ok"
    assert all(result["checks"].values())
    root = tmp_path / "contests" / "fake-interactive-demo" / "operator"
    solved = (root / "solved.jsonl").read_text(encoding="utf-8")
    submissions = (root / "submissions.jsonl").read_text(encoding="utf-8")
    summary = result["metrics_summary"]

    assert "easy-misc-1" in solved
    assert "easy-misc-1" in submissions
    assert summary["claimed_count"] >= 4
    assert summary["submitted_count"] == 1
    assert summary["accepted_count"] == 1
    assert summary["writeup_ko_count"] == 1
    assert summary["writeup_en_count"] == 1
    assert summary["cleanup_count"] == 1
    assert summary["stalled_count"] == 1
    assert result["claims"]["duplicate_blocked"]["status"] == "blocked"
    assert result["claims"]["duplicate_allowed"]["status"] == "claimed"
    assert result["claims"]["next_after_solved"]["challenge_id"] != "easy-misc-1"

    ko = writeup_root / "[misc]easy-misc-1Writeup.ko.md"
    en = writeup_root / "[misc]easy-misc-1Writeup.en.md"
    assert ko.exists()
    assert en.exists()
    for path in (ko, en):
        text = path.read_text(encoding="utf-8")
        assert "## solver/exploit 전체 코드" in text or "## Full Solver / Exploit Code" in text
        assert "def main() -> int:" in text
        assert "raise SystemExit(main())" in text
        assert "flag =" not in text
    assert not list(writeup_root.glob("*stalled*Writeup.*.md"))


def test_interactive_e2e_smoke_allows_release_smoke_id(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))

    result = _run_json(
        [
            "interactive",
            "e2e-smoke",
            "--contest-id",
            "release-interactive-e2e",
            "--agents",
            "2",
            "--writeup-root",
            str(tmp_path / "writeups"),
            "--json",
        ]
    )

    assert result["status"] == "ok"
    assert all(result["checks"].values())


class FakeAcceptedPlatform:
    policy = {"allow_submission": True}

    def submit_flag(self, challenge_id: str, flag: str, live: bool = False, confirm: bool = False) -> PlatformAction:
        return PlatformAction(
            action="submit_flag",
            live=live,
            network=True,
            status="accepted",
            details={"challenge_id": challenge_id, "flag_hash": "fakehash", "result_summary_redacted": {"status": "correct"}},
        )


class FakeSyncPlatform:
    def discover_challenges(self, live: bool = False) -> PlatformAction:
        return PlatformAction(
            action="discover_challenges",
            live=live,
            network=live,
            status="ok",
            details={
                "challenges": [
                    {"challenge_id": "birdhouse", "name": "Birdhouse", "category": "web", "statement": "Real challenge statement"},
                    {"challenge_id": "birdhouse-static", "name": "birdhouse-static", "category": "web", "statement": "favicon css"},
                ]
            },
        )


class FakeDefconSyncPlatform:
    def discover_challenges(self, live: bool = False) -> PlatformAction:
        return PlatformAction(
            action="discover_challenges",
            live=live,
            network=live,
            status="ok",
            details={
                "challenges": [
                    _static_shell("birdhouse-static"),
                    {"challenge_id": "birdhouse", "name": "Birdhouse", "category": "web", "statement": "Real Birdhouse challenge with enough detail to solve.", "file_count": 1},
                    _static_shell("favorite-static"),
                    {
                        "challenge_id": "FavoriteInstructions",
                        "name": "FavoriteInstructions",
                        "category": "misc",
                        "statement": "Alias page for My Favorite Instructions.",
                        "file_count": 0,
                    },
                    _static_shell("my-favorite-instructions-static"),
                    {
                        "challenge_id": "my-favorite-instructions",
                        "name": "My Favorite Instructions",
                        "category": "misc",
                        "statement": "Real favorite instructions challenge with actual solver-relevant details.",
                        "file_count": 1,
                    },
                    {"challenge_id": "stork", "name": "stork", "category": "rev", "statement": "DEF CON CTF Quals 2026", "file_count": 0},
                    {"challenge_id": "Stork", "name": "Stork", "category": "rev", "statement": "Real Stork challenge statement.", "file_count": 1},
                    {"challenge_id": "twobirdtwocan", "name": "twobirdtwocan", "category": "pwn", "statement": "DEF CON CTF Quals 2026", "file_count": 0},
                    {"challenge_id": "2bird2can", "name": "2bird2can", "category": "pwn", "statement": "Real 2bird2can challenge statement.", "file_count": 1},
                    {"challenge_id": "waybird-machine", "name": "waybird-machine", "category": "crypto", "statement": "DEF CON CTF Quals 2026", "file_count": 0},
                    {
                        "challenge_id": "waybird-machine-main",
                        "name": "Waybird Machine",
                        "category": "crypto",
                        "statement": "Real Waybird Machine challenge statement.",
                        "file_count": 1,
                    },
                    {"challenge_id": "livectf", "name": "livectf", "category": "misc", "statement": "DEF CON CTF Quals 2026", "file_count": 0},
                    {"challenge_id": "livectf-phase1", "name": "livectf-phase1", "category": "misc", "statement": "phase metadata", "file_count": 0},
                    {"challenge_id": "LiveCTF", "name": "LiveCTF", "category": "misc", "statement": "Real LiveCTF challenge statement.", "file_count": 1},
                ]
            },
        )


class FakeSolvedSyncPlatform:
    def discover_challenges(self, live: bool = False) -> PlatformAction:
        return PlatformAction(
            action="discover_challenges",
            live=live,
            network=live,
            status="ok",
            details={
                "challenges": [
                    {
                        "challenge_id": "team-solved",
                        "name": "Team Solved",
                        "category": "misc",
                        "statement": "Already solved by another teammate.",
                        "solved": True,
                        "submission": {"status": "correct", "candidate": "TOKEN_SYNTHETIC_SUBMISSION_MARKER"},
                    }
                ]
            },
        )


class FakeRefreshSyncPlatform:
    def __init__(self, challenges: list[dict]):
        self.challenges = challenges
        self.calls = 0
        self.live_values: list[bool] = []

    def discover_challenges(self, live: bool = False) -> PlatformAction:
        self.calls += 1
        self.live_values.append(live)
        return PlatformAction(
            action="discover_challenges",
            live=live,
            network=live,
            status="ok",
            details={"challenges": list(self.challenges)},
        )


def _static_shell(challenge_id: str) -> dict:
    return {
        "challenge_id": challenge_id,
        "name": challenge_id,
        "category": "misc",
        "statement": "DEF CON CTF Quals 2026",
        "file_count": 0,
        "links": [{"url": "/favicon.ico"}, {"url": "/assets/style.css"}],
    }


def _sync_defcon_fixture(tmp_path: Path, monkeypatch) -> dict:
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))
    profile = tmp_path / "profile.yaml"
    profile.write_text("name: defcon\n", encoding="utf-8")
    monkeypatch.setattr("ctf_runner.interactive.load_platform_adapter", lambda profile: FakeDefconSyncPlatform())
    return _run_json(["interactive", "sync", "--contest-id", "defcon", "--profile", str(profile), "--live", "--json"])


class ArtifactUploadServer:
    def __init__(self, *, raw_secret_marker: str):
        self.raw_secret_marker = raw_secret_marker
        self.request_paths: list[str] = []
        self.upload_count = 0
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _ArtifactUploadHandler)
        self._httpd.owner = self
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self._httpd.server_address[1]}"

    def __enter__(self):
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread:
            self._thread.join(timeout=2)
        return False


class _ArtifactUploadHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        owner: ArtifactUploadServer = self.server.owner
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        owner.request_paths.append(self.path)
        owner.upload_count += 1
        status = "accepted" if b"\x00asm" in body else "rejected"
        self._send_json({"status": status, "active": status == "accepted", "token": owner.raw_secret_marker})

    def do_GET(self):
        owner: ArtifactUploadServer = self.server.owner
        owner.request_paths.append(self.path)
        self._send_json({"status": "active", "active": True, "cookie": owner.raw_secret_marker})

    def log_message(self, format, *args):
        return

    def _send_json(self, payload: dict):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def _seed_board(tmp_path: Path, monkeypatch, profile: Path | None = None) -> None:
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))
    args = ["interactive", "init", "--contest-id", "demo", "--json"]
    if profile:
        profile.write_text("name: demo\n", encoding="utf-8")
        args.extend(["--profile", str(profile)])
    _run_json(args)
    board = tmp_path / "contests" / "demo" / "operator" / "board.json"
    board.write_text(
        json.dumps(
            {
                "contest_id": "demo",
                "challenges": [
                    {
                        "challenge_id": "birdhouse",
                        "name": "Birdhouse",
                        "category": "misc",
                        "status": "todo",
                        "priority": 100,
                        "path": str(tmp_path / "contests" / "demo" / "misc" / "Birdhouse"),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def _seed_target_planning_board(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))
    _run_json(["interactive", "init", "--contest-id", "planning", "--json"])
    root = tmp_path / "contests" / "planning"
    challenge = root / "web" / "Real_Target"
    raw = challenge / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    (raw / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n@app.route('/api/check')\ndef check(): pass\n", encoding="utf-8")
    (challenge / "brief.md").write_text("# Brief\nRemote: nc real.example 31337\n", encoding="utf-8")
    board = root / "operator" / "board.json"
    board.write_text(
        json.dumps(
            {
                "contest_id": "planning",
                "challenges": [
                    {
                        "challenge_id": "alias-target",
                        "canonical_id": "real-target",
                        "canonical_name": "Real Target",
                        "name": "Real Target Alias",
                        "category": "web",
                        "status": "todo",
                        "priority": 1,
                        "is_alias": True,
                        "claimable": True,
                        "has_files": True,
                    },
                    {
                        "challenge_id": "real-target-static",
                        "canonical_id": "real-target",
                        "canonical_name": "Real Target",
                        "name": "real-target-static",
                        "category": "web",
                        "status": "skipped",
                        "priority": 1,
                        "is_static_shell": True,
                        "is_static_alias": True,
                        "claimable": False,
                    },
                    {
                        "challenge_id": "artifact-row",
                        "canonical_id": "real-target",
                        "canonical_name": "Real Target",
                        "name": "artifact-row",
                        "category": "web",
                        "status": "todo",
                        "priority": 0,
                        "is_artifact_source": True,
                        "claimable": True,
                        "has_files": True,
                    },
                    {
                        "challenge_id": "text-only",
                        "name": "Text Only",
                        "canonical_id": "text-only",
                        "canonical_name": "Text Only",
                        "category": "misc",
                        "statement": "DEF CON CTF Quals 2026",
                        "status": "todo",
                        "priority": 1,
                        "has_files": False,
                        "file_count": 0,
                        "claimable": True,
                    },
                    {
                        "challenge_id": "real-target",
                        "name": "Real Target",
                        "canonical_id": "real-target",
                        "canonical_name": "Real Target",
                        "category": "web",
                        "statement": "Real challenge with a Flask route and nc real.example 31337.",
                        "status": "todo",
                        "priority": 100,
                        "has_files": True,
                        "file_count": 1,
                        "claimable": True,
                        "path": str(challenge),
                        "aliases": ["alias-target", "Real Target Alias"],
                        "artifact_sources": ["real-target-static"],
                        "source_ids": ["real-target", "alias-target", "real-target-static"],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )


def _seed_pwn_target_board(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))
    _run_json(["interactive", "init", "--contest-id", "pwn-plan", "--json"])
    root = tmp_path / "contests" / "pwn-plan"
    challenge = root / "pwn" / "Overflow"
    raw = challenge / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    (raw / "chall").write_bytes(b"\x7fELF\x02\x01\x01\x00overflow")
    (challenge / "brief.md").write_text("# Brief\npwn service: nc pwn.example 4444\n", encoding="utf-8")
    board = root / "operator" / "board.json"
    board.write_text(
        json.dumps(
            {
                "contest_id": "pwn-plan",
                "challenges": [
                    {
                        "challenge_id": "overflow",
                        "name": "Overflow",
                        "canonical_id": "overflow",
                        "canonical_name": "Overflow",
                        "category": "pwn",
                        "statement": "Exploit the service at nc pwn.example 4444.",
                        "status": "todo",
                        "priority": 100,
                        "has_files": True,
                        "file_count": 1,
                        "claimable": True,
                        "path": str(challenge),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def _seed_rev_triage_board(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))
    _run_json(["interactive", "init", "--contest-id", "rev-triage", "--json"])
    root = tmp_path / "contests" / "rev-triage"
    challenge = root / "rev" / "Crackme"
    raw = challenge / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    (raw / "crackme").write_bytes(b"\x7fELF\x02\x01\x01\x00fake-rev-binary-check-verify-key")
    (raw / "notes.txt").write_text("verify candidate with xor key and base64 decoder\n", encoding="utf-8")
    (challenge / "brief.md").write_text("# Brief\nReverse the crackme and recover the key.\n", encoding="utf-8")
    (root / "operator" / "board.json").write_text(
        json.dumps(
            {
                "contest_id": "rev-triage",
                "challenges": [
                    {
                        "challenge_id": "crackme",
                        "name": "Crackme",
                        "canonical_id": "crackme",
                        "canonical_name": "Crackme",
                        "category": "rev",
                        "statement": "Reverse the local crackme.",
                        "status": "todo",
                        "priority": 100,
                        "has_files": True,
                        "file_count": 2,
                        "claimable": True,
                        "path": str(challenge),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def _seed_category_starter_board(tmp_path: Path, monkeypatch, *, contest_id: str, category: str) -> None:
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))
    _run_json(["interactive", "init", "--contest-id", contest_id, "--json"])
    root = tmp_path / "contests" / contest_id
    challenge = root / category / "Demo"
    raw = challenge / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    if category == "web":
        (raw / "app.py").write_text("from flask import Flask\napp=Flask(__name__)\n@app.route('/api/check')\ndef check(): pass\n", encoding="utf-8")
    elif category == "pwn":
        (raw / "chall").write_bytes(b"\x7fELF\x02\x01\x01\x00demo-pwn")
    elif category == "crypto":
        (raw / "params.txt").write_text("n = 3233\ne = 17\nc = 855\n", encoding="utf-8")
    (challenge / "brief.md").write_text(f"# Brief\n{category} starter smoke.\n", encoding="utf-8")
    (root / "operator" / "board.json").write_text(
        json.dumps(
            {
                "contest_id": contest_id,
                "challenges": [
                    {
                        "challenge_id": "demo",
                        "name": "Demo",
                        "canonical_id": "demo",
                        "canonical_name": "Demo",
                        "category": category,
                        "statement": f"{category} local starter smoke.",
                        "status": "todo",
                        "priority": 100,
                        "has_files": True,
                        "file_count": 1,
                        "claimable": True,
                        "path": str(challenge),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def _seed_solve_harness_board(tmp_path: Path, monkeypatch, *, contest_id: str, profile: Path | None = None) -> None:
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))
    args = ["interactive", "init", "--contest-id", contest_id, "--json"]
    if profile:
        profile.write_text("name: demo\n", encoding="utf-8")
        args.extend(["--profile", str(profile)])
    _run_json(args)
    root = tmp_path / "contests" / contest_id
    challenge = root / "misc" / "Auto"
    raw = challenge / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    (raw / "notes.txt").write_text("local solve harness fixture\n", encoding="utf-8")
    (challenge / "brief.md").write_text("# Brief\nRun the local starter and submit the verified candidate.\n", encoding="utf-8")
    (root / "operator" / "board.json").write_text(
        json.dumps(
            {
                "contest_id": contest_id,
                "challenges": [
                    {
                        "challenge_id": "auto",
                        "name": "Auto",
                        "canonical_id": "auto",
                        "canonical_name": "Auto",
                        "category": "misc",
                        "statement": "Local solve harness fixture.",
                        "status": "todo",
                        "priority": 100,
                        "has_files": True,
                        "file_count": 1,
                        "claimable": True,
                        "path": str(challenge),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def _run_json(argv: list[str]) -> dict:
    result, output, code = _run(argv)
    assert code == 0, output
    return result


def _run_json_fail(argv: list[str]) -> dict:
    result, output, code = _run(argv)
    assert code != 0, output
    return result


def _run_json_with_output(argv: list[str]) -> tuple[dict, str]:
    result, output, code = _run(argv)
    assert code == 0, output
    return result, output


def _run(argv: list[str]) -> tuple[dict, str, int]:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = main(argv)
    output = buffer.getvalue()
    return json.loads(output), output, code


def _append_jsonl(path: Path, payload: dict) -> None:
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, sort_keys=True))
        fh.write("\n")
