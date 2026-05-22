import json
from pathlib import Path

from ctf_runner.postsolve import archive_postsolve, generate_postsolve
from ctf_runner.submit import hash_flag


def test_postsolve_generates_local_only_docs_and_manifest(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))
    raw = "FLAG" + "{" + "local_postsolve_archive_alpha" + "}"
    digest = hash_flag(raw)
    challenge_dir = tmp_path / "contests" / "local-fake" / "solved-1"
    _write_artifacts(challenge_dir, raw)

    state = {
        "id": "solved-1",
        "contest_id": "local-fake",
        "name": "Local Archive",
        "category": "misc",
        "points": 100,
        "status": "solved",
        "metadata": json.dumps({"challenge_dir": str(challenge_dir)}),
    }
    result = {
        "status": "solved",
        "worker_id": "worker-test",
        "solver_result": {
            "summary": f"extracted candidate {raw}",
            "facts": [f"log contained {raw}", "used raw/note.txt"],
            "attempts": ["python3 exploits/solve.py"],
            "flag_candidates": [{"flag_hash": digest}],
        },
        "submit_plans": [{"status": "accepted", "confidence": "high", "flag_hash": digest}],
    }

    generated = generate_postsolve("local-fake", "solved-1", state=state, result=result)

    postsolve_dir = challenge_dir / "postsolve"
    assert generated["status"] == "ok"
    for name in (
        "solve_summary.md",
        "writeup_draft.md",
        "skill_candidate.md",
        "artifacts_manifest.json",
        "timeline.jsonl",
        "postsolve_summary.json",
    ):
        assert (postsolve_dir / name).exists()
    generated_text = "\n".join((postsolve_dir / name).read_text(encoding="utf-8") for name in postsolve_dir.iterdir() if name.is_file())
    assert raw not in generated_text
    assert digest in generated_text
    assert "[REDACTED" in generated_text

    manifest = json.loads((postsolve_dir / "artifacts_manifest.json").read_text(encoding="utf-8"))
    metadata_only_paths = {item["path"] for item in manifest["metadata_only"]}
    assert "logs/run.log" in metadata_only_paths
    assert "auth/session_cookie.txt" in metadata_only_paths


def test_archive_excludes_sensitive_files_and_content(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))
    raw = "FLAG" + "{" + "archive_sensitive_content_beta" + "}"
    challenge_dir = tmp_path / "contests" / "local-fake" / "solved-2"
    _write_artifacts(challenge_dir, raw)
    state = {
        "id": "solved-2",
        "contest_id": "local-fake",
        "status": "solved",
        "metadata": json.dumps({"challenge_dir": str(challenge_dir)}),
    }

    archived = archive_postsolve("local-fake", "solved-2", state=state)

    archive_dir = Path(str(archived["archive_dir"]).replace("~/", str(Path.home()) + "/", 1))
    copied_root = archive_dir / "files"
    assert archived["status"] == "ok"
    assert (copied_root / "raw" / "note.txt").exists()
    assert (copied_root / "exploits" / "solve.py").exists()
    assert not (copied_root / "logs" / "run.log").exists()
    assert not (copied_root / "auth" / "session_cookie.txt").exists()
    copied_text = "\n".join(path.read_text(encoding="utf-8", errors="ignore") for path in copied_root.rglob("*") if path.is_file())
    assert raw not in copied_text

    manifest_text = (archive_dir / "artifacts_manifest.json").read_text(encoding="utf-8")
    assert raw not in manifest_text
    assert "sensitive_content" in manifest_text
    assert "sensitive_filename" in manifest_text


def _write_artifacts(challenge_dir: Path, raw_flag: str) -> None:
    (challenge_dir / "raw").mkdir(parents=True)
    (challenge_dir / "extracted").mkdir()
    (challenge_dir / "exploits").mkdir()
    (challenge_dir / "logs").mkdir()
    (challenge_dir / "auth").mkdir()
    (challenge_dir / "raw" / "note.txt").write_text("local note without secrets\n", encoding="utf-8")
    (challenge_dir / "extracted" / "readme.txt").write_text("decoded clue\n", encoding="utf-8")
    (challenge_dir / "exploits" / "solve.py").write_text("print('sanitized solver')\n", encoding="utf-8")
    (challenge_dir / "logs" / "run.log").write_text(f"candidate={raw_flag}\n", encoding="utf-8")
    (challenge_dir / "auth" / "session_cookie.txt").write_text("session=local-secret\n", encoding="utf-8")
