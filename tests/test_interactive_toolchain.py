import contextlib
import io
import json
import os
from pathlib import Path

from ctf_runner.cli import main


def test_capabilities_detects_synthetic_path_and_records_metrics(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))
    _set_fake_path(monkeypatch, tmp_path, ["python3", "git", "curl", "file", "strings", "openssl", "nc"])

    result = _run_json(["interactive", "capabilities", "--contest-id", "tools", "--category", "pwn", "--json"])

    root = tmp_path / "contests" / "tools" / "operator"
    by_name = {row["name"]: row for row in result["tools"]}
    events = (root / "metrics" / "events.jsonl").read_text(encoding="utf-8")

    assert result["status"] == "ok"
    assert by_name["python3"]["available"] is True
    assert by_name["ncat"]["available"] is False
    assert "ncat" in result["missing_high_priority_tools"]
    assert (root / "toolchain" / "capabilities.json").exists()
    assert (root / "toolchain" / "capabilities.md").exists()
    assert "toolchain_checked" in events
    assert str(tmp_path) not in events


def test_fallback_ncat_and_cpio_return_expected_suggestions():
    ncat = _run_json(["interactive", "fallback", "--tool", "ncat", "--json"])
    cpio = _run_json(["interactive", "fallback", "--tool", "cpio", "--json"])

    assert ncat["status"] == "ok"
    assert "openssl_s_client" in [row["id"] for row in ncat["suggestions"]]
    assert cpio["status"] == "ok"
    assert "bsdtar_cpio_extract" in [row["id"] for row in cpio["suggestions"]]
    assert cpio["install_hints"]
    assert cpio["no_auto_install"] is True


def test_target_pack_includes_toolchain_warnings(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))
    _set_fake_path(monkeypatch, tmp_path, ["python3", "git", "curl", "file", "strings", "openssl", "nc"])
    _seed_pwn_toolchain_board(tmp_path, "pwn-tools")

    result = _run_json(["interactive", "target-pack", "--contest-id", "pwn-tools", "--challenge-id", "overflow", "--agent", "a1", "--json"])
    text = Path(result["target_pack_path"].replace("~", str(Path.home()), 1)).read_text(encoding="utf-8")

    assert result["status"] == "ok"
    assert "## Toolchain Capability" in text
    assert "available_tools:" in text
    assert "missing_critical_tools:" in text
    assert "ncat" in text
    assert "recommended_fallbacks:" in text
    assert "openssl_s_client" in text


def test_triage_avoids_missing_required_tool_in_first_commands(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))
    _set_fake_path(monkeypatch, tmp_path, ["python3", "git", "curl", "file", "strings", "readelf", "openssl", "nc"])
    _seed_pwn_toolchain_board(tmp_path, "pwn-triage")

    result = _run_json(["interactive", "triage", "--contest-id", "pwn-triage", "--challenge-id", "overflow", "--agent", "a1", "--category", "pwn", "--json"])

    assert result["status"] == "ok"
    assert all("checksec" not in command for command in result["first_commands"])
    assert any("readelf" in command for command in result["first_commands"])
    assert result["skipped_tools"]


def test_pwn_starter_uses_pwntools_optional_fallback(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))
    _set_fake_path(monkeypatch, tmp_path, ["python3", "git", "curl", "file", "strings"])
    _seed_pwn_toolchain_board(tmp_path, "pwn-starter")

    result = _run_json(["interactive", "starter", "--contest-id", "pwn-starter", "--challenge-id", "overflow", "--category", "pwn", "--json"])
    text = Path(result["starter_path"].replace("~", str(Path.home()), 1)).read_text(encoding="utf-8")

    assert result["status"] == "ok"
    assert "from pwn import" in text
    assert "except ImportError" in text
    assert "SocketTube" in text
    assert "MISSING_CRITICAL_TOOLS" in text


def test_solve_loop_records_missing_tool_and_next_steps(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))
    _set_fake_path(monkeypatch, tmp_path, ["python3", "git", "curl", "file", "strings"])
    _seed_pwn_toolchain_board(tmp_path, "missing-tool-loop")
    challenge = tmp_path / "contests" / "missing-tool-loop" / "pwn" / "Overflow"
    (challenge / "exploit.py").write_text("import subprocess\nsubprocess.run(['ncat', '127.0.0.1', '1'], check=False)\n", encoding="utf-8")

    result = _run_json(
        [
            "interactive",
            "solve-loop",
            "--contest-id",
            "missing-tool-loop",
            "--agent",
            "a1",
            "--challenge-id",
            "overflow",
            "--max-attempts",
            "2",
            "--json",
        ]
    )

    root = tmp_path / "contests" / "missing-tool-loop" / "operator"
    events = (root / "metrics" / "events.jsonl").read_text(encoding="utf-8")
    next_steps = (challenge / "next_steps.md").read_text(encoding="utf-8")

    assert result["status"] == "stalled"
    assert result["reason"] == "missing_tool"
    assert result["missing_tool"]["tool"] == "ncat"
    assert "missing_tool_observed" in events
    assert "fallback" in next_steps


def _set_fake_path(monkeypatch, tmp_path: Path, names: list[str]) -> Path:
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    for name in names:
        path = bindir / name
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(0o755)
    monkeypatch.setenv("PATH", str(bindir))
    return bindir


def _seed_pwn_toolchain_board(tmp_path: Path, contest_id: str) -> None:
    _run_json(["interactive", "init", "--contest-id", contest_id, "--json"])
    root = tmp_path / "contests" / contest_id
    challenge = root / "pwn" / "Overflow"
    handout = challenge / "handout"
    handout.mkdir(parents=True)
    (challenge / "brief.md").write_text("# Overflow\nConnect with ncat --ssl tls.example 443.\n", encoding="utf-8")
    (handout / "chall").write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 128)
    for name in ["memory.md", "evidence.md", "attempts.md", "next_steps.md", "operator_notes.md"]:
        (challenge / name).write_text(f"# {name}\n", encoding="utf-8")
    board = {
        "contest_id": contest_id,
        "updated_at": "now",
        "challenges": [
            {
                "challenge_id": "overflow",
                "name": "Overflow",
                "canonical_id": "overflow",
                "canonical_name": "Overflow",
                "category": "pwn",
                "status": "todo",
                "path": str(challenge),
                "has_files": True,
                "connection_info": "ncat --ssl tls.example 443",
            }
        ],
    }
    (root / "operator" / "board.json").write_text(json.dumps(board), encoding="utf-8")


def _run_json(argv: list[str]) -> dict:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = main(argv)
    output = buffer.getvalue()
    assert code == 0, output
    return json.loads(output)
