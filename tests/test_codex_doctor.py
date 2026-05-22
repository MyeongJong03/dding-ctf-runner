from __future__ import annotations

import os
from pathlib import Path

from ctf_runner import codex_doctor


def _write_fake_codex(path: Path, version: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!/usr/bin/env bash\necho 'codex-cli {version}'\n", encoding="utf-8")
    path.chmod(0o755)


def test_choose_preferred_binary_uses_highest_semver(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("CTF_CODEX_BIN", raising=False)
    old_bin = tmp_path / ".local/bin/codex"
    new_bin = tmp_path / ".npm-global/bin/codex"
    _write_fake_codex(old_bin, "0.128.0")
    _write_fake_codex(new_bin, "0.130.0")
    monkeypatch.setenv("PATH", f"{old_bin.parent}:{new_bin.parent}:{os.environ['PATH']}")
    monkeypatch.setattr(codex_doctor, "_candidate_paths", lambda: [old_bin, new_bin])

    preferred = codex_doctor.choose_preferred_codex_binary()

    assert preferred["path"] == str(new_bin)
    assert preferred["version"] == "0.130.0"


def test_choose_preferred_binary_honors_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    active_bin = tmp_path / ".local/bin/codex"
    override_bin = tmp_path / "custom/codex"
    _write_fake_codex(active_bin, "0.128.0")
    _write_fake_codex(override_bin, "0.120.0")
    monkeypatch.setenv("PATH", f"{active_bin.parent}:{os.environ['PATH']}")
    monkeypatch.setenv("CTF_CODEX_BIN", str(override_bin))
    monkeypatch.setattr(codex_doctor, "_candidate_paths", lambda: [active_bin])

    preferred = codex_doctor.choose_preferred_codex_binary()

    assert preferred["path"] == str(override_bin)
    assert preferred["selected_reason"] == "env_override"


def test_diagnose_codex_update_issue_detects_path_conflict(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("CTF_CODEX_BIN", raising=False)
    active_bin = tmp_path / ".local/bin/codex"
    newer_bin = tmp_path / ".npm-global/bin/codex"
    _write_fake_codex(active_bin, "0.128.0")
    _write_fake_codex(newer_bin, "0.130.0")
    monkeypatch.setenv("PATH", f"{active_bin.parent}:{newer_bin.parent}:{os.environ['PATH']}")
    monkeypatch.setattr(codex_doctor, "_candidate_paths", lambda: [active_bin, newer_bin])
    monkeypatch.setattr(codex_doctor, "_shell_alias_status", lambda: {"detected": False, "definition": ""})

    diagnosis = codex_doctor.diagnose_codex_update_issue()

    assert diagnosis["active_binary"]["path"] == str(active_bin)
    assert diagnosis["preferred_binary"]["path"] == str(newer_bin)
    assert diagnosis["path_conflict"] is True
    assert diagnosis["update_mismatch"] is True
