from __future__ import annotations

import os
import subprocess
from pathlib import Path


def _repo() -> Path:
    return Path(__file__).resolve().parents[1]


def _fake_openai_codex_symlink(home: Path, prefix: str, version: str) -> Path:
    root = home / prefix
    target = root / "lib/node_modules/@openai/codex/bin/codex.js"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(f"#!/usr/bin/env bash\necho 'codex-cli {version}'\n", encoding="utf-8")
    target.chmod(0o755)
    link = root / "bin/codex"
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(Path("../lib/node_modules/@openai/codex/bin/codex.js"))
    return link


def _run_fix(repo: Path, home: Path, preferred: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["PATH"] = f"{preferred.parent}:{env['PATH']}"
    env["CTF_CODEX_BIN"] = str(preferred)
    return subprocess.run(
        [str(repo / "scripts" / "fix-codex-install.sh"), *args],
        cwd=repo,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_fix_codex_install_dry_run_reports_stale_local_symlink(tmp_path):
    repo = _repo()
    old = _fake_openai_codex_symlink(tmp_path, ".local", "0.128.0")
    preferred = _fake_openai_codex_symlink(tmp_path, ".npm-global", "0.130.0")
    (tmp_path / ".bashrc").write_text("# shell\n", encoding="utf-8")

    result = _run_fix(repo, tmp_path, preferred)

    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "mode: dry-run" in output
    assert f"path={old}" in output
    assert "version=0.128.0" in output
    assert "rename_to=" in output
    assert old.is_symlink()
    assert not list(old.parent.glob("codex.disabled.*"))
    assert (tmp_path / ".bashrc").read_text(encoding="utf-8") == "# shell\n"


def test_fix_codex_install_apply_renames_only_lower_version_symlink(tmp_path):
    repo = _repo()
    old = _fake_openai_codex_symlink(tmp_path, ".local", "0.128.0")
    old_target = old.resolve()
    preferred = _fake_openai_codex_symlink(tmp_path, ".npm-global", "0.130.0")

    result = _run_fix(repo, tmp_path, preferred, "--apply")

    output = result.stdout + result.stderr
    disabled = list(old.parent.glob("codex.disabled.*"))
    assert result.returncode == 0, output
    assert "disabled_stale_symlink:" in output
    assert not old.exists()
    assert len(disabled) == 1
    assert disabled[0].is_symlink()
    assert old_target.exists()
    bashrc = (tmp_path / ".bashrc").read_text(encoding="utf-8")
    assert f'export CTF_CODEX_BIN="{preferred}"' in bashrc
    assert "alias ctf-worker-1=" in bashrc


def test_fix_codex_install_apply_keeps_same_or_newer_local_symlink(tmp_path):
    repo = _repo()
    local = _fake_openai_codex_symlink(tmp_path, ".local", "0.130.0")
    preferred = _fake_openai_codex_symlink(tmp_path, ".npm-global", "0.130.0")

    result = _run_fix(repo, tmp_path, preferred, "--apply")

    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "disabled_stale_symlink:" not in output
    assert local.is_symlink()
    assert not list(local.parent.glob("codex.disabled.*"))
