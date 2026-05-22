from __future__ import annotations

import os
import subprocess
from pathlib import Path


def _repo() -> Path:
    return Path(__file__).resolve().parents[1]


def _fake_codex(path: Path, version: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!/usr/bin/env bash\necho 'codex-cli {version}'\n", encoding="utf-8")
    path.chmod(0o755)


def test_fix_codex_shell_dry_run_adds_block(tmp_path):
    repo = _repo()
    bashrc = tmp_path / ".bashrc"
    bashrc.write_text("alias codex='old-codex'\n", encoding="utf-8")
    codex = tmp_path / ".local/bin/codex"
    _fake_codex(codex, "0.130.0")

    env = os.environ.copy()
    env["HOME"] = str(tmp_path)
    env["PATH"] = f"{codex.parent}:{env['PATH']}"
    env["CTF_CODEX_BIN"] = str(codex)

    result = subprocess.run(
        [str(repo / "scripts" / "fix-codex-shell.sh")],
        cwd=repo,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "planned block:" in output
    assert 'export CTF_CODEX_BIN="' in output
    assert "alias ctf-worker-1='~/dding-ctf-runner/scripts/ctf-worker-1'" in output
    assert "dry-run only; no files changed" in output
    assert "alias codex='old-codex'" in bashrc.read_text(encoding="utf-8")


def test_fix_codex_shell_apply_creates_backup_and_updates_block(tmp_path):
    repo = _repo()
    bashrc = tmp_path / ".bashrc"
    bashrc.write_text(
        "\n".join(
            [
                "alias codex='legacy-codex'",
                "# >>> dding-ctf-runner codex aliases >>>",
                "export CTF_CODEX_BIN=\"/old/path/codex\"",
                "# <<< dding-ctf-runner codex aliases <<<",
                "",
            ]
        ),
        encoding="utf-8",
    )
    codex = tmp_path / ".npm-global/bin/codex"
    _fake_codex(codex, "0.130.0")

    env = os.environ.copy()
    env["HOME"] = str(tmp_path)
    env["PATH"] = f"{codex.parent}:{env['PATH']}"
    env["CTF_CODEX_BIN"] = str(codex)

    result = subprocess.run(
        [str(repo / "scripts" / "fix-codex-shell.sh"), "--apply"],
        cwd=repo,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    output = result.stdout + result.stderr
    content = bashrc.read_text(encoding="utf-8")
    backups = sorted(tmp_path.glob(".bashrc.bak.*"))

    assert result.returncode == 0, output
    assert backups, output
    assert content.count("# >>> dding-ctf-runner codex aliases >>>") == 1
    assert 'export CTF_CODEX_BIN="' in content
    assert "alias codex='legacy-codex'" in content
    assert 'alias codex="$CTF_CODEX_BIN -a never -s danger-full-access"' in content
