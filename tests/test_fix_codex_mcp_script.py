from __future__ import annotations

import os
import subprocess
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _write_config(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        """
[mcp_servers.dreamhack_solver]
command = "dreamhack-secret-command"
args = ["--opaque", "raw-arg-value"]
env = { OPAQUE = "raw-env-value" }

[mcp_servers.ReVa]
command = "reva-secret-command"

[mcp_servers.ctf_solver]
command = "ctf-secret-command"
""",
        encoding="utf-8",
    )


def _run_script(tmp_path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["HOME"] = str(tmp_path)
    return subprocess.run(
        [str(_repo_root() / "scripts" / "fix-codex-mcp.sh"), *args],
        cwd=_repo_root(),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )


def test_fix_codex_mcp_dry_run_does_not_modify_or_leak_raw_values(tmp_path: Path):
    config = tmp_path / ".codex" / "config.toml"
    _write_config(config)
    before = config.read_text(encoding="utf-8")

    result = _run_script(tmp_path, "--remove-legacy-dreamhack")
    combined = result.stdout + result.stderr

    assert result.returncode == 0
    assert "mode: dry-run" in result.stdout
    assert "found_server_names: ReVa,ctf_solver,dreamhack_solver" in result.stdout
    assert "would_remove: yes" in result.stdout
    assert "applied: no" in result.stdout
    assert config.read_text(encoding="utf-8") == before
    for raw in ("dreamhack-secret-command", "raw-arg-value", "raw-env-value", "reva-secret-command"):
        assert raw not in combined


def test_fix_codex_mcp_apply_creates_backup_and_removes_only_legacy(tmp_path: Path):
    config = tmp_path / ".codex" / "config.toml"
    _write_config(config)

    result = _run_script(tmp_path, "--remove-legacy-dreamhack", "--apply")
    combined = result.stdout + result.stderr

    assert result.returncode == 0
    assert "mode: apply" in result.stdout
    assert "applied: yes" in result.stdout
    backups = list(config.parent.glob("config.toml.bak.*"))
    assert len(backups) == 1
    content = config.read_text(encoding="utf-8")
    assert "dreamhack_solver" not in content
    assert "[mcp_servers.ReVa]" in content
    assert "[mcp_servers.ctf_solver]" in content
    backup = backups[0].read_text(encoding="utf-8")
    assert "dreamhack_solver" in backup
    for raw in ("dreamhack-secret-command", "raw-arg-value", "raw-env-value", "reva-secret-command"):
        assert raw not in combined
