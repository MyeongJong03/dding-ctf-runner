import os
import subprocess
from pathlib import Path

import pytest


def _repo() -> Path:
    return Path(__file__).resolve().parents[1]


def test_ctf_worker_rejects_unknown_worker(tmp_path):
    repo = _repo()
    env = os.environ.copy()
    env["HOME"] = str(tmp_path)

    result = subprocess.run(
        [str(repo / "scripts" / "ctf-worker"), "worker-6", "interactive", "--dry-run"],
        cwd=repo,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    assert "unknown worker: worker-6" in result.stderr
    assert ".codex/auth.json" not in result.stdout + result.stderr


def test_ctf_worker_dry_run_prints_runner_context_without_auth_material():
    repo = _repo()
    env = os.environ.copy()
    env.pop("CTF_CODEX_MODEL", None)

    result = subprocess.run(
        [str(repo / "scripts" / "ctf-worker"), "worker-1", "interactive", "--dry-run"],
        cwd=Path("/tmp"),
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    home = Path.home()
    expected_repo = str(repo).replace(str(home), "~", 1) if repo.is_relative_to(home) else str(repo)
    assert expected_repo in output
    assert "CODEX_HOME=~/.codex-workers/worker-1" in output
    assert "--ask-for-approval never" in output
    assert "--sandbox danger-full-access" in output
    assert "--model" not in output
    assert "worker-1" in output
    assert "plain codex" in output
    assert "[warn] competition worker uses model=auto/unpinned approval=never sandbox=danger-full-access" in output
    assert ".codex/auth.json" not in output
    assert "dummy-secret" not in output


def test_ctf_worker_dry_run_respects_safe_override(tmp_path):
    repo = _repo()
    worker_home = tmp_path / ".codex-workers" / "worker-1"
    worker_home.mkdir(parents=True)
    (worker_home / "AGENTS.md").write_text("# slim\n", encoding="utf-8")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_codex = bin_dir / "codex"
    fake_codex.write_text("#!/usr/bin/env bash\necho \"$*\"\n", encoding="utf-8")
    fake_codex.chmod(0o755)

    env = os.environ.copy()
    env["HOME"] = str(tmp_path)
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    env["CTF_CODEX_BIN"] = str(fake_codex)
    env["CTF_CODEX_DANGER"] = "0"
    env["CTF_CODEX_SANDBOX"] = "workspace-write"
    env.pop("CTF_CODEX_MODEL", None)

    result = subprocess.run(
        [str(repo / "scripts" / "ctf-worker"), "worker-1", "interactive", "--dry-run"],
        cwd=repo,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "--sandbox workspace-write" in output
    dry_run_line = next(line for line in output.splitlines() if line.startswith("dry-run command:"))
    assert dry_run_line.count("--ask-for-approval") == 1
    assert dry_run_line.count("--model") == 0


def test_ctf_worker_dry_run_respects_model_override(tmp_path):
    repo = _repo()
    worker_home = tmp_path / ".codex-workers" / "worker-1"
    worker_home.mkdir(parents=True)
    (worker_home / "AGENTS.md").write_text("# slim\n", encoding="utf-8")
    fake_codex = tmp_path / "codex"
    fake_codex.write_text("#!/usr/bin/env bash\necho \"$*\"\n", encoding="utf-8")
    fake_codex.chmod(0o755)

    env = os.environ.copy()
    env["HOME"] = str(tmp_path)
    env["CTF_CODEX_BIN"] = str(fake_codex)
    env["CTF_CODEX_MODEL"] = "gpt-test"

    result = subprocess.run(
        [str(repo / "scripts" / "ctf-worker"), "worker-1", "interactive", "--dry-run"],
        cwd=repo,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    dry_run_line = next(line for line in output.splitlines() if line.startswith("dry-run command:"))
    assert "--model gpt-test" in dry_run_line
    assert dry_run_line.count("--model") == 1


@pytest.mark.parametrize("model_value", ["", "auto"])
def test_ctf_worker_dry_run_can_omit_model_flag(tmp_path, model_value):
    repo = _repo()
    worker_home = tmp_path / ".codex-workers" / "worker-1"
    worker_home.mkdir(parents=True)
    (worker_home / "AGENTS.md").write_text("# slim\n", encoding="utf-8")
    fake_codex = tmp_path / "codex"
    fake_codex.write_text("#!/usr/bin/env bash\necho \"$*\"\n", encoding="utf-8")
    fake_codex.chmod(0o755)

    env = os.environ.copy()
    env["HOME"] = str(tmp_path)
    env["CTF_CODEX_BIN"] = str(fake_codex)
    env["CTF_CODEX_MODEL"] = model_value

    result = subprocess.run(
        [str(repo / "scripts" / "ctf-worker"), "worker-1", "interactive", "--dry-run"],
        cwd=repo,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    dry_run_line = next(line for line in output.splitlines() if line.startswith("dry-run command:"))
    assert "--model" not in dry_run_line
    assert "model=auto/unpinned" in output
