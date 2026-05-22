import os
import subprocess
from pathlib import Path


def test_run_codex_worker_exec_uses_worker_home_and_prompt(tmp_path):
    repo = Path(__file__).resolve().parents[1]

    home = tmp_path / "home"
    worker_home = home / ".codex-workers" / "worker-1"
    worker_home.mkdir(parents=True)
    (worker_home / "AGENTS.md").write_text("# slim\n", encoding="utf-8")

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_codex = bin_dir / "codex"
    fake_codex.write_text(
        "#!/usr/bin/env bash\n"
        "printf 'FAKE_CODEX_HOME=%s\\n' \"$CODEX_HOME\"\n"
        "printf 'FAKE_HOME=%s\\n' \"$HOME\"\n"
        "printf 'FAKE_CODEX_ARGS=%s\\n' \"$*\"\n",
        encoding="utf-8",
    )
    fake_codex.chmod(0o755)

    env = os.environ.copy()
    env["HOME"] = str(home)
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    env["CTF_CODEX_BIN"] = str(fake_codex)
    env.pop("CTF_CODEX_MODEL", None)

    result = subprocess.run(
        [
            str(repo / "scripts" / "run-codex-worker.sh"),
            "--run",
            "worker-1",
            "exec",
            "Reply with exactly: RUNNER_SMOKE_OK",
        ],
        cwd=repo,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert f"FAKE_CODEX_HOME={worker_home}" in result.stdout
    assert f"FAKE_HOME={home}" in result.stdout
    assert "--model" not in result.stdout
    assert "--ask-for-approval never" in result.stdout
    assert "--sandbox danger-full-access" in result.stdout
    assert f"--add-dir {repo}" in result.stdout
    assert "FAKE_CODEX_ARGS=--ask-for-approval never --sandbox danger-full-access" in result.stdout
    assert "exec Reply with exactly: RUNNER_SMOKE_OK" in result.stdout
    assert "placeholder" not in result.stdout


def test_run_codex_worker_respects_automation_env(tmp_path):
    repo = Path(__file__).resolve().parents[1]

    home = tmp_path / "home"
    worker_home = home / ".codex-workers" / "worker-1"
    worker_home.mkdir(parents=True)
    (worker_home / "AGENTS.md").write_text("# slim\n", encoding="utf-8")

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_codex = bin_dir / "codex"
    fake_codex.write_text(
        "#!/usr/bin/env bash\n"
        "printf 'FAKE_CODEX_HOME=%s\\n' \"$CODEX_HOME\"\n"
        "printf 'FAKE_HOME=%s\\n' \"$HOME\"\n"
        "printf 'FAKE_CODEX_ARGS=%s\\n' \"$*\"\n",
        encoding="utf-8",
    )
    fake_codex.chmod(0o755)

    env = os.environ.copy()
    env["HOME"] = str(home)
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    env["CTF_CODEX_BIN"] = str(fake_codex)
    env["CTF_CODEX_APPROVAL"] = "on-request"
    env["CTF_CODEX_SANDBOX"] = "workspace-write"
    env["CTF_CODEX_EXTRA_ADD_DIRS"] = f"{repo}:{home / 'extra'}"
    env["CTF_CODEX_IGNORE_USER_CONFIG"] = "1"
    env["CTF_CODEX_DANGER"] = "0"
    env.pop("CTF_CODEX_MODEL", None)

    result = subprocess.run(
        [
            str(repo / "scripts" / "run-codex-worker.sh"),
            "--run",
            "worker-1",
            "exec",
            "Reply with exactly: RUNNER_ENV_OK",
        ],
        cwd=repo,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert f"FAKE_CODEX_HOME={worker_home}" in result.stdout
    assert f"FAKE_HOME={worker_home}" in result.stdout
    assert "--model" not in result.stdout
    assert "--ask-for-approval on-request" in result.stdout
    assert "--sandbox workspace-write" in result.stdout
    fake_line = next(line for line in result.stdout.splitlines() if line.startswith("FAKE_CODEX_ARGS="))
    assert fake_line.count(f"--add-dir {repo}") == 1
    assert f"--add-dir {home / 'extra'}" in result.stdout
    assert fake_line.count("--ask-for-approval") == 1
    assert fake_line.count("--model") == 0
