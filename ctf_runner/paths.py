from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def expand(path: str | Path) -> Path:
    return Path(path).expanduser().resolve()


def repo_root() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "pyproject.toml").exists() and (parent / "ctf_runner").is_dir():
            return parent
    return here.parents[1]


def is_under_mnt_c(path: str | Path) -> bool:
    try:
        resolved = expand(path)
    except OSError:
        resolved = Path(path).expanduser().absolute()
    return str(resolved).startswith("/mnt/c/")


@dataclass(frozen=True)
class RunnerPaths:
    repo: Path
    state_root: Path
    contests_root: Path
    docker_workspace_root: Path
    secrets_root: Path

    @property
    def db_path(self) -> Path:
        return self.state_root / "queue.sqlite3"

    @property
    def telemetry_path(self) -> Path:
        return self.state_root / "events.jsonl"

    def warnings(self) -> list[str]:
        warnings: list[str] = []
        for label, path in {
            "repo": self.repo,
            "state_root": self.state_root,
            "contests_root": self.contests_root,
            "docker_workspace_root": self.docker_workspace_root,
            "secrets_root": self.secrets_root,
        }.items():
            if is_under_mnt_c(path):
                warnings.append(f"{label} is under /mnt/c; use WSL ext4 for performance and fewer file-lock issues")
        return warnings


def get_paths() -> RunnerPaths:
    home = Path.home()
    return RunnerPaths(
        repo=repo_root(),
        state_root=expand(os.environ.get("CTF_RUNNER_STATE_ROOT", home / ".ctf-solver" / "runner-state")),
        contests_root=expand(os.environ.get("CTF_CONTESTS_ROOT", home / "CTF" / "contests")),
        docker_workspace_root=expand(os.environ.get("CTF_DOCKER_WORKSPACE_ROOT", home / "CTF" / "workspaces")),
        secrets_root=expand(os.environ.get("CTF_RUNNER_SECRETS_ROOT", home / ".ctf-solver" / "secrets")),
    )
