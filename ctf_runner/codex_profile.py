from __future__ import annotations

import os
import re
import shlex
import json
import tomllib
from pathlib import Path
from typing import Any

from .codex_doctor import choose_preferred_codex_binary
from .paths import is_under_mnt_c, repo_root


MAX_SLIM_AGENTS_TOKENS = 1_500
GLOBAL_LONG_AGENTS_TOKENS = 5_000
DEFAULT_CODEX_MODEL_POLICY = "auto/unpinned"
DEFAULT_WORKER_IDS = tuple(f"worker-{n}" for n in range(1, 6))
_WORKER_ID_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_TOP_LEVEL_MODEL_RE = re.compile(r"^\s*model\s*=")
DEFAULT_ADD_DIRS = (
    "~/dding-ctf-runner",
    "~/CTF",
    "~/.ctf-solver",
    "~/.codex-workers",
)


def _validate_worker_id(worker_id: str) -> None:
    if not worker_id or not _WORKER_ID_RE.fullmatch(worker_id):
        raise ValueError("worker_id must contain only letters, numbers, dot, underscore, and dash")


def _estimate_tokens(path: Path) -> int:
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return 0
    return max(1, (size + 3) // 4) if size else 0


def _path_info(path: Path) -> dict[str, Any]:
    try:
        st = path.lstat()
    except FileNotFoundError:
        return {"exists": False, "size_bytes": 0, "is_symlink": False}
    return {"exists": True, "size_bytes": st.st_size, "is_symlink": path.is_symlink()}


def _display_path(path: Path) -> str:
    home = Path.home()
    try:
        return f"~/{path.resolve().relative_to(home.resolve())}"
    except ValueError:
        return str(path)


def worker_home(worker_id: str) -> Path:
    _validate_worker_id(worker_id)
    return Path.home() / ".codex-workers" / worker_id


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip() in {"1", "true", "TRUE", "yes", "YES"}


def _expand_user_path(raw: str, home: Path) -> str:
    if raw == "~":
        return str(home)
    if raw.startswith("~/"):
        return str(home / raw[2:])
    return str(Path(raw).expanduser())


def _dedupe_paths(paths: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for raw in paths:
        value = raw.strip()
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _toml_string(value: str) -> str:
    return json.dumps(value)


def _normalize_model_override(raw: str | None) -> str | None:
    value = (raw or "").strip()
    if not value or value.lower() == "auto":
        return None
    return value


def _model_policy(model: str | None) -> str:
    return "hard-pinned" if model else DEFAULT_CODEX_MODEL_POLICY


def _read_config_model(config: Path) -> dict[str, Any]:
    info = _path_info(config)
    result: dict[str, Any] = {
        "config_toml": info,
        "model": None,
        "model_provider": None,
        "parse_error": "",
    }
    if not info["exists"]:
        return result
    try:
        data = tomllib.loads(config.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - status should summarize safely.
        result["parse_error"] = type(exc).__name__
        return result
    for key in ("model", "model_provider"):
        value = data.get(key)
        if isinstance(value, str):
            result[key] = value
    return result


def _set_top_level_model(config: Path, model: str) -> None:
    model_line = f"model = {_toml_string(model)}"
    try:
        lines = config.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(f"{model_line}\n", encoding="utf-8")
        return

    out: list[str] = []
    replaced = False
    in_top_level = True
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("["):
            in_top_level = False
        if in_top_level and _TOP_LEVEL_MODEL_RE.match(line):
            if not replaced:
                out.append(model_line)
                replaced = True
            continue
        out.append(line)

    if not replaced:
        section_index = next((idx for idx, line in enumerate(out) if line.strip().startswith("[")), len(out))
        insert: list[str] = [model_line]
        if section_index < len(out) and section_index > 0 and out[section_index - 1].strip():
            insert.append("")
        out[section_index:section_index] = insert

    config.write_text("\n".join(out).rstrip() + "\n", encoding="utf-8")


def _unset_top_level_model(config: Path) -> bool:
    try:
        lines = config.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return False

    out: list[str] = []
    removed = False
    in_top_level = True
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("["):
            in_top_level = False
        if in_top_level and _TOP_LEVEL_MODEL_RE.match(line):
            removed = True
            continue
        out.append(line)

    if removed:
        config.write_text("\n".join(out).rstrip() + "\n", encoding="utf-8")
    return removed


def codex_launch_plan(worker_id: str, mode: str, *, force_auto_model: bool = False) -> dict[str, Any]:
    if mode not in {"interactive", "exec"}:
        raise ValueError("mode must be interactive or exec")

    target = worker_home(worker_id)
    user_home = Path.home()
    approval = os.environ.get("CTF_CODEX_APPROVAL", "").strip() or "never"
    sandbox_override = os.environ.get("CTF_CODEX_SANDBOX", "").strip()
    extra_add_dirs = os.environ.get("CTF_CODEX_EXTRA_ADD_DIRS", "").strip()
    ignore_user_config = _env_truthy("CTF_CODEX_IGNORE_USER_CONFIG")
    danger_mode = os.environ.get("CTF_CODEX_DANGER", "").strip() not in {"0", "false", "FALSE", "no", "NO"}
    model_env_set = "CTF_CODEX_MODEL" in os.environ
    model = None if force_auto_model else _normalize_model_override(os.environ.get("CTF_CODEX_MODEL") if model_env_set else None)
    preferred = choose_preferred_codex_binary()
    add_dirs = [
        _expand_user_path(raw, user_home)
        for raw in DEFAULT_ADD_DIRS
    ]
    if extra_add_dirs:
        add_dirs.extend(_expand_user_path(raw, user_home) for raw in extra_add_dirs.split(":"))
    add_dirs = _dedupe_paths(add_dirs)

    argv = [preferred["path"] or "codex"]
    if model:
        argv.extend(["--model", model])
    effective_sandbox = "danger-full-access" if danger_mode else (sandbox_override or "workspace-write")
    argv.extend(["--ask-for-approval", approval, "--sandbox", effective_sandbox])
    for add_dir in add_dirs:
        argv.extend(["--add-dir", add_dir])
    if mode == "exec":
        argv.extend(["exec", "<prompt-file-or-text>"])

    env = {
        "CODEX_HOME": str(target),
    }
    if ignore_user_config:
        env["HOME"] = str(target)

    return {
        "worker_id": worker_id,
        "mode": mode,
        "argv": argv,
        "env": env,
        "approval_policy": approval or None,
        "model": model or None,
        "model_flag_present": bool(model),
        "model_source": "forced_auto" if force_auto_model else ("env" if model else ("env_auto" if model_env_set else "default_auto")),
        "model_policy": _model_policy(model),
        "model_auto_default": model is None,
        "default_model_policy": DEFAULT_CODEX_MODEL_POLICY,
        "sandbox_mode": effective_sandbox,
        "danger_mode": danger_mode,
        "ignore_user_config": ignore_user_config,
        "add_dirs": add_dirs,
        "codex_binary": preferred["path"] or "codex",
        "codex_binary_reason": preferred.get("selected_reason", ""),
    }


def _write_worker_config(target: Path, worker_id: str) -> None:
    config = target / "config.toml"
    config.write_text(
        "\n".join(
            [
                "# Worker-local Codex config.",
                "# This file intentionally does not copy ~/.codex/config.toml.",
                "# Keep secrets in auth.json only, preferably as a local symlink.",
                "# Model policy is auto/unpinned unless explicitly set for reproducibility.",
                "",
                "[runner]",
                f'worker_id = "{worker_id}"',
                f'repo_root = "{repo_root()}"',
                'plain_codex_forbidden = true',
                "",
            ]
        ),
        encoding="utf-8",
    )


def _copy_slim_agents(target: Path) -> dict[str, Any]:
    runner_agents = repo_root() / "AGENTS.md"
    worker_agents = target / "AGENTS.md"
    warnings: list[str] = []
    if not runner_agents.exists():
        warnings.append("runner_slim_agents_missing")
        return {"agents_path": str(worker_agents), "agents_size_bytes": 0, "warnings": warnings}

    content = runner_agents.read_text(encoding="utf-8")
    worker_agents.write_text(content, encoding="utf-8")
    return {"agents_path": str(worker_agents), "agents_size_bytes": worker_agents.stat().st_size, "warnings": warnings}


def _link_auth(target: Path, link_auth: bool) -> tuple[bool, list[str]]:
    warnings: list[str] = []
    auth_link = target / "auth.json"
    source = Path.home() / ".codex" / "auth.json"
    if not link_auth:
        return auth_link.is_symlink(), warnings
    if not source.exists():
        warnings.append("global_auth_json_missing")
        return False, warnings
    if auth_link.is_symlink():
        try:
            if auth_link.resolve() == source.resolve():
                return True, warnings
        except OSError:
            warnings.append("auth_symlink_broken")
            return False, warnings
        warnings.append("auth_symlink_points_elsewhere")
        return False, warnings
    if auth_link.exists():
        warnings.append("auth_json_exists_not_symlink")
        return False, warnings
    auth_link.symlink_to(source)
    return True, warnings


def init_worker_home(worker_id: str, link_auth: bool = False) -> dict[str, Any]:
    target = worker_home(worker_id)
    target.mkdir(parents=True, exist_ok=True)
    agents_result = _copy_slim_agents(target)
    _write_worker_config(target, worker_id)
    auth_linked, auth_warnings = _link_auth(target, link_auth)
    warnings = [*agents_result["warnings"], *auth_warnings]
    validation = validate_worker_launch_context(worker_id, repo_root())
    warnings.extend(validation["warnings"])
    return {
        "worker_id": worker_id,
        "worker_home": str(target),
        "agents_md": {"exists": (target / "AGENTS.md").exists(), "size_bytes": agents_result["agents_size_bytes"]},
        "config_toml": _path_info(target / "config.toml"),
        "auth_linked": auth_linked,
        "warnings": sorted(set(warnings)),
    }


def create_worker_codex_home(worker_id: str) -> dict[str, Any]:
    return init_worker_home(worker_id, link_auth=False)


def status_worker_home(worker_id: str) -> dict[str, Any]:
    target = worker_home(worker_id)
    auth_path = target / "auth.json"
    model_status = _read_config_model(target / "config.toml")
    return {
        "worker_id": worker_id,
        "worker_home": str(target),
        "exists": target.exists(),
        "agents_md": _path_info(target / "AGENTS.md"),
        "config_toml": _path_info(target / "config.toml"),
        "auth_json": {
            "exists": auth_path.exists(),
            "is_symlink": auth_path.is_symlink(),
        },
        "auth_linked": auth_path.is_symlink(),
        "model": model_status["model"],
        "model_provider": model_status["model_provider"],
        "model_policy": _model_policy(model_status["model"]),
    }


def codex_model_status(worker_id: str | None = None) -> dict[str, Any]:
    worker_ids = (worker_id,) if worker_id else DEFAULT_WORKER_IDS
    workers: list[dict[str, Any]] = []
    for wid in worker_ids:
        target = worker_home(wid)
        model_info = _read_config_model(target / "config.toml")
        model = model_info["model"]
        workers.append(
            {
                "worker_id": wid,
                "worker_home": str(target),
                "config_toml": model_info["config_toml"],
                "model": model,
                "model_provider": model_info["model_provider"],
                "model_pinned": bool(model),
                "model_policy": _model_policy(model),
                "model_auto_default": model is None,
                "parse_error": model_info["parse_error"],
            }
        )
    return {
        "default_model_policy": DEFAULT_CODEX_MODEL_POLICY,
        "model_auto_default": all(not item["model_pinned"] for item in workers),
        "workers": workers,
    }


def set_worker_model(worker_id: str, model: str) -> dict[str, Any]:
    value = model.strip()
    if not value or value.lower() == "auto":
        raise ValueError("model must be a concrete non-auto value; use unset-model for auto policy")
    target = worker_home(worker_id)
    target.mkdir(parents=True, exist_ok=True)
    _set_top_level_model(target / "config.toml", value)
    return codex_model_status(worker_id)["workers"][0]


def set_worker_model_all(model: str) -> dict[str, Any]:
    workers = [set_worker_model(worker_id, model) for worker_id in DEFAULT_WORKER_IDS]
    return {
        "default_model_policy": DEFAULT_CODEX_MODEL_POLICY,
        "model_auto_default": all(not item["model_pinned"] for item in workers),
        "workers": workers,
    }


def unset_worker_model(worker_id: str) -> dict[str, Any]:
    target = worker_home(worker_id)
    removed = _unset_top_level_model(target / "config.toml")
    status = codex_model_status(worker_id)["workers"][0]
    return {
        **status,
        "removed_model_key": removed,
    }


def unset_worker_model_all() -> dict[str, Any]:
    workers = [unset_worker_model(worker_id) for worker_id in DEFAULT_WORKER_IDS]
    return {
        "default_model_policy": DEFAULT_CODEX_MODEL_POLICY,
        "model_auto_default": all(not item["model_pinned"] for item in workers),
        "workers": workers,
    }


def validate_worker_launch_context(worker_id: str, root: str | Path | None = None) -> dict[str, Any]:
    target_repo = Path(root).expanduser().resolve() if root is not None else repo_root()
    target = worker_home(worker_id)
    worker_agents = target / "AGENTS.md"
    global_agents = Path.home() / ".codex" / "AGENTS.md"
    warnings: list[str] = []
    ok = True

    expected_repo = Path.home() / "dding-ctf-runner"
    repo_ok = target_repo == expected_repo.resolve()
    if not repo_ok:
        ok = False
        warnings.append("repo_root_not_runner")
    if is_under_mnt_c(target_repo):
        ok = False
        warnings.append("repo_under_mnt_c")

    worker_agents_tokens = _estimate_tokens(worker_agents)
    worker_agents_ok = worker_agents.exists() and worker_agents_tokens <= MAX_SLIM_AGENTS_TOKENS
    if not worker_agents_ok:
        ok = False
        warnings.append("worker_agents_not_slim")

    global_agents_tokens = _estimate_tokens(global_agents)
    if global_agents.exists() and global_agents_tokens >= GLOBAL_LONG_AGENTS_TOKENS:
        warnings.append("global_long_agents")

    return {
        "ok": ok,
        "worker_id": worker_id,
        "repo_root": str(target_repo),
        "repo_root_ok": repo_ok,
        "repo_under_mnt_c": is_under_mnt_c(target_repo),
        "worker_home": str(target),
        "worker_agents_exists": worker_agents.exists(),
        "worker_agents_estimated_tokens": worker_agents_tokens,
        "worker_agents_slim": worker_agents_ok,
        "global_agents_exists": global_agents.exists(),
        "global_agents_estimated_tokens": global_agents_tokens,
        "warnings": sorted(set(warnings)),
    }


def launch_command(worker_id: str, mode: str) -> dict[str, Any]:
    plan = codex_launch_plan(worker_id, mode)
    repo = repo_root()
    env_parts = [f"{key}={_display_path(Path(value))}" for key, value in plan["env"].items()]
    argv_parts = [shlex.quote(part) for part in plan["argv"]]
    command = (
        f"cd {_display_path(repo)} && "
        f"{' '.join(env_parts + argv_parts)}"
    )
    return {
        **plan,
        "dry_run": True,
        "command": command,
        "repo_root": str(repo),
        "worker_home": plan["env"]["CODEX_HOME"],
        "validation": validate_worker_launch_context(worker_id, repo),
    }


def init_worker_range(count: int, link_auth: bool = False) -> list[dict[str, Any]]:
    if count < 1:
        raise ValueError("count must be >= 1")
    return [init_worker_home(f"worker-{n}", link_auth=link_auth) for n in range(1, count + 1)]


def default_cwd_risk() -> dict[str, Any]:
    cwd = Path(os.getcwd()).expanduser().resolve()
    ctf = Path.home() / "CTF"
    global_agents = Path.home() / ".codex" / "AGENTS.md"
    global_agents_tokens = _estimate_tokens(global_agents)
    warnings: list[str] = []
    if cwd == ctf.resolve() or ctf.resolve() in cwd.parents:
        warnings.append("cwd_under_ctf")
    if global_agents.exists() and global_agents_tokens >= GLOBAL_LONG_AGENTS_TOKENS:
        warnings.append("global_long_agents")
    return {
        "cwd": str(cwd),
        "cwd_under_ctf": "cwd_under_ctf" in warnings,
        "global_agents_exists": global_agents.exists(),
        "global_agents_estimated_tokens": global_agents_tokens,
        "warnings": warnings,
    }
