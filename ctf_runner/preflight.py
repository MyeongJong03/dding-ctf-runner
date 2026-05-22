from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from .browser_smoke import playwright_import_status, run_browser_smoke
from .codex_doctor import diagnose_codex_update_issue, diagnose_mcp_legacy
from .callback_smoke import run_callback_smoke
from .codex_notice import notice_status
from .codex_profile import (
    DEFAULT_WORKER_IDS,
    codex_model_status,
    default_cwd_risk,
    launch_command,
    status_worker_home,
    validate_worker_launch_context,
)
from .codex_smoke import default_model_smoke
from .docker_pool import docker_environment, image_exists, pool_readiness
from .paths import get_paths, is_under_mnt_c
from .redact import redact_text
from .tunnel import check_tunnel_providers


GLOBAL_LONG_AGENTS_GUIDANCE = "Use scripts/ctf-worker-* wrappers; plain codex may load long ~/CTF instructions."


def _run_version(cmd: list[str], timeout: float = 5.0) -> dict[str, Any]:
    exe = shutil.which(cmd[0])
    if not exe:
        return {"found": False}
    try:
        proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, check=False)
        return {"found": True, "version": redact_text(proc.stdout.strip().splitlines()[0] if proc.stdout.strip() else ""), "returncode": proc.returncode}
    except Exception as exc:  # noqa: BLE001 - preflight should summarize failures, not crash.
        return {"found": True, "error": redact_text(str(exc))}


def _command_found(name: str) -> dict[str, Any]:
    return {"found": shutil.which(name) is not None}


def _path_size(path: Path) -> dict[str, Any]:
    try:
        st = path.stat()
    except FileNotFoundError:
        return {"exists": False, "size_bytes": 0}
    return {"exists": True, "size_bytes": st.st_size}


def _docker_reachable() -> dict[str, Any]:
    return docker_environment()


def _docker_image_exists(image: str) -> dict[str, Any]:
    return image_exists(image)


def _docker_one_shot_timing(image: str) -> dict[str, Any]:
    docker = docker_environment()
    if not docker.get("reachable"):
        return {"attempted": False, "ok": False, "reason": docker.get("classification") or docker.get("reason"), "docker": docker}
    start = time.perf_counter()
    try:
        proc = subprocess.run(["docker", "run", "--rm", image, "true"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=20, check=False)
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        return {"attempted": True, "ok": proc.returncode == 0, "elapsed_ms": elapsed_ms, "stderr": redact_text(proc.stderr.decode("utf-8", errors="replace") if isinstance(proc.stderr, bytes) else str(proc.stderr or ""))}
    except Exception as exc:  # noqa: BLE001
        return {"attempted": True, "ok": False, "error": redact_text(str(exc))}


def _docker_pool_readiness() -> dict[str, Any]:
    return pool_readiness()


def _pwn_rev_enabled() -> bool:
    return os.environ.get("CTF_PWN_REV_ENABLED", "").strip().lower() in {"1", "true", "yes", "on"}


def collect_preflight(include_timing: bool = False, deep: bool = False, model_smoke: bool = False) -> dict[str, Any]:
    paths = get_paths()
    tools = {
        "python3": _run_version(["python3", "--version"]),
        "uv": _command_found("uv"),
        "git": _run_version(["git", "--version"]),
        "curl": _command_found("curl"),
        "nc": _command_found("nc"),
        "file": _command_found("file"),
        "strings": _command_found("strings"),
        "gdb": _command_found("gdb"),
        "checksec": _command_found("checksec"),
        "sage": {
            "found": shutil.which("sage") is not None
            or bool(os.environ.get("SAGE_BIN") and Path(os.environ["SAGE_BIN"]).exists())
            or (Path.home() / "miniforge3/envs/sage/bin/sage").exists()
        },
    }
    playwright = {
        **playwright_import_status(),
        "cli": shutil.which("playwright") is not None,
        "node": shutil.which("node") is not None,
    }
    browser_smoke = run_browser_smoke() if deep else {"attempted": False}
    callback_smoke = run_callback_smoke()
    tunnels = check_tunnel_providers()
    codex_default_cwd = default_cwd_risk()
    codex_doctor = diagnose_codex_update_issue()
    codex_mcp = diagnose_mcp_legacy()
    worker_homes = {worker_id: status_worker_home(worker_id) for worker_id in DEFAULT_WORKER_IDS}
    worker_models = codex_model_status()
    worker_notices = notice_status()
    worker_validation = {worker_id: validate_worker_launch_context(worker_id, paths.repo) for worker_id in DEFAULT_WORKER_IDS}
    worker_launch = launch_command(DEFAULT_WORKER_IDS[0], "interactive")
    default_model_smoke_result = (
        default_model_smoke(DEFAULT_WORKER_IDS[0])
        if deep and model_smoke
        else {"attempted": False, "reason": "disabled" if not model_smoke else "requires_deep"}
    )
    runner_launch_wrapper = paths.repo / "scripts" / "run-codex-worker.sh"
    docker = _docker_reachable()
    ctf_pwn = _docker_image_exists("ctf-pwn:latest")
    docker_pool = _docker_pool_readiness()
    pwn_rev_enabled = _pwn_rev_enabled()

    high: list[str] = []
    medium: list[str] = []
    low: list[str] = []
    info: list[str] = []

    if is_under_mnt_c(paths.repo):
        high.append("repo_under_mnt_c")
    if not tools["python3"]["found"] or not tools["git"]["found"]:
        high.append("core_tool_missing")
    if not docker.get("reachable"):
        docker_risk = str(docker.get("classification") or docker.get("reason") or "docker_unreachable")
        if docker_risk == "codex_sandbox_docker_unreachable":
            low.append(docker_risk)
        else:
            medium.append(docker_risk)
    if not runner_launch_wrapper.exists() or not os.access(runner_launch_wrapper, os.X_OK):
        high.append("runner_launch_wrapper_missing")
    if not codex_doctor["preferred_binary"]["exists"]:
        high.append("preferred_codex_missing")
    if not playwright["playwright_import"]:
        high.append("playwright_missing")
    if deep and browser_smoke.get("playwright_import") and not browser_smoke.get("chromium_launch"):
        high.append("chromium_launch_fail")
    if not callback_smoke.get("ok"):
        high.append("local_callback_smoke_fail")
    if ctf_pwn.get("checked") and not ctf_pwn.get("exists"):
        if pwn_rev_enabled:
            high.append("ctf_pwn_image_missing")
        else:
            medium.append("ctf_pwn_image_missing")
    for name in ("curl", "nc", "file", "strings", "gdb", "checksec", "sage"):
        if not tools[name]["found"]:
            medium.append(f"{name}_missing")
    if not tunnels.get("public_provider_installed"):
        medium.append("tunnel_provider_missing")
    if not any(status["exists"] for status in worker_homes.values()):
        medium.append("no_worker_codex_home")
    if codex_doctor["path_conflict"]:
        medium.append("codex_path_conflict")
    if codex_doctor["update_mismatch"]:
        medium.append("codex_update_mismatch")
    if codex_doctor.get("stale_binary_present"):
        medium.append("stale_codex_binary_present")
    if codex_mcp["legacy_dreamhack_present"]:
        medium.append("legacy_dreamhack_solver_mcp")
    if not codex_mcp["canonical_ctf_solver_present"]:
        info.append("ctf_solver_mcp_missing")
    if "global_long_agents" in codex_default_cwd["warnings"]:
        medium.append("global_long_agents")
        codex_default_cwd["warning_text"] = GLOBAL_LONG_AGENTS_GUIDANCE
    worker_cmd = worker_launch["command"]
    if "--ask-for-approval never" not in worker_cmd or "--sandbox danger-full-access" not in worker_cmd:
        high.append("worker_not_no_prompt_default")
    if worker_launch.get("model_flag_present") or any(item["model_pinned"] for item in worker_models["workers"]):
        medium.append("model_hard_pinned")
    if default_model_smoke_result.get("attempted"):
        if default_model_smoke_result.get("observed_default_model"):
            info.append("default_model_observed")
        else:
            low.append("default_model_unknown")
    if any(item["safe_notice_candidates"] for item in worker_notices["workers"]):
        medium.append("codex_notice_stale")
    if not tools["uv"]["found"]:
        low.append("uv_missing")

    risk_guidance: dict[str, str] = {}
    if "global_long_agents" in medium:
        risk_guidance["global_long_agents"] = GLOBAL_LONG_AGENTS_GUIDANCE
    if "model_hard_pinned" in medium:
        risk_guidance["model_hard_pinned"] = (
            "Explicit Codex model pins are allowed for reproducibility; unset CTF_CODEX_MODEL "
            "and run ctfctl codex unset-model-all to follow Codex defaults."
        )
    if "default_model_unknown" in low:
        risk_guidance["default_model_unknown"] = (
            "Run ctfctl codex default-model-smoke --worker-id worker-1 --json "
            "to observe the current CLI default model."
        )
    if "stale_codex_binary_present" in medium:
        risk_guidance["stale_codex_binary_present"] = (
            "A lower-version Codex binary is still installed. Review scripts/fix-codex-install.sh "
            "and apply only after confirming the preferred binary."
        )
    if "legacy_dreamhack_solver_mcp" in medium:
        risk_guidance["legacy_dreamhack_solver_mcp"] = (
            "Legacy dreamhack_solver MCP is configured and can make plain Codex startup noisy. "
            "Review scripts/fix-codex-mcp.sh --remove-legacy-dreamhack, then apply with --apply."
        )
    if "ctf_solver_mcp_missing" in info:
        risk_guidance["ctf_solver_mcp_missing"] = (
            "ctf_solver MCP is not registered. This is informational because the runner is shell-first through ctfctl."
        )
    if "codex_sandbox_docker_unreachable" in low:
        risk_guidance["codex_sandbox_docker_unreachable"] = (
            "Docker is unreachable from this Codex sandbox/preflight context. Re-check in a normal WSL terminal before pwn/rev work."
        )
    for docker_issue in ("docker_cli_missing", "docker_desktop_integration_missing", "docker_daemon_unreachable", "docker_socket_permission"):
        if docker_issue in medium:
            if docker_issue == "docker_desktop_integration_missing":
                risk_guidance[docker_issue] = (
                    "Enable Docker Desktop WSL Integration for this distro, run hash -r, or use the /mnt/wsl/docker-desktop CLI symlink fallback."
                )
            else:
                risk_guidance[docker_issue] = (
                    "Docker should be reachable from the normal WSL terminal before starting pwn/rev workers."
                )
    if "ctf_pwn_image_missing" in high or "ctf_pwn_image_missing" in medium:
        risk_guidance["ctf_pwn_image_missing"] = (
            "Build or load ctf-pwn:latest before starting persistent pwn/rev Docker pools; docker image inspect reports docker_image_missing."
        )

    summary: dict[str, Any] = {
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "is_wsl": "microsoft" in platform.release().lower() or bool(os.environ.get("WSL_DISTRO_NAME")),
        },
        "paths": {
            "repo": str(paths.repo),
            "repo_under_mnt_c": is_under_mnt_c(paths.repo),
            "warnings": paths.warnings(),
        },
        "codex": _run_version(["codex", "--version"]),
        "codex_worker_isolation": {
            "default_cwd_risk": codex_default_cwd,
            "doctor_summary": {
                "active_version": codex_doctor["active_binary"]["version"] if codex_doctor["active_binary"] else "",
                "preferred_version": codex_doctor["preferred_binary"]["version"],
                "path_conflict": codex_doctor["path_conflict"],
                "update_mismatch": codex_doctor["update_mismatch"],
            },
            "doctor": codex_doctor,
            "mcp_status": codex_mcp,
            "automation_env": {
                "approval_set": bool(os.environ.get("CTF_CODEX_APPROVAL", "").strip()),
                "sandbox_set": bool(os.environ.get("CTF_CODEX_SANDBOX", "").strip()),
                "extra_add_dirs_set": bool(os.environ.get("CTF_CODEX_EXTRA_ADD_DIRS", "").strip()),
                "model_set": bool(os.environ.get("CTF_CODEX_MODEL", "").strip()),
                "ignore_user_config": os.environ.get("CTF_CODEX_IGNORE_USER_CONFIG", "").strip() in {"1", "true", "TRUE", "yes", "YES"},
                "danger_mode": os.environ.get("CTF_CODEX_DANGER", "").strip() not in {"0", "false", "FALSE", "no", "NO"},
            },
            "runner_launch_wrapper": {
                "exists": runner_launch_wrapper.exists(),
                "executable": os.access(runner_launch_wrapper, os.X_OK) if runner_launch_wrapper.exists() else False,
                "path": str(runner_launch_wrapper),
            },
            "worker_default_launch": worker_launch,
            "worker_default_model": worker_launch.get("model"),
            "observed_default_model": default_model_smoke_result.get("observed_default_model"),
            "default_model_smoke": default_model_smoke_result,
            "model_auto_default": bool(worker_launch.get("model_auto_default"))
            and all(item["model_auto_default"] for item in worker_models["workers"]),
            "worker_model_status": worker_models,
            "notice_status": worker_notices,
            "worker_homes": worker_homes,
            "worker_validation": worker_validation,
        },
        "docker": docker,
        "ctf_pwn_image": ctf_pwn,
        "docker_pool": docker_pool,
        "pwn_rev_enabled": pwn_rev_enabled,
        "tools": tools,
        "playwright": playwright,
        "browser_smoke": browser_smoke,
        "callback_smoke": callback_smoke,
        "callback_local_ok": bool(callback_smoke.get("ok")),
        "tunnels": tunnels,
        "public_provider_installed": bool(tunnels.get("public_provider_installed")),
        "preferred_tunnel_provider": str((tunnels.get("recommendation") or {}).get("provider") or ""),
        "agents_files": {
            "~/.codex/AGENTS.md": _path_size(Path.home() / ".codex" / "AGENTS.md"),
            "~/CTF/AGENTS.md": _path_size(Path.home() / "CTF" / "AGENTS.md"),
        },
        "risk": {"High": high, "Medium": medium, "Low": low, "Info": info},
        "risk_guidance": risk_guidance,
    }
    if include_timing:
        summary["docker_one_shot_timing"] = _docker_one_shot_timing("ctf-pwn:latest")
    return summary


def preflight_json(include_timing: bool = False, deep: bool = False, model_smoke: bool = False) -> str:
    return redact_text(json.dumps(collect_preflight(include_timing=include_timing, deep=deep, model_smoke=model_smoke), indent=2, sort_keys=True))
