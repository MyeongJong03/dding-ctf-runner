from __future__ import annotations

import os
import re
import subprocess
from typing import Any

from .codex_doctor import choose_preferred_codex_binary
from .codex_profile import codex_launch_plan
from .paths import repo_root
from .redact import redact_text


DEFAULT_MODEL_SMOKE_PROMPT = "Reply with exactly: DEFAULT_MODEL_SMOKE_OK"
DEFAULT_MODEL_SMOKE_MARKER = "DEFAULT_MODEL_SMOKE_OK"
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_MODEL_LINE_RE = re.compile(r"^\s*model\s*:\s*(?P<model>[A-Za-z0-9_.:/+-]+)\s*$", re.IGNORECASE)


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def parse_observed_default_model(output: str) -> str | None:
    for line in _strip_ansi(output).splitlines():
        match = _MODEL_LINE_RE.match(line.strip())
        if match:
            return match.group("model")
    return None


def _response_ok(output: str) -> bool:
    for line in _strip_ansi(output).splitlines():
        if line.strip() == DEFAULT_MODEL_SMOKE_MARKER:
            return True
    return False


def _codex_version(path: str) -> str:
    if not path:
        return ""
    try:
        proc = subprocess.run(
            [path, "--version"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=5,
            check=False,
        )
    except Exception as exc:  # noqa: BLE001
        return redact_text(f"error: {exc}")
    first_line = (proc.stdout or "").strip().splitlines()
    return redact_text(first_line[0] if first_line else "")


def default_model_smoke(worker_id: str = "worker-1", timeout: float = 180.0) -> dict[str, Any]:
    plan = codex_launch_plan(worker_id, "exec", force_auto_model=True)
    argv = list(plan["argv"])
    if len(argv) >= 2 and argv[-2] == "exec" and argv[-1] == "<prompt-file-or-text>":
        argv[-1] = DEFAULT_MODEL_SMOKE_PROMPT
    else:
        argv.extend(["exec", DEFAULT_MODEL_SMOKE_PROMPT])

    model_flag_used = "--model" in argv
    preferred = choose_preferred_codex_binary()
    result: dict[str, Any] = {
        "attempted": True,
        "ok": False,
        "worker_id": worker_id,
        "observed_default_model": None,
        "codex_version": (
            preferred.get("version")
            or preferred.get("version_text")
            or _codex_version(plan["codex_binary"])
        ),
        "model_flag_used": model_flag_used,
        "response_ok": False,
        "returncode": None,
        "timeout_seconds": timeout,
        "approval_policy": plan["approval_policy"],
        "sandbox_mode": plan["sandbox_mode"],
        "codex_binary": plan["codex_binary"],
    }
    if model_flag_used:
        result["error"] = "internal error: default model smoke command unexpectedly included --model"
        return result

    env = os.environ.copy()
    env.update(plan["env"])
    try:
        proc = subprocess.run(
            argv,
            cwd=repo_root(),
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        result["error"] = "codex default model smoke timed out"
        return result
    except Exception as exc:  # noqa: BLE001
        result["error"] = redact_text(str(exc))
        return result

    combined = f"{proc.stdout or ''}\n{proc.stderr or ''}"
    observed = parse_observed_default_model(combined)
    response_ok = _response_ok(combined)
    result.update(
        {
            "ok": proc.returncode == 0 and response_ok,
            "observed_default_model": observed,
            "response_ok": response_ok,
            "returncode": proc.returncode,
        }
    )
    return result
