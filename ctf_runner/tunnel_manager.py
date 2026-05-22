from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

from .callback_server import listener_status, start_listener, stop_listener
from .paths import get_paths, repo_root
from .redact import REDACTION, redact_text
from .tunnel import check_tunnel_providers
from .url_safety import redact_public_urls


START_TIMEOUT_SEC = 25.0
HTTP_PROBE_TIMEOUT_SEC = 6.0
HTTP_PROBE_ATTEMPTS = 20

_CLOUDFLARED_URL_RE = re.compile(r"https://[A-Za-z0-9.-]+\.trycloudflare\.com[^\s\"'<>]*")
_BORE_PUBLIC_RE = re.compile(r"(?:(?:tcp|http)://)?(?P<host>[A-Za-z0-9.-]*bore\.pub):(?P<port>\d{2,5})")


def start_tunnel(
    provider: str,
    local_port: int,
    *,
    allow_public: bool = False,
    state_root: str | Path | None = None,
    timeout: float = START_TIMEOUT_SEC,
) -> dict[str, Any]:
    provider = _resolve_provider(provider)
    if provider in {"cloudflared", "bore"} and not allow_public:
        return {
            "status": "blocked",
            "reason": "public_tunnel_requires_allow_public",
            "provider": provider,
            "local_port": int(local_port),
            "required_flags": ["--allow-public"],
        }
    if provider == "manual":
        return _manual_tunnel_payload(local_port)
    if provider not in {"cloudflared", "bore"}:
        return {
            "status": "missing",
            "reason": "no_supported_public_provider",
            "provider": provider,
            "local_port": int(local_port),
            "setup_command": "./scripts/setup-tunnel-tools.sh",
        }

    port = _validate_port(local_port)
    try:
        command = build_tunnel_command(provider, port)
    except FileNotFoundError:
        return {
            "status": "missing",
            "reason": "provider_not_installed",
            "provider": provider,
            "local_port": port,
            "setup_command": "./scripts/setup-tunnel-tools.sh",
        }
    tunnel_id = f"tn-{_timestamp_id()}-{uuid.uuid4().hex[:10]}"
    root = tunnel_root(tunnel_id, state_root=state_root)
    root.mkdir(parents=True, exist_ok=False)
    log_path = root / "tunnel.log"
    metadata = {
        "status": "starting",
        "tunnel_id": tunnel_id,
        "provider": provider,
        "provider_type": "http" if provider == "cloudflared" else "tcp_forward",
        "local_port": port,
        "local_url": f"http://127.0.0.1:{port}",
        "public_url": "",
        "started_at": _utc_now(),
        "command_redacted": [redact_text(item) for item in command],
        "log_path": _display_path(log_path),
    }
    _write_json(root / "tunnel.json", metadata)
    with log_path.open("ab") as log_fh:
        proc = subprocess.Popen(  # noqa: S603 - provider executable was selected explicitly.
            command,
            cwd=repo_root(),
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            close_fds=True,
        )
    (root / "provider.pid").write_text(f"{proc.pid}\n", encoding="utf-8")
    metadata["pid"] = proc.pid
    _write_json(root / "tunnel.json", metadata)

    parsed: dict[str, Any] | None = None
    deadline = time.monotonic() + timeout
    last_output = ""
    while time.monotonic() < deadline:
        last_output = _read_text(log_path)
        parsed = parse_provider_public_endpoint(provider, last_output)
        if parsed:
            break
        if proc.poll() is not None:
            break
        time.sleep(0.2)

    if not parsed:
        _terminate_pid(proc.pid)
        _unlink_if_exists(root / "provider.pid")
        metadata.update(
            {
                "status": "error",
                "reason": "public_url_not_found",
                "provider_exit_code": proc.poll(),
                "log_tail": _tail_lines(last_output, 12),
                "stopped_at": _utc_now(),
            }
        )
        _write_json(root / "tunnel.json", metadata)
        return _public_tunnel_payload(metadata, root)

    metadata.update(
        {
            "status": "started",
            "public_url": parsed["public_url"],
            "provider_type": parsed["provider_type"],
            "public_endpoint": parsed,
        }
    )
    _write_json(root / "tunnel.json", metadata)
    return _public_tunnel_payload(metadata, root)


def stop_tunnel(tunnel_id: str, *, state_root: str | Path | None = None, timeout: float = 5.0) -> dict[str, Any]:
    root = tunnel_root(tunnel_id, state_root=state_root)
    metadata = _read_json(root / "tunnel.json")
    if not metadata:
        return {"status": "missing", "tunnel_id": _safe_id(tunnel_id), "stopped": False}
    pid = _read_pid(root / "provider.pid") or _int_value(metadata.get("pid"))
    stopped = False
    reason = ""
    if pid and _pid_alive(pid):
        provider = str(metadata.get("provider") or "")
        if _pid_cmdline_contains_provider(pid, provider):
            _terminate_pid(pid)
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline and _pid_alive(pid):
                time.sleep(0.05)
            if _pid_alive(pid):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            stopped = True
        else:
            reason = "pid_provider_mismatch"
    elif pid:
        reason = "pid_not_running"
    else:
        reason = "pid_missing"
    _unlink_if_exists(root / "provider.pid")
    metadata.update({"status": "stopped", "stopped_at": _utc_now()})
    _write_json(root / "tunnel.json", metadata)
    payload = _public_tunnel_payload(metadata, root)
    payload.update({"stopped": stopped or reason in {"pid_not_running", "pid_missing"}, "reason": reason or "stopped"})
    return payload


def tunnel_status(tunnel_id: str, *, state_root: str | Path | None = None) -> dict[str, Any]:
    root = tunnel_root(tunnel_id, state_root=state_root)
    metadata = _read_json(root / "tunnel.json")
    if not metadata:
        return {"status": "missing", "tunnel_id": _safe_id(tunnel_id)}
    pid = _read_pid(root / "provider.pid") or _int_value(metadata.get("pid"))
    provider = str(metadata.get("provider") or "")
    if pid and _pid_alive(pid) and _pid_cmdline_contains_provider(pid, provider):
        metadata["status"] = "running" if metadata.get("status") == "started" else metadata.get("status", "running")
    elif metadata.get("status") in {"started", "running"}:
        metadata["status"] = "stale"
    _write_json(root / "tunnel.json", metadata)
    return _public_tunnel_payload(metadata, root)


def tunnel_logs(tunnel_id: str, *, tail: int = 80, state_root: str | Path | None = None) -> dict[str, Any]:
    root = tunnel_root(tunnel_id, state_root=state_root)
    metadata = _read_json(root / "tunnel.json")
    if not metadata:
        return {"status": "missing", "tunnel_id": _safe_id(tunnel_id), "lines": []}
    lines = _tail_lines(_read_text(root / "tunnel.log"), max(0, int(tail)))
    return {
        "status": "ok",
        "tunnel_id": metadata.get("tunnel_id") or _safe_id(tunnel_id),
        "provider": metadata.get("provider") or "",
        "log_path": _display_path(root / "tunnel.log"),
        "lines": lines,
    }


def parse_provider_public_endpoint(provider: str, output: str) -> dict[str, Any] | None:
    if provider == "cloudflared":
        public_url = parse_cloudflared_public_url(output)
        if public_url:
            return {"provider_type": "http", "public_url": public_url, "url_kind": "https"}
        return None
    if provider == "bore":
        bore = parse_bore_public_endpoint(output)
        if bore:
            return bore
        return None
    return None


def parse_cloudflared_public_url(output: str) -> str:
    match = _CLOUDFLARED_URL_RE.search(output)
    if not match:
        return ""
    return sanitize_public_url(match.group(0).rstrip(".,);]"))


def parse_bore_public_endpoint(output: str) -> dict[str, Any] | None:
    match = _BORE_PUBLIC_RE.search(output)
    if not match:
        return None
    host = match.group("host")
    port = int(match.group("port"))
    return {
        "provider_type": "tcp_forward",
        "public_url": f"tcp://{host}:{port}",
        "public_host": host,
        "public_port": port,
        "http_note": "bore exposes a public TCP forward; HTTP probing is provider/target dependent",
    }


def sanitize_public_url(url: str) -> str:
    try:
        parts = urlsplit(redact_text(url))
    except ValueError:
        return redact_text(url)
    if not parts.query:
        return urlunsplit((parts.scheme, parts.netloc, parts.path.rstrip("/"), "", parts.fragment))
    query = [(key, REDACTION if value else "") for key, value in parse_qsl(parts.query, keep_blank_values=True)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path.rstrip("/"), urlencode(query), parts.fragment))


def build_tunnel_command(provider: str, local_port: int) -> list[str]:
    port = _validate_port(local_port)
    if provider == "cloudflared":
        exe = shutil.which("cloudflared")
        if not exe:
            raise FileNotFoundError("cloudflared is not installed")
        return [exe, "tunnel", "--url", f"http://127.0.0.1:{port}"]
    if provider == "bore":
        exe = shutil.which("bore")
        if not exe:
            raise FileNotFoundError("bore is not installed")
        return [exe, "local", str(port), "--to", "bore.pub"]
    raise ValueError(f"unsupported tunnel provider: {provider}")


def run_callback_public_smoke(
    *,
    provider: str = "auto",
    allow_public: bool = False,
    contest_id: str | None = None,
    challenge_id: str | None = None,
    worker_id: str | None = None,
    state_root: str | Path | None = None,
) -> dict[str, Any]:
    if not allow_public:
        return {
            "status": "blocked",
            "reason": "public_smoke_requires_allow_public",
            "required_flags": ["--allow-public"],
            "listener": {"started": False},
            "tunnel": {"started": False},
        }
    listener = start_listener(state_root=state_root)
    tunnel: dict[str, Any] = {}
    http_probe: dict[str, Any] = {"attempted": False, "reason": "not_started"}
    tunnel_stop: dict[str, Any] = {}
    listener_stop: dict[str, Any] = {}
    result: dict[str, Any]
    try:
        if listener.get("status") != "running":
            result = {"status": "error", "reason": "listener_start_failed", "listener": listener}
            return result
        if contest_id:
            from .contest_resources import record_callback_resource

            record_callback_resource(contest_id, listener, challenge_id=challenge_id, worker_id=worker_id, state_root=state_root)
        tunnel = start_tunnel(provider, int(listener["port"]), allow_public=True, state_root=state_root)
        if tunnel.get("status") != "started":
            result = {"status": "error", "reason": "tunnel_start_failed", "listener": listener, "tunnel": tunnel}
            return result
        if contest_id:
            from .contest_resources import record_tunnel_resource

            record_tunnel_resource(
                contest_id,
                tunnel,
                challenge_id=challenge_id,
                worker_id=worker_id,
                listener_id=str(listener.get("listener_id") or ""),
                state_root=state_root,
            )
        if tunnel.get("provider_type") == "http" and tunnel.get("public_url"):
            http_probe = _probe_public_ping(str(tunnel["public_url"]))
        else:
            http_probe = {"attempted": False, "reason": "provider_not_http"}
        final_listener = listener_status(str(listener["listener_id"]), state_root=state_root)
        ok = bool(
            tunnel.get("status") == "started"
            and (
                (http_probe.get("attempted") and http_probe.get("ok") and int(final_listener.get("hit_count") or 0) >= 1)
                or (not http_probe.get("attempted") and tunnel.get("provider_type") == "tcp_forward")
            )
        )
        result = {
            "status": "ok" if ok else "error",
            "provider": tunnel.get("provider"),
            "provider_type": tunnel.get("provider_type"),
            "listener": final_listener,
            "tunnel": tunnel,
            "http_probe": http_probe,
        }
        return result
    finally:
        if tunnel.get("tunnel_id"):
            tunnel_stop = stop_tunnel(str(tunnel["tunnel_id"]), state_root=state_root)
            if contest_id:
                from .contest_resources import update_tunnel_resource

                update_tunnel_resource(str(tunnel["tunnel_id"]), contest_id=contest_id, tunnel=tunnel_stop, state_root=state_root)
        if listener.get("listener_id"):
            listener_stop = stop_listener(str(listener["listener_id"]), state_root=state_root)
            if contest_id:
                from .contest_resources import update_callback_resource

                update_callback_resource(str(listener["listener_id"]), contest_id=contest_id, listener=listener_stop, state_root=state_root)
        if "result" in locals():
            result["tunnel_stop"] = tunnel_stop
            result["listener_stop"] = listener_stop
        if tunnel_stop or listener_stop:
            _write_smoke_cleanup_note(state_root, tunnel_stop=tunnel_stop, listener_stop=listener_stop)


def tunnel_root(tunnel_id: str, *, state_root: str | Path | None = None) -> Path:
    return tunnels_root(state_root=state_root) / _safe_id(tunnel_id)


def tunnels_root(*, state_root: str | Path | None = None) -> Path:
    if state_root is None:
        return get_paths().state_root / "tunnels"
    return Path(state_root).expanduser().resolve() / "tunnels"


def _probe_public_ping(public_url: str) -> dict[str, Any]:
    url = public_url.rstrip("/") + "/ping"
    last_error = ""
    for attempt in range(1, HTTP_PROBE_ATTEMPTS + 1):
        try:
            request = Request(url, headers={"User-Agent": "ctf-runner-callback-smoke"})
            with urlopen(request, timeout=HTTP_PROBE_TIMEOUT_SEC) as response:  # noqa: S310 - explicit operator-gated smoke URL.
                status = int(getattr(response, "status", response.getcode()))
                body = response.read(200)
            return {"attempted": True, "ok": 200 <= status < 300, "http_status": status, "body_length": len(body), "attempts": attempt}
        except Exception as exc:  # noqa: BLE001 - smoke reports errors and keeps retrying.
            last_error = redact_text(str(exc))[:300]
            time.sleep(1.0)
    return {"attempted": True, "ok": False, "error": last_error, "attempts": HTTP_PROBE_ATTEMPTS}


def _resolve_provider(provider: str) -> str:
    provider = str(provider or "auto").strip().lower()
    if provider != "auto":
        return provider
    status = check_tunnel_providers()
    recommendation = status.get("recommendation") or {}
    recommended = str(recommendation.get("provider") or "")
    if recommended in {"cloudflared", "bore"}:
        return recommended
    return ""


def _manual_tunnel_payload(local_port: int) -> dict[str, Any]:
    return {
        "status": "manual_required",
        "provider": "manual",
        "provider_type": "manual",
        "local_port": _validate_port(local_port),
        "local_url": f"http://127.0.0.1:{int(local_port)}",
        "public_url": "",
        "instructions": [
            "Start a reviewed public tunnel manually only for this listener port.",
            "Do not expose secret-bearing local applications.",
            "Stop the manual tunnel immediately after the challenge workflow.",
        ],
    }


def _public_tunnel_payload(metadata: dict[str, Any], root: Path) -> dict[str, Any]:
    pid_value = _int_value(metadata.get("pid"))
    alive = bool(pid_value and _pid_alive(pid_value) and _pid_cmdline_contains_provider(pid_value, str(metadata.get("provider") or "")))
    return {
        "status": metadata.get("status") or "unknown",
        "reason": metadata.get("reason") or "",
        "tunnel_id": metadata.get("tunnel_id") or root.name,
        "provider": metadata.get("provider") or "",
        "provider_type": metadata.get("provider_type") or "",
        "local_port": metadata.get("local_port") or 0,
        "local_url": metadata.get("local_url") or "",
        "public_url": metadata.get("public_url") or "",
        "public_endpoint": metadata.get("public_endpoint") or {},
        "pid": metadata.get("pid") or 0,
        "alive": alive,
        "log_path": _display_path(root / "tunnel.log"),
        "started_at": metadata.get("started_at") or "",
        "stopped_at": metadata.get("stopped_at") or "",
    }


def _validate_port(value: int) -> int:
    port = int(value)
    if port < 1 or port > 65535:
        raise ValueError("local_port must be between 1 and 65535")
    return port


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    return value if isinstance(value, dict) else {}


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(_redact_object(data), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""


def _tail_lines(text: str, tail: int) -> list[str]:
    lines = text.splitlines()
    if tail:
        lines = lines[-tail:]
    return [redact_public_urls(line)[:1000] for line in lines]


def _read_pid(path: Path) -> int | None:
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (FileNotFoundError, ValueError, OSError):
        return None


def _int_value(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    if _pid_is_zombie(pid):
        return False
    return True


def _pid_is_zombie(pid: int) -> bool:
    stat_path = Path(f"/proc/{pid}/stat")
    if not stat_path.exists():
        return False
    try:
        stat = stat_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    tail = stat.rsplit(")", 1)[-1].strip().split()
    return bool(tail and tail[0] == "Z")


def _pid_cmdline_contains_provider(pid: int, provider: str) -> bool:
    cmdline = Path(f"/proc/{pid}/cmdline")
    if not cmdline.exists():
        return True
    try:
        data = cmdline.read_text(encoding="utf-8", errors="replace").replace("\x00", " ")
    except OSError:
        return False
    return bool(provider and provider in data)


def _terminate_pid(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return


def _unlink_if_exists(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _safe_id(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", str(value).strip())
    if not safe or safe in {".", ".."}:
        raise ValueError("invalid tunnel id")
    return safe


def _timestamp_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _display_path(path: Path) -> str:
    try:
        return str(path).replace(str(Path.home()), "~", 1)
    except RuntimeError:
        return str(path)


def _write_smoke_cleanup_note(
    state_root: str | Path | None,
    *,
    tunnel_stop: dict[str, Any],
    listener_stop: dict[str, Any],
) -> None:
    root = (Path(state_root).expanduser().resolve() if state_root is not None else get_paths().state_root) / "tunnels"
    root.mkdir(parents=True, exist_ok=True)
    note = {
        "ts": _utc_now(),
        "event": "callback_public_smoke_cleanup",
        "tunnel_stop": tunnel_stop,
        "listener_stop": listener_stop,
    }
    with (root / "public-smoke-cleanup.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(_redact_object(note), sort_keys=True) + "\n")


def _redact_object(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _redact_object(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_object(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
