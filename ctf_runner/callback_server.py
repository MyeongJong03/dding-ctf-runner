from __future__ import annotations

import argparse
import json
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from .paths import get_paths, repo_root
from .redact import REDACTION, redact_text


LOCAL_CALLBACK_HOST = "127.0.0.1"
MAX_BODY_BYTES = 65536
START_TIMEOUT_SEC = 5.0
SENSITIVE_NAME_MARKERS = (
    "auth",
    "bearer",
    "cookie",
    "csrf",
    "flag",
    "jwt",
    "key",
    "passwd",
    "password",
    "secret",
    "session",
    "token",
)


class _LoopbackHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address: tuple[str, int], handler: type[BaseHTTPRequestHandler], *, listener_id: str, root: Path) -> None:
        super().__init__(server_address, handler)
        self.listener_id = listener_id
        self.root = root
        self.hit_lock = threading.Lock()
        self.hit_count = _hit_count(root)


class _CallbackHandler(BaseHTTPRequestHandler):
    server: _LoopbackHTTPServer

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API.
        self._handle_request()

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API.
        self._handle_request()

    def do_PUT(self) -> None:  # noqa: N802 - stdlib handler API.
        self._handle_request()

    def do_PATCH(self) -> None:  # noqa: N802 - stdlib handler API.
        self._handle_request()

    def do_HEAD(self) -> None:  # noqa: N802 - stdlib handler API.
        self._handle_request(head_only=True)

    def _handle_request(self, *, head_only: bool = False) -> None:
        body, body_truncated = self._read_body()
        hit = summarize_request(
            self.command,
            self.path,
            self.headers,
            body,
            body_truncated=body_truncated,
            listener_id=self.server.listener_id,
        )
        _record_hit(self.server, hit)
        status, response_body = _response_for_path(urlsplit(self.path).path)
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0" if head_only else str(len(response_body)))
        self.end_headers()
        if not head_only:
            self.wfile.write(response_body)

    def _read_body(self) -> tuple[bytes, bool]:
        if self.command not in {"POST", "PUT", "PATCH"}:
            return b"", False
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            length = 0
        if length <= 0:
            return b"", False
        read_len = min(length, MAX_BODY_BYTES)
        body = self.rfile.read(read_len)
        truncated = length > read_len
        if truncated:
            self.close_connection = True
        return body, truncated

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib API.
        return


def start_listener(*, state_root: str | Path | None = None, timeout: float = START_TIMEOUT_SEC) -> dict[str, Any]:
    resolved_state_root = _state_root(state_root)
    listener_id = f"cb-{_timestamp_id()}-{uuid.uuid4().hex[:10]}"
    root = callback_root(listener_id, state_root=resolved_state_root)
    root.mkdir(parents=True, exist_ok=False)
    server_log = root / "server.log"
    argv = [
        sys.executable,
        "-m",
        "ctf_runner.callback_server",
        "--serve",
        "--listener-id",
        listener_id,
        "--state-root",
        str(resolved_state_root),
    ]
    with server_log.open("ab") as log_fh:
        proc = subprocess.Popen(  # noqa: S603 - argv is fixed to this package module.
            argv,
            cwd=repo_root(),
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            close_fds=True,
        )

    deadline = time.monotonic() + timeout
    metadata_path = _metadata_path(root)
    last_error = ""
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            last_error = f"listener process exited with code {proc.returncode}"
            break
        metadata = _read_json(metadata_path)
        if metadata.get("port"):
            return _public_listener_payload(metadata, root)
        time.sleep(0.05)

    _terminate_process(proc.pid)
    metadata = {
        "status": "error",
        "listener_id": listener_id,
        "reason": "listener_start_timeout",
        "error": redact_text(last_error),
        "log_path": _display_path(_hits_path(root)),
    }
    _write_json(metadata_path, metadata)
    return metadata


def listener_status(listener_id: str, *, state_root: str | Path | None = None) -> dict[str, Any]:
    root = callback_root(listener_id, state_root=state_root)
    metadata = _read_json(_metadata_path(root))
    if not metadata:
        return {"status": "missing", "listener_id": _safe_id(listener_id), "hit_count": 0}
    alive = _listener_alive(root, metadata)
    status = "running" if alive else str(metadata.get("status") or "stopped")
    if status == "running":
        if not _port_bound(str(metadata.get("host") or LOCAL_CALLBACK_HOST), _int_value(metadata.get("port")) or 0):
            status = "stale"
            metadata["status"] = "stale"
        else:
            metadata["status"] = "running"
    elif status in {"running", "starting"} or (root / "listener.pid").exists():
        status = "stale"
        metadata["status"] = "stale"
    metadata["hit_count"] = _hit_count(root)
    _write_json(_metadata_path(root), metadata)
    return _public_listener_payload(metadata, root)


def listener_hits(listener_id: str, *, state_root: str | Path | None = None, tail: int | None = None) -> dict[str, Any]:
    root = callback_root(listener_id, state_root=state_root)
    metadata = _read_json(_metadata_path(root))
    if not metadata:
        return {"status": "missing", "listener_id": _safe_id(listener_id), "hit_count": 0, "hits": []}
    hits = _read_hits(root)
    if tail is not None and tail >= 0:
        hits = hits[-tail:]
    return {
        "status": "ok",
        "listener_id": metadata.get("listener_id") or _safe_id(listener_id),
        "hit_count": _hit_count(root),
        "log_path": _display_path(_hits_path(root)),
        "hits": hits,
    }


def stop_listener(listener_id: str, *, state_root: str | Path | None = None, timeout: float = 3.0) -> dict[str, Any]:
    root = callback_root(listener_id, state_root=state_root)
    metadata_path = _metadata_path(root)
    metadata = _read_json(metadata_path)
    if not metadata:
        return {"status": "missing", "listener_id": _safe_id(listener_id), "stopped": False}
    pid = _read_pid(root / "listener.pid") or _int_value(metadata.get("pid"))
    stopped = False
    reason = ""
    if pid and _pid_alive(pid):
        if _pid_cmdline_contains(pid, metadata.get("listener_id") or _safe_id(listener_id)):
            _terminate_process(pid)
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
            reason = "pid_marker_mismatch"
    elif pid:
        reason = "pid_not_running"
    else:
        reason = "pid_missing"

    _unlink_if_exists(root / "listener.pid")
    metadata.update({"status": "stopped", "stopped_at": _utc_now(), "hit_count": _hit_count(root)})
    _write_json(metadata_path, metadata)
    payload = _public_listener_payload(metadata, root)
    payload.update({"stopped": stopped or reason in {"pid_not_running", "pid_missing"}, "reason": reason or "stopped"})
    return payload


def summarize_request(
    method: str,
    path: str,
    headers: Any,
    body: bytes = b"",
    *,
    body_truncated: bool = False,
    listener_id: str = "",
) -> dict[str, Any]:
    parts = urlsplit(path)
    return {
        "listener_id": listener_id,
        "ts": _utc_now(),
        "method": str(method).upper(),
        "endpoint": _endpoint_summary(parts.path),
        "query": _query_summary(parts.query),
        "headers": _headers_summary(headers),
        "body": _body_summary(str(headers.get("Content-Type") or ""), body, truncated=body_truncated),
    }


def callback_root(listener_id: str, *, state_root: str | Path | None = None) -> Path:
    return callbacks_root(state_root=state_root) / _safe_id(listener_id)


def callbacks_root(*, state_root: str | Path | None = None) -> Path:
    return _state_root(state_root) / "callbacks"


def serve_listener(listener_id: str, *, state_root: str | Path | None = None) -> int:
    listener_id = _safe_id(listener_id)
    root = callback_root(listener_id, state_root=state_root)
    root.mkdir(parents=True, exist_ok=True)
    server = _LoopbackHTTPServer((LOCAL_CALLBACK_HOST, 0), _CallbackHandler, listener_id=listener_id, root=root)
    port = int(server.server_address[1])
    pid_path = root / "listener.pid"
    pid_path.write_text(f"{os.getpid()}\n", encoding="utf-8")
    metadata = {
        "status": "running",
        "listener_id": listener_id,
        "pid": os.getpid(),
        "host": LOCAL_CALLBACK_HOST,
        "port": port,
        "local_url": f"http://{LOCAL_CALLBACK_HOST}:{port}",
        "started_at": _utc_now(),
        "hit_count": _hit_count(root),
        "log_path": _display_path(_hits_path(root)),
        "endpoints": ["/", "/ping", "/hit/<token>", "/collect"],
    }
    _write_json(_metadata_path(root), metadata)

    def _shutdown(_signum: int, _frame: Any) -> None:
        threading.Thread(target=server.shutdown, name="callback-server-shutdown", daemon=True).start()

    previous_term = signal.getsignal(signal.SIGTERM)
    previous_int = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        signal.signal(signal.SIGTERM, previous_term)
        signal.signal(signal.SIGINT, previous_int)
        server.server_close()
        _unlink_if_exists(pid_path)
        current = _read_json(_metadata_path(root))
        current.update({"status": "stopped", "stopped_at": _utc_now(), "hit_count": _hit_count(root)})
        _write_json(_metadata_path(root), current)
    return 0


def _record_hit(server: _LoopbackHTTPServer, hit: dict[str, Any]) -> None:
    with server.hit_lock:
        server.hit_count += 1
        hit["sequence"] = server.hit_count
        line = json.dumps(_redact_object(hit), sort_keys=True)
        _hits_path(server.root).parent.mkdir(parents=True, exist_ok=True)
        with _hits_path(server.root).open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        metadata = _read_json(_metadata_path(server.root))
        metadata["hit_count"] = server.hit_count
        metadata["last_hit_at"] = hit["ts"]
        _write_json(_metadata_path(server.root), metadata)


def _endpoint_summary(path: str) -> dict[str, Any]:
    if path == "/":
        return {"kind": "root"}
    if path == "/ping":
        return {"kind": "ping"}
    if path == "/collect":
        return {"kind": "collect"}
    if path.startswith("/hit/"):
        token = path[len("/hit/") :]
        return {"kind": "hit", "path_token_value": REDACTION if token else "", "path_token_length": len(token)}
    return {"kind": "other", "path_length": len(path), "segment_count": len([item for item in path.split("/") if item])}


def _query_summary(query: str) -> dict[str, Any]:
    pairs = parse_qsl(query, keep_blank_values=True)
    fields = []
    for key, value in pairs[:50]:
        safe_key = redact_text(str(key))[:120]
        fields.append({"key": safe_key, "value": REDACTION if value else ""})
    sensitive_keys = sorted({redact_text(str(key))[:120] for key, _value in pairs if _is_sensitive_name(str(key))})
    return {
        "param_count": len(pairs),
        "truncated": len(pairs) > 50,
        "keys": sorted({redact_text(str(key))[:120] for key, _value in pairs})[:50],
        "sensitive_keys": sensitive_keys[:50],
        "fields": fields,
    }


def _headers_summary(headers: Any) -> dict[str, Any]:
    fields = []
    sensitive_names: list[str] = []
    names: list[str] = []
    for key, value in headers.items():
        name = redact_text(str(key))[:120]
        names.append(name)
        sensitive = _is_sensitive_name(name) or _value_looks_sensitive(str(value))
        if sensitive:
            sensitive_names.append(name)
        fields.append({"name": name, "value": REDACTION if sensitive else "[OMITTED]"})
    return {
        "count": len(names),
        "names": sorted(set(names))[:80],
        "sensitive_names": sorted(set(sensitive_names))[:80],
        "fields": fields[:80],
    }


def _body_summary(content_type: str, body: bytes, *, truncated: bool) -> dict[str, Any]:
    text = body.decode("utf-8", errors="replace") if body else ""
    fields: list[dict[str, str]] = []
    parsed_as = "empty" if not body else "opaque"
    if body and ("application/x-www-form-urlencoded" in content_type or "=" in text):
        parsed_as = "form"
        for key, value in parse_qsl(text, keep_blank_values=True)[:50]:
            fields.append({"key": redact_text(str(key))[:120], "value": REDACTION if value else ""})
    elif body and "json" in content_type:
        parsed_as = "json"
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            parsed_as = "json_invalid"
        else:
            if isinstance(value, dict):
                for key, item in list(value.items())[:50]:
                    fields.append({"key": redact_text(str(key))[:120], "value": "" if item in (None, "") else REDACTION})
            else:
                parsed_as = "json_non_object"
    sensitive_keys = sorted({item["key"] for item in fields if _is_sensitive_name(item["key"])})[:50]
    return {
        "length": len(body),
        "truncated": truncated,
        "content_type": redact_text(content_type)[:120] if content_type else "",
        "parsed_as": parsed_as,
        "field_count": len(fields),
        "sensitive_keys": sensitive_keys,
        "sensitive_text_detected": bool(text and redact_text(text) != text),
        "fields": fields,
    }


def _response_for_path(path: str) -> tuple[int, bytes]:
    if path == "/":
        return 200, b"callback listener ok\n"
    if path == "/ping":
        return 200, b"callback ping ok\n"
    if path.startswith("/hit/"):
        return 200, b"callback hit ok\n"
    if path == "/collect":
        return 200, b"callback collect ok\n"
    return 404, b"not found\n"


def _public_listener_payload(metadata: dict[str, Any], root: Path) -> dict[str, Any]:
    return {
        "status": metadata.get("status") or "unknown",
        "listener_id": metadata.get("listener_id") or root.name,
        "local_url": metadata.get("local_url") or "",
        "host": metadata.get("host") or LOCAL_CALLBACK_HOST,
        "port": metadata.get("port") or 0,
        "pid": metadata.get("pid") or 0,
        "alive": _listener_alive(root, metadata),
        "hit_count": _hit_count(root),
        "log_path": _display_path(_hits_path(root)),
        "endpoints": metadata.get("endpoints") or ["/", "/ping", "/hit/<token>", "/collect"],
        "started_at": metadata.get("started_at") or "",
        "stopped_at": metadata.get("stopped_at") or "",
        "last_hit_at": metadata.get("last_hit_at") or "",
    }


def _listener_alive(root: Path, metadata: dict[str, Any]) -> bool:
    pid = _read_pid(root / "listener.pid") or _int_value(metadata.get("pid"))
    return bool(pid and _pid_alive(pid) and _pid_cmdline_contains(pid, metadata.get("listener_id") or root.name))


def _read_hits(root: Path) -> list[dict[str, Any]]:
    hits = []
    path = _hits_path(root)
    if not path.exists():
        return hits
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            hits.append(value)
    return hits


def _hit_count(root: Path) -> int:
    path = _hits_path(root)
    if not path.exists():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())


def _hits_path(root: Path) -> Path:
    return root / "hits.jsonl"


def _metadata_path(root: Path) -> Path:
    return root / "listener.json"


def _state_root(state_root: str | Path | None) -> Path:
    if state_root is not None:
        return Path(state_root).expanduser().resolve()
    return get_paths().state_root


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


def _pid_cmdline_contains(pid: int, marker: str) -> bool:
    cmdline = Path(f"/proc/{pid}/cmdline")
    if not cmdline.exists():
        return True
    try:
        data = cmdline.read_text(encoding="utf-8", errors="replace").replace("\x00", " ")
    except OSError:
        return False
    return "ctf_runner.callback_server" in data and marker in data


def _port_bound(host: str, port: int) -> bool:
    if port <= 0:
        return False
    try:
        with socket.create_connection((host, port), timeout=0.2):
            return True
    except OSError:
        return False


def _terminate_process(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return


def _unlink_if_exists(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _is_sensitive_name(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in SENSITIVE_NAME_MARKERS)


def _value_looks_sensitive(value: str) -> bool:
    return bool(value and redact_text(value) != value)


def _safe_id(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", str(value).strip())
    if not safe or safe in {".", ".."}:
        raise ValueError("invalid listener id")
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


def _redact_object(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _redact_object(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_object(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m ctf_runner.callback_server")
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--listener-id", required=True)
    parser.add_argument("--state-root", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if not args.serve:
        raise ValueError("--serve is required")
    return serve_listener(args.listener_id, state_root=args.state_root)


if __name__ == "__main__":
    raise SystemExit(main())
