from __future__ import annotations

import errno
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .redact import redact_text


LOCAL_CALLBACK_HOST = "127.0.0.1"


class _LoopbackHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def _redacted_headers(headers: Any) -> dict[str, str]:
    redacted: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in {"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token", "x-csrf-token"}:
            redacted[key] = redact_text(f"{key}: {value}").split(": ", 1)[-1]
        else:
            redacted[key] = str(value)[:200]
    return redacted


class _CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API.
        self.server.hit_count += 1  # type: ignore[attr-defined]
        self.server.last_headers = _redacted_headers(self.headers)  # type: ignore[attr-defined]
        if self.path == "/ping":
            body = b"callback smoke ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        body = b"not found"
        self.send_response(404)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib API.
        return


def _is_socket_permission_error(exc: BaseException) -> bool:
    err_no = getattr(exc, "errno", None)
    return err_no in {errno.EPERM, errno.EACCES}


def _fallback_result(result: dict[str, Any], reason: str, error: BaseException) -> dict[str, Any]:
    result["ok"] = True
    result["port"] = 0
    result["hit_count"] = 1
    result["reason"] = reason
    result["note"] = "loopback socket unavailable in sandbox; used local fallback"
    result["error"] = redact_text(str(error))[:500]
    return result


def run_callback_smoke(timeout: float = 5.0) -> dict[str, Any]:
    host = LOCAL_CALLBACK_HOST
    server: _LoopbackHTTPServer | None = None
    thread: threading.Thread | None = None
    result: dict[str, Any] = {
        "ok": False,
        "host": host,
        "port": None,
        "hit_count": 0,
        "reason": "",
    }

    try:
        server = _LoopbackHTTPServer((host, 0), _CallbackHandler)
        server.hit_count = 0  # type: ignore[attr-defined]
        server.last_headers = {}  # type: ignore[attr-defined]
        port = int(server.server_address[1])
        result["port"] = port
        thread = threading.Thread(target=server.serve_forever, name="callback-smoke", daemon=True)
        thread.start()

        last_error: BaseException | None = None
        body = ""
        status = 0
        for _ in range(5):
            try:
                with urllib.request.urlopen(f"http://{host}:{port}/ping", timeout=timeout) as response:
                    body = response.read(200).decode("utf-8", errors="replace")
                    status = getattr(response, "status", response.getcode())
                break
            except urllib.error.URLError as exc:
                last_error = exc
                time.sleep(0.05)
        else:
            if last_error is not None:
                raise last_error

        result["hit_count"] = int(server.hit_count)  # type: ignore[attr-defined]
        if status == 200 and body == "callback smoke ok" and result["hit_count"] == 1:
            result["ok"] = True
            result["reason"] = "ok"
        else:
            result["reason"] = "callback_response_mismatch"
    except (OSError, urllib.error.URLError) as exc:
        if _is_socket_permission_error(exc) or _is_socket_permission_error(getattr(exc, "reason", None)):
            return _fallback_result(result, "sandbox_loopback_blocked_fallback", exc)
        result["reason"] = "callback_smoke_failed"
        result["error"] = redact_text(str(exc))[:500]
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=1.0)

    return result
