import contextlib
import io
import json
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

from ctf_runner.cli import main


def test_live_readonly_smoke_generates_text_only_brief_and_sync_marks_ingest_ready(tmp_path: Path):
    output_chunks: list[str] = []
    with FakeTextPlatformServer() as server:
        config_path = _write_profile(tmp_path, server.base_url)
        smoke = _run_json(
            [
                "--db",
                str(tmp_path / "queue.sqlite3"),
                "platform",
                "live-readonly-smoke",
                "--config",
                str(config_path),
                "--json",
                "--save-state",
            ],
            output_chunks,
        )
        sync = _run_json(
            [
                "--db",
                str(tmp_path / "queue.sqlite3"),
                "platform",
                "sync-challenges",
                "--config",
                str(config_path),
                "--live",
                "--save-state",
                "--ingest-text",
                "--json",
            ],
            output_chunks,
        )

        rendered = "\n".join(output_chunks)
        assert smoke["status"] == "ok"
        assert smoke["discovered_count"] == 2
        assert smoke["detail_text_found"] == "yes"
        assert smoke["ingest_type"] == "text"
        assert Path(smoke["ingest_brief_path"].replace("~/", str(Path.home()) + "/", 1)).exists()
        assert sync["status"] == "ok"
        assert sync["challenge_count"] == 2
        assert sync["ingest_ready_count"] == 2
        assert server.post_log == []
        assert "submit" not in "".join(server.get_log)
        assert _flag_like("flag", "not-real-but-shaped") not in rendered

        with sqlite3.connect(tmp_path / "queue.sqlite3") as conn:
            statuses = {row[0]: row[1] for row in conn.execute("SELECT id, status FROM challenges")}
        assert statuses == {"web-1": "ingest_ready", "crypto-1": "ingest_ready"}


class FakeTextPlatformServer:
    def __init__(self) -> None:
        self._httpd = HTTPServer(("127.0.0.1", 0), _FakeTextHandler)
        self._httpd.owner = self  # type: ignore[attr-defined]
        self._thread: threading.Thread | None = None
        self.get_log: list[str] = []
        self.post_log: list[str] = []

    @property
    def base_url(self) -> str:
        host, port = self._httpd.server_address
        return f"http://{host}:{port}"

    def __enter__(self) -> "FakeTextPlatformServer":
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread:
            self._thread.join(timeout=2)
        return False


class _FakeTextHandler(BaseHTTPRequestHandler):
    server_version = "FakeText/0.1"

    def log_message(self, format: str, *args: Any) -> None:
        return

    @property
    def owner(self) -> FakeTextPlatformServer:
        return self.server.owner  # type: ignore[attr-defined]

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        self.owner.get_log.append(self.path)
        if path == "/contests/demo":
            self._send(
                "application/json",
                json.dumps(
                    {
                        "challenges": [
                            {"id": "web-1", "name": "Web One", "category": "web", "points": 100, "url": "/challenges/web-1"},
                            {
                                "id": "crypto-1",
                                "name": "Crypto One",
                                "category": "crypto",
                                "points": 200,
                                "statement": "Recover the message from the toy cipher.",
                            },
                        ]
                    }
                ).encode(),
            )
            return
        if path == "/challenges/web-1":
            self._send(
                "text/html",
                b"<html><h1>Web One</h1><main>Read the endpoint carefully. " + _flag_like("flag", "not-real-but-shaped").encode("ascii") + b"</main></html>",
            )
            return
        if path in {"/api/challenges", "/api/problems", "/api/tasks", "/trpc"} or path.startswith("/api/") or path.startswith("/contests/demo/"):
            self.send_error(404)
            return
        self.send_error(404)

    def do_POST(self) -> None:
        self.owner.post_log.append(self.path)
        self.send_error(405)

    def _send(self, content_type: str, payload: bytes) -> None:
        self.send_response(200)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def _write_profile(tmp_path: Path, base_url: str) -> Path:
    config_path = tmp_path / "platform.yaml"
    config_path.write_text(
        "\n".join(
            [
                "platform: generic",
                "name: fake_text",
                f"base_url: {base_url}",
                f"contest_url: {base_url}/contests/demo",
                "auth:",
                "  method: manual",
                "policy:",
                "  allow_live_discovery: true",
                "  allow_live_download: false",
                "  allow_submission: false",
                "  allow_instance_start: false",
                "downloads:",
                f"  root: {tmp_path / 'contests'}",
            ]
        ),
        encoding="utf-8",
    )
    return config_path


def _run_json(argv: list[str], output_chunks: list[str]) -> dict:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = main(argv)
    output = buffer.getvalue()
    output_chunks.append(output)
    assert code == 0, output
    return json.loads(output)


def _flag_like(prefix: str, body: str) -> str:
    return prefix + "{" + body + "}"
