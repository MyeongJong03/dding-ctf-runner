import contextlib
import io
import json
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

from ctf_runner.cli import main


def test_sync_challenges_respects_limit_and_avoids_duplicate_state_entries(tmp_path: Path):
    with FakeManyPlatformServer() as server:
        config_path = _write_profile(tmp_path, server.base_url)
        first = _run_json(
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
                "--max-challenges",
                "2",
                "--max-detail-fetch",
                "2",
                "--json",
            ]
        )
        second = _run_json(
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
                "--max-challenges",
                "2",
                "--max-detail-fetch",
                "2",
                "--json",
            ]
        )

        assert first["challenge_count"] == 2
        assert first["state_save"]["count"] == 2
        assert first["ingest_ready_count"] == 2
        assert second["state_save"]["count"] == 2
        assert server.post_log == []

        with sqlite3.connect(tmp_path / "queue.sqlite3") as conn:
            count = conn.execute("SELECT COUNT(*) FROM challenges").fetchone()[0]
            statuses = [row[0] for row in conn.execute("SELECT status FROM challenges ORDER BY id")]
        assert count == 2
        assert statuses == ["ingest_ready", "ingest_ready"]


class FakeManyPlatformServer:
    def __init__(self) -> None:
        self._httpd = HTTPServer(("127.0.0.1", 0), _FakeManyHandler)
        self._httpd.owner = self  # type: ignore[attr-defined]
        self._thread: threading.Thread | None = None
        self.get_log: list[str] = []
        self.post_log: list[str] = []

    @property
    def base_url(self) -> str:
        host, port = self._httpd.server_address
        return f"http://{host}:{port}"

    def __enter__(self) -> "FakeManyPlatformServer":
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread:
            self._thread.join(timeout=2)
        return False


class _FakeManyHandler(BaseHTTPRequestHandler):
    server_version = "FakeMany/0.1"

    def log_message(self, format: str, *args: Any) -> None:
        return

    @property
    def owner(self) -> FakeManyPlatformServer:
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
                            {"id": "a", "name": "A", "category": "misc", "points": 10, "statement": "A statement"},
                            {"id": "b", "name": "B", "category": "misc", "points": 20, "statement": "B statement"},
                            {"id": "c", "name": "C", "category": "misc", "points": 30, "statement": "C statement"},
                        ]
                    }
                ).encode(),
            )
            return
        if path.startswith("/api/") or path.startswith("/contests/demo/") or path == "/trpc":
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
                "name: fake_many",
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


def _run_json(argv: list[str]) -> dict:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = main(argv)
    output = buffer.getvalue()
    assert code == 0, output
    return json.loads(output)
