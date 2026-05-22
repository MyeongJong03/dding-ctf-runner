import contextlib
import io
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

from ctf_runner.cli import main


def test_generic_live_readonly_smoke_discovers_downloads_ingests_without_submit(tmp_path: Path):
    output_chunks: list[str] = []
    with FakeGenericPlatformServer() as server:
        config_path = tmp_path / "platform.yaml"
        config_path.write_text(
            "\n".join(
                [
                    "platform: generic",
                    "name: fake_generic",
                    f"base_url: {server.base_url}",
                    f"contest_url: {server.base_url}/contests/demo",
                    "auth:",
                    "  method: manual",
                    "policy:",
                    "  allow_live_discovery: true",
                    "  allow_live_download: true",
                    "  allow_submission: false",
                    "  allow_instance_start: false",
                    "downloads:",
                    f"  root: {tmp_path / 'contests'}",
                ]
            ),
            encoding="utf-8",
        )

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
        download = _run_json(
            [
                "platform",
                "generic-download",
                "--config",
                str(config_path),
                "--challenge-id",
                "web-1",
                "--live",
                "--json",
            ],
            output_chunks,
        )
        ingest = _run_json(
            [
                "--db",
                str(tmp_path / "queue.sqlite3"),
                "platform",
                "generic-ingest",
                "--config",
                str(config_path),
                "--challenge-id",
                "web-1",
                "--live",
                "--json",
            ],
            output_chunks,
        )

        rendered = "\n".join(output_chunks)
        assert smoke["status"] == "ok"
        assert smoke["discovered_count"] == 1
        assert smoke["selected_challenge_id"] == "web-1"
        assert smoke["downloaded_count"] == 1
        assert smoke["ingest_status"] == "ok"
        assert smoke["state_saved"] == "yes"
        assert download["status"] == "ok"
        assert Path(download["details"]["downloads"][0]["fs_path"]).exists()
        assert ingest["ingest"]["status"] == "ok"
        assert server.post_log == []
        assert not any("submit" in item.lower() or "attempt" in item.lower() for item in server.get_log)
        assert "signed-download-token" not in rendered
        assert "?token=" not in rendered


class FakeGenericPlatformServer:
    def __init__(self) -> None:
        self._httpd = HTTPServer(("127.0.0.1", 0), _FakeGenericHandler)
        self._httpd.owner = self  # type: ignore[attr-defined]
        self._thread: threading.Thread | None = None
        self.get_log: list[str] = []
        self.post_log: list[str] = []

    @property
    def base_url(self) -> str:
        host, port = self._httpd.server_address
        return f"http://{host}:{port}"

    def __enter__(self) -> "FakeGenericPlatformServer":
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread:
            self._thread.join(timeout=2)
        return False


class _FakeGenericHandler(BaseHTTPRequestHandler):
    server_version = "FakeGeneric/0.1"

    def log_message(self, format: str, *args: Any) -> None:
        return

    @property
    def owner(self) -> FakeGenericPlatformServer:
        return self.server.owner  # type: ignore[attr-defined]

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        self.owner.get_log.append(self.path)
        if path == "/contests/demo":
            self._send(
                "text/html",
                b"""
                <html>
                  <a class="challenge-card" href="/challenges/web-1">Web One</a>
                  <script>
                    window.__routes = ["/api/contests/demo/challenges", "/api/challenges/attempt"];
                  </script>
                </html>
                """,
            )
            return
        if path == "/api/contests/demo/challenges":
            self._send(
                "application/json",
                json.dumps(
                    {
                        "challenges": [
                            {
                                "id": "web-1",
                                "name": "Web One",
                                "category": "web",
                                "points": 100,
                                "solves": 3,
                                "url": "/challenges/web-1",
                            }
                        ]
                    }
                ).encode(),
            )
            return
        if path == "/api/challenges":
            self._send("application/json", b'{"challenges":[]}')
            return
        if path == "/api/problems" or path == "/api/tasks":
            self.send_error(404)
            return
        if path == "/challenges/web-1":
            self._send(
                "text/html",
                b"""
                <html>
                  <a href="/files/web-one.zip?token=signed-download-token" download>download</a>
                  <script type="application/json">
                    {"challenge":{"id":"web-1","name":"Web One","category":"web","points":100,
                     "files":[{"name":"web-one.zip","url":"/files/web-one.zip?token=signed-download-token"}]}}
                  </script>
                </html>
                """,
            )
            return
        if path == "/files/web-one.zip":
            self._send("application/zip", b"fake attachment bytes")
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


def _run_json(argv: list[str], output_chunks: list[str]) -> dict:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = main(argv)
    output = buffer.getvalue()
    output_chunks.append(output)
    assert code == 0, output
    return json.loads(output)
