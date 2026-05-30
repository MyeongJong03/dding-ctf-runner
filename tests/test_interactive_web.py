import contextlib
import io
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from ctf_runner.browser_smoke import run_browser_smoke
from ctf_runner.cli import main


def test_web_config_stores_base_url_and_auth_source_without_secret_value(tmp_path: Path, monkeypatch):
    root, _challenge = _seed_web_board(tmp_path, monkeypatch, "web-config")
    cookie_file = tmp_path / "team.cookie"
    secret = "WEB_COOKIE_UNIT_SECRET"
    cookie_file.write_text(f"session={secret}", encoding="utf-8")

    result = _run_json(
        [
            "interactive",
            "web-config",
            "--contest-id",
            "web-config",
            "--challenge-id",
            "web",
            "--base-url",
            "http://127.0.0.1:31337",
            "--auth-source",
            "cookie-file",
            "--cookie-file",
            str(cookie_file),
            "--json",
        ]
    )

    operator_text = (root / "operator" / "operator.json").read_text(encoding="utf-8")
    board_text = (root / "operator" / "board.json").read_text(encoding="utf-8")
    metadata = json.loads(operator_text)["challenge_web_metadata"]["web"]
    status = _run_json(["interactive", "web-status", "--contest-id", "web-config", "--challenge-id", "web", "--json"])

    assert result["status"] == "ok"
    assert secret not in operator_text
    assert secret not in board_text
    assert metadata["base_url"] == "http://127.0.0.1:31337"
    assert metadata["auth_source"]["type"] == "cookie-file"
    assert metadata["auth_source"]["cookie_file"] == str(cookie_file)
    assert status["status"] == "ok"
    assert status["auth_source_present"] is True


def test_web_probe_local_fake_app_extracts_title_forms_links_scripts(tmp_path: Path, monkeypatch):
    with FakeWebServer() as server:
        root, _challenge = _seed_web_board(tmp_path, monkeypatch, "web-probe")
        _run_json(
            [
                "interactive",
                "web-config",
                "--contest-id",
                "web-probe",
                "--challenge-id",
                "web",
                "--base-url",
                server.base_url,
                "--auth-source",
                "none",
                "--json",
            ]
        )
        result = _run_json(["interactive", "web-probe", "--contest-id", "web-probe", "--challenge-id", "web", "--timeout", "5", "--json"])

    probe_path = Path(result["probe_path"])
    events = (root / "operator" / "metrics" / "events.jsonl").read_text(encoding="utf-8")
    form_paths = {row["action_path"] for row in result["forms"]}
    link_paths = {row["path"] for row in result["links"]}
    script_paths = {row["path"] for row in result["scripts"]}
    endpoints = set(result["endpoint_candidates"])

    assert result["status"] == "ok"
    assert result["http_status"] == 200
    assert result["title"] == "Fake Web"
    assert "/login" in form_paths
    assert "/api/info" in link_paths
    assert "/static/app.js" in script_paths
    assert "/api/flag" in endpoints
    assert probe_path.exists()
    assert "web_probe_completed" in events


def test_browser_probe_local_fake_app_works_or_is_unavailable(tmp_path: Path, monkeypatch):
    with FakeWebServer() as server:
        _seed_web_board(tmp_path, monkeypatch, "browser-probe")
        _run_json(
            [
                "interactive",
                "web-config",
                "--contest-id",
                "browser-probe",
                "--challenge-id",
                "web",
                "--base-url",
                server.base_url,
                "--json",
            ]
        )
        result = _run_json(["interactive", "browser-probe", "--contest-id", "browser-probe", "--challenge-id", "web", "--timeout", "5", "--json"])

    if result["status"] == "unavailable":
        assert result["reason"] == "playwright_unavailable"
        return
    assert result["status"] == "ok"
    assert result["title"] == "Fake Web"
    assert Path(result["screenshot_path"]).exists()
    assert result["network_summary"]


def test_web_attempt_script_gets_base_url_env_and_records_candidate(tmp_path: Path, monkeypatch):
    with FakeWebServer() as server:
        root, challenge = _seed_web_board(tmp_path, monkeypatch, "web-attempt")
        _run_json(["interactive", "web-config", "--contest-id", "web-attempt", "--challenge-id", "web", "--base-url", server.base_url, "--json"])
        script = challenge / "solve_web.py"
        script.write_text(
            "import os, urllib.request\n"
            "base = os.environ['CTF_WEB_BASE_URL']\n"
            "print(base)\n"
            "print(urllib.request.urlopen(base + '/flag', timeout=5).read().decode())\n",
            encoding="utf-8",
        )

        result = _run_json(["interactive", "web-attempt", "--contest-id", "web-attempt", "--challenge-id", "web", "--script", "solve_web.py", "--timeout", "10", "--json"])

    candidate = "FLAG{unit_web_attempt_candidate}"
    attempt = Path(result["attempt_path"]).read_text(encoding="utf-8")
    candidates = (challenge / "candidates.jsonl").read_text(encoding="utf-8")
    events = (root / "operator" / "metrics" / "events.jsonl").read_text(encoding="utf-8")

    assert result["status"] == "ok"
    assert server.base_url in result["stdout"]
    assert candidate in result["stdout"]
    assert candidate in attempt
    assert candidate in candidates
    assert "web_attempt_completed" in events


def test_web_attempt_request_json_extracts_candidate_from_response(tmp_path: Path, monkeypatch):
    with FakeWebServer() as server:
        _root, challenge = _seed_web_board(tmp_path, monkeypatch, "web-request")
        _run_json(["interactive", "web-config", "--contest-id", "web-request", "--challenge-id", "web", "--base-url", server.base_url, "--json"])
        spec = challenge / "request.json"
        spec.write_text(json.dumps({"method": "GET", "path": "/flag"}), encoding="utf-8")
        result = _run_json(["interactive", "web-attempt", "--contest-id", "web-request", "--challenge-id", "web", "--request-json", "request.json", "--json"])

    assert result["status"] == "ok"
    assert result["candidates"][0]["value"] == "FLAG{unit_web_attempt_candidate}"
    assert result["response"]["http_status"] == 200
    assert result["response"]["body_sha256"]


def test_browser_attempt_records_screenshot_console_network_when_available(tmp_path: Path, monkeypatch):
    smoke = run_browser_smoke()
    if not smoke.get("ok"):
        pytest.skip(f"Playwright unavailable: {smoke.get('reason')}")
    with FakeWebServer() as server:
        _root, challenge = _seed_web_board(tmp_path, monkeypatch, "browser-attempt")
        _run_json(["interactive", "web-config", "--contest-id", "browser-attempt", "--challenge-id", "web", "--base-url", server.base_url, "--json"])
        script = challenge / "solve_browser.py"
        script.write_text(
            "import json, os\n"
            "from pathlib import Path\n"
            "from playwright.sync_api import sync_playwright\n"
            "console_path = Path(os.environ['CTF_BROWSER_CONSOLE_JSONL'].replace('~', str(Path.home()), 1))\n"
            "network_path = Path(os.environ['CTF_BROWSER_NETWORK_JSONL'].replace('~', str(Path.home()), 1))\n"
            "with sync_playwright() as pw:\n"
            "    browser = pw.chromium.launch(headless=True)\n"
            "    page = browser.new_page()\n"
            "    page.on('console', lambda msg: console_path.open('a').write(json.dumps({'type': msg.type, 'text': msg.text}) + '\\n'))\n"
            "    page.on('response', lambda res: network_path.open('a').write(json.dumps({'method': res.request.method, 'url': res.url, 'status': res.status, 'content_type': res.headers.get('content-type', '')}) + '\\n'))\n"
            "    page.goto(os.environ['CTF_WEB_BASE_URL'], wait_until='domcontentloaded', timeout=10000)\n"
            "    page.screenshot(path=os.environ['CTF_BROWSER_SCREENSHOT'].replace('~', str(Path.home()), 1), full_page=True)\n"
            "    print(page.title())\n"
            "    browser.close()\n",
            encoding="utf-8",
        )

        result = _run_json(["interactive", "browser-attempt", "--contest-id", "browser-attempt", "--challenge-id", "web", "--script", "solve_browser.py", "--timeout", "20", "--json"])

    assert result["status"] == "ok"
    assert Path(result["screenshot_path"].replace("~", str(Path.home()), 1)).exists()
    assert any(row["text"] == "browser console ok" for row in result["console_summary"])
    assert result["network_summary"]


def test_public_snapshot_excludes_web_cookie_storage_raw_response_and_candidate(tmp_path: Path, monkeypatch):
    with FakeWebServer() as server:
        _root, challenge = _seed_web_board(tmp_path, monkeypatch, "web-public")
        cookie_file = tmp_path / "web.cookie"
        storage_state = tmp_path / "storage_state.json"
        secret = "WEB_PUBLIC_COOKIE_SECRET"
        cookie_file.write_text(f"session={secret}", encoding="utf-8")
        storage_state.write_text(json.dumps({"cookies": [{"name": "session", "value": secret, "domain": "127.0.0.1", "path": "/"}], "origins": []}), encoding="utf-8")
        _run_json(
            [
                "interactive",
                "web-config",
                "--contest-id",
                "web-public",
                "--challenge-id",
                "web",
                "--base-url",
                server.base_url,
                "--auth-source",
                "cookie-file",
                "--cookie-file",
                str(cookie_file),
                "--json",
            ]
        )
        spec = challenge / "request.json"
        spec.write_text(json.dumps({"method": "GET", "path": "/flag"}), encoding="utf-8")
        _run_json(["interactive", "web-attempt", "--contest-id", "web-public", "--challenge-id", "web", "--request-json", "request.json", "--json"])

    snapshot_root = tmp_path / "public" / "web-public"
    snapshot = _run_json(
        [
            "interactive",
            "metrics",
            "publish-snapshot",
            "--contest-id",
            "web-public",
            "--output-root",
            str(snapshot_root),
            "--contest-ended",
            "--json",
        ]
    )
    combined = "\n".join(path.read_text(encoding="utf-8") for path in snapshot_root.glob("*.public.*"))

    assert snapshot["public_safe"] is True
    assert secret not in combined
    assert "storage_state" not in combined
    assert "FLAG{unit_web_attempt_candidate}" not in combined
    assert "unit_web_attempt_candidate" not in combined
    assert "flag_hash" in combined


def test_target_pack_and_starter_include_web_metadata(tmp_path: Path, monkeypatch):
    with FakeWebServer() as server:
        _root, _challenge = _seed_web_board(tmp_path, monkeypatch, "web-pack")
        _run_json(["interactive", "web-config", "--contest-id", "web-pack", "--challenge-id", "web", "--base-url", server.base_url, "--json"])
        pack = _run_json(["interactive", "target-pack", "--contest-id", "web-pack", "--challenge-id", "web", "--json"])
        starter = _run_json(["interactive", "starter", "--contest-id", "web-pack", "--challenge-id", "web", "--category", "web", "--json"])

    pack_text = Path(pack["target_pack_path"].replace("~", str(Path.home()), 1)).read_text(encoding="utf-8")
    starter_text = Path(starter["starter_path"].replace("~", str(Path.home()), 1)).read_text(encoding="utf-8")

    assert "## Web" in pack_text
    assert server.base_url in pack_text
    assert "web-probe --contest-id web-pack --challenge-id web --json" in pack_text
    assert "WEB_BASE_URL" in starter_text
    assert "requests.Session" in starter_text


class FakeWebServer:
    def __init__(self) -> None:
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _FakeWebHandler)
        self._thread: threading.Thread | None = None
        self.requests: list[str] = []
        self._httpd.owner = self  # type: ignore[attr-defined]

    @property
    def base_url(self) -> str:
        host, port = self._httpd.server_address
        return f"http://{host}:{port}"

    def __enter__(self) -> "FakeWebServer":
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread:
            self._thread.join(timeout=2)
        return False


class _FakeWebHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        return

    @property
    def owner(self) -> FakeWebServer:
        return self.server.owner  # type: ignore[attr-defined]

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        self.owner.requests.append(self.path)
        if path == "/":
            self._send(
                "text/html",
                b"""
                <!doctype html>
                <html>
                  <head>
                    <title>Fake Web</title>
                    <link rel="stylesheet" href="/static/app.css">
                    <script src="/static/app.js"></script>
                  </head>
                  <body>
                    <form method="post" action="/login">
                      <input name="user">
                      <input type="password" name="password">
                    </form>
                    <a href="/api/info">API</a>
                    <script>console.log('browser console ok'); fetch('/api/flag');</script>
                  </body>
                </html>
                """,
            )
            return
        if path == "/flag":
            self._send("text/plain", b"FLAG{unit_web_attempt_candidate}\n")
            return
        if path == "/api/info":
            self._send("application/json", b'{"ok": true}')
            return
        if path == "/static/app.js":
            self._send("application/javascript", b"window.appLoaded = true;")
            return
        if path == "/static/app.css":
            self._send("text/css", b"body { color: #111; }")
            return
        self.send_error(404)

    def _send(self, content_type: str, payload: bytes) -> None:
        self.send_response(200)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def _seed_web_board(tmp_path: Path, monkeypatch, contest_id: str) -> tuple[Path, Path]:
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))
    _run_json(["interactive", "init", "--contest-id", contest_id, "--json"])
    root = tmp_path / "contests" / contest_id
    challenge = root / "web" / "Web"
    challenge.mkdir(parents=True, exist_ok=True)
    (challenge / "brief.md").write_text("# Web\nUse the configured base URL.\n", encoding="utf-8")
    for name in ["memory.md", "evidence.md", "attempts.md", "next_steps.md", "operator_notes.md"]:
        (challenge / name).write_text(f"# {name}\n", encoding="utf-8")
    board = {
        "contest_id": contest_id,
        "updated_at": "now",
        "challenges": [
            {
                "challenge_id": "web",
                "name": "Web",
                "canonical_id": "web",
                "canonical_name": "Web",
                "category": "web",
                "status": "todo",
                "path": str(challenge),
            }
        ],
    }
    (root / "operator" / "board.json").write_text(json.dumps(board), encoding="utf-8")
    return root, challenge


def _run_json(argv: list[str]) -> dict:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = main(argv)
    output = buffer.getvalue()
    assert code == 0, output
    return json.loads(output)
