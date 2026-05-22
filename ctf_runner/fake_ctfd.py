from __future__ import annotations

import base64
import hashlib
import json
import threading
import urllib.parse
from contextlib import AbstractContextManager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .platform_base import action_to_dict
from .platform_ctfd import CTFdPlatform
from .redact import redact_text
from .submit import hash_flag, redact_flag


CHALLENGE_ID = "easy-misc-1"
CHALLENGE_NAME = "easy-misc-1"
CHALLENGE_CATEGORY = "misc"
CHALLENGE_VALUE = 100
ATTACHMENT_NAME = "DDING_MOCK_SOLVER_SOLVED_easy_misc_note.txt"


@dataclass(frozen=True)
class ChallengeFixture:
    challenge_id: str
    name: str
    category: str
    value: int
    attachment_name: str
    description: str
    body: str
    correct_flag: str
    tags: tuple[str, ...] = ("local", "smoke")


def default_correct_flag() -> str:
    return "DDING" + "{" + "mock_solver_verified_value" + "}"


def stalled_correct_flag() -> str:
    return "DDING" + "{" + "stalled_unreachable_value" + "}"


def wrong_flag() -> str:
    return "FLAG" + "{" + "wrong_vault_path_48291" + "}"


def fake_decoy_flag() -> str:
    return "FLAG" + "{" + "example_dummy_flag" + "}"


def duplicate_real_flag() -> str:
    return default_correct_flag()


def _fixture_body(kind: str, correct_flag: str) -> str:
    if kind == "misc":
        return "\n".join(
            [
                "Local fake CTFd misc challenge.",
                "DDING_MOCK_SOLVER_SOLVED",
                f"candidate: {correct_flag}",
                "Provenance: source=file_read local_verified=true evidence=note.txt",
                "",
            ]
        )
    if kind == "crypto":
        encoded = base64.b64encode(correct_flag.encode("utf-8")).decode("ascii")
        as_hex = correct_flag.encode("utf-8").hex()
        return "\n".join(
            [
                "Local fake CTFd crypto challenge.",
                "DDING_MOCK_SOLVER_SOLVED",
                f"base64: {encoded}",
                f"hex: {as_hex}",
                "Decode either value and submit the verified candidate.",
                "",
            ]
        )
    if kind == "web":
        return "\n".join(
            [
                "from flask import Flask",
                "app = Flask(__name__)",
                "",
                f"ROUTE_SECRET = {correct_flag!r}",
                "",
                "@app.get('/local-only')",
                "def local_only():",
                "    return ROUTE_SECRET",
                "",
                "# DDING_MOCK_SOLVER_SOLVED",
                "",
            ]
        )
    if kind == "stalled":
        return "\n".join(
            [
                "Local fake CTFd stalled challenge.",
                "DDING_MOCK_SOLVER_STALLED",
                f"decoy: {fake_decoy_flag()}",
                "No locally verified real candidate is present in this attachment.",
                "",
            ]
        )
    if kind == "duplicate_decoy":
        return "\n".join(
            [
                "Local fake CTFd duplicate/decoy challenge.",
                "DDING_MOCK_SOLVER_DECOY_THEN_SOLVED",
                f"fake-looking candidate: {fake_decoy_flag()}",
                f"real-looking candidate: {correct_flag}",
                "The worker should block the fake-like candidate and submit the verified one once.",
                "",
            ]
        )
    raise ValueError(f"unknown fixture body kind: {kind}")


def default_fixtures(correct_flag: str | None = None) -> list[ChallengeFixture]:
    shared = correct_flag or default_correct_flag()
    return [
        ChallengeFixture(
            challenge_id=CHALLENGE_ID,
            name="easy-misc-1",
            category=CHALLENGE_CATEGORY,
            value=CHALLENGE_VALUE,
            attachment_name=ATTACHMENT_NAME,
            description="Find the candidate in a simple local note attachment.",
            body=_fixture_body("misc", shared),
            correct_flag=shared,
        ),
        ChallengeFixture(
            challenge_id="easy-crypto-1",
            name="easy-crypto-1",
            category="crypto",
            value=100,
            attachment_name="DDING_MOCK_SOLVER_SOLVED_easy_crypto.txt",
            description="Decode the simple local encoding and verify the candidate.",
            body=_fixture_body("crypto", shared),
            correct_flag=shared,
        ),
        ChallengeFixture(
            challenge_id="easy-web-1",
            name="easy-web-1",
            category="web",
            value=100,
            attachment_name="DDING_MOCK_SOLVER_SOLVED_app.py",
            description="Inspect the local source route and secret value.",
            body=_fixture_body("web", shared),
            correct_flag=shared,
        ),
        ChallengeFixture(
            challenge_id="stalled-1",
            name="stalled-1",
            category="misc",
            value=50,
            attachment_name="DDING_MOCK_SOLVER_STALLED_stalled_note.txt",
            description="This fixture intentionally contains no verified real candidate.",
            body=_fixture_body("stalled", stalled_correct_flag()),
            correct_flag=stalled_correct_flag(),
        ),
        ChallengeFixture(
            challenge_id="duplicate-decoy-1",
            name="duplicate-decoy-1",
            category="misc",
            value=100,
            attachment_name="DDING_MOCK_SOLVER_DECOY_THEN_SOLVED_note.txt",
            description="Contains both a fake-like candidate and a locally verified candidate.",
            body=_fixture_body("duplicate_decoy", duplicate_real_flag() if correct_flag is None else shared),
            correct_flag=duplicate_real_flag() if correct_flag is None else shared,
        ),
    ]


def platform_config(base_url: str, downloads_root: str | Path | None = None) -> dict[str, Any]:
    config: dict[str, Any] = {
        "platform": "ctfd",
        "name": "fake_ctfd",
        "base_url": base_url,
        "auth": {"method": "manual"},
        "policy": {
            "allow_live_discovery": True,
            "allow_live_download": True,
            "allow_submission": True,
            "allow_instance_start": False,
        },
    }
    if downloads_root is not None:
        config["downloads"] = {"root": str(Path(downloads_root).expanduser())}
    return config


class FakeCTFdServer(AbstractContextManager["FakeCTFdServer"]):
    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        correct_flag: str | None = None,
        fixtures: list[ChallengeFixture] | None = None,
    ):
        if host != "127.0.0.1":
            raise ValueError("fake CTFd may only bind to 127.0.0.1")
        self.host = host
        self.port = int(port)
        self.fixtures = fixtures or default_fixtures(correct_flag)
        if not self.fixtures:
            raise ValueError("at least one fake CTFd fixture is required")
        self._by_id = {fixture.challenge_id: fixture for fixture in self.fixtures}
        self._by_attachment = {fixture.attachment_name: fixture for fixture in self.fixtures}
        self.request_log: list[str] = []
        self.submission_log: list[dict[str, Any]] = []
        self._solved: set[str] = set()
        self._lock = threading.Lock()
        self._httpd = _FakeHTTPServer((self.host, self.port), _FakeCTFdHandler, owner=self)
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.bound_port}"

    @property
    def bound_port(self) -> int:
        return int(self._httpd.server_address[1])

    @property
    def correct_flag(self) -> str:
        return self.fixtures[0].correct_flag

    @property
    def flag_hash(self) -> str:
        return hash_flag(self.correct_flag)

    @property
    def correct_flags(self) -> list[str]:
        return [fixture.correct_flag for fixture in self.fixtures]

    def start(self) -> "FakeCTFdServer":
        if self._thread is None:
            self._thread = threading.Thread(target=self._httpd.serve_forever, name="fake-ctfd", daemon=True)
            self._thread.start()
        return self

    def serve_forever(self) -> None:
        self._httpd.serve_forever()

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def __enter__(self) -> "FakeCTFdServer":
        return self.start()

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.stop()
        return False

    def public_info(self) -> dict[str, Any]:
        return {
            "status": "ok",
            "base_url": self.base_url,
            "bind_host": "127.0.0.1",
            "challenge_id": self.fixtures[0].challenge_id,
            "challenge_name": self.fixtures[0].name,
            "challenge_count": len(self.fixtures),
            "challenge_ids": [fixture.challenge_id for fixture in self.fixtures],
            "flag_hash": self.flag_hash,
            "candidate_preview": redact_flag(self.correct_flag),
            "challenges": [
                {
                    "challenge_id": fixture.challenge_id,
                    "name": fixture.name,
                    "category": fixture.category,
                    "flag_hash": hash_flag(fixture.correct_flag),
                    "candidate_preview": redact_flag(fixture.correct_flag),
                    "solved": fixture.challenge_id in self._solved,
                }
                for fixture in self.fixtures
            ],
        }

    def challenge_list_item(self, fixture: ChallengeFixture | None = None) -> dict[str, Any]:
        fixture = fixture or self.fixtures[0]
        files = [f"/files/{urllib.parse.quote(fixture.attachment_name)}"] if fixture.attachment_name else []
        return {
            "id": fixture.challenge_id,
            "name": fixture.name,
            "category": fixture.category,
            "value": fixture.value,
            "solves": 1 if fixture.challenge_id in self._solved else 0,
            "description": fixture.description,
            "tags": [{"value": value} for value in fixture.tags],
            "files": files,
            "connection_info": None,
        }

    def challenge_detail(self, challenge_id: str) -> dict[str, Any] | None:
        fixture = self._by_id.get(str(challenge_id))
        if fixture is None:
            return None
        item = self.challenge_list_item(fixture)
        item["description"] = fixture.description
        item["files"] = (
            [{"name": fixture.attachment_name, "url": f"/files/{urllib.parse.quote(fixture.attachment_name)}"}]
            if fixture.attachment_name
            else []
        )
        return item

    def attachment_bytes(self, filename: str) -> bytes | None:
        fixture = self._by_attachment.get(Path(filename).name)
        if fixture is None:
            return None
        return fixture.body.encode("utf-8")

    def submit(self, challenge_id: str | int | None, submission: str) -> dict[str, Any]:
        fixture = self._by_id.get(str(challenge_id))
        accepted = bool(fixture and submission == fixture.correct_flag)
        with self._lock:
            already_solved = bool(fixture and fixture.challenge_id in self._solved)
            if accepted and not already_solved:
                self._solved.add(fixture.challenge_id)
            status = "already_solved" if accepted and already_solved else ("correct" if accepted else "incorrect")
            self.submission_log.append(
                {
                    "challenge_id": str(challenge_id or ""),
                    "flag_hash": hash_flag(submission),
                    "status": status,
                }
            )
        return {
            "success": True,
            "data": {
                "status": status,
                "message": "Already solved" if status == "already_solved" else ("Correct" if accepted else "Incorrect"),
            },
        }

    def log_request_safe(self, method: str, path: str, status: int) -> None:
        parsed = urllib.parse.urlsplit(path)
        self.request_log.append(redact_text(f"{method} {parsed.path} {status}"))


class _FakeHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address: tuple[str, int], handler_class: type[BaseHTTPRequestHandler], *, owner: FakeCTFdServer):
        super().__init__(server_address, handler_class)
        self.owner = owner


class _FakeCTFdHandler(BaseHTTPRequestHandler):
    server: _FakeHTTPServer

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API.
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/api/v1/challenges":
            self._send_json(200, {"success": True, "data": [self.server.owner.challenge_list_item(item) for item in self.server.owner.fixtures]})
            return
        if parsed.path.startswith("/api/v1/challenges/"):
            challenge_id = urllib.parse.unquote(parsed.path.rsplit("/", 1)[-1])
            detail = self.server.owner.challenge_detail(challenge_id)
            if detail is None:
                self._send_json(404, {"success": False, "message": "not found"})
                return
            self._send_json(200, {"success": True, "data": detail})
            return
        if parsed.path.startswith("/files/"):
            filename = urllib.parse.unquote(parsed.path.rsplit("/", 1)[-1])
            data = self.server.owner.attachment_bytes(filename)
            if data is None:
                self._send_json(404, {"success": False, "message": "not found"})
                return
            self._send_bytes(200, data, content_type="text/plain; charset=utf-8")
            return
        self._send_json(404, {"success": False, "message": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API.
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path != "/api/v1/challenges/attempt":
            self._send_json(404, {"success": False, "message": "not found"})
            return
        try:
            length = min(int(self.headers.get("Content-Length", "0") or "0"), 64 * 1024)
        except ValueError:
            length = 0
        body = self.rfile.read(length)
        try:
            payload = json.loads(body.decode("utf-8", errors="replace")) if body else {}
        except json.JSONDecodeError:
            self._send_json(400, {"success": False, "message": "invalid json"})
            return
        response = self.server.owner.submit(payload.get("challenge_id"), str(payload.get("submission") or ""))
        self._send_json(200, response)

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, sort_keys=True).encode("utf-8")
        self._send_bytes(status, data, content_type="application/json")

    def _send_bytes(self, status: int, data: bytes, *, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        self.server.owner.log_request_safe(self.command, self.path, status)


def run_smoke(*, port: int = 0, downloads_root: str | Path | None = None) -> dict[str, Any]:
    import tempfile

    temp_ctx = None
    root = downloads_root
    if root is None:
        temp_ctx = tempfile.TemporaryDirectory(prefix="fake-ctfd-smoke-")
        root = Path(temp_ctx.name) / "contests"
    try:
        with FakeCTFdServer(port=port) as server:
            config = platform_config(server.base_url, downloads_root=root)
            platform = CTFdPlatform(config=config)
            discover = platform.discover_challenges(live=True)
            detail = platform.get_challenge(CHALLENGE_ID, live=True)
            download = platform.download_attachments(CHALLENGE_ID, live=True)
            wrong = platform.submit_flag(CHALLENGE_ID, wrong_flag(), live=True, confirm=True)
            accepted = platform.submit_flag(CHALLENGE_ID, server.correct_flag, live=True, confirm=True)
            duplicate = platform.submit_flag(CHALLENGE_ID, server.correct_flag, live=True, confirm=True)
            rendered = json.dumps(
                {
                    "discover": action_to_dict(discover),
                    "detail": action_to_dict(detail),
                    "download": action_to_dict(download),
                    "wrong": action_to_dict(wrong),
                    "accepted": action_to_dict(accepted),
                    "duplicate": action_to_dict(duplicate),
                    "server_log": server.request_log,
                    "submission_log": server.submission_log,
                },
                sort_keys=True,
            )
            raw_leaked = any(flag in rendered for flag in [*server.correct_flags, wrong_flag(), fake_decoy_flag()])
            return {
                "status": "ok"
                if (
                    discover.status == "ok"
                    and discover.details.get("challenge_count") == len(server.fixtures)
                    and detail.status == "ok"
                    and download.status == "ok"
                    and wrong.status == "rejected"
                    and accepted.status == "accepted"
                    and duplicate.status == "accepted"
                    and not raw_leaked
                )
                else "error",
                "server": server.public_info(),
                "discover": action_to_dict(discover),
                "detail": action_to_dict(detail),
                "download": action_to_dict(download),
                "wrong_submit_status": wrong.status,
                "accepted_submit_status": accepted.status,
                "duplicate_submit_status": duplicate.status,
                "raw_leak_detected": raw_leaked,
                "request_log": server.request_log,
                "downloads_root": str(Path(root).expanduser()),
            }
    finally:
        if temp_ctx is not None:
            temp_ctx.cleanup()
