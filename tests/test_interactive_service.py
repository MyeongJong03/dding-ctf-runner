import contextlib
import io
import json
import shutil
import socket
import ssl
import subprocess
import threading
from pathlib import Path

import pytest

from ctf_runner.cli import main


def test_service_config_stores_endpoint_without_token_value(tmp_path: Path, monkeypatch):
    root, _challenge = _seed_service_board(tmp_path, monkeypatch, "svc-config")
    token_file = tmp_path / "team-token.txt"
    secret = "SERVICE_TOKEN_UNIT_SECRET"
    token_file.write_text(secret, encoding="utf-8")

    result = _run_json(
        [
            "interactive",
            "service-config",
            "--contest-id",
            "svc-config",
            "--challenge-id",
            "remote",
            "--host",
            "127.0.0.1",
            "--port",
            "31337",
            "--plain",
            "--token-source",
            "file",
            "--token-file",
            str(token_file),
            "--json",
        ]
    )

    operator_text = (root / "operator" / "operator.json").read_text(encoding="utf-8")
    board_text = (root / "operator" / "board.json").read_text(encoding="utf-8")
    operator = json.loads(operator_text)
    status = _run_json(["interactive", "service-status", "--contest-id", "svc-config", "--challenge-id", "remote", "--json"])

    assert result["status"] == "ok"
    assert secret not in operator_text
    assert secret not in board_text
    metadata = operator["challenge_service_metadata"]["remote"]
    assert metadata["endpoint"]["host"] == "127.0.0.1"
    assert metadata["endpoint"]["port"] == 31337
    assert metadata["endpoint"]["transport"] == "plain"
    assert metadata["token_source"]["type"] == "file"
    assert metadata["token_source"]["file"] == str(token_file)
    assert status["status"] == "ok"
    assert status["endpoint"]["transport"] == "plain"
    assert status["token_source_present"] is True
    assert status["pow_helper_present"] is False


def test_service_probe_detects_banner_from_local_tcp_service(tmp_path: Path, monkeypatch):
    root, _challenge = _seed_service_board(tmp_path, monkeypatch, "svc-probe")
    with OneShotService(lambda conn: conn.sendall(b"hello service\nchoice> ")) as service:
        _run_json(
            [
                "interactive",
                "service-config",
                "--contest-id",
                "svc-probe",
                "--challenge-id",
                "remote",
                "--host",
                service.host,
                "--port",
                str(service.port),
                "--plain",
                "--json",
            ]
        )
        result = _run_json(["interactive", "service-probe", "--contest-id", "svc-probe", "--challenge-id", "remote", "--timeout", "3", "--json"])

    probe_path = Path(result["probe_path"])
    events = (root / "operator" / "metrics" / "events.jsonl").read_text(encoding="utf-8")

    assert result["status"] == "ok"
    assert "hello service" in result["banner"]
    assert result["prompts"]["menu_prompt"] is True
    assert probe_path.exists()
    assert "hello service" in probe_path.read_text(encoding="utf-8")
    assert "service_probe_completed" in events


def test_service_probe_detects_banner_from_local_tls_service(tmp_path: Path, monkeypatch):
    cert, key = _make_self_signed_cert(tmp_path)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert, keyfile=key)
    _seed_service_board(tmp_path, monkeypatch, "svc-tls")

    with OneShotService(lambda conn: conn.sendall(b"tls hello\n> "), tls_context=context) as service:
        _run_json(
            [
                "interactive",
                "service-config",
                "--contest-id",
                "svc-tls",
                "--challenge-id",
                "remote",
                "--host",
                service.host,
                "--port",
                str(service.port),
                "--tls",
                "--json",
            ]
        )
        result = _run_json(["interactive", "service-probe", "--contest-id", "svc-tls", "--challenge-id", "remote", "--timeout", "3", "--json"])

    assert result["status"] == "ok"
    assert result["transport"] == "tls"
    assert result["connector"] == "python_ssl"
    assert "tls hello" in result["banner"]


def test_service_attempt_injects_token_and_records_sanitized_transcript(tmp_path: Path, monkeypatch):
    root, challenge = _seed_service_board(tmp_path, monkeypatch, "svc-attempt")
    token_file = tmp_path / "team-token.txt"
    secret = "SERVICE_TOKEN_ATTEMPT_SECRET"
    token_file.write_text(secret, encoding="utf-8")
    raw_candidate = "FLAG{unit_service_candidate}"
    received: list[str] = []

    def handler(conn: socket.socket):
        conn.sendall(b"Team token: ")
        token = _recv_line(conn)
        received.append(token)
        conn.sendall(f"accepted token {token}\n{raw_candidate}\n".encode("utf-8"))

    with OneShotService(handler) as service:
        _run_json(
            [
                "interactive",
                "service-config",
                "--contest-id",
                "svc-attempt",
                "--challenge-id",
                "remote",
                "--host",
                service.host,
                "--port",
                str(service.port),
                "--plain",
                "--token-source",
                "file",
                "--token-file",
                str(token_file),
                "--json",
            ]
        )
        result, output = _run_json_with_output(["interactive", "service-attempt", "--contest-id", "svc-attempt", "--challenge-id", "remote", "--timeout", "5", "--json"])

    attempt_path = Path(result["attempt_path"])
    attempt_text = attempt_path.read_text(encoding="utf-8")
    candidates = (challenge / "candidates.jsonl").read_text(encoding="utf-8")
    events = (root / "operator" / "metrics" / "events.jsonl").read_text(encoding="utf-8")

    assert result["status"] == "ok"
    assert received == [secret]
    assert result["token_injected"] is True
    assert secret not in output
    assert secret not in attempt_text
    assert "[REDACTED_SERVICE_SECRET]" in attempt_text
    assert raw_candidate in result["transcript"]
    assert raw_candidate in candidates
    assert "service_token_prompt_detected" in events
    assert "service_attempt_completed" in events
    assert "service_candidate_found" in events


def test_public_snapshot_excludes_service_token_transcript_and_raw_candidate(tmp_path: Path, monkeypatch):
    _seed_service_board(tmp_path, monkeypatch, "svc-public")
    token_file = tmp_path / "team-token.txt"
    secret = "SERVICE_TOKEN_PUBLIC_SECRET"
    token_file.write_text(secret, encoding="utf-8")
    raw_candidate = "FLAG{unit_service_public_candidate}"

    def handler(conn: socket.socket):
        conn.sendall(b"token: ")
        _recv_line(conn)
        conn.sendall(f"{raw_candidate}\n".encode("utf-8"))

    with OneShotService(handler) as service:
        _run_json(
            [
                "interactive",
                "service-config",
                "--contest-id",
                "svc-public",
                "--challenge-id",
                "remote",
                "--host",
                service.host,
                "--port",
                str(service.port),
                "--plain",
                "--token-source",
                "file",
                "--token-file",
                str(token_file),
                "--json",
            ]
        )
        _run_json(["interactive", "service-attempt", "--contest-id", "svc-public", "--challenge-id", "remote", "--json"])

    snapshot_root = tmp_path / "public" / "svc-public"
    snapshot = _run_json(
        [
            "interactive",
            "metrics",
            "publish-snapshot",
            "--contest-id",
            "svc-public",
            "--output-root",
            str(snapshot_root),
            "--contest-ended",
            "--json",
        ]
    )
    combined = "\n".join(path.read_text(encoding="utf-8") for path in snapshot_root.glob("*.public.*"))

    assert snapshot["public_safe"] is True
    assert secret not in combined
    assert raw_candidate not in combined
    assert "unit_service_public_candidate" not in combined
    assert "flag_hash" in combined


def test_target_pack_includes_service_metadata_and_probe_command(tmp_path: Path, monkeypatch):
    _seed_service_board(tmp_path, monkeypatch, "svc-pack")
    _run_json(
        [
            "interactive",
            "service-config",
            "--contest-id",
            "svc-pack",
            "--challenge-id",
            "remote",
            "--host",
            "127.0.0.1",
            "--port",
            "31337",
            "--plain",
            "--json",
        ]
    )

    result = _run_json(["interactive", "target-pack", "--contest-id", "svc-pack", "--challenge-id", "remote", "--json"])
    text = Path(result["target_pack_path"]).read_text(encoding="utf-8")

    assert result["status"] == "ok"
    assert "## Remote Service" in text
    assert "host: 127.0.0.1" in text
    assert "transport: plain" in text
    assert "service-probe --contest-id svc-pack --challenge-id remote --json" in text


def test_solve_loop_uses_service_attempt_for_configured_service(tmp_path: Path, monkeypatch):
    root, challenge = _seed_service_board(tmp_path, monkeypatch, "svc-loop")
    (challenge / "solve_misc.py").write_text("print('solve')\n", encoding="utf-8")
    raw_candidate = "FLAG{unit_service_loop_candidate}"

    def handler(conn: socket.socket):
        conn.sendall(b"payload> ")
        payload = _recv_line(conn)
        if payload == "solve":
            conn.sendall(f"{raw_candidate}\n".encode("utf-8"))
        else:
            conn.sendall(b"nope\n")

    with OneShotService(handler) as service:
        _run_json(
            [
                "interactive",
                "service-config",
                "--contest-id",
                "svc-loop",
                "--challenge-id",
                "remote",
                "--host",
                service.host,
                "--port",
                str(service.port),
                "--plain",
                "--json",
            ]
        )
        result = _run_json(
            [
                "interactive",
                "solve-loop",
                "--contest-id",
                "svc-loop",
                "--agent",
                "a1",
                "--challenge-id",
                "remote",
                "--max-attempts",
                "1",
                "--json",
            ]
        )

    events = (root / "operator" / "metrics" / "events.jsonl").read_text(encoding="utf-8")

    assert result["status"] == "submit_planned"
    assert result["attempts"][0]["attempt_kind"] == "service"
    assert raw_candidate in result["attempts"][0]["transcript"]
    assert "service_attempt_completed" in events


class OneShotService:
    def __init__(self, handler, tls_context: ssl.SSLContext | None = None):
        self.handler = handler
        self.tls_context = tls_context
        self.host = "127.0.0.1"
        self.port = 0
        self._thread: threading.Thread | None = None
        self._server: socket.socket | None = None
        self._ready = threading.Event()
        self.error: BaseException | None = None

    def __enter__(self):
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((self.host, 0))
        self._server.listen(1)
        self.port = int(self._server.getsockname()[1])
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        self._ready.wait(timeout=2)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2)
        if self.error and exc is None:
            raise self.error

    def _serve(self):
        assert self._server is not None
        self._ready.set()
        try:
            conn, _addr = self._server.accept()
            with conn:
                active = self.tls_context.wrap_socket(conn, server_side=True) if self.tls_context else conn
                with active:
                    self.handler(active)
        except OSError:
            pass
        except BaseException as exc:  # pragma: no cover - surfaced in __exit__.
            self.error = exc


def _recv_line(conn: socket.socket) -> str:
    data = bytearray()
    while not data.endswith(b"\n"):
        chunk = conn.recv(1)
        if not chunk:
            break
        data.extend(chunk)
    return data.decode("utf-8", errors="replace").strip()


def _make_self_signed_cert(tmp_path: Path) -> tuple[str, str]:
    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("openssl is required to generate a local TLS test certificate")
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    completed = subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        pytest.skip("openssl could not generate a local TLS test certificate")
    return str(cert), str(key)


def _seed_service_board(tmp_path: Path, monkeypatch, contest_id: str) -> tuple[Path, Path]:
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))
    _run_json(["interactive", "init", "--contest-id", contest_id, "--json"])
    root = tmp_path / "contests" / contest_id
    challenge = root / "misc" / "Remote"
    challenge.mkdir(parents=True, exist_ok=True)
    (challenge / "brief.md").write_text("# Remote\nConnect with nc 127.0.0.1 31337.\n", encoding="utf-8")
    for name in ["memory.md", "evidence.md", "attempts.md", "next_steps.md", "operator_notes.md"]:
        (challenge / name).write_text(f"# {name}\n", encoding="utf-8")
    board = {
        "contest_id": contest_id,
        "updated_at": "now",
        "challenges": [
            {
                "challenge_id": "remote",
                "name": "Remote",
                "canonical_id": "remote",
                "canonical_name": "Remote",
                "category": "misc",
                "status": "todo",
                "path": str(challenge),
                "connection_info": "nc 127.0.0.1 31337",
            }
        ],
    }
    (root / "operator" / "board.json").write_text(json.dumps(board), encoding="utf-8")
    return root, challenge


def _run_json(argv: list[str]) -> dict:
    result, _output = _run_json_with_output(argv)
    return result


def _run_json_with_output(argv: list[str]) -> tuple[dict, str]:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = main(argv)
    output = buffer.getvalue()
    assert code == 0, output
    return json.loads(output), output
