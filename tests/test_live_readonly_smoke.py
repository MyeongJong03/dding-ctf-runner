import contextlib
import io
import json
import urllib.parse
from pathlib import Path
from typing import Any

from ctf_runner.cli import main
from ctf_runner.fake_ctfd import CHALLENGE_ID, FakeCTFdServer


def test_live_readonly_smoke_discovers_downloads_ingests_without_submit(tmp_path: Path):
    secret_path = tmp_path / "ctfd.cookie"
    raw_cookie = "session=raw-live-readonly-cookie"
    secret_path.write_text(raw_cookie, encoding="utf-8")
    config_path = tmp_path / "platform.local.yaml"
    output_chunks: list[str] = []

    with FakeCTFdServer() as server:
        original_detail = server.challenge_detail

        def signed_detail(challenge_id: str) -> dict[str, Any] | None:
            detail = original_detail(challenge_id)
            if detail and str(challenge_id) == CHALLENGE_ID:
                filename = detail["files"][0]["name"]
                detail["files"] = [
                    {
                        "name": filename,
                        "url": f"/files/{urllib.parse.quote(filename)}?token=signed-download-token",
                    }
                ]
            return detail

        server.challenge_detail = signed_detail  # type: ignore[method-assign]
        config_path.write_text(
            "\n".join(
                [
                    "platform: ctfd",
                    "name: fake_ctfd",
                    f"base_url: {server.base_url}",
                    "auth:",
                    "  method: cookie_header_file",
                    f"  path: {secret_path}",
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

        result = _run_json(
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

        rendered = "\n".join(output_chunks)
        assert result["status"] == "ok"
        assert result["discovered_count"] == len(server.fixtures)
        assert result["selected_challenge_id"] == CHALLENGE_ID
        assert result["downloaded_count"] == 1
        assert result["ingest_status"] == "ok"
        assert Path(result["ingest_brief_path"].replace("~/", str(Path.home()) + "/", 1)).exists()
        assert result["state_saved"] == "yes"
        assert server.submission_log == []
        assert not any("/api/v1/challenges/attempt" in item for item in server.request_log)
        assert not any("instance" in item.lower() for item in server.request_log)
        assert "signed-download-token" not in rendered
        assert "?token=" not in rendered
        assert raw_cookie not in rendered


def _run_json(argv: list[str], output_chunks: list[str]) -> dict:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = main(argv)
    output = buffer.getvalue()
    output_chunks.append(output)
    assert code == 0, output
    return json.loads(output)
