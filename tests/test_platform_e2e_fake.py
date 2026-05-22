import contextlib
import io
import json
from pathlib import Path

from ctf_runner.cli import main
from ctf_runner.fake_ctfd import CHALLENGE_ID, FakeCTFdServer, platform_config
from ctf_runner.state import get_challenge_state


def test_platform_cli_discover_download_ingest_fake_ctfd(tmp_path: Path):
    db = tmp_path / "queue.sqlite3"
    config_path = tmp_path / "platform.json"
    output_chunks: list[str] = []

    with FakeCTFdServer() as server:
        config_path.write_text(json.dumps(platform_config(server.base_url, tmp_path / "contests")), encoding="utf-8")

        discover = _run_json(
            [
                "--db",
                str(db),
                "platform",
                "discover",
                "--config",
                str(config_path),
                "--live",
                "--save-state",
                "--json",
            ],
            output_chunks,
        )
        detail = _run_json(
            ["--db", str(db), "platform", "get", "--config", str(config_path), "--challenge-id", CHALLENGE_ID, "--live", "--json"],
            output_chunks,
        )
        download = _run_json(
            [
                "--db",
                str(db),
                "platform",
                "download",
                "--config",
                str(config_path),
                "--challenge-id",
                CHALLENGE_ID,
                "--live",
                "--json",
            ],
            output_chunks,
        )
        ingest = _run_json(
            [
                "--db",
                str(db),
                "platform",
                "ingest",
                "--config",
                str(config_path),
                "--challenge-id",
                CHALLENGE_ID,
                "--name",
                "Local Codex Smoke",
                "--category",
                "misc",
                "--live",
                "--json",
            ],
            output_chunks,
        )

        assert discover["status"] == "ok"
        assert discover["details"]["state_save"]["count"] == len(server.fixtures)
        assert detail["status"] == "ok"
        assert download["status"] == "ok"
        assert Path(download["details"]["downloads"][0]["fs_path"]).exists()
        assert ingest["ingest"]["status"] == "ok"
        assert Path(ingest["ingest"]["brief_path"].replace("~/", str(Path.home()) + "/", 1)).exists()
        assert get_challenge_state(CHALLENGE_ID, db)["status"] == "ingest_ready"

        rendered = "\n".join(output_chunks)
        assert server.correct_flag not in rendered
        assert "127.0.0.1" in rendered


def _run_json(argv: list[str], output_chunks: list[str]) -> dict:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = main(argv)
    output = buffer.getvalue()
    output_chunks.append(output)
    assert code == 0, output
    return json.loads(output)
