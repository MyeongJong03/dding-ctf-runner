import contextlib
import io
import json
from pathlib import Path

from ctf_runner.cli import main
from ctf_runner.platform_base import PlatformAction
from ctf_runner.public_check import run_public_check


def test_interactive_init_creates_files_idempotently(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))

    first = _run_json(["interactive", "init", "--contest-id", "demo", "--agents", "4", "--json"])
    second = _run_json(["interactive", "init", "--contest-id", "demo", "--agents", "4", "--json"])

    root = tmp_path / "contests" / "demo" / "operator"
    assert first["status"] == "ok"
    assert second["status"] == "ok"
    for name in ["BOARD.md", "board.json", "solved.jsonl", "external_solved.txt", "stalled.jsonl"]:
        assert (root / name).exists()
    assert (root / "claims").is_dir()
    assert (root / "memos").is_dir()


def test_interactive_init_lock_idempotent(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))
    root = tmp_path / "contests" / "demo" / "operator"
    root.mkdir(parents=True)
    (root / ".init.lock").write_text("{}", encoding="utf-8")

    result = _run_json(["interactive", "init", "--contest-id", "demo", "--json"])

    assert result["status"] == "ok"
    assert (root / "board.json").exists()
    assert (root / ".init.lock").exists()


def test_claim_prevents_and_allows_duplicate(tmp_path: Path, monkeypatch):
    _seed_board(tmp_path, monkeypatch)

    first = _run_json(["interactive", "claim", "--contest-id", "demo", "--agent", "a1", "--json"])
    duplicate = _run_json_fail(["interactive", "claim", "--contest-id", "demo", "--agent", "a2", "--challenge", "Birdhouse", "--json"])
    allowed = _run_json(["interactive", "claim", "--contest-id", "demo", "--agent", "a2", "--challenge", "Birdhouse", "--allow-duplicate", "--json"])

    assert first["status"] == "claimed"
    assert duplicate["status"] == "blocked"
    assert duplicate["reason"] == "already_claimed_on_this_machine"
    assert allowed["status"] == "claimed"


def test_external_solved_prevents_future_claim(tmp_path: Path, monkeypatch):
    _seed_board(tmp_path, monkeypatch)

    marked = _run_json(["interactive", "external-solved", "--contest-id", "demo", "--challenge", "Birdhouse", "--json"])
    claim = _run_json(["interactive", "claim", "--contest-id", "demo", "--agent", "a1", "--json"])

    assert marked["status"] == "ok"
    assert claim["status"] == "empty"


def test_interactive_sync_marks_static_aliases_not_default_targets(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))
    profile = tmp_path / "profile.yaml"
    profile.write_text("name: demo\n", encoding="utf-8")
    monkeypatch.setattr("ctf_runner.interactive.load_platform_adapter", lambda profile: FakeSyncPlatform())

    result = _run_json(["interactive", "sync", "--contest-id", "demo", "--profile", str(profile), "--live", "--json"])
    claim = _run_json(["interactive", "claim", "--contest-id", "demo", "--agent", "a1", "--json"])

    assert result["status"] == "ok"
    assert result["target_count"] == 1
    assert result["alias_count"] == 1
    assert result["canonical_map"]["birdhouse-static"] == "birdhouse"
    assert claim["challenge_id"] == "birdhouse"


def test_stalled_records_note_and_releases_claim(tmp_path: Path, monkeypatch):
    _seed_board(tmp_path, monkeypatch)
    _run_json(["interactive", "claim", "--contest-id", "demo", "--agent", "a1", "--json"])

    stalled = _run_json(
        ["interactive", "stalled", "--contest-id", "demo", "--agent", "a1", "--challenge", "Birdhouse", "--reason", "need new idea", "--json"]
    )
    root = tmp_path / "contests" / "demo" / "operator"

    assert stalled["status"] == "stalled"
    assert not list((root / "claims").glob("*.lock"))
    assert "need new idea" in (tmp_path / "contests" / "demo" / "misc" / "Birdhouse" / "operator_notes.md").read_text(encoding="utf-8")


def test_submit_accepted_updates_solved_without_raw_flag(tmp_path: Path, monkeypatch):
    _seed_board(tmp_path, monkeypatch, profile=tmp_path / "profile.yaml")
    monkeypatch.setattr("ctf_runner.interactive.load_platform_adapter", lambda profile: FakeAcceptedPlatform())
    flag_path = tmp_path / "flag.txt"
    raw_flag = "FLAG{unit_verified_value}"
    flag_path.write_text(raw_flag, encoding="utf-8")

    result, output = _run_json_with_output(
        ["interactive", "submit", "--contest-id", "demo", "--challenge-id", "birdhouse", "--flag-file", str(flag_path), "--confirm", "--json"]
    )

    assert result["status"] == "accepted"
    assert result["flag_hash"]
    assert raw_flag not in output
    solved = (tmp_path / "contests" / "demo" / "operator" / "solved.jsonl").read_text(encoding="utf-8")
    assert "accepted" in solved
    assert raw_flag not in solved


def test_writeup_refuses_unsolved_and_creates_ko_en_with_code_for_accepted(tmp_path: Path, monkeypatch):
    _seed_board(tmp_path, monkeypatch)
    blocked = _run_json_fail(["interactive", "writeup", "--contest-id", "demo", "--challenge-id", "birdhouse", "--category", "misc", "--json"])
    assert blocked["reason"] == "accepted_solve_required"

    root = tmp_path / "contests" / "demo"
    operator = root / "operator"
    _append_jsonl(operator / "solved.jsonl", {"challenge_id": "birdhouse", "status": "accepted", "flag_hash": "abc", "timestamp": "now"})
    solver = root / "misc" / "Birdhouse" / "solver.py"
    solver.parent.mkdir(parents=True, exist_ok=True)
    solver.write_text("print('solved')\n", encoding="utf-8")

    result = _run_json(["interactive", "writeup", "--contest-id", "demo", "--challenge-id", "birdhouse", "--category", "misc", "--include-code", "--json"])

    assert result["status"] == "ok"
    ko = Path(result["files"]["ko"].replace("~", str(Path.home()), 1))
    en = Path(result["files"]["en"].replace("~", str(Path.home()), 1))
    assert ko.exists()
    assert en.exists()
    assert "```python\nprint('solved')\n```" in ko.read_text(encoding="utf-8")
    assert "```python\nprint('solved')\n```" in en.read_text(encoding="utf-8")


def test_cleanup_keeps_final_artifacts_and_removes_safe_temp(tmp_path: Path, monkeypatch):
    _seed_board(tmp_path, monkeypatch)
    challenge = tmp_path / "contests" / "demo" / "misc" / "Birdhouse"
    challenge.mkdir(parents=True, exist_ok=True)
    (challenge / "solver.py").write_text("print('keep')\n", encoding="utf-8")
    (challenge / "run.log").write_text("remove\n", encoding="utf-8")
    cache = challenge / "__pycache__"
    cache.mkdir()
    (cache / "x.pyc").write_bytes(b"x")

    result = _run_json(["interactive", "cleanup", "--contest-id", "demo", "--challenge-id", "birdhouse", "--safe", "--json"])

    assert result["status"] == "ok"
    assert (challenge / "solver.py").exists()
    assert not (challenge / "run.log").exists()
    assert not cache.exists()


def test_public_check_ignores_untracked_operator_runtime_files(tmp_path: Path):
    from tests.test_public_check import _required_tracked_files, _write_required_public_files

    _write_required_public_files(tmp_path)
    result = run_public_check(
        repo=tmp_path,
        include_preflight=False,
        tracked_files=_required_tracked_files(),
        untracked_files=["contests/demo/operator/board.json"],
    )

    assert result["status"] == "ok"
    assert result["untracked_runtime_paths"] == []


class FakeAcceptedPlatform:
    policy = {"allow_submission": True}

    def submit_flag(self, challenge_id: str, flag: str, live: bool = False, confirm: bool = False) -> PlatformAction:
        return PlatformAction(
            action="submit_flag",
            live=live,
            network=True,
            status="accepted",
            details={"challenge_id": challenge_id, "flag_hash": "fakehash", "result_summary_redacted": {"status": "correct"}},
        )


class FakeSyncPlatform:
    def discover_challenges(self, live: bool = False) -> PlatformAction:
        return PlatformAction(
            action="discover_challenges",
            live=live,
            network=live,
            status="ok",
            details={
                "challenges": [
                    {"challenge_id": "birdhouse", "name": "Birdhouse", "category": "web", "statement": "Real challenge statement"},
                    {"challenge_id": "birdhouse-static", "name": "birdhouse-static", "category": "web", "statement": "favicon css"},
                ]
            },
        )


def _seed_board(tmp_path: Path, monkeypatch, profile: Path | None = None) -> None:
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))
    args = ["interactive", "init", "--contest-id", "demo", "--json"]
    if profile:
        profile.write_text("name: demo\n", encoding="utf-8")
        args.extend(["--profile", str(profile)])
    _run_json(args)
    board = tmp_path / "contests" / "demo" / "operator" / "board.json"
    board.write_text(
        json.dumps(
            {
                "contest_id": "demo",
                "challenges": [
                    {
                        "challenge_id": "birdhouse",
                        "name": "Birdhouse",
                        "category": "misc",
                        "status": "todo",
                        "priority": 100,
                        "path": str(tmp_path / "contests" / "demo" / "misc" / "Birdhouse"),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def _run_json(argv: list[str]) -> dict:
    result, output, code = _run(argv)
    assert code == 0, output
    return result


def _run_json_fail(argv: list[str]) -> dict:
    result, output, code = _run(argv)
    assert code != 0, output
    return result


def _run_json_with_output(argv: list[str]) -> tuple[dict, str]:
    result, output, code = _run(argv)
    assert code == 0, output
    return result, output


def _run(argv: list[str]) -> tuple[dict, str, int]:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = main(argv)
    output = buffer.getvalue()
    return json.loads(output), output, code


def _append_jsonl(path: Path, payload: dict) -> None:
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, sort_keys=True))
        fh.write("\n")
