from pathlib import Path

from ctf_runner.public_check import run_public_check


def test_public_check_detects_tracked_sensitive_file(tmp_path: Path):
    _write_required_public_files(tmp_path)
    (tmp_path / "auth.json").write_text("{}", encoding="utf-8")

    result = run_public_check(
        repo=tmp_path,
        include_preflight=False,
        tracked_files=["README.md", "GUIDE.md", "auth.json"],
        untracked_files=[],
    )

    assert result["status"] == "blocked"
    assert "tracked_sensitive_paths" in result["high"]
    assert result["tracked_sensitive_paths"] == ["auth.json"]


def test_public_check_docs_and_gitignore_coverage_ok(tmp_path: Path):
    _write_required_public_files(tmp_path)

    result = run_public_check(
        repo=tmp_path,
        include_preflight=False,
        tracked_files=_required_tracked_files(),
        untracked_files=[],
    )

    assert result["status"] == "ok"
    assert result["required"]["missing"] == []
    assert result["gitignore"]["missing_patterns"] == []
    assert result["repo_local_forbidden_paths"] == []
    assert result["uv_lock"]["policy_ok"] is True
    assert result["release_commands"]["missing"] == []
    assert "mock_full_rehearsal" in result["test_commands"]
    assert "fresh_clone_check" in result["test_commands"]


def test_public_check_requires_operations_doc(tmp_path: Path):
    _write_required_public_files(tmp_path)
    (tmp_path / "OPERATIONS.md").unlink()

    result = run_public_check(
        repo=tmp_path,
        include_preflight=False,
        tracked_files=[path for path in _required_tracked_files() if path != "OPERATIONS.md"],
        untracked_files=[],
    )

    assert result["status"] == "blocked"
    assert "required_docs_missing" in result["high"]
    assert "OPERATIONS.md" in result["required"]["missing"]


def test_public_check_secret_like_content_blocks_non_fixture_file(tmp_path: Path):
    _write_required_public_files(tmp_path)
    app = tmp_path / "notes" / "unsafe_note.py"
    app.parent.mkdir()
    app.write_text("value = 'FLAG' + '{' + 'not_raw_but_safe' + '}'\n", encoding="utf-8")
    raw = tmp_path / "notes" / "raw_note.txt"
    raw.write_text("candidate=" + _flag_like("FLAG", "unit_secret_value") + "\n", encoding="utf-8")

    result = run_public_check(
        repo=tmp_path,
        include_preflight=False,
        tracked_files=[*_required_tracked_files(), "notes/unsafe_note.py", "notes/raw_note.txt"],
        untracked_files=[],
    )

    assert result["status"] == "blocked"
    assert "tracked_secret_like_content" in result["high"]
    assert result["content_findings"] == [{"path": "notes/raw_note.txt", "reason": "secret_like_content"}]


def test_public_check_blocks_repo_local_runtime_even_when_ignored(tmp_path: Path):
    _write_required_public_files(tmp_path)
    (tmp_path / "state").mkdir()

    result = run_public_check(
        repo=tmp_path,
        include_preflight=False,
        tracked_files=_required_tracked_files(),
        untracked_files=[],
    )

    assert result["status"] == "blocked"
    assert "repo_local_forbidden_paths" in result["high"]
    assert result["repo_local_forbidden_paths"] == ["state"]


def test_public_check_blocks_untracked_sensitive_file(tmp_path: Path):
    _write_required_public_files(tmp_path)

    result = run_public_check(
        repo=tmp_path,
        include_preflight=False,
        tracked_files=_required_tracked_files(),
        untracked_files=["queue.sqlite3"],
    )

    assert result["status"] == "blocked"
    assert "untracked_sensitive_paths" in result["high"]
    assert result["untracked_sensitive_paths"] == ["queue.sqlite3"]


def test_public_check_blocks_public_doc_flag_like_literal(tmp_path: Path):
    _write_required_public_files(tmp_path)
    raw_shape = "FLAG" + "{" + "public_doc_literal" + "}"
    (tmp_path / "docs" / "contest-operations.md").write_text(raw_shape + "\n", encoding="utf-8")

    result = run_public_check(
        repo=tmp_path,
        include_preflight=False,
        tracked_files=_required_tracked_files(),
        untracked_files=[],
    )

    assert result["status"] == "blocked"
    assert "public_docs_sensitive_content" in result["high"]
    assert result["public_doc_findings"] == [{"path": "docs/contest-operations.md", "reasons": ["flag_like_literal"]}]


def test_public_check_blocks_real_ctf_name_in_public_docs(tmp_path: Path):
    _write_required_public_files(tmp_path)
    (tmp_path / "README.md").write_text("private event: Hack" + "ForAChange\n", encoding="utf-8")

    result = run_public_check(
        repo=tmp_path,
        include_preflight=False,
        tracked_files=_required_tracked_files(),
        untracked_files=[],
    )

    assert result["status"] == "blocked"
    assert "public_docs_sensitive_content" in result["high"]
    assert result["public_doc_findings"] == [{"path": "README.md", "reasons": ["real_ctf_name"]}]


def _write_required_public_files(root: Path) -> None:
    (root / "README.md").write_text("# README\n", encoding="utf-8")
    (root / "GUIDE.md").write_text("# GUIDE\n", encoding="utf-8")
    (root / "OPERATIONS.md").write_text("# OPERATIONS\n", encoding="utf-8")
    (root / "pyproject.toml").write_text("[project]\nname = \"example\"\n", encoding="utf-8")
    (root / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    (root / ".gitignore").write_text(
        "\n".join(
            [
                "contests/",
                "state/",
                "secrets/",
                "downloads/",
                "writeups/",
                "browser-artifacts/",
                "callback-hits/",
                "callbacks/",
                "tunnels/",
                "runner-state/",
                ".codex-workers/",
                "auth.json",
                "queue.sqlite3",
                "*.local.yaml",
                "*.local.yml",
                "*.local.toml",
                ".env",
                ".env.*",
                "*.env",
                "*cookie*",
                "*token*",
                "*flag*",
                "storage_state*.json",
                "*.storage_state.json",
                "*storage_state*",
                "*.sqlite3",
                "*.db",
                "*.pem",
                "*.key",
                "",
            ]
        ),
        encoding="utf-8",
    )
    for doc in _required_docs():
        path = root / doc
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# doc\n", encoding="utf-8")
    for script in ["scripts/ctfctl", "scripts/release-check.sh", "scripts/fresh-clone-check.sh", "scripts/history-scan.sh"]:
        path = root / script
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/usr/bin/env bash\n", encoding="utf-8")
        path.chmod(0o755)


def _required_docs() -> list[str]:
    return [
        "docs/setup-windows-wsl.md",
        "docs/setup-macos.md",
        "docs/architecture.md",
        "docs/platform-automation.md",
        "docs/worker-loop.md",
        "docs/contest-operations.md",
        "docs/callbacks.md",
        "docs/postsolve.md",
        "docs/threat-model.md",
        "docs/ingest.md",
    ]


def _required_tracked_files() -> list[str]:
    return ["README.md", "GUIDE.md", "OPERATIONS.md", "pyproject.toml", "uv.lock", ".gitignore", *_required_docs()]


def _flag_like(prefix: str, body: str) -> str:
    return prefix + "{" + body + "}"
