from __future__ import annotations

import fnmatch
import re
import subprocess
from pathlib import Path
from urllib.parse import urlparse
from typing import Any, Iterable, Sequence

from .paths import repo_root
from .preflight import collect_preflight
from .redact import redact_text


RUNTIME_PATHS = (
    "contests",
    "state",
    "secrets",
    "run",
    "work",
    "downloads",
    "generated",
    "browser-artifacts",
    "callback-hits",
    "callbacks",
    "tunnels",
    "runner-state",
    "writeups",
    ".codex-workers",
)

SENSITIVE_GLOBS = (
    "auth.json",
    "*.local.yaml",
    "*.local.yml",
    "*.local.toml",
    ".env",
    ".env.*",
    "*.env",
    "*.cookies",
    "*cookie*",
    "*token*",
    "*flag*",
    "storage_state*.json",
    "*.storage_state.json",
    "*storage_state*",
    "queue.sqlite3",
    "*.sqlite3",
    "*.db",
    "*.pem",
    "*.key",
)

REQUIRED_FILES = (
    "README.md",
    "GUIDE.md",
    "OPERATIONS.md",
    "pyproject.toml",
    "uv.lock",
    ".gitignore",
)

REQUIRED_DOCS = (
    "docs/setup-windows-wsl.md",
    "docs/setup-macos.md",
    "docs/architecture.md",
    "docs/platform-automation.md",
    "docs/worker-loop.md",
    "docs/interactive-operations.md",
    "docs/contest-operations.md",
    "docs/callbacks.md",
    "docs/postsolve.md",
    "docs/threat-model.md",
    "docs/ingest.md",
    "docs/prompt-templates.ko.md",
)

EXPECTED_GITIGNORE_PATTERNS = (
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
    "*cookie*",
    "*token*",
    "*flag*",
    "storage_state*.json",
    "*.storage_state.json",
    "*storage_state*",
    "*.sqlite3",
    "*.db",
    ".env",
    ".env.*",
    "*.env",
    "*.pem",
    "*.key",
)

REQUIRED_RELEASE_SCRIPTS = (
    "scripts/ctfctl",
    "scripts/release-check.sh",
    "scripts/fresh-clone-check.sh",
    "scripts/history-scan.sh",
)

CONTENT_SECRET_RE = re.compile(
    rb"([A-Za-z0-9_]{2,32}\{[^{}\s]{4,256}\}|Bearer\s+[A-Za-z0-9._~+/=-]{8,}|"
    rb"^\s*(authorization|cookie|set-cookie)\s*:|"
    rb"\b(password|passwd|api[_-]?key|secret|session)\s*[:=]\s*['\"]?[^'\"\s,}]+)",
    re.IGNORECASE | re.MULTILINE,
)

CONTENT_ALLOW_PREFIXES = ("docs/", "tests/", "config/", "ctf_runner/", "scripts/")
CONTENT_ALLOW_FILES = (".gitignore", "README.md", "GUIDE.md", "OPERATIONS.md")

PUBLIC_DOC_FLAG_RE = re.compile(r"\b[A-Za-z0-9_]{2,32}\{[^{}\s]{4,256}\}")
REAL_CTF_DOC_RE = re.compile(r"\b(hack\s*for\s*a\s*change|hackforachange|h4c)\b", re.IGNORECASE)
DOC_URL_RE = re.compile(r"https?://[^\s)>'\"]+")
ALLOWED_PUBLIC_DOC_HOSTS = {
    "ctf.example.com",
    "example.com",
    "example.invalid",
    "pkg.cloudflare.com",
}
IGNORED_EXISTING_DIRS = {
    ".git",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "dist",
    "build",
    "htmlcov",
    ".playwright",
    "playwright-report",
    "test-results",
}


def run_public_check(
    *,
    repo: str | Path | None = None,
    include_preflight: bool = True,
    tracked_files: Sequence[str] | None = None,
    untracked_files: Sequence[str] | None = None,
) -> dict[str, Any]:
    root = Path(repo).expanduser().resolve() if repo else repo_root()
    tracked = list(tracked_files) if tracked_files is not None else _git_files(root, ["ls-files"])
    untracked = list(untracked_files) if untracked_files is not None else _git_files(root, ["ls-files", "-o", "--exclude-standard"])

    docs = _required_status(root, [*REQUIRED_FILES, *REQUIRED_DOCS])
    gitignore = _gitignore_status(root)
    uv_lock = _uv_lock_policy(root, tracked)
    release_commands = _release_command_status(root)
    tracked_sensitive = _sensitive_paths(tracked)
    untracked_sensitive = _sensitive_paths(untracked)
    tracked_runtime = [path for path in tracked if _runtime_path(path)]
    untracked_runtime = [path for path in untracked if _runtime_path(path) and not _operator_runtime_path(path)]
    existing_runtime = _existing_runtime_paths(root)
    ignored_runtime = _ignored_runtime_status(root, existing_runtime)
    repo_local_forbidden = _existing_forbidden_paths(root)
    content_findings = _content_findings(root, tracked)
    public_doc_findings = _public_doc_findings(root, tracked)

    preflight_summary = None
    if include_preflight:
        preflight = collect_preflight(deep=False)
        risk = preflight.get("risk") or {}
        preflight_summary = {
            "High": list(risk.get("High") or []),
            "Medium": list(risk.get("Medium") or []),
            "Low": list(risk.get("Low") or []),
            "Info": list(risk.get("Info") or []),
            "repo_under_mnt_c": bool(((preflight.get("paths") or {}).get("repo_under_mnt_c"))),
        }

    high: list[str] = []
    if tracked_sensitive:
        high.append("tracked_sensitive_paths")
    if tracked_runtime:
        high.append("tracked_runtime_paths")
    if untracked_sensitive:
        high.append("untracked_sensitive_paths")
    if untracked_runtime:
        high.append("untracked_runtime_paths")
    if repo_local_forbidden:
        high.append("repo_local_forbidden_paths")
    if docs["missing"]:
        high.append("required_docs_missing")
    if gitignore["missing_patterns"]:
        high.append("gitignore_missing_runtime_patterns")
    if not uv_lock["policy_ok"]:
        high.append("uv_lock_policy")
    if release_commands["missing"] or release_commands["not_executable"]:
        high.append("release_command_missing")
    if content_findings:
        high.append("tracked_secret_like_content")
    if public_doc_findings:
        high.append("public_docs_sensitive_content")
    if preflight_summary and preflight_summary["High"]:
        high.append("preflight_high_risk")

    warnings: list[str] = []
    if any(not item["ignored"] for item in ignored_runtime):
        warnings.append("existing_runtime_path_not_ignored")
    if untracked:
        warnings.append("untracked_files_present")

    interactive_test_commands = {
        "interactive_init": "./scripts/ctfctl interactive init --contest-id release-interactive-smoke --writeup-root /tmp/dding-ctf-runner-release-writeups --agents 2 --json",
        "interactive_e2e_smoke": "./scripts/ctfctl interactive e2e-smoke --contest-id release-interactive-e2e --agents 2 --json",
        "interactive_metrics_baseline": "./scripts/ctfctl interactive metrics baseline --name release-smoke --output-dir /tmp/dding-ctf-runner-release-metrics --json",
        "interactive_metrics_publish_snapshot_active_block": "./scripts/ctfctl interactive metrics publish-snapshot --contest-id active-contest-block-smoke --json",
        "interactive_toolchain_doctor": "./scripts/ctfctl interactive toolchain doctor --json",
        "interactive_capabilities": "./scripts/ctfctl interactive capabilities --contest-id release-interactive-smoke --json",
        "interactive_fallback": "./scripts/ctfctl interactive fallback --tool ncat --json",
        "interactive_prompt": "./scripts/ctfctl interactive prompt --contest-id release-interactive-smoke --agent smoke-1",
        "interactive_prompt_template": "./scripts/ctfctl interactive prompt-template --kind dreamhack",
        "interactive_next": "./scripts/ctfctl interactive next --contest-id release-interactive-smoke --agent smoke-1 --dry-run --json",
        "interactive_target_pack": "./scripts/ctfctl interactive target-pack --contest-id release-interactive-smoke --challenge-id <id> --agent smoke-1 --json",
        "interactive_triage": "./scripts/ctfctl interactive triage --contest-id release-interactive-smoke --challenge-id <id> --agent smoke-1 --json",
        "interactive_starter": "./scripts/ctfctl interactive starter --contest-id release-interactive-smoke --challenge-id <id> --json",
        "interactive_prepare_target": "./scripts/ctfctl interactive prepare-target --contest-id release-interactive-smoke --agent smoke-1 --challenge-id <id> --json",
        "interactive_run_attempt": "./scripts/ctfctl interactive run-attempt --contest-id release-interactive-smoke --challenge-id <id> --script <path> --json",
        "interactive_service_config": "./scripts/ctfctl interactive service-config --contest-id release-interactive-smoke --challenge-id <id> --host 127.0.0.1 --port 31337 --plain --token-source none --json",
        "interactive_service_probe": "./scripts/ctfctl interactive service-probe --contest-id release-interactive-smoke --challenge-id <id> --json",
        "interactive_service_attempt": "./scripts/ctfctl interactive service-attempt --contest-id release-interactive-smoke --challenge-id <id> --payload-file <path> --json",
        "interactive_service_status": "./scripts/ctfctl interactive service-status --contest-id release-interactive-smoke --challenge-id <id> --json",
        "interactive_web_config": "./scripts/ctfctl interactive web-config --contest-id release-interactive-smoke --challenge-id <id> --base-url http://127.0.0.1:8080 --auth-source none --json",
        "interactive_web_probe": "./scripts/ctfctl interactive web-probe --contest-id release-interactive-smoke --challenge-id <id> --json",
        "interactive_browser_probe": "./scripts/ctfctl interactive browser-probe --contest-id release-interactive-smoke --challenge-id <id> --json",
        "interactive_web_attempt": "./scripts/ctfctl interactive web-attempt --contest-id release-interactive-smoke --challenge-id <id> --script <path> --json",
        "interactive_browser_attempt": "./scripts/ctfctl interactive browser-attempt --contest-id release-interactive-smoke --challenge-id <id> --script <path> --json",
        "interactive_web_status": "./scripts/ctfctl interactive web-status --contest-id release-interactive-smoke --challenge-id <id> --json",
        "interactive_candidates": "./scripts/ctfctl interactive candidates --contest-id release-interactive-smoke --challenge-id <id> --json",
        "interactive_verify_candidate": "./scripts/ctfctl interactive verify-candidate --contest-id release-interactive-smoke --challenge-id <id> --candidate-file <path> --json",
        "interactive_solve_loop": "./scripts/ctfctl interactive solve-loop --contest-id release-interactive-smoke --agent smoke-1 --challenge-id <id> --json",
        "interactive_brief": "./scripts/ctfctl interactive brief --contest-id release-interactive-smoke --challenge-id <id> --json",
    }
    legacy_advanced_test_commands = {
        "legacy_fake_ctfd_smoke": "./scripts/ctfctl fake-ctfd smoke --json",
        "legacy_worker_local_e2e": "./scripts/ctfctl worker local-e2e --workers 3 --solver mock --fake-ctfd --json",
        "legacy_mock_full_rehearsal": "./scripts/ctfctl contest full-rehearsal --contest-id final-fake --workers 5 --solver mock --json",
        "legacy_codex_mini_rehearsal": "./scripts/ctfctl contest full-rehearsal --contest-id final-fake-codex --workers 3 --max-parallel-codex 2 --solver codex --allow-codex-call --json",
    }

    result = {
        "status": "ok" if not high else "blocked",
        "high": high,
        "warnings": warnings,
        "repo": _display_path(root),
        "tracked_file_count": len(tracked),
        "untracked_file_count": len(untracked),
        "tracked_sensitive_paths": tracked_sensitive,
        "tracked_runtime_paths": tracked_runtime,
        "untracked_sensitive_paths": untracked_sensitive,
        "untracked_runtime_paths": untracked_runtime,
        "repo_local_forbidden_paths": repo_local_forbidden,
        "required": docs,
        "gitignore": gitignore,
        "uv_lock": uv_lock,
        "release_commands": release_commands,
        "existing_runtime_paths": ignored_runtime,
        "content_findings": content_findings,
        "public_doc_findings": public_doc_findings,
        "preflight": preflight_summary,
        "interactive_test_commands": interactive_test_commands,
        "legacy_advanced_test_commands": legacy_advanced_test_commands,
        "test_commands": {
            "compileall": "python3 -m compileall -q ctf_runner",
            "pytest": "python3 -m pytest -q",
            "preflight": "./scripts/ctfctl preflight --deep --json",
            **interactive_test_commands,
            "public_check": "./scripts/ctfctl repo public-check --json",
            "release_check": "./scripts/release-check.sh",
            "fresh_clone_check": "./scripts/fresh-clone-check.sh",
            "history_scan": "./scripts/history-scan.sh",
        },
    }
    return _redact_object(result)


def _git_files(root: Path, args: list[str]) -> list[str]:
    try:
        completed = subprocess.run(["git", *args], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    except OSError:
        return []
    if completed.returncode != 0:
        return []
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


def _required_status(root: Path, paths: Sequence[str]) -> dict[str, Any]:
    existing = [path for path in paths if (root / path).exists()]
    missing = [path for path in paths if not (root / path).exists()]
    return {"existing": existing, "missing": missing}


def _gitignore_status(root: Path) -> dict[str, Any]:
    path = root / ".gitignore"
    lines = _gitignore_lines(path)
    missing = [pattern for pattern in EXPECTED_GITIGNORE_PATTERNS if pattern not in lines]
    return {"path": ".gitignore", "exists": path.exists(), "missing_patterns": missing, "expected_patterns": list(EXPECTED_GITIGNORE_PATTERNS)}


def _gitignore_lines(path: Path) -> set[str]:
    if not path.exists():
        return set()
    lines = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        item = line.strip()
        if item and not item.startswith("#"):
            lines.add(item)
    return lines


def _sensitive_paths(paths: Iterable[str]) -> list[str]:
    return [path for path in paths if _sensitive_path(path)]


def _sensitive_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    name = Path(normalized).name.lower()
    lower_path = normalized.lower()
    return any(fnmatch.fnmatch(name, pattern.lower()) or fnmatch.fnmatch(lower_path, pattern.lower()) for pattern in SENSITIVE_GLOBS)


def _runtime_path(path: str) -> bool:
    first = path.replace("\\", "/").split("/", 1)[0]
    return first in RUNTIME_PATHS


def _operator_runtime_path(path: str) -> bool:
    parts = path.replace("\\", "/").split("/")
    return len(parts) >= 4 and parts[0] == "contests" and parts[2] == "operator"


def _existing_runtime_paths(root: Path) -> list[str]:
    return [path for path in RUNTIME_PATHS if (root / path).exists()]


def _existing_forbidden_paths(root: Path) -> list[str]:
    findings: list[str] = []
    seen: set[str] = set()
    for runtime_path in RUNTIME_PATHS:
        path = root / runtime_path
        if path.exists():
            findings.append(runtime_path)
            seen.add(runtime_path)
    if not root.exists():
        return findings
    for path in _walk_public_repo(root):
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            continue
        first = rel.split("/", 1)[0]
        if rel in seen or first in seen:
            continue
        if _runtime_path(rel) or _sensitive_path(rel):
            findings.append(rel)
            seen.add(rel)
    return sorted(findings)


def _walk_public_repo(root: Path) -> Iterable[Path]:
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            name = entry.name
            if entry.is_dir():
                if name in IGNORED_EXISTING_DIRS:
                    continue
                stack.append(entry)
                continue
            yield entry


def _ignored_runtime_status(root: Path, paths: Sequence[str]) -> list[dict[str, Any]]:
    return [{"path": path, "ignored": _is_ignored(root, path)} for path in paths]


def _is_ignored(root: Path, path: str) -> bool:
    try:
        completed = subprocess.run(["git", "check-ignore", "-q", "--", path], cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        if completed.returncode in {0, 1}:
            return completed.returncode == 0
    except OSError:
        pass
    return _matches_gitignore(root / ".gitignore", path)


def _matches_gitignore(gitignore: Path, path: str) -> bool:
    lines = _gitignore_lines(gitignore)
    normalized = path.replace("\\", "/")
    name = Path(normalized).name
    for pattern in lines:
        if pattern.endswith("/") and normalized.startswith(pattern.rstrip("/") + "/") or pattern.rstrip("/") == normalized:
            return True
        if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(normalized, pattern):
            return True
    return False


def _content_findings(root: Path, paths: Sequence[str]) -> list[dict[str, Any]]:
    findings = []
    for path in paths:
        if _content_allowed(path):
            continue
        file_path = root / path
        if not file_path.is_file():
            continue
        try:
            data = file_path.read_bytes()
        except OSError:
            continue
        if b"\x00" in data[:4096]:
            continue
        if CONTENT_SECRET_RE.search(data):
            findings.append({"path": path, "reason": "secret_like_content"})
    return findings


def _public_doc_findings(root: Path, paths: Sequence[str]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path in paths:
        normalized = path.replace("\\", "/")
        if normalized not in {"README.md", "GUIDE.md", "OPERATIONS.md"} and not normalized.startswith("docs/"):
            continue
        file_path = root / normalized
        if not file_path.is_file():
            continue
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        reasons: list[str] = []
        if PUBLIC_DOC_FLAG_RE.search(text):
            reasons.append("flag_like_literal")
        if REAL_CTF_DOC_RE.search(text):
            reasons.append("real_ctf_name")
        blocked_urls = _blocked_public_doc_urls(text)
        if blocked_urls:
            reasons.append("non_generic_ctf_url")
        if reasons:
            finding: dict[str, Any] = {"path": normalized, "reasons": sorted(set(reasons))}
            if blocked_urls:
                finding["url_hosts"] = sorted(set(blocked_urls))
            findings.append(finding)
    return findings


def _blocked_public_doc_urls(text: str) -> list[str]:
    hosts: list[str] = []
    for match in DOC_URL_RE.finditer(text):
        parsed = urlparse(match.group(0))
        host = (parsed.hostname or "").lower()
        if not host or host in ALLOWED_PUBLIC_DOC_HOSTS:
            continue
        if "ctf" in host or "challenge" in host or "contest" in host:
            hosts.append(host)
    return hosts


def _uv_lock_policy(root: Path, tracked: Sequence[str]) -> dict[str, Any]:
    pyproject_exists = (root / "pyproject.toml").exists()
    lock_exists = (root / "uv.lock").exists()
    lock_tracked = "uv.lock" in set(tracked)
    return {
        "pyproject_exists": pyproject_exists,
        "uv_lock_exists": lock_exists,
        "uv_lock_tracked": lock_tracked,
        "policy_ok": pyproject_exists and lock_exists and lock_tracked,
    }


def _release_command_status(root: Path) -> dict[str, Any]:
    missing: list[str] = []
    not_executable: list[str] = []
    for script in REQUIRED_RELEASE_SCRIPTS:
        path = root / script
        if not path.exists():
            missing.append(script)
        elif not path.is_file() or not _is_executable(path):
            not_executable.append(script)
    return {
        "required": list(REQUIRED_RELEASE_SCRIPTS),
        "missing": missing,
        "not_executable": not_executable,
        "legacy_full_rehearsal_available": (root / "scripts" / "ctfctl").exists(),
    }


def _is_executable(path: Path) -> bool:
    return bool(path.stat().st_mode & 0o111)


def _content_allowed(path: str) -> bool:
    normalized = path.replace("\\", "/")
    return normalized in CONTENT_ALLOW_FILES or any(normalized.startswith(prefix) for prefix in CONTENT_ALLOW_PREFIXES)


def _redact_object(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _redact_object(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_object(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def _display_path(path: Path) -> str:
    try:
        return str(path).replace(str(Path.home()), "~", 1)
    except RuntimeError:
        return str(path)
