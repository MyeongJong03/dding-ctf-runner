#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="$ROOT"
JSON=0

usage() {
  cat <<'EOF'
Usage: scripts/history-scan.sh [--repo DIR] [--json]

Scans public git history for sensitive path names and scans HEAD for sensitive
patterns. It reports only file names and pattern names, never matched values.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      REPO="${2:-}"
      if [[ -z "$REPO" ]]; then
        echo "[history-scan] --repo requires a directory" >&2
        exit 2
      fi
      shift 2
      ;;
    --json)
      JSON=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "[history-scan] unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

python3 - "$REPO" "$JSON" <<'PY'
from __future__ import annotations

import fnmatch
import json
import re
import subprocess
import sys
from pathlib import Path

repo = Path(sys.argv[1]).expanduser().resolve()
json_output = sys.argv[2] == "1"

SENSITIVE_PATH_GLOBS = (
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

RUNTIME_PREFIXES = (
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
)

HEAD_PATTERNS = {
    "auth_json": r"auth\.json",
    "bearer": r"\bBearer\b",
    "authorization": r"\bauthorization\b",
    "cookie": r"\bcookie\b",
    "token": r"\btoken\b",
    "password": r"\bpassword\b",
    "session": r"\bsession\b",
    "storage_state": r"storage[_-]?state",
    "tjctf_flag_shape": r"tjctf\{",
    "generic_flag_shape": r"\bflag\{",
    "real_ctf_name": r"\b(hack\s*for\s*a\s*change|hackforachange)\b",
}

PUBLIC_DOC_FLAG_RE = re.compile(r"\b[A-Za-z0-9_]{2,32}\{[^{}\s]{4,256}\}")
REAL_CTF_RE = re.compile(r"\b(hack\s*for\s*a\s*change|hackforachange|h4c)\b", re.IGNORECASE)


def git(args: list[str], *, check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=check,
    )


def path_sensitive(path: str) -> bool:
    normalized = path.replace("\\", "/")
    lowered = normalized.lower()
    name = Path(normalized).name.lower()
    if any(lowered.startswith(prefix) for prefix in RUNTIME_PREFIXES):
        return True
    return any(fnmatch.fnmatch(name, glob.lower()) or fnmatch.fnmatch(lowered, glob.lower()) for glob in SENSITIVE_PATH_GLOBS)


git(["rev-parse", "--is-inside-work-tree"], check=True)

history_names = git(["log", "--all", "--name-only", "--pretty=format:"]).stdout.splitlines()
history_sensitive_paths = sorted({path.strip() for path in history_names if path.strip() and path_sensitive(path.strip())})

head_pattern_files: list[dict[str, object]] = []
for name, pattern in HEAD_PATTERNS.items():
    completed = git(["grep", "-I", "-i", "-l", "-E", pattern, "HEAD", "--", "."], check=False)
    if completed.returncode not in (0, 1):
        continue
    files = sorted({line.split(":", 1)[1] if line.startswith("HEAD:") else line for line in completed.stdout.splitlines() if line.strip()})
    if files:
        head_pattern_files.append({"pattern": name, "files": files})

tracked = git(["ls-tree", "-r", "--name-only", "HEAD"], check=True).stdout.splitlines()
public_doc_findings: list[dict[str, object]] = []
for path in tracked:
    if path not in {"README.md", "GUIDE.md"} and not path.startswith("docs/"):
        continue
    worktree_path = repo / path
    if worktree_path.is_file():
        text = worktree_path.read_text(encoding="utf-8", errors="replace")
    else:
        blob = git(["show", f"HEAD:{path}"], check=False)
        if blob.returncode != 0:
            continue
        text = blob.stdout
    reasons: list[str] = []
    if PUBLIC_DOC_FLAG_RE.search(text):
        reasons.append("flag_like_literal")
    if REAL_CTF_RE.search(text):
        reasons.append("real_ctf_name")
    if reasons:
        public_doc_findings.append({"path": path, "reasons": sorted(set(reasons))})

high: list[str] = []
if history_sensitive_paths:
    high.append("history_sensitive_paths")
if public_doc_findings:
    high.append("public_docs_sensitive_content")

result = {
    "status": "ok" if not high else "blocked",
    "high": high,
    "history_sensitive_paths": history_sensitive_paths,
    "public_doc_findings": public_doc_findings,
    "head_pattern_files": head_pattern_files,
    "review_pattern_count": sum(len(item["files"]) for item in head_pattern_files),
}

if json_output:
    print(json.dumps(result, indent=2, sort_keys=True))
else:
    print({"status": result["status"], "high": result["high"], "history_sensitive_path_count": len(history_sensitive_paths), "review_pattern_count": result["review_pattern_count"]})

raise SystemExit(0 if result["status"] == "ok" else 1)
PY
