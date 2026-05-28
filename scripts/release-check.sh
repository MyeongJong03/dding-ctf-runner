#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

source "$ROOT/scripts/lib/macos-fd-limit.sh"
ctf_runner_raise_macos_fd_limit

tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

echo "[release-check] compileall"
python3 -m compileall -q ctf_runner

echo "[release-check] pytest"
python3 -m pytest -q

echo "[release-check] preflight"
preflight_json="$tmpdir/preflight.json"
./scripts/ctfctl preflight --deep --json > "$preflight_json"
python3 - "$preflight_json" <<'PY'
import json
import sys

data = json.loads(open(sys.argv[1], encoding="utf-8").read())
risk = data.get("risk") or {}
high = list(risk.get("High") or [])
medium = list(risk.get("Medium") or [])
allowed_medium = {
    "tunnel_provider_missing",
    "global_long_agents",
    "legacy_dreamhack_solver_mcp",
    "ctf_pwn_image_missing",
    "docker_cli_missing",
    "docker_daemon_unreachable",
    "docker_socket_permission",
}
unexpected_medium = [item for item in medium if item not in allowed_medium]
print({"High": high, "Medium": medium, "unexpected_medium": unexpected_medium})
if high or unexpected_medium:
    raise SystemExit(1)
PY

echo "[release-check] public-check"
public_json="$tmpdir/public-check.json"
./scripts/ctfctl repo public-check --json > "$public_json"
python3 - "$public_json" <<'PY'
import json
import sys

data = json.loads(open(sys.argv[1], encoding="utf-8").read())
commands = data.get("test_commands") or {}
interactive_commands = data.get("interactive_test_commands") or {}
legacy_commands = data.get("legacy_advanced_test_commands") or {}
release_commands = data.get("release_commands") or {}
uv_lock = data.get("uv_lock") or {}
summary = {
    "status": data.get("status"),
    "high": data.get("high") or [],
    "warnings": data.get("warnings") or [],
    "tracked_file_count": data.get("tracked_file_count"),
    "untracked_file_count": data.get("untracked_file_count"),
    "uv_lock_policy_ok": uv_lock.get("policy_ok"),
    "release_commands_missing": release_commands.get("missing") or [],
    "release_commands_not_executable": release_commands.get("not_executable") or [],
    "interactive_test_commands": sorted(interactive_commands),
    "legacy_advanced_test_commands": sorted(legacy_commands),
}
print(summary)
required_commands = {"compileall", "pytest", "preflight", "interactive_init", "interactive_e2e_smoke", "interactive_metrics_baseline", "interactive_metrics_publish_snapshot_active_block", "interactive_prompt", "fresh_clone_check", "history_scan"}
required_interactive = {"interactive_init", "interactive_e2e_smoke", "interactive_metrics_baseline", "interactive_metrics_publish_snapshot_active_block", "interactive_prompt"}
missing_command_summaries = sorted(required_commands - set(commands))
missing_interactive_summaries = sorted(required_interactive - set(interactive_commands))
if data.get("status") != "ok" or not uv_lock.get("policy_ok") or missing_command_summaries or missing_interactive_summaries:
    raise SystemExit(1)
PY

echo "[release-check] interactive init"
interactive_init_json="$tmpdir/interactive-init.json"
./scripts/ctfctl interactive init --contest-id release-interactive-smoke --writeup-root "$tmpdir/writeups" --agents 2 --json > "$interactive_init_json"
python3 - "$interactive_init_json" <<'PY'
import json
import sys

data = json.loads(open(sys.argv[1], encoding="utf-8").read())
print({"status": data.get("status"), "contest_id": data.get("contest_id")})
if data.get("status") != "ok":
    raise SystemExit(1)
PY

echo "[release-check] interactive prompt"
interactive_prompt_json="$tmpdir/interactive-prompt.json"
./scripts/ctfctl interactive prompt --contest-id release-interactive-smoke --agent smoke-1 --json > "$interactive_prompt_json"
python3 - "$interactive_prompt_json" <<'PY'
import json
import sys

data = json.loads(open(sys.argv[1], encoding="utf-8").read())
prompt = str(data.get("prompt") or "")
summary = {"status": data.get("status"), "contest_id": data.get("contest_id"), "agent": data.get("agent")}
print(summary)
if data.get("status") != "ok" or "ctfctl interactive claim" not in prompt:
    raise SystemExit(1)
PY

echo "[release-check] interactive e2e-smoke"
interactive_e2e_json="$tmpdir/interactive-e2e.json"
./scripts/ctfctl interactive e2e-smoke --contest-id release-interactive-e2e --agents 2 --writeup-root "$tmpdir/e2e-writeups" --json > "$interactive_e2e_json"
python3 - "$interactive_e2e_json" <<'PY'
import json
import sys

data = json.loads(open(sys.argv[1], encoding="utf-8").read())
checks = data.get("checks") or {}
summary = {
    "status": data.get("status"),
    "contest_id": data.get("contest_id"),
    "checks_ok": all(checks.values()) if checks else False,
}
print(summary)
if data.get("status") != "ok" or not checks or not all(checks.values()):
    raise SystemExit(1)
PY

echo "[release-check] interactive metrics baseline"
metrics_baseline_json="$tmpdir/interactive-metrics-baseline.json"
./scripts/ctfctl interactive metrics baseline --name release-smoke --output-dir "$tmpdir/metrics-runs" --json > "$metrics_baseline_json"
python3 - "$metrics_baseline_json" <<'PY'
import json
import sys
from pathlib import Path

data = json.loads(open(sys.argv[1], encoding="utf-8").read())
path = Path(str(data.get("baseline_path") or "").replace("~", str(Path.home()), 1))
print({"status": data.get("status"), "baseline_exists": path.exists()})
if data.get("status") != "ok" or not path.exists():
    raise SystemExit(1)
PY

echo "[release-check] interactive metrics publish-snapshot active-contest block"
metrics_publish_json="$tmpdir/interactive-metrics-publish-block.json"
if ./scripts/ctfctl interactive metrics publish-snapshot --contest-id active-contest-block-smoke --json > "$metrics_publish_json"; then
  echo "[release-check] active publish unexpectedly allowed" >&2
  exit 1
fi
python3 - "$metrics_publish_json" <<'PY'
import json
import sys

data = json.loads(open(sys.argv[1], encoding="utf-8").read())
print({"status": data.get("status"), "public_safe": data.get("public_safe"), "reason": data.get("reason")})
if data.get("status") != "blocked" or data.get("public_safe") is not False:
    raise SystemExit(1)
PY

echo "[release-check] git status"
git status --short

echo "[release-check] diff check"
git diff --check

if [[ "${RELEASE_CHECK_FAKE_SMOKE:-0}" == "1" ]]; then
  echo "[release-check] fake-ctfd smoke"
  smoke_json="$tmpdir/fake-smoke.json"
  ./scripts/ctfctl fake-ctfd smoke --json > "$smoke_json"
  python3 - "$smoke_json" <<'PY'
import json
import sys

data = json.loads(open(sys.argv[1], encoding="utf-8").read())
print({"status": data.get("status"), "raw_leak_detected": data.get("raw_leak_detected")})
if data.get("status") != "ok" or data.get("raw_leak_detected"):
    raise SystemExit(1)
PY
fi

if [[ "${RELEASE_CHECK_LOCAL_E2E:-0}" == "1" ]]; then
  echo "[release-check] local e2e"
  e2e_json="$tmpdir/local-e2e.json"
  ./scripts/ctfctl worker local-e2e --workers 3 --solver mock --fake-ctfd --json > "$e2e_json"
  python3 - "$e2e_json" <<'PY'
import json
import sys

data = json.loads(open(sys.argv[1], encoding="utf-8").read())
summary = {
    "status": data.get("status"),
    "expected_met": data.get("expected_met"),
    "raw_leak_detected": data.get("raw_leak_detected"),
    "workers_requested": data.get("workers_requested"),
}
print(summary)
if data.get("status") != "ok" or not data.get("expected_met") or data.get("raw_leak_detected"):
    raise SystemExit(1)
PY
fi

echo "[release-check] ok"
