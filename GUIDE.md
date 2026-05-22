# dding CTF Runner Guide

This guide describes the public-safe operating model for `dding-ctf-runner`. Commands use placeholders only; keep real contest URLs, profile paths, cookies, tokens, browser storage, attachments, queue DBs, writeups, and flags outside this repository.

For the short event-day command sequence, see [OPERATIONS.md](OPERATIONS.md).

## 1. Operating Concept

The runner is a shell-first CTF control plane:

- `ctfctl` is the primary operator interface.
- SQLite queue state tracks challenges, claims, submissions, and worker status.
- Codex workers run through `scripts/ctf-worker-*` wrappers with isolated worker homes.
- Platform automation is policy-gated and defaults to read-only setup/rehearsal behavior.
- Solves, submissions, and postsolve artifacts are separated from public repo files.

## 2. Setup, Rehearsal, Competition

Run modes:

- `setup`: local setup and profile validation. Real solve, live submit, instance start, automated login, and public tunnels are blocked.
- `rehearsal`: read-only real platform sync can run intentionally. Real solving needs an explicit dry-run override; live submit remains blocked.
- `competition`: real solve workers require `--confirm-competition` and an armed contest.

Resolve mode explicitly when operating:

```bash
./scripts/ctfctl --mode setup preflight --deep --json
./scripts/ctfctl --mode rehearsal platform sync-challenges --config <profile> --live --save-state --ingest-text --json
./scripts/ctfctl --mode competition contest arm --contest-id <contest> --profile <profile> --confirm-competition --json
```

## 3. Windows WSL Setup

Keep the repo under WSL ext4, for example:

```bash
cd ~
git clone <repo-url> dding-ctf-runner
cd dding-ctf-runner
```

Avoid `/mnt/c`. Docker Desktop WSL integration should be enabled. Use Python 3.12:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e . pytest
```

Install Playwright only if browser-based discovery or manual storage capture is needed:

```bash
./scripts/setup-browser.sh
```

## 4. Codex Worker Setup

Initialize worker homes:

```bash
./scripts/init-codex-workers.sh --count 5 --link-auth
```

Start workers only through wrappers:

```bash
./scripts/ctf-worker-1
./scripts/ctf-worker-2
```

Wrapper defaults:

- model: `auto/unpinned`
- approval: `never`
- sandbox: `danger-full-access`
- worker home: `~/.codex-workers/<worker-id>`
- prompt mode: no-prompt automation through the runner wrapper

Do not use plain `codex` for competition workers. It can load unrelated global instructions and bypass runner-specific worker setup.

## 5. Preflight

Run preflight before rehearsal and before competition:

```bash
./scripts/ctfctl preflight --deep --json
```

Expected public-readiness state:

- `risk.High` is empty.
- `tunnel_provider_missing` can be Medium when no public tunnel provider is installed.
- `global_long_agents` can be Medium when global instructions are long, as long as worker wrappers are used.

## 6. Platform Profile

Store platform profiles outside the repo:

```text
~/.ctf-solver/platforms/<contest>.yaml
~/.ctf-solver/secrets/<contest>.cookie
~/.ctf-solver/secrets/<contest>.token
~/.ctf-solver/secrets/<contest>.storage_state.json
```

Profile auth methods:

```yaml
auth:
  method: cookie_header_file
  path: "~/.ctf-solver/secrets/<contest>.cookie"
```

```yaml
auth:
  method: api_token_file
  path: "~/.ctf-solver/secrets/<contest>.token"
```

```yaml
auth:
  method: storage_state_file
  path: "~/.ctf-solver/secrets/<contest>.storage_state.json"
```

Check profiles without printing raw auth:

```bash
./scripts/ctfctl platform profile-check --config ~/.ctf-solver/platforms/<contest>.yaml --json
./scripts/ctfctl auth storage-check --path ~/.ctf-solver/secrets/<contest>.storage_state.json --json
```

## 7. Rehearsal Read-Only Sync

Read-only sync can prepare local briefs without arming the contest:

```bash
./scripts/ctfctl platform sync-challenges \
  --mode rehearsal \
  --config ~/.ctf-solver/platforms/<contest>.yaml \
  --live \
  --save-state \
  --ingest-text \
  --json
```

This should not solve challenges, submit flags, start instances, automate browser login, or expose tunnels.

## 8. Contest Arm And Disarm

Prestart checks are local by default:

```bash
./scripts/ctfctl contest prestart \
  --contest-id <contest> \
  --profile ~/.ctf-solver/platforms/<contest>.yaml \
  --json
```

Arm only when the real competition solve window is intended:

```bash
./scripts/ctfctl contest arm \
  --contest-id <contest> \
  --profile ~/.ctf-solver/platforms/<contest>.yaml \
  --confirm-competition \
  --max-workers 5 \
  --max-parallel-codex 2 \
  --json
```

Competition arm enables live submit by default. Add `--no-live-submit` to solve without live submissions, or keep the profile policy at `allow_submission: false`. Disarm after the contest or any pause:

```bash
./scripts/ctfctl contest disarm --contest-id <contest> --stop-workers --json
```

## 9. Worker Execution

Supervisor dry run and apply:

```bash
./scripts/ctfctl contest start-workers --contest-id <contest> --dry-run --json
./scripts/ctfctl contest start-workers \
  --contest-id <contest> \
  --apply \
  --workers 5 \
  --solver codex \
  --allow-codex-call \
  --max-parallel-codex 2 \
  --no-stop-when-empty \
  --postsolve \
  --json
```

Monitor and stop:

```bash
./scripts/ctfctl contest worker-status --contest-id <contest> --json
./scripts/ctfctl contest worker-logs --contest-id <contest> --worker-id worker-1 --tail 80 --json
./scripts/ctfctl contest stop-workers --contest-id <contest> --json
```

Manual wrapper commands remain available:

```bash
./scripts/ctfctl contest worker-commands --contest-id <contest> --json
```

Run only the emitted `scripts/ctf-worker-*` commands in separate terminals. Respect `max_parallel_codex`.

Local fake E2E:

```bash
./scripts/ctfctl fake-ctfd smoke --json
./scripts/ctfctl worker local-e2e --workers 3 --solver mock --fake-ctfd --json
./scripts/ctfctl contest supervisor-smoke --workers 3 --solver mock --fake-ctfd --json
./scripts/ctfctl docker benchmark --image ctf-pwn:latest --json
./scripts/ctfctl docker pool-smoke --contest-id local-docker-smoke --workers 2 --json
./scripts/ctfctl docker pool-stop --contest-id local-docker-smoke --json
./scripts/ctfctl callback public-smoke --contest-id local-callback-smoke --provider auto --allow-public --json
```

The Docker commands exercise the persistent pool and then stop it. The callback smoke starts a loopback dummy listener, exposes only that listener through the selected provider, sends a safe probe, and cleans up listener/tunnel resources.

## 10. Before First Real Contest

Run the final full fake competition rehearsal before using the automation on a real event:

```bash
./scripts/ctfctl contest full-rehearsal --contest-id final-fake --workers 5 --solver mock --json
```

Codex mini rehearsal:

```bash
./scripts/ctfctl contest full-rehearsal \
  --contest-id final-fake-codex \
  --workers 3 \
  --max-parallel-codex 2 \
  --solver codex \
  --allow-codex-call \
  --json
```

Proceed only after the mock full rehearsal reports `status: ok`, the Codex mini rehearsal reports `status: ok`, active worker/tunnel/callback/Docker counts are zero after cleanup, duplicate claims/submissions are zero, and `raw_leak_detected` is false. The deterministic local Codex mini release target is 3/3 easy challenges solved and accepted. The reports are local-only under `~/.ctf-solver/runner-state/contests/<contest_id>/`.

Do not prepare a GitHub/public release until the full rehearsal and `scripts/release-check.sh` pass.

## 11. Release And Public Checks

Run the release gate before publishing:

```bash
python3 -m compileall -q ctf_runner
python3 -m pytest -q
./scripts/ctfctl preflight --deep --json
./scripts/ctfctl contest full-rehearsal --contest-id final-fake --workers 5 --solver mock --json
./scripts/ctfctl contest full-rehearsal --contest-id final-fake-codex --workers 3 --max-parallel-codex 2 --solver codex --allow-codex-call --json
./scripts/release-check.sh
./scripts/fresh-clone-check.sh
./scripts/history-scan.sh
```

`ctfctl repo public-check --json` is part of `release-check.sh`. It verifies required docs, `pyproject.toml`, `uv.lock`, runtime ignore patterns, public-safe docs, absence of repo-local runtime directories, and release command availability. `fresh-clone-check.sh` creates a temporary file-based clone, overlays current non-ignored changes, runs compile/tests/release-check/preflight/fake smoke/local E2E, and removes the temp directory unless `--keep-dir` is passed.

Before the first GitHub push, manually review commit history:

```bash
git status --short
git log --stat
./scripts/history-scan.sh
```

If history contains unrelated local runtime material or you are not sure whether old commits are public-safe, create a clean public branch or a fresh repository with a squashed initial commit. Push only source, docs, scripts, tests, and public fixtures.

## 12. Auto-Submit Policy

Live submit requires:

- armed contest
- arm state with live submit enabled; this is the competition default unless `--no-live-submit` is used
- worker submit confirmation is added by `contest start-workers`; manual platform submit still requires `--confirm`
- platform policy `allow_submission: true`
- submit policy pass

Setup and rehearsal block real submit even when the profile allows submission. The submit policy checks duplicate hashes, confidence, fake-like values, cooldowns, and wrong-answer limits. Public payloads store hashes and redacted summaries only.

## 13. Postsolve And Archive

For solved challenges:

```bash
./scripts/ctfctl postsolve generate --contest-id <contest> --challenge-id <challenge> --json
./scripts/ctfctl postsolve status --contest-id <contest> --challenge-id <challenge> --json
./scripts/ctfctl postsolve archive --contest-id <contest> --challenge-id <challenge> --json
```

Generated files live under:

```text
~/CTF/contests/<contest>/<challenge>/postsolve/
```

They are local-only and ignored. Raw flags are replaced by hashes or redaction placeholders.

## 14. Skill Candidate Review

`skill_candidate.md` is a candidate only. After the contest, review it manually and promote only sanitized reusable patterns. The runner does not modify existing personal skill repositories.

## 15. Troubleshooting

Plain Codex loads unrelated global instructions:

```bash
./scripts/ctf-worker-1 --dry-run
./scripts/ctfctl codex doctor --json
```

`global_long_agents`:

- Expected when global instruction files are large.
- Use `scripts/ctf-worker-*` wrappers.

`tunnel_provider_missing`:

- Expected if no tunnel provider is installed.
- Install one manually only when a challenge requires public callback exposure.

Playwright/Chromium issues:

```bash
./scripts/ctfctl browser smoke --json
./scripts/fix-playwright-deps.sh --apply
```

Codex binary mismatch:

```bash
./scripts/ctfctl codex doctor --json
./scripts/fix-codex-install.sh
```

Legacy MCP warnings:

```bash
./scripts/ctfctl codex mcp-status --json
./scripts/fix-codex-mcp.sh --remove-legacy-dreamhack
```

## 16. Safety Checklist

Before publishing or running a real contest:

- Repo is not under `/mnt/c`.
- `risk.High` is empty.
- `ctfctl repo public-check --json` is `ok`.
- `scripts/fresh-clone-check.sh` passes.
- `scripts/history-scan.sh` has no high findings.
- No real auth, cookies, tokens, storage state, queue DBs, downloads, writeups, or flags are tracked.
- Workers are launched through wrappers only.
- Real platform sync is rehearsal/read-only unless competition is armed.
- Competition auto-submit requires arm, profile policy, and submit policy; use `--no-live-submit` to turn it off.
- Generated postsolve/archive material stays local-only.
- No public git push happens during active CTF work.
