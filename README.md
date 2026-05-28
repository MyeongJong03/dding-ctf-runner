# dding CTF Runner

`dding-ctf-runner` is a shell-first control plane for live CTF operations. The default live workflow is an interactive Codex swarm: the operator prepares board state with `ctfctl`, then opens several visible Codex terminals from `~/CTF`. Every Codex terminal is an autonomous solver. There is no controller/solver split in the default path.

This repository is public-safe by design. Keep real contest URLs, auth material, downloaded private files, runtime state, writeups, exploits, and raw flags outside git and public services.

## What It Does

- Coordinates interactive Codex solvers with `ctfctl interactive`.
- Syncs challenge metadata, downloads, and local briefs through policy-gated platform helpers.
- Blocks same-machine duplicate claims by default.
- Supports guarded submit and upload-submit through `ctfctl`.
- Keeps operator board state, memos, accepted solves, stalled handoffs, and writeups local-only.
- Provides Docker, callback, auth, download, sync, submit, and cleanup helpers.
- Keeps legacy background worker/supervisor flows for advanced rehearsals only.
- Runs public-safety checks before release.

## Requirements

- Python 3.12.
- Codex CLI for visible interactive solving.
- Docker for pwn/rev workloads.
- Playwright/Chromium only when browser-based discovery or manual storage capture is needed.
- Optional tunnel tooling only when a challenge explicitly needs a public callback.

Use Windows WSL as the primary heavy runner. Keep this repo on the WSL Linux filesystem, not `/mnt/c`. macOS is supported as a secondary/mobile runner; Apple Silicon can use Docker Desktop emulation for linux/amd64 images, but pwn/rev-heavy work should prefer Windows WSL unless Mac timing has been validated.

## Quick Start

```bash
git clone <repo-url> dding-ctf-runner
cd dding-ctf-runner

python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e . pytest

./scripts/ctfctl preflight --deep --json
```

Prepare the contest from the runner repo:

```bash
export CONTEST_ID=<contest>
export PROFILE=~/.ctf-solver/platforms/<contest>.yaml
export AGENTS=4

./scripts/ctfctl platform profile-check --config "$PROFILE" --json
./scripts/ctfctl interactive e2e-smoke --contest-id fake-interactive-smoke --agents 2 --json
./scripts/ctfctl interactive init --contest-id "$CONTEST_ID" --profile "$PROFILE" --agents "$AGENTS" --json
./scripts/ctfctl interactive sync --contest-id "$CONTEST_ID" --profile "$PROFILE" --live --download --ingest --json
./scripts/ctfctl interactive board --contest-id "$CONTEST_ID" --json
./scripts/ctfctl interactive prompt --contest-id "$CONTEST_ID" --agent agent-1
```

Open one terminal per agent and start plain interactive Codex from the CTF workspace:

```bash
cd ~/CTF
codex
```

Paste one generated prompt into each Codex terminal. Recommended width:

- Windows WSL: up to 6 Codex terminals.
- MacBook: up to 4 Codex terminals.

Inside the same computer, duplicate claims are blocked by default. Use `ctfctl interactive claim --allow-duplicate` only when you intentionally want multiple local Codex sessions on the same problem. Duplicate claims across different computers are not coordinated.

## Solver Loop

Each Codex terminal should keep going until the contest ends, the operator stops it, or there is no useful next work:

```bash
ctfctl interactive claim --contest-id "$CONTEST_ID" --agent agent-1 --json
ctfctl interactive memo --contest-id "$CONTEST_ID" --challenge-id <id> --kind memory --append "short fact" --json
ctfctl interactive submit --contest-id "$CONTEST_ID" --challenge-id <id> --flag-file <path> --confirm --json
ctfctl interactive upload-submit --contest-id "$CONTEST_ID" --challenge-id <id> --artifact <path> --confirm --json
ctfctl interactive writeup --contest-id "$CONTEST_ID" --challenge-id <id> --category <category> --languages ko,en --include-code --json
ctfctl interactive cleanup --contest-id "$CONTEST_ID" --challenge-id <id> --safe --json
ctfctl interactive metrics summary --contest-id "$CONTEST_ID" --json
ctfctl interactive metrics report --contest-id "$CONTEST_ID" --json
```

Writeups are accepted-only. Accepted challenges produce both Korean and English files named:

```text
[category]ChallengeNameWriteup.ko.md
[category]ChallengeNameWriteup.en.md
```

If solver or exploit code exists, include the complete code in fenced markdown blocks. Unsolved challenges do not get writeups; leave compact `memory`, `evidence`, `attempts`, `next_steps`, `operator_notes`, and `stalled` records instead.

## Runtime State

Keep runtime state outside this repo:

```text
~/.ctf-solver/platforms/
~/.ctf-solver/secrets/
~/.ctf-solver/runner-state/
~/CTF/contests/
```

Local terminal output may include flags, solver output, and exploit output when needed for solving and verification. During an active contest, do not commit, push, paste publicly, publish, or upload flags, writeups, exploits, tokens, cookies, sessions, browser storage, private keys, auth material, downloaded private challenge files, or callback hits to public services, public repositories, public pastes, issue trackers, or external writeup locations.

Interactive metrics are stored under the operator root in `metrics/events.jsonl`, `metrics/sessions.jsonl`, `metrics/challenge_metrics.jsonl`, `metrics/tool_benchmarks.jsonl`, `metrics/summary.json`, and `metrics/regression_report.md`. These files are local raw metrics and stay outside this repo.

Before the next contest, run `ctfctl interactive e2e-smoke --contest-id fake-interactive-smoke --agents 2 --json`. It uses only local fake CTFd fixtures and verifies init, sync, claim, accepted submit, solved/submission records, ko/en writeups with full solver code, cleanup, stalled metrics without writeups, metrics summary, and duplicate-claim behavior.

GitHub-managed metrics must be public-safe snapshots only:

- Do not upload contest flags, writeups, exploit bodies, auth material, or private artifacts during an active contest.
- Unsolved challenges get stalled metrics with high-level blockers and next steps, not writeups.
- After an accepted solve, run submit -> ko/en writeup -> cleanup -> metrics update -> next challenge.
- After a stall, record memo/attempts/next_steps -> metrics update -> next challenge.
- At contest end, run `ctfctl interactive metrics publish-snapshot --contest-id "$CONTEST_ID" --contest-ended`, then `ctfctl interactive metrics dashboard`, then optionally commit the generated public-safe files.
- During a contest, `publish-snapshot` is blocked unless both `--allow-active-contest` and `--confirm-public-safe` are provided.

## Legacy Background Workers

`ctfctl contest start-workers`, `worker_loop`, `worker_supervisor`, `multi_worker`, and `scripts/ctf-worker-*` remain available for fake/local E2E, compatibility testing, and deliberate advanced automation. They are not the recommended live contest workflow.

For event-day commands, use [OPERATIONS.md](OPERATIONS.md). For the full user guide, use [GUIDE.md](GUIDE.md).

## Release Check

Before publishing or merging public docs, run the interactive-first release gate:

```bash
python3 -m compileall -q ctf_runner
python3 -m pytest -q
./scripts/ctfctl interactive init --contest-id release-interactive-smoke --writeup-root /tmp/dding-ctf-runner-release-writeups --agents 2 --json
./scripts/ctfctl interactive e2e-smoke --contest-id release-interactive-e2e --agents 2 --json
./scripts/ctfctl interactive metrics baseline --name release-smoke --output-dir /tmp/dding-ctf-runner-release-metrics --json
./scripts/ctfctl interactive metrics publish-snapshot --contest-id active-contest-block-smoke --json  # expected blocked
./scripts/ctfctl interactive prompt --contest-id release-interactive-smoke --agent smoke-1
./scripts/release-check.sh
./scripts/ctfctl repo public-check --json
./scripts/fresh-clone-check.sh
./scripts/history-scan.sh
git diff --check
```

`public-check` reports these under `interactive_test_commands`. Legacy full-rehearsal and background worker checks remain under legacy/advanced command metadata.

Do not push public git changes from this repo during live CTF work.

## Documentation

- [GUIDE.md](GUIDE.md): end-to-end interactive operating guide.
- [OPERATIONS.md](OPERATIONS.md): short contest-day runbook.
- [docs/interactive-operations.md](docs/interactive-operations.md): interactive CLI and operator file details.
- [docs/contest-operations.md](docs/contest-operations.md): legacy/advanced background worker controls.
- [docs/worker-loop.md](docs/worker-loop.md): legacy worker loop reference.
- [docs/postsolve.md](docs/postsolve.md): accepted-only writeup and local postsolve policy.
- [docs/setup-windows-wsl.md](docs/setup-windows-wsl.md): Windows WSL setup.
- [docs/setup-macos.md](docs/setup-macos.md): macOS secondary runner setup.
- [docs/threat-model.md](docs/threat-model.md): public-safety and live-operation risks.
