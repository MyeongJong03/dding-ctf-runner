# dding CTF Runner

`dding-ctf-runner` is a shell-first control plane for running CTF competition workflows with isolated Codex workers. It is built around `ctfctl`, local queue state, explicit run modes, and policy gates so setup and rehearsal work cannot accidentally become live solving or live submission.

This repository is intended to be public-safe. Real secrets, browser state, downloaded challenge material, generated writeups, state databases, and raw flags must stay outside git.

## Features

- Preflight checks for WSL paths, Docker, browser readiness, worker isolation, Codex binary state, and tunnel tooling.
- Codex worker isolation through `scripts/ctf-worker-*` wrappers and per-worker `CODEX_HOME`.
- Local ingest and `brief.md` generation for attachment and text-only challenge material.
- CTFd and generic read-only platform discovery with explicit `--live` and policy gates.
- Submit planning with confidence, duplicate-hash, fake-like, cooldown, and wrong-answer guards.
- Worker solve loop and process supervisor for fake/local E2E and guarded competition mode.
- Contest arm/disarm control plane for switching from rehearsal into competition.
- Final fake competition full rehearsal covering preflight, fake discovery/ingest, arm, Docker pool, callback public-smoke, workers, postsolve, cleanup, and release-check. The current release target passes the mock full rehearsal and the Codex mini rehearsal with 3/3 local easy challenges accepted.
- Local-only postsolve summaries, writeup drafts, skill candidates, and artifact archives.
- Public release checks through `scripts/release-check.sh`, `scripts/fresh-clone-check.sh`, `scripts/history-scan.sh`, and `ctfctl repo public-check --json`.

## Requirements

- WSL Ubuntu on the Linux filesystem, not `/mnt/c`.
- Python 3.12.
- Docker Desktop with WSL integration for container-backed challenge work.
- Codex CLI for worker execution.
- Playwright/Chromium for optional browser-based read-only discovery or manual storage capture.
- Optional public tunnel provider only when a challenge explicitly requires it; none is bundled or started automatically.

## Quick Start

```bash
git clone <repo-url>
cd dding-ctf-runner

python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e . pytest

./scripts/ctfctl preflight --deep --json
./scripts/init-codex-workers.sh --count 5 --link-auth
./scripts/ctfctl fake-ctfd smoke --json
./scripts/ctfctl worker local-e2e --workers 3 --solver mock --fake-ctfd --json
./scripts/ctfctl contest supervisor-smoke --workers 3 --solver mock --fake-ctfd --json
./scripts/ctfctl contest full-rehearsal --contest-id final-fake --workers 5 --solver mock --json
./scripts/ctfctl contest full-rehearsal --contest-id final-fake-codex --workers 3 --max-parallel-codex 2 --solver codex --allow-codex-call --json
```

Use only the `scripts/ctf-worker-*` wrappers for competition workers. Plain `codex` can load unrelated global instructions and is not the runner control surface.

For real event day commands, use [OPERATIONS.md](OPERATIONS.md).

## Modes And Gates

- `setup`: configure local tools and profiles. Real challenge solving, live submit, instance start, browser login automation, and public tunnels are blocked.
- `rehearsal`: read-only real platform sync can be run intentionally. Real solving is blocked unless a dry-run solve override is explicit; live submit remains blocked.
- `competition`: real solve workers require `--confirm-competition` and an armed contest.

`ctfctl contest start-workers` is dry-run by default. Passing `--apply` launches supervised workers and writes PID/status/log files under `~/.ctf-solver/runner-state/contests/<contest>/workers/`.

Live submit requires every gate:

- contest is armed
- arm state allows live submit, which is the competition arm default unless `--no-live-submit` is used
- worker submit uses the built-in competition confirmation; manual platform submit still uses `--confirm`
- platform policy allows submission
- submit policy passes confidence, duplicate, fake-like, cooldown, and wrong-answer checks

Setup and rehearsal always block real live submission. In competition, `policy.allow_submission: true` lets high-confidence worker candidates auto-submit after the submit policy passes; `policy.allow_submission: false` keeps solving read-only.

## Secrets And Runtime State

Keep secrets outside this repository, for example:

```text
~/.ctf-solver/secrets/
~/.ctf-solver/platforms/
~/CTF/contests/
~/.ctf-solver/runner-state/
```

Never commit or print raw cookies, tokens, auth headers, browser storage, API keys, passwords, private keys, shell history, real flags, downloaded private challenge files, queue DBs, callback logs, or generated writeups.

Ignored runtime paths include `contests/`, `state/`, `runner-state/`, `secrets/`, `downloads/`, `writeups/`, `browser-artifacts/`, `callback-hits/`, `callbacks/`, `tunnels/`, `.codex-workers/`, `*.sqlite3`, `*.db`, `.env*`, `auth.json`, and storage-state files.

The release/public checks now also fail on repo-local runtime directories or sensitive filenames, even when they are ignored. Keep all contest state, queue databases, profiles, callback hits, Docker workspaces, and postsolve material outside the repository before publishing.

## Package Policy

`uv.lock` is committed because the current project has no third-party runtime dependencies and the lockfile is small and public-safe. If future optional dependency groups grow, update the lockfile intentionally and run the release checks before publishing.

## Release Check

Before publishing:

```bash
python3 -m compileall -q ctf_runner
python3 -m pytest -q
./scripts/ctfctl preflight --deep --json
./scripts/ctfctl contest full-rehearsal --contest-id final-fake --workers 5 --solver mock --json
./scripts/ctfctl contest full-rehearsal --contest-id final-fake-codex --workers 3 --max-parallel-codex 2 --solver codex --allow-codex-call --json
./scripts/ctfctl repo public-check --json
./scripts/release-check.sh
./scripts/fresh-clone-check.sh
./scripts/history-scan.sh
git diff --check
```

Optional local-only smoke checks:

```bash
./scripts/ctfctl fake-ctfd smoke --json
./scripts/ctfctl worker local-e2e --workers 3 --solver mock --fake-ctfd --json
./scripts/ctfctl contest supervisor-smoke --workers 3 --solver mock --fake-ctfd --json
./scripts/ctfctl docker benchmark --image ctf-pwn:latest --json
./scripts/ctfctl docker pool-smoke --contest-id local-docker-smoke --workers 2 --json
./scripts/ctfctl docker pool-stop --contest-id local-docker-smoke --json
./scripts/ctfctl callback public-smoke --contest-id local-callback-smoke --provider auto --allow-public --json
```

Final fake rehearsal acceptance requires mock `status: ok`, Codex mini `status: ok`, at least the required local easy set solved, duplicate claims/submissions at zero, `raw_leak_detected: false`, and zero active workers, tunnels, callback listeners, and Docker pool containers after cleanup. The deterministic Codex mini release fixture target is 3/3 solved and accepted.

## GitHub Publish Checklist

Before the first public push:

- Run the release commands above from the WSL repo, not `/mnt/c`.
- Run `git status --short` and keep only source, docs, scripts, tests, and config intended for publication.
- Run `git log --stat`, `git grep` for sensitive patterns, and `scripts/history-scan.sh`.
- If commit history is noisy or uncertain, create a clean public branch or a fresh public repository with a squashed initial commit.
- Do not push local runtime history, generated challenge content, real platform profiles, browser storage, queue databases, callback logs, downloads, or postsolve output.

## Limitations

- Real platform variants differ; generic discovery is bounded and read-only, not a universal crawler.
- Tunnel providers are detected but not bundled or launched by default.
- Competition auto-submit is intentionally gated behind contest arm, profile submission policy, and submit policy. Use `contest arm --no-live-submit` or `policy.allow_submission: false` to keep solving without live submissions.
- Postsolve writeups and archives are local-only draft material and must be reviewed before any public release.

## Documentation

- [GUIDE.md](GUIDE.md): end-to-end operating guide.
- [OPERATIONS.md](OPERATIONS.md): short event-day command guide.
- [docs/architecture.md](docs/architecture.md): system architecture.
- [docs/setup-windows-wsl.md](docs/setup-windows-wsl.md): WSL and worker setup.
- [docs/platform-automation.md](docs/platform-automation.md): platform profiles and read-only sync.
- [docs/contest-operations.md](docs/contest-operations.md): arm/disarm and worker commands.
- [docs/postsolve.md](docs/postsolve.md): local-only postsolve and archive policy.
- [docs/threat-model.md](docs/threat-model.md): risks and mitigations.
