# Contest Operations

This is the operator path for moving from setup/rehearsal into a real competition solve window without accidental solve or submit, then producing local-only postsolve notes after accepted solves.

## Default Safety

Any open real event stays in rehearsal until the operator explicitly arms a contest:

```bash
./scripts/ctfctl preflight --deep --json
./scripts/ctfctl contest prestart \
  --contest-id <contest> \
  --profile ~/.ctf-solver/platforms/<contest>.yaml \
  --json
./scripts/ctfctl docker pool-status --contest-id <contest> --json
./scripts/ctfctl contest status --contest-id <contest> --json
./scripts/ctfctl contest worker-commands --contest-id <contest> --json
```

When a real contest is not armed, `worker-commands` must not include `CTF_RUN_MODE=competition`. Do not run real solve workers, submit flags, automate browser login, or expose public tunnels during rehearsal.

`contest prestart` runs deep local preflight and includes Docker reachability, `ctf-pwn:latest` image readiness, active Docker pool count, and Docker warnings in its JSON. For pwn/rev-heavy events, resolve Docker warnings before arming.

## Rehearsal Sync

Read-only sync can run in rehearsal without arming the contest:

```bash
./scripts/ctfctl platform profile-check \
  --mode rehearsal \
  --config ~/.ctf-solver/platforms/<contest>.yaml \
  --json

./scripts/ctfctl platform sync-challenges \
  --mode rehearsal \
  --config ~/.ctf-solver/platforms/<contest>.yaml \
  --live \
  --save-state \
  --ingest-text \
  --json
```

The sync path discovers and ingests local briefs only. It does not solve, submit, start instances, or start workers.

## Competition Arm

Arm only when the event is ready for actual solving:

```bash
./scripts/ctfctl contest prestart \
  --contest-id <contest> \
  --profile ~/.ctf-solver/platforms/<contest>.yaml \
  --json

./scripts/ctfctl contest arm \
  --contest-id <contest> \
  --profile ~/.ctf-solver/platforms/<contest>.yaml \
  --confirm-competition \
  --max-workers 5 \
  --max-parallel-codex 2 \
  --json
```

Competition arm enables the runner live-submit gate by default. Add `--no-live-submit` when you want real solving without automatic submissions, or keep the platform profile at `policy.allow_submission: false`. `--allow-live-submit` is still accepted for older operator prompts. Add `--allow-instance-start` only when instance start is explicitly allowed by platform policy and contest rules.

The arm command writes local control state only. It does not start workers or submit anything.

For pwn/rev-heavy contests, start the persistent Docker pool before starting workers:

```bash
./scripts/ctfctl docker benchmark --image ctf-pwn:latest --json
./scripts/ctfctl docker pool-smoke --contest-id local-docker-smoke --workers 2 --json
./scripts/ctfctl docker pool-stop --contest-id local-docker-smoke --json

./scripts/ctfctl docker pool-start \
  --contest-id <contest> \
  --workers 5 \
  --image ctf-pwn:latest \
  --json

./scripts/ctfctl docker pool-status --contest-id <contest> --json
```

`contest prestart` and `contest status` report Docker reachability, `ctf-pwn:latest` readiness, active pool counts, and warnings such as `docker_unreachable`, `ctf_pwn_image_missing`, or `docker_pool_not_started`.

Stop contest pool containers explicitly during pause or shutdown:

```bash
./scripts/ctfctl docker pool-stop --contest-id <contest> --json
./scripts/ctfctl contest disarm --contest-id <contest> --stop-docker-pool --json
```

## Worker Supervisor

Use `start-workers` for supervised background workers. The default is still a dry run:

```bash
./scripts/ctfctl contest start-workers --contest-id <contest> --dry-run --json
```

For a real armed competition, inspect the dry-run command first, then apply:

```bash
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

In an armed competition with live submit enabled, the dry-run JSON reports `live_submit_default: true`, and each worker command includes `--live-submit` and `--confirm-submit`. If the contest was armed with `--no-live-submit`, those flags are omitted.

Monitor and control workers:

```bash
./scripts/ctfctl contest worker-status --contest-id <contest> --json
./scripts/ctfctl contest worker-logs --contest-id <contest> --worker-id worker-1 --tail 80 --json
./scripts/ctfctl contest restart-worker --contest-id <contest> --worker-id worker-1 --json
./scripts/ctfctl contest stop-workers --contest-id <contest> --json
```

Supervisor runtime files live under `~/.ctf-solver/runner-state/contests/<contest>/workers/`, outside git. Command files store redacted argv and safe control env only, not raw auth values.

Manual wrapper terminals remain supported:

```bash
./scripts/ctfctl contest worker-commands --contest-id <contest> --json
```

Start only the emitted `scripts/ctf-worker-*` commands in separate terminals. Respect `max_parallel_codex`; for example, with `max_parallel_codex=2`, start at most two Codex worker terminals at once.

## Callback And Tunnel Resources

For challenge workflows that need callbacks, start the local listener and public tunnel with contest linkage:

```bash
./scripts/ctfctl callback start \
  --contest-id <contest> \
  --challenge-id <challenge> \
  --worker-id worker-1 \
  --json

./scripts/ctfctl tunnel start \
  --listener-id <listener> \
  --contest-id <contest> \
  --challenge-id <challenge> \
  --worker-id worker-1 \
  --provider auto \
  --allow-public \
  --json
```

Inspect active and stale resources during the event:

```bash
./scripts/ctfctl contest resources --contest-id <contest> --json
./scripts/ctfctl contest status --contest-id <contest> --json
```

Default output redacts public tunnel hosts and strips URL queries. Use `--show-public-url` only in a local terminal when an active workflow needs the query-stripped public URL. Do not paste public tunnel URLs, callback hit summaries, or tunnel logs into writeups or commits.

Clean up after a challenge or pause:

```bash
./scripts/ctfctl contest cleanup-resources --contest-id <contest> --json
```

Cleanup stops active callback listeners and tunnel provider processes, updates stale PID records, and appends local cleanup events. It does not delete useful logs by default.

## Submit Gate

Live submit requires all gates:

- contest is armed
- arm state has `allow_live_submit: true`; competition arm sets this by default unless `--no-live-submit` is used
- worker submit uses the internal `--confirm-submit` added by `contest start-workers`; manual platform submit uses `--confirm`
- platform profile has `policy.allow_submission: true`
- submit policy passes confidence, duplicate hash, cooldown, wrong-limit, and fake-like checks

Setup and rehearsal block real live submit before platform submit code is called. Without all competition gates, the runner records a blocked or planned submit and must not call the live submit endpoint.

## Disarm

After the contest or any pause in live operations:

```bash
./scripts/ctfctl contest disarm --contest-id <contest> --stop-workers --cleanup-resources --stop-docker-pool --json
./scripts/ctfctl contest status --contest-id <contest> --json
```

Disarm removes the active arm lock and marks the contest back to rehearsal. With `--stop-workers`, it also terminates supervised workers. With `--cleanup-resources`, it stops tracked callback listeners and public tunnels. With `--stop-docker-pool`, it removes contest Docker pool containers. Without those cleanup flags, disarm reports warnings when supervised workers, callback/tunnel resources, or active Docker pool containers remain. It does not delete downloads, briefs, state DB rows, telemetry, handoffs, callback logs, tunnel logs, Docker workspace files, postsolve drafts, or artifact archives.

After disarm, review local postsolve status before any cleanup:

```bash
./scripts/ctfctl postsolve batch --contest-id <contest> --status solved --json
./scripts/ctfctl postsolve skill-candidates --contest-id <contest> --json
```

Do not push generated writeups, archives, downloaded files, queue DBs, telemetry, or flags during a contest.

## Local-Only Postsolve

Accepted fake/local solves can generate postsolve files automatically. Real competition postsolve generation is allowed only while the contest is armed; rehearsal and unarmed real challenges do not auto-generate solve drafts.

For a solved challenge:

```bash
./scripts/ctfctl postsolve generate \
  --contest-id <contest> \
  --challenge-id <challenge> \
  --json

./scripts/ctfctl postsolve status \
  --contest-id <contest> \
  --challenge-id <challenge> \
  --json

./scripts/ctfctl postsolve archive \
  --contest-id <contest> \
  --challenge-id <challenge> \
  --json
```

Generated files live under `~/CTF/contests/<contest>/<challenge>/postsolve/` by default. `writeup_draft.md` is a private operator draft for later organizer formatting, not a public writeup. `skill_candidate.md` is only a review candidate; after the contest, manually decide whether a sanitized pattern belongs in the existing personal skill repository.

## Local Fake Smoke

Use a fake/example profile for arm smoke tests:

```bash
./scripts/ctfctl contest arm \
  --contest-id local-fake \
  --profile config/platforms.yaml.example \
  --confirm-competition \
  --max-workers 3 \
  --max-parallel-codex 2 \
  --json

./scripts/ctfctl contest worker-commands --contest-id local-fake --json
./scripts/ctfctl contest disarm --contest-id local-fake --json
```

Supervisor smoke uses only a loopback fake CTFd server:

```bash
./scripts/ctfctl contest supervisor-smoke --workers 3 --solver mock --fake-ctfd --json
./scripts/ctfctl contest worker-status --contest-id local-fake --json
./scripts/ctfctl contest stop-workers --contest-id local-fake --json
```

Do not arm a real contest during rehearsal. Keep real auth profiles, cookies, browser storage, downloads, queue DBs, writeups, and flags outside git.

## Final Full Rehearsal

Before the first real contest, run the full fake competition rehearsal. It uses only a loopback fake CTFd server, local fake challenges, a local callback public-smoke listener, and the local Docker pool:

```bash
./scripts/ctfctl contest full-rehearsal \
  --contest-id final-fake \
  --workers 5 \
  --solver mock \
  --json
```

For an actual Codex mini rehearsal against local fake challenges:

```bash
./scripts/ctfctl contest full-rehearsal \
  --contest-id final-fake-codex \
  --workers 3 \
  --max-parallel-codex 2 \
  --solver codex \
  --allow-codex-call \
  --json
```

The mock full rehearsal must report `status: ok`. The Codex mini release rehearsal must also report `status: ok`; `status: acceptable` means cleanup and safety criteria passed but the model did not solve enough local mini fixtures for release readiness. The current deterministic local target is 3/3 easy Codex challenges solved and accepted.

Acceptance criteria checked by the full rehearsal:

- preflight `risk.High` is empty
- fake platform starts and stops on `127.0.0.1`
- at least five fake challenges are discovered and ingested for the mock run
- workers start, finish, and leave zero active workers
- duplicate claims and duplicate submissions are zero
- easy fake challenges solve, the stalled fixture stalls, and a handoff is recorded
- accepted submissions are recorded hash-only
- postsolve summaries are generated for solved fake challenges
- callback/tunnel resources and Docker pool containers are zero after cleanup
- raw leak detection is false
- release-check passes
- per-challenge failure summaries are present and public-safe when anything fails

Reports are local-only:

```text
~/.ctf-solver/runner-state/contests/<contest_id>/rehearsal_report.json
~/.ctf-solver/runner-state/contests/<contest_id>/rehearsal_summary.md
```

Do not copy report internals into public writeups. The CLI summary is already redacted and public-safe.

## Release Hardening Commands

Before publishing a public repository, run:

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

`fresh-clone-check.sh` verifies that a temporary file-based clone can compile, test, pass public checks, run preflight, start the fake CTFd smoke, and complete the mock local E2E without relying on untracked local state. Use `--keep-dir` only for local debugging, then delete the clone before publishing.

## Recommended Competition Flow

1. `./scripts/ctfctl preflight --deep --json`
2. `./scripts/ctfctl contest full-rehearsal --contest-id final-fake --workers 5 --solver mock --json`
3. Codex mini: `./scripts/ctfctl contest full-rehearsal --contest-id final-fake-codex --workers 3 --max-parallel-codex 2 --solver codex --allow-codex-call --json`
4. Rehearsal read-only sync with `platform sync-challenges --mode rehearsal ... --live --save-state --ingest-text --json`
5. `./scripts/ctfctl contest prestart --contest-id <contest> --profile <local-profile> --json`
6. `./scripts/ctfctl contest arm --contest-id <contest> --profile <local-profile> --confirm-competition --json`
7. `./scripts/ctfctl contest start-workers --contest-id <contest> --dry-run --json`
8. `./scripts/ctfctl contest start-workers --contest-id <contest> --apply --solver codex --allow-codex-call --json`
9. Monitor with `worker-status` and `worker-logs`.
10. `./scripts/ctfctl contest disarm --contest-id <contest> --stop-workers --cleanup-resources --stop-docker-pool --json`
