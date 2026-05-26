# Legacy Worker Solve Loop

This is legacy/advanced documentation. The default live CTF workflow is the
interactive Codex swarm: run `ctfctl interactive ...`, then start visible
Codex sessions with `cd ~/CTF && codex`. See
[interactive-operations.md](interactive-operations.md).

Use the worker loop only for fake/local E2E, compatibility tests, or an
explicit advanced automation decision.

## Guarded Modes

Worker execution is guarded by run mode:

- `setup`: fake/local challenges are allowed; real platform challenges are blocked before prompt construction, Codex calls, or submit planning.
- `rehearsal`: real platform challenges are blocked unless `--allow-real-solve-dry-run` is present; live submit is disabled.
- `competition`: real platform challenges require `--confirm-competition` and an armed contest. Live submit still needs profile `allow_submission: true` and submit policy approval.

## One-Shot Worker Flow

```bash
ctfctl worker once --worker-id worker-1 --solver mock --json
ctfctl worker once --worker-id worker-1 --solver codex --allow-codex-call --json
```

Flow:

1. Claim the next queue challenge.
2. Load or generate a compact `brief.md`.
3. Build a bounded solve prompt.
4. Run `mock` or an explicitly allowed Codex call.
5. Parse solver output for candidates.
6. Plan submit with duplicate, confidence, wrong-limit, cooldown, and fake-like guards.
7. Record solved, submit-planned, stalled, error, or blocked state.
8. Generate local-only postsolve output only for accepted solves when enabled.
9. Write redacted/hash-only telemetry.

Raw candidates stay in memory for submit planning. Runtime state stores hashes or redacted summaries only.

## Local E2E

```bash
ctfctl worker local-e2e --workers 5 --solver mock --fake-ctfd --json
ctfctl worker local-e2e --workers 3 --max-parallel 2 --solver codex --fake-ctfd --json
ctfctl worker status --json
```

The fake CTFd server binds only to `127.0.0.1`. The local E2E path reports
counts, worker stats, accepted/rejected/blocked submissions, duplicate claim
count, handoff count, and postsolve summary count. It does not print raw
candidates.

## Supervisor Workers

Dry run:

```bash
ctfctl contest start-workers --contest-id <id> --dry-run --json
```

Apply only for deliberate legacy/advanced automation:

```bash
ctfctl contest start-workers --contest-id <id> --apply --workers 5 --solver codex --allow-codex-call --json
```

Monitor and stop:

```bash
ctfctl contest worker-status --contest-id <id> --json
ctfctl contest worker-logs --contest-id <id> --worker-id worker-1 --tail 80 --json
ctfctl contest restart-worker --contest-id <id> --worker-id worker-1 --json
ctfctl contest stop-workers --contest-id <id> --json
```

Supervisor files live under
`~/.ctf-solver/runner-state/contests/<id>/workers/` outside git. Command and log
output is redacted before display.

## Manual Legacy Wrappers

```bash
ctfctl contest worker-commands --contest-id <id> --json
```

Run only the emitted `scripts/ctf-worker-*` commands. These wrappers set
worker-specific `CODEX_HOME` and avoid relying on plain `codex`.

## Docker Pool

Pwn/rev workers can use the persistent Docker pool:

```bash
ctfctl docker pool-start --contest-id <contest> --workers 5 --json
ctfctl docker pool-exec --contest-id <contest> --worker-id worker-1 --command "file ./chall" --json
ctfctl docker pool-stop --contest-id <contest> --json
```

Keep secrets out of Docker env vars, command args, logs, and copied files. On
macOS, pool workspaces should live under
`~/.ctf-solver/runner-state/docker-workspaces/` rather than `~/CTF`.

## Handoffs And Stalled Work

Stalled workers write compact local handoffs with facts, attempts, next ideas,
and flag hashes only. Do not write raw flags, raw exploit transcripts, auth
material, browser storage, callback payloads, or downloaded private files into
handoffs.

## Before Any Legacy Competition Run

```bash
ctfctl preflight --deep --json
ctfctl platform profile-check --config <local-profile> --json
ctfctl contest prestart --contest-id <id> --profile <local-profile> --json
ctfctl contest arm --contest-id <id> --profile <local-profile> --confirm-competition --json
ctfctl contest start-workers --contest-id <id> --dry-run --json
```

Review the dry run before `--apply`. After the event:

```bash
ctfctl contest disarm --contest-id <id> --stop-workers --cleanup-resources --stop-docker-pool --json
```
