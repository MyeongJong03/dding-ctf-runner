# Contest Operations: Legacy And Advanced Controls

This page is not the default live runbook. The normal contest workflow is the
interactive Codex swarm described in [interactive-operations.md](interactive-operations.md):

```bash
./scripts/ctfctl interactive init --contest-id <contest> --profile ~/.ctf-solver/platforms/<contest>.yaml --agents 4 --json
./scripts/ctfctl interactive sync --contest-id <contest> --profile ~/.ctf-solver/platforms/<contest>.yaml --live --download --ingest --json
./scripts/ctfctl interactive prompt --contest-id <contest> --agent agent-1
cd ~/CTF && codex
```

Use the background worker flow only for fake/local E2E, compatibility tests,
legacy automation, or an explicit operator decision.

## Advanced Safety Gates

Real platform actions stay behind `ctfctl`, `--live`, and confirmation gates.
Prestart does not start workers or submit anything:

```bash
./scripts/ctfctl preflight --deep --json
./scripts/ctfctl contest prestart --contest-id <contest> --profile ~/.ctf-solver/platforms/<contest>.yaml --json
./scripts/ctfctl contest status --contest-id <contest> --json
```

Arm only when deliberately testing advanced competition automation:

```bash
./scripts/ctfctl contest arm \
  --contest-id <contest> \
  --profile ~/.ctf-solver/platforms/<contest>.yaml \
  --confirm-competition \
  --max-workers 5 \
  --max-parallel-codex 2 \
  --json
```

Competition arm enables the live-submit gate by default. Add
`--no-live-submit` to keep advanced workers from submitting live candidates.
Profile `policy.allow_submission: false` also blocks live submit.

## Read-Only Sync

For default live play, prefer:

```bash
./scripts/ctfctl interactive sync --contest-id <contest> --profile ~/.ctf-solver/platforms/<contest>.yaml --live --download --ingest --json
```

The older platform sync remains useful for rehearsals:

```bash
./scripts/ctfctl platform sync-challenges \
  --mode rehearsal \
  --config ~/.ctf-solver/platforms/<contest>.yaml \
  --live \
  --save-state \
  --ingest-text \
  --json
```

This path discovers and ingests local briefs only. It must not solve, submit,
start instances, or expose tunnels.

## Legacy Background Workers

Dry run first:

```bash
./scripts/ctfctl contest start-workers --contest-id <contest> --dry-run --json
```

Apply only after an explicit advanced-automation decision:

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

Monitor and stop:

```bash
./scripts/ctfctl contest worker-status --contest-id <contest> --json
./scripts/ctfctl contest worker-logs --contest-id <contest> --worker-id worker-1 --tail 80 --json
./scripts/ctfctl contest stop-workers --contest-id <contest> --json
```

Supervisor files live under
`~/.ctf-solver/runner-state/contests/<contest>/workers/` and store redacted
commands/status, not raw auth values. Local terminal output may include flags,
solver output, and exploit output when needed for solving and verification, but
do not commit, push, paste publicly, publish, or upload flags or auth material
during an active contest.

Manual legacy wrapper commands:

```bash
./scripts/ctfctl contest worker-commands --contest-id <contest> --json
```

Run only the emitted `scripts/ctf-worker-*` commands. Do not start these with
plain `codex`.

## Docker Pool

Interactive solvers can also use the Docker helpers directly. Start a pool only
when pwn/rev work needs it:

```bash
./scripts/ctfctl docker benchmark --image ctf-pwn:latest --json
./scripts/ctfctl docker pool-start --contest-id <contest> --workers 4 --image ctf-pwn:latest --json
./scripts/ctfctl docker pool-status --contest-id <contest> --json
./scripts/ctfctl docker pool-stop --contest-id <contest> --json
```

On macOS, keep Docker workspaces outside `~/CTF`:

```bash
export CTF_DOCKER_WORKSPACE_ROOT="$HOME/.ctf-solver/runner-state/docker-workspaces"
```

## Callback And Tunnel Resources

Start public exposure only for a challenge that needs it:

```bash
./scripts/ctfctl callback start --contest-id <contest> --challenge-id <challenge> --worker-id agent-1 --json
./scripts/ctfctl tunnel start --contest-id <contest> --challenge-id <challenge> --worker-id agent-1 --listener-id <listener> --provider auto --allow-public --json
```

Inspect and cleanup:

```bash
./scripts/ctfctl contest resources --contest-id <contest> --json
./scripts/ctfctl contest cleanup-resources --contest-id <contest> --json
```

Do not paste public tunnel URLs, callback hit summaries, or tunnel logs into
writeups or commits.

## Disarm And Cleanup

For advanced worker runs:

```bash
./scripts/ctfctl contest disarm --contest-id <contest> --stop-workers --cleanup-resources --stop-docker-pool --json
./scripts/ctfctl contest status --contest-id <contest> --json
```

Disarm does not delete downloads, briefs, local evidence, memos, writeups,
handoffs, callback logs, or Docker workspace files.

## Local Rehearsal

Loopback-only checks:

```bash
./scripts/ctfctl fake-ctfd smoke --json
./scripts/ctfctl worker local-e2e --workers 3 --solver mock --fake-ctfd --json
./scripts/ctfctl contest supervisor-smoke --workers 3 --solver mock --fake-ctfd --json
```

Legacy/advanced full fake rehearsal:

```bash
./scripts/ctfctl contest full-rehearsal --contest-id final-fake --workers 5 --solver mock --json
./scripts/ctfctl contest full-rehearsal --contest-id final-fake-codex --workers 3 --max-parallel-codex 2 --solver codex --allow-codex-call --json
```

Reports are local-only under
`~/.ctf-solver/runner-state/contests/<contest_id>/`.

## Release Hardening

Default release hardening is interactive-first. Keep worker/full-rehearsal checks as legacy/advanced compatibility coverage.

```bash
python3 -m compileall -q ctf_runner
python3 -m pytest -q
./scripts/ctfctl interactive e2e-smoke --contest-id release-interactive-e2e --agents 2 --json
./scripts/ctfctl interactive metrics baseline --name release-smoke --output-dir /tmp/dding-ctf-runner-release-metrics --json
./scripts/release-check.sh
./scripts/ctfctl repo public-check --json
./scripts/fresh-clone-check.sh
./scripts/history-scan.sh
git diff --check
```
