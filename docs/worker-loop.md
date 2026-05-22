# Worker Solve Loop

Phase 6 connects the local solve path. Setup and rehearsal do not make real live submissions; armed competition supervisor workers auto-submit high-confidence candidates when profile and submit-policy gates pass. Phase 6.3 adds a local fake CTFd multi-worker smoke that exercises concurrent queue claims and guarded local loopback submissions.

Worker execution is guarded by run mode:

- `setup`: fake/local challenges are allowed; real platform challenges are blocked before prompt construction, Codex calls, or submit planning.
- `rehearsal`: real platform challenges are blocked unless the worker command includes `--allow-real-solve-dry-run`; live submit is still disabled.
- `competition`: real platform challenges can run only with `--confirm-competition` and an armed contest. Live submit is on by default for supervised workers when the arm state allows it; it still needs profile `allow_submission: true` and submit policy approval.

Pwn/rev workers should use the persistent Docker pool when it has been started for the contest. Start it before assigning pwn/rev-heavy queues so workers avoid repeated one-shot `docker run` startup cost:

```bash
ctfctl docker pool-start --contest-id <contest> --workers 5 --json
ctfctl docker pool-exec --contest-id <contest> --worker-id worker-1 --command "file ./chall" --json
```

For pwn/rev category claims, the solve prompt includes a safe Docker hint with the contest ID, worker ID, container name, workspace path, and `ctfctl docker pool-exec` form. The worker should keep secrets out of Docker env, command args, logs, and copied files. The pool workspace is `~/CTF/workspaces/<contest>/<worker>` on Linux/WSL or `~/.ctf-solver/runner-state/docker-workspaces/<contest>/<worker>` on macOS, mounted at `/workspace`.

Flow:

1. Queue claim: `ctfctl worker once --worker-id worker-1 --solver mock --json` claims the next `new`, `queued`, or `ingest_ready` challenge.
2. Brief: the worker uses an existing `brief.md` under the contest tree or creates a minimal generated brief under runner state.
3. Prompt: `ctf_runner.solve_prompt` builds a compact prompt with metadata, brief content, selected file evidence, strict output schema, and safety rules.
4. Solver: `mock` is the default and performs no external calls. `codex` is disabled unless `--allow-codex-call` is passed.
5. Parse: `ctf_runner.solve_result` looks for `FLAG_CANDIDATE: <flag>` and fallback flag-like strings.
6. Submit planning: candidates go through `submit.should_submit`; raw candidates are used only in memory for planning.
7. State: accepted local fake submissions move the challenge to `solved`; accepted plans without a live local submit move the challenge to `submit_planned`; no usable candidate moves it to `stalled`; worker exceptions move it to `error`.
8. Postsolve: accepted fake/local solves generate local-only postsolve drafts by default. Real competition solves generate them only while the contest is armed. Use `--postsolve` to request generation and `--no-postsolve` to suppress it.
9. Telemetry: worker events are appended with redacted/hash-only details.

Multi-worker local E2E:

- Mock smoke: `ctfctl worker local-e2e --workers 5 --solver mock --fake-ctfd --json`
- Codex smoke: `ctfctl worker local-e2e --workers 3 --max-parallel 2 --solver codex --fake-ctfd --json`
- Alias: `ctfctl worker parallel-smoke --workers 5 --solver mock --json`
- Status: `ctfctl worker status --json`

The fake CTFd server binds only to `127.0.0.1`. The local E2E command starts it, discovers five fixture challenges, downloads and ingests all attachments, then runs one worker attempt per configured worker. Runtime output reports counts, worker stats, accepted/rejected/blocked submission counts, duplicate claim count, handoff count, and postsolve summary count. It does not print raw candidates.

Supervisor workers:

- Dry run command generation: `ctfctl contest start-workers --contest-id <id> --dry-run --json`
- Start supervised workers: `ctfctl contest start-workers --contest-id <id> --apply --workers 5 --json`
- Monitor: `ctfctl contest worker-status --contest-id <id> --json`
- Tail redacted logs: `ctfctl contest worker-logs --contest-id <id> --worker-id worker-1 --tail 80 --json`
- Restart one worker: `ctfctl contest restart-worker --contest-id <id> --worker-id worker-1 --json`
- Stop all workers: `ctfctl contest stop-workers --contest-id <id> --json`

The supervisor writes PID, status, redacted command, and log files under `~/.ctf-solver/runner-state/contests/<id>/workers/`. Fake/local smoke may run in setup mode. Real platform competition workers require an armed contest before `--apply` can start them.

Manual wrapper terminals:

- `ctfctl contest worker-commands --contest-id <id> --json` emits `scripts/ctf-worker-*` commands.
- Use manual terminals when interactive observation matters.
- Use the supervisor when the goal is long-running unattended worker processes.
- Wrapper launches default to no-prompt automation with model auto/unpinned unless `CTF_CODEX_MODEL` explicitly pins a model.

Parallel policy:

- `mock` defaults to `--max-parallel == --workers`.
- `codex` defaults to `--max-parallel 2`; raise it only after observing local machine and Codex session behavior.
- Fake/mock supervisor smoke can use 5 workers.
- Real Codex competitions should start with 4-5 workers and `--max-parallel-codex 2`, then increase only after observing stability and rate limits.
- Workers use `worker-1` through `worker-N`; Codex calls go through `scripts/run-codex-worker.sh`, which sets worker-specific `CODEX_HOME`.
- Each local E2E run creates a separate ignored `state/local-e2e/...` run directory with per-worker work subdirectories.

Queue and stale claims:

- SQLite uses WAL mode, a busy timeout, and `BEGIN IMMEDIATE` during claims.
- `claim_next_challenge` atomically registers the worker, reclaims stale active claims, selects a claimable challenge, and records the active claim.
- `solved`, `submit_planned`, `stalled`, `error`, `blocked_by_mode`, and `abandoned` are not immediately claimable.
- Active claims carry `heartbeat_at`; stale claims can be reclaimed after `stale_after_sec` and are archived in `claim_history`.

Solver output format:

```text
STATUS: solved|stalled
CONFIDENCE: high|medium|low
EVIDENCE_SOURCE: <local path or unknown>
DERIVATION: <compact steps, redacted>
FLAG_CANDIDATE: <flag>
REJECTED_CANDIDATES:
- <redacted candidate reason, or none>
NEXT_IDEAS:
- <next action>
```

The parser also accepts JSON objects, markdown tables, and natural language fallbacks, but workers should emit the structured block above. Submit planning treats local evidence plus derivation as strong provenance and excludes rejected candidates from submit plans.

Handoff format:

- File: `<runner-state>/handoffs/handoff.jsonl`
- Fields: timestamp, challenge_id, status, reason, facts, attempts, next_ideas, flag_hashes.
- Raw flags and transcripts are not written.
- The `stalled-1` fake fixture should create exactly one handoff in the 5-worker mock smoke.

Duplicate submit guards:

- Duplicate detection is SHA-256 based per challenge.
- Already solved challenges are blocked before another worker submits.
- Fake/test/example-like candidates are blocked by submit policy.
- The fake CTFd server remembers solved challenge IDs and returns an already-solved style response for repeated accepted submissions.

Dry-run and mock testing:

- Default: `ctfctl worker once --worker-id worker-1 --solver mock --json`
- Disable automatic local postsolve generation: `ctfctl worker once --worker-id worker-1 --solver mock --no-postsolve --json`
- Request postsolve generation explicitly: `ctfctl worker once --worker-id worker-1 --solver mock --postsolve --json`
- Prompt preview: `ctfctl solve prompt --challenge-id <id> --json`
- Parse preview: `ctfctl solve parse --text "STATUS: stalled" --json`
- Codex call: add `--solver codex --allow-codex-call` only for an intentional one-shot model call.
- Full local fake CTFd replay: `ctfctl worker local-e2e --workers 5 --solver mock --fake-ctfd --json`

For a real generic platform, sync read-only challenge briefs first, then run a single dry-run worker:

```bash
ctfctl platform sync-challenges --mode rehearsal --config <local-profile> --live --save-state --ingest-text --json
ctfctl worker once --mode rehearsal --worker-id worker-1 --solver codex --allow-codex-call --json
ctfctl worker once --mode rehearsal --allow-real-solve-dry-run --worker-id worker-1 --solver codex --allow-codex-call --json
```

The first worker command is the expected default guard check: rehearsal mode blocks real platform solving with `rehearsal_requires_allow_real_solve_dry_run` before prompt construction or Codex execution. Only the second command intentionally permits a dry-run solve against local briefs, and it still cannot submit. The worker reads the local `brief.md` generated from attachments or text-only statements. It should not browse the live platform, submit flags, start instances, or expose tunnels. Any candidate remains a submit plan unless competition mode and live submission gates are explicitly enabled.

Token budget notes:

- Prompts target 20KB or less.
- Brief content is preferred over broad file inclusion.
- Selected file excerpts are bounded and sensitive-looking filenames are skipped.

Before real competition worker execution:

- Run `ctfctl preflight --deep --json` and verify `risk.High` is empty.
- Run `ctfctl docker benchmark --image ctf-pwn:latest --json` from a normal WSL terminal.
- Run `ctfctl docker pool-smoke --contest-id local-docker-smoke --workers 2 --json` and stop it with `ctfctl docker pool-stop --contest-id local-docker-smoke --json`.
- Start the pwn/rev pool before assigning pwn/rev-heavy queues: `ctfctl docker pool-start --contest-id <id> --workers 5 --json`.
- Run `ctfctl platform profile-check --config <local-profile> --json` before any live traffic.
- Run `ctfctl platform sync-challenges --mode rehearsal --config <local-profile> --live --save-state --ingest-text --json` to prepare local briefs without solving.
- Run the 5-worker mock local E2E and inspect duplicate claim/submission counts.
- Run a bounded Codex mini rehearsal with `--workers 3 --max-parallel-codex 2`; release readiness expects `status: ok` and the deterministic local easy set solved 3/3.
- Run `ctfctl contest prestart --contest-id <id> --profile <local-profile> --json`; this does not make live requests unless `--live-readonly-check` is added.
- Arm only when ready: `ctfctl contest arm --contest-id <id> --profile <local-profile> --confirm-competition --json`.
- Generate supervised commands first: `ctfctl contest start-workers --contest-id <id> --dry-run --json`.
- Start supervised workers only after reviewing the dry run: `ctfctl contest start-workers --contest-id <id> --apply --solver codex --allow-codex-call --no-stop-when-empty --json`.
- Alternatively, generate manual terminal commands with `ctfctl contest worker-commands --contest-id <id> --json` and use the emitted `scripts/ctf-worker-*` wrappers.
- After the event, run `ctfctl contest disarm --contest-id <id> --stop-workers --json`.
- Stop pwn/rev containers with `ctfctl contest disarm --contest-id <id> --stop-docker-pool --json` or `ctfctl docker pool-stop --contest-id <id> --json`.
- Keep live platform actions behind `ctfctl`, `--live`, and confirmation gates.
- Confirm runtime state, telemetry, downloads, writeups, and handoffs are outside git.

Competition start order:

1. `ctfctl preflight --deep --json`
2. Rehearsal read-only sync with `ctfctl platform sync-challenges --mode rehearsal ... --live --save-state --ingest-text --json`
3. `ctfctl contest prestart --contest-id <id> --profile <local-profile> --json`
4. If pwn/rev is expected, `ctfctl docker pool-start --contest-id <id> --workers 5 --json`
5. `ctfctl contest arm --contest-id <id> --profile <local-profile> --confirm-competition --json`
6. `ctfctl contest start-workers --contest-id <id> --dry-run --json`
7. `ctfctl contest start-workers --contest-id <id> --apply --solver codex --allow-codex-call --no-stop-when-empty --json`
8. Monitor with `ctfctl contest worker-status --contest-id <id> --json` and `ctfctl contest worker-logs --contest-id <id> --worker-id worker-1 --tail 80 --json`.
9. `ctfctl contest disarm --contest-id <id> --stop-workers --stop-docker-pool --json` after the contest.
