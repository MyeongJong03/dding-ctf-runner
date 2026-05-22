# Architecture

`dding-ctf-runner` is a shell-first competition runner. `ctfctl` is the stable control plane for preflight, local state, queue claims, worker registration, persistent Docker containers, auth metadata checks, platform adapters, and guarded submissions.

`~/ctf-solver` remains unchanged and can be used as a library or reference toolbox. This repo provides the competition-specific automation layer around workers and live platform policy.

Local state lives outside git by default in `~/.ctf-solver/runner-state`. Secrets live outside git in `~/.ctf-solver/secrets`. Challenge downloads and workspaces live under `~/CTF/contests` and `~/CTF/workspaces` unless configured otherwise.

## Run Modes

`ctfctl` resolves an execution guard mode from `--mode`, then `CTF_RUN_MODE`, then the default `setup`. The supported modes are:

- `setup`: local fake/mock tests, profile checks, and real read-only discovery are allowed. Real platform download/ingest requires `--allow-real-readonly`. Real challenge solve, live submit, instance start, browser login automation, and public tunnel exposure are blocked.
- `rehearsal`: real platform read-only discovery, download, and ingest are allowed. Real challenge solve remains blocked unless a one-shot worker uses `--allow-real-solve-dry-run`, and live submit remains blocked.
- `competition`: real challenge solve can run only after `--confirm-competition` and an armed contest control state. Live submit is enabled by default when the contest is armed, unless `--no-live-submit` is used, and still needs profile submission policy plus submit-policy approval. Instance start likewise needs an armed contest that allows instance start plus platform policy.

The mode guard is enforced in the CLI and worker loop. A setup-mode worker that claims a real platform challenge stops before prompt construction or solver execution and records `blocked_by_mode`.

## Contest Control Plane

Phase 8 adds a contest control plane for the transition from rehearsal to real competition execution. Control state lives outside git at:

```text
~/.ctf-solver/runner-state/contests/<contest_id>/
```

The directory contains `control.json`, `arm.lock`, `disarm.log`, generated `worker_commands.sh`, and a `workers/` supervisor subdirectory. `control.json` stores only non-secret control metadata: contest ID, profile path, run mode, armed state, timestamps, operator confirmation marker, live submit and instance-start booleans, worker limits, and notes. It never stores raw cookies, tokens, browser storage, auth headers, passwords, private keys, or flags.

The arm sequence is explicit:

```bash
ctfctl contest prestart --contest-id <id> --profile <profile> --json
ctfctl contest arm --contest-id <id> --profile <profile> --confirm-competition --json
ctfctl contest start-workers --contest-id <id> --dry-run --json
ctfctl contest start-workers --contest-id <id> --apply --json
```

`prestart` runs local checks and profile/storage metadata checks without live platform traffic by default. `arm` writes the control state but does not sync challenges, start workers, submit flags, start instances, automate login, or expose tunnels. `start-workers` is dry-run by default and requires `--apply` to launch supervised processes. Manual `worker-commands` still emits wrapper-based `scripts/ctf-worker-*` terminal commands and includes `CTF_RUN_MODE=competition` only while the contest is armed.

The supervisor stores `worker-N.pid`, `worker-N.status.json`, `worker-N.log`, `worker-N.command.json`, and `supervisor_events.jsonl` under `workers/`. Command records contain redacted argv and safe control env only.

Disarming removes the active arm lock, marks the control state as rehearsal, and preserves artifacts for local review:

```bash
ctfctl contest disarm --contest-id <id> --stop-workers --json
```

Codex workers are isolated from the user's global Codex profile. Plain `codex` is forbidden for competition workers because it may start from `~/CTF`, load the long global prompt, or inherit an interactive-shell alias that injects approval or sandbox flags. Operators use `scripts/ctf-worker-*` shortcuts, which call `scripts/ctf-worker`, then `scripts/run-codex-worker.sh`. This execution model changes to `~/dding-ctf-runner`, sets `CODEX_HOME=~/.codex-workers/<worker-id>`, adds the runner-safe writable directories with de-duplication, and relies on the runner's slim `AGENTS.md`.

The runner resolves a preferred real Codex binary through `ctfctl codex preferred-bin` and executes that path directly instead of relying on shell alias expansion. Selection prefers `CTF_CODEX_BIN` when set, otherwise the highest detected semantic version, then PATH order on ties. `ctfctl codex doctor` reports active vs preferred binaries, alias detection, PATH conflicts, and likely update mismatch causes.

The runner is not MCP-first. MCP configuration is treated as plain Codex hygiene: `ctfctl codex mcp-status --json` reports only MCP server names from `~/.codex/config.toml` and `~/.codex-workers/*/config.toml`, never command args or env values. A legacy `dreamhack_solver` MCP entry can cause plain Codex startup warnings, so `scripts/fix-codex-mcp.sh --remove-legacy-dreamhack --apply` removes only that entry after a backup. This warning is not a direct blocker for runner workers because they use shell-first `ctfctl` and isolated worker homes, but leaving it in place creates startup noise and operator confusion. `ReVa` may remain for Ghidra workflows; `ctf_solver` MCP can be registered later if a future workflow explicitly needs it.

Competition workers default to Codex model auto-selection: the wrapper omits `--model` unless `CTF_CODEX_MODEL` is set to a concrete non-`auto` value. Auto/unpinned means "use the installed Codex CLI's current default model"; it does not promise the newest or strongest available model. The runner repo intentionally does not hard-code a default model. Worker-local `config.toml` also stays unpinned by default; `ctfctl codex set-model` is for reproducibility, and `ctfctl codex unset-model` / `unset-model-all` returns workers to auto/unpinned policy. A hard-pinned model is a preflight warning, not a blocker.

Competition workers also default to no-prompt automation: `--ask-for-approval never` plus `--sandbox danger-full-access`. Operators can opt down with `CTF_CODEX_DANGER=0` and an explicit `CTF_CODEX_SANDBOX` such as `workspace-write`. `CTF_CODEX_IGNORE_USER_CONFIG=1` isolates the launch through the worker home without modifying `~/CTF/AGENTS.md`, `~/CTF/CLAUDE.md`, `~/.codex/AGENTS.md`, or raw `~/.codex/config.toml`. A preflight `global_long_agents` warning is acceptable when workers are launched through these wrappers.

Recommended launches:

- Default: `./scripts/ctf-worker-1`
- Reproducible model override: `CTF_CODEX_MODEL=gpt-5.4 ./scripts/ctf-worker-1`
- Safer local override: `CTF_CODEX_DANGER=0 CTF_CODEX_SANDBOX=workspace-write ./scripts/ctf-worker-1`
- Diagnose wrapper shape: `./scripts/ctf-worker-1 --dry-run`
- Observe actual default model: `./scripts/ctfctl codex default-model-smoke --worker-id worker-1 --json`
- Include default-model observation in deep preflight: `./scripts/ctfctl preflight --deep --model-smoke --json`

Plain `codex` can keep the user's existing alias preference for non-runner work, but competition solving should use `ctf-worker-*` only. For reproducibility, record a concrete model in the contest profile at event start; for latest/default tracking, leave `CTF_CODEX_MODEL` unset or empty.

Codex product caches, including model onboarding caches such as `models_cache.json`, are not automatically deleted by the runner. Product-managed notices may still appear after model pins are removed; the runner's responsibility is to avoid forcing a stale model so Codex can follow current defaults.

Phase 2 adds readiness checks for browser, callback, and tunnel work:

- `ctf_runner.browser_smoke` verifies Playwright import and, in deep mode, launches Chromium against local HTML only.
- `ctf_runner.callback_smoke` starts a loopback-only HTTP callback server on `127.0.0.1` and validates a local `/ping` request.
- `ctf_runner.tunnel` detects public tunnel providers without starting them and reports cloudflared/bore preference plus manual fallbacks.
- `ctfctl preflight --deep` combines import checks, local callback smoke, tunnel detection, and browser launch smoke without external CTF traffic.

Phase 3 adds an attachment-aware ingest pipeline:

- `ctf_runner.archive` safely extracts supported archives into an `extracted/` tree with path traversal, symlink/hardlink, file count, total size, and single-file limits.
- `ctf_runner.file_manifest` records every discovered file as bounded metadata: relative path, size, extension, detected type, hash, category, preview eligibility, and redacted previews for small text/source/config files.
- `ctf_runner.source_scan` performs bounded non-executing quick signal detection for web, pwn/rev, crypto, forensics, and misc workflows.
- `ctf_runner.brief` renders a compact `brief.md` intended as the initial worker context.
- `ctf_runner.ingest` ties raw preservation, extraction, manifest generation, scan generation, and brief rendering together behind `ctfctl ingest ...`.

Codex workers should start from `brief.md`, `manifest/manifest.json`, `manifest/scan.json`, and a small selected file set rather than receiving whole attachment trees. Raw attachments remain preserved under `raw/`; generated reports redact flag-like values, cookies, tokens, and secret-looking material. The ingestor does not submit flags, perform browser login, expose public tunnels, contact external CTF sites, or execute attachment binaries.

Phase 4 adds a live-readonly platform path for CTFd-like targets:

1. `ctfctl platform auth-check` reads auth metadata only.
2. `ctfctl platform discover --live` fetches redacted challenge summaries and can upsert them into local SQLite state.
3. `ctfctl platform get --live` fetches redacted challenge detail and attachment metadata.
4. `ctfctl platform download --live` stores attachments under the configured contests root.
5. `ctfctl platform ingest --live` chains download into ingest, producing `manifest.json`, `scan.json`, and `brief.md`.
6. Workers then solve from the local challenge tree instead of directly hitting the contest platform.

Phase 6 adds a dry-run-first worker solve loop:

1. `ctfctl worker once` claims the next `new`, `queued`, or `ingest_ready` challenge.
2. The worker locates an existing `brief.md` or writes a minimal generated brief when no ingest artifacts exist.
3. `ctf_runner.solve_prompt` builds a bounded prompt from challenge metadata and the brief.
4. A solver backend runs. The default `mock` backend is deterministic and does not call external services. The `codex` backend is blocked unless `--allow-codex-call` is present for one explicit call through the runner wrapper.
5. `ctf_runner.solve_result` parses solver output, detects flag-like candidates, and creates hash/redacted candidate objects for display and state.
6. The worker calls submit policy planning. In armed competition, supervisor workers include live-submit and confirm-submit flags by default when the arm state allows it; setup/rehearsal and profile policy still block real submit.
7. Accepted local fake submits become `solved`; planned non-submitted candidates become `submit_planned`; no candidate or blocked-only candidates become `stalled` with a compact handoff. Errors become `error`.
8. Worker events are written to SQLite and JSONL telemetry with redacted/hash-only details.

Phase 6.3 adds a local multi-worker E2E path:

1. `ctfctl worker local-e2e --workers 5 --solver mock --fake-ctfd --json` starts a loopback-only fake CTFd server.
2. The fake server exposes five local challenges: easy misc, easy crypto, easy web, an intentionally stalled fixture, and a duplicate/decoy fixture.
3. The runner discovers, downloads, ingests, and saves all challenges into an ignored run directory.
4. Worker claims are atomic through SQLite WAL and `BEGIN IMMEDIATE`; terminal and stalled states are not claimable.
5. Mock workers run at full requested width; Codex workers default to bounded concurrency with `--max-parallel 2`.
6. Local fake submissions are confirmed internally and recorded as accepted, rejected, blocked, or already solved using hash-only state.
7. Solved challenges can write local-only postsolve bundles under `postsolve/`, including `solve_summary.md`, `writeup_draft.md`, `skill_candidate.md`, manifests, timeline, worker ID, and flag hash; stalled challenges write compact handoffs.

The intended promotion path is:

1. Local E2E: fake CTFd only, no external contest traffic, no browser login, no public tunnel.
2. Real live-readonly: real platform discovery, detail, download, and ingest only; solve from local artifacts.
3. Real submit: enable guarded submit only after preflight, confidence, duplicate, cooldown, wrong-limit, and operator confirmation checks pass.

Future phases:

1. Platform-specific instancer plugins beyond the CTFd skeleton.
2. Persistent container pool for pwn/rev execution.
3. Broader live worker submit execution after additional confidence and rate-limit validation.
4. Postsolve compact summaries and skill candidate extraction.
