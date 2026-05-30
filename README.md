# dding CTF Runner

`dding-ctf-runner` is a shell-first control plane for live CTF operations. The default live workflow is an interactive Codex swarm: the operator prepares board state with `ctfctl`, then opens several visible Codex terminals from `~/CTF`. Every Codex terminal is an autonomous solver. There is no controller/solver split in the default path.

This repository is public-safe by design. Local terminal output may include raw flags when needed for solving, verification, and local operator visibility. Keep real contest URLs, auth material, downloaded private files, runtime state, writeups, exploits, and raw flags outside git, public snapshots, public pastes, and public services.

## What It Does

- Coordinates interactive Codex solvers with `ctfctl interactive`.
- Syncs challenge metadata, downloads, and local briefs through policy-gated platform helpers.
- Blocks same-machine duplicate claims by default.
- Generates local auto-triage summaries and category starter files before manual solving.
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
./scripts/ctfctl interactive toolchain doctor --json
./scripts/ctfctl interactive e2e-smoke --contest-id fake-interactive-smoke --agents 2 --json
./scripts/ctfctl interactive init --contest-id "$CONTEST_ID" --profile "$PROFILE" --agents "$AGENTS" --json
./scripts/ctfctl interactive capabilities --contest-id "$CONTEST_ID" --json
./scripts/ctfctl interactive sync --contest-id "$CONTEST_ID" --profile "$PROFILE" --live --download --ingest --pull-solved --json
./scripts/ctfctl interactive board --contest-id "$CONTEST_ID" --json
./scripts/ctfctl interactive status --contest-id "$CONTEST_ID" --json
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

`interactive sync` builds a canonical challenge map before solvers claim work. Static shell pages, slug aliases, spacing/case variants, and phase metadata are folded into the canonical challenge's `aliases`, `artifact_sources`, and `source_ids` in `board.json`, then excluded from default claims. Add `--pull-solved` when the platform exposes team solved/submission state; alias or static solved names are resolved onto the canonical challenge as `solved_by_platform`, `solved_source=platform`, `solved_synced_at`, and `solved_aliases`. The sync JSON reports `canonical_count`, `new_count`, `updated_count`, `alias_count`, `skipped_static_count`, `claimable_count`, `solved_synced_count`, `external_solved_count`, `solved_alias_resolved_count`, and `solved_status_source`.

There is no background refresh loop. During a live contest, refresh happens only when a Codex/operator explicitly runs `interactive sync --live --pull-solved`, `interactive next --refresh`, or `interactive prepare-target --refresh`. `next --refresh` and `prepare-target --refresh` perform one live discovery using the configured profile and pull solved status when available, then continue with normal ranking/preparation. New challenges discovered by that single refresh become claimable immediately; platform-solved and manually external-solved canonical challenges are skipped.

Inside the same computer, duplicate claims are blocked by default on the canonical challenge. Use `ctfctl interactive claim --allow-duplicate` only when you intentionally want multiple local Codex sessions on the same problem. Duplicate claims across different computers are not coordinated.

## Solver Loop

Each Codex terminal should keep going until the contest ends, the operator stops it, or every challenge is solved, externally solved, or stalled-documented:

```bash
ctfctl interactive next --contest-id "$CONTEST_ID" --agent agent-1 --json
ctfctl interactive next --contest-id "$CONTEST_ID" --agent agent-1 --refresh --profile "$PROFILE" --json
ctfctl interactive prepare-target --contest-id "$CONTEST_ID" --agent agent-1 --challenge-id <id> --json
ctfctl interactive prepare-target --contest-id "$CONTEST_ID" --agent agent-1 --refresh --profile "$PROFILE" --json
ctfctl interactive solve-loop --contest-id "$CONTEST_ID" --agent agent-1 --challenge-id <id> --json
ctfctl interactive status --contest-id "$CONTEST_ID" --json
ctfctl interactive target-pack --contest-id "$CONTEST_ID" --challenge-id <id> --agent agent-1 --json
ctfctl interactive triage --contest-id "$CONTEST_ID" --challenge-id <id> --agent agent-1 --json
ctfctl interactive starter --contest-id "$CONTEST_ID" --challenge-id <id> --json
ctfctl interactive run-attempt --contest-id "$CONTEST_ID" --challenge-id <id> --script <path> --json
ctfctl interactive web-config --contest-id "$CONTEST_ID" --challenge-id <id> --base-url <url> --auth-source none --json
ctfctl interactive web-probe --contest-id "$CONTEST_ID" --challenge-id <id> --json
ctfctl interactive browser-probe --contest-id "$CONTEST_ID" --challenge-id <id> --json
ctfctl interactive web-attempt --contest-id "$CONTEST_ID" --challenge-id <id> --script <path> --json
ctfctl interactive browser-attempt --contest-id "$CONTEST_ID" --challenge-id <id> --script <path> --json
ctfctl interactive web-status --contest-id "$CONTEST_ID" --challenge-id <id> --json
ctfctl interactive service-config --contest-id "$CONTEST_ID" --challenge-id <id> --host <host> --port <port> --plain --token-source none --json
ctfctl interactive service-probe --contest-id "$CONTEST_ID" --challenge-id <id> --json
ctfctl interactive service-attempt --contest-id "$CONTEST_ID" --challenge-id <id> --script <path> --json
ctfctl interactive service-status --contest-id "$CONTEST_ID" --challenge-id <id> --json
ctfctl interactive candidates --contest-id "$CONTEST_ID" --challenge-id <id> --json
ctfctl interactive verify-candidate --contest-id "$CONTEST_ID" --challenge-id <id> --json
ctfctl interactive brief --contest-id "$CONTEST_ID" --challenge-id <id> --json
ctfctl interactive capabilities --contest-id "$CONTEST_ID" --category pwn --refresh --json
ctfctl interactive fallback --tool ncat --json
ctfctl interactive memo --contest-id "$CONTEST_ID" --challenge-id <id> --kind memory --append "short fact" --json
ctfctl interactive submit --contest-id "$CONTEST_ID" --challenge-id <id> --flag-file <path> --confirm --json
ctfctl interactive submit-config --contest-id "$CONTEST_ID" --challenge-id <id> --submit-type artifact_upload --endpoint https://example.invalid/submit --field-name file --json
ctfctl interactive upload-submit --contest-id "$CONTEST_ID" --challenge-id <id> --artifact <path> --confirm --json
ctfctl interactive writeup --contest-id "$CONTEST_ID" --challenge-id <id> --category <category> --languages ko,en --include-code --json
ctfctl interactive cleanup --contest-id "$CONTEST_ID" --challenge-id <id> --safe --json
ctfctl interactive metrics summary --contest-id "$CONTEST_ID" --json
ctfctl interactive metrics report --contest-id "$CONTEST_ID" --json
```

`interactive solve-loop` is the preferred automation harness after target setup. It ensures `prepare-target`, executes the starter as a structured attempt, records stdout/stderr/returncode/runtime under `attempts/`, extracts local flag-like candidates into `candidates.jsonl`, verifies confidence and duplicate/wrong guards, and submits only high-confidence candidates through the guarded interactive submit path. Accepted solves continue to ko/en writeup, safe cleanup, and metrics summary; exhausted attempts mark the challenge stalled without creating a writeup.

`interactive status` summarizes board completion: `active`, `needs_sync`, `no_claimable`, `all_solved`, or `all_solved_or_stalled`. It also reports active local claims, stale claims, canonical/todo/claimed/solved/external_solved/stalled/skipped counts, `solved_by_platform_count`, `solved_by_external_count`, `solved_sync_available`, alias count, and artifact source count. Stop only when the contest ends, the user stops the solver, or `completion_status` is `all_solved` or `all_solved_or_stalled`.

`interactive prepare-target` is the preferred manual solver starter. With no `--challenge-id`, it runs `next`, generates the target pack, runs local-only category triage, creates a category starter file, and returns `target_pack_path`, `triage_summary_path`, `starter_path`, `top_files`, `first_commands`, and `next_steps`. With `--refresh`, it first performs the same one-shot sync path as `next --refresh`.

`interactive next` ranks canonical claimable targets by useful signal instead of board order: attachments, remote endpoints, category confidence, existing progress, and clear `next_steps` raise priority; alias/static rows, generic no-file statements, locally solved, platform-solved, external-solved, and stalled-documented challenges are skipped. It claims the selected challenge unless `--dry-run` is used and returns `target_pack_path`.

`interactive capabilities` writes `operator/toolchain/capabilities.json` and `.md` with category tool availability, missing high-priority tools, Docker/`ctf-pwn:latest` status, platform notes, and fallback suggestions. `interactive toolchain doctor` is the repo/contest-independent pre-contest check. These commands never install tools or run sudo; install commands are only operator-planned hints.

`interactive target-pack` writes `operator/target-packs/<challenge>.md` with canonical/alias/artifact-source identity, actual challenge and brief paths, raw/extracted files, web metadata, remote service metadata, recommended probe/attempt commands, toolchain capability summary, existing memory/evidence/attempts/next_steps/operator_notes summaries, recommended first commands, category playbooks, stall criteria, and cleanup reminders. `interactive brief` is the short status view to answer "what are you working on?" without stopping the solver loop.

`interactive triage` reads only local challenge artifacts, briefs, manifests, and memos. It avoids requiring missing tools when a usable fallback exists, writes `triage/summary.md`, `triage/files.json`, `triage/commands.jsonl`, and `triage/findings.jsonl`, then updates `memory.md`, `evidence.md`, `attempts.md`, `next_steps.md`, and `operator_notes.md`. `interactive starter` creates fallback-aware `solve_web.py`, `exploit.py`, `solve_rev.py`, `solve_crypto.py`, `solve_misc.py`, or `solve_ai_ml.py` and records the starter path in operator/board metadata. Neither command creates writeups.

For manual experiments, use `run-attempt -> candidates -> verify-candidate`. Attempt JSON stores raw local stdout/stderr and raw candidates for solving. If an attempt fails because a tool is missing, `attempts.md` and `next_steps.md` record the blocker and fallback path, and metrics records `missing_tool_observed`. Public-safe metrics snapshots include only candidate hash, length, source, status, confidence, and timestamp.

For web/browser challenges, use `web-config -> web-probe -> web-attempt`, with `browser-probe` or `browser-attempt` when DOM execution matters. `web-config` stores only base URL and auth source metadata: `none`, `profile`, `cookie-file`, `header-file`, `storage-state`, or `env`. It stores file paths or environment variable names, never cookie/header/storage values. `web-probe` performs one bounded GET and records title, forms, links, scripts, endpoint candidates, and header summaries under `web/probes/` without storing raw response bodies. `browser-probe` stores screenshot, console summary, and network path/status/content-type summaries under `web/browser_probes/` and uses storage state by path only. `web-attempt` and `browser-attempt` run local scripts or request specs, pass base URL/auth source metadata through environment variables, extract local candidates, and record `web_*`/`browser_*` metrics without raw responses, cookies, headers, storage values, or raw candidates in public-safe snapshots.

For nc/ncat/openssl-style services, use `service-config -> service-probe -> service-attempt`. `service-config` stores only host, port, transport, token source metadata, and optional PoW helper path; it never stores the service token value. `service-probe` uses plain sockets or Python TLS fallback, detects token/PoW/menu prompts, and stores a sanitized local-only transcript under `service/probes/`. `service-attempt` injects configured service tokens without printing them, runs a configured PoW helper when needed, stores sanitized local-only transcripts under `service/attempts/`, extracts local candidates, and records `service_*` metrics without raw transcript, token, or candidate values in public-safe snapshots.

When a teammate solves a challenge outside this machine and the platform does not expose team-solved state, record any canonical name, challenge ID, static slug, artifact source, or alias:

```bash
ctfctl interactive external-solved --contest-id "$CONTEST_ID" --challenge <id-or-alias> --json
```

This manual fallback writes `external_solved.txt`, marks the canonical row `solved_by_external` with `solved_source=external_solved_txt`, records `external_solved_recorded`, and releases claim locks for aliases/artifact sources. Platform-solved teammate work does not create this agent's accepted writeup; writeups still require local accepted evidence.

Writeups are accepted-only. Accepted challenges produce both Korean and English files named:

```text
[category]ChallengeNameWriteup.ko.md
[category]ChallengeNameWriteup.en.md
```

If solver or exploit code exists, include the complete code in fenced markdown blocks. Unsolved challenges do not get writeups; leave compact `memory`, `evidence`, `attempts`, `next_steps`, `operator_notes`, and `stalled` records instead.

For wasm/file/artifact-submit challenges, save official endpoint metadata before uploading:

```bash
ctfctl interactive submit-config --contest-id "$CONTEST_ID" --challenge-id rfc1149b --submit-type artifact_upload --endpoint https://example.invalid/submit --field-name file --json
ctfctl interactive upload-submit --contest-id "$CONTEST_ID" --challenge-id rfc1149b --artifact ./solution.wasm --confirm --json
```

`upload-submit` blocks instead of uploading when no configured or CLI endpoint exists, when the endpoint is not on the profile `base_url` origin, or when profile policy does not allow submission. It records artifact SHA-256, size, submit timestamp, response status, and active status locally in `submissions.jsonl`; raw auth material and raw response bodies are not stored or printed.

## Runtime State

Keep runtime state outside this repo:

```text
~/.ctf-solver/platforms/
~/.ctf-solver/secrets/
~/.ctf-solver/runner-state/
~/CTF/contests/
```

Local terminal output may include raw flags, solver output, and exploit output when needed for solving, verification, and local operator visibility. During an active contest, do not commit, push, paste publicly, publish, or upload flags, writeups, exploits, tokens, cookies, sessions, browser storage, private keys, auth material, downloaded private challenge files, or callback hits to public services, public repositories, public pastes, issue trackers, public snapshots, or external writeup locations.

Interactive metrics are stored under the operator root in `metrics/events.jsonl`, `metrics/sessions.jsonl`, `metrics/challenge_metrics.jsonl`, `metrics/tool_benchmarks.jsonl`, `metrics/summary.json`, and `metrics/regression_report.md`. These files are local raw metrics and stay outside this repo.

Before the next contest, run `ctfctl interactive e2e-smoke --contest-id fake-interactive-smoke --agents 2 --json`. It uses only local fake CTFd fixtures and verifies init, sync, claim, accepted submit, solved/submission records, ko/en writeups with full solver code, cleanup, stalled metrics without writeups, metrics summary, and duplicate-claim behavior.

GitHub-managed metrics must be public-safe snapshots only:

- Do not publish, upload, commit, push, paste publicly, or place contest flags, writeups, exploit bodies, auth material, or private artifacts in public locations during an active contest.
- Unsolved challenges get stalled metrics with high-level blockers and next steps, not writeups.
- Artifact upload public snapshots may include artifact SHA-256, size, and status only; they must not include auth, tokens, cookies, sessions, browser storage, auth headers, paths, raw responses, or private artifact contents.
- Candidate public snapshots may include candidate hash, length, source, status, confidence, and timestamp only; they must not include raw flags, raw candidate values, tokens, auth, or session material.
- After an accepted solve, run submit -> ko/en writeup -> cleanup -> metrics update -> next challenge.
- After a stall, record memo/attempts/next_steps -> stalled metrics update -> next challenge.
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
