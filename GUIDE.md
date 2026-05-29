# dding CTF Runner Guide

This guide is the user-facing operating manual for the interactive Codex swarm workflow. Commands use placeholders only. Keep real contest URLs, cookies, tokens, browser storage, downloads, writeups, and raw flags outside this repository.

For the shortest contest-day checklist, see [OPERATIONS.md](OPERATIONS.md).

## 1. Operating Model

The default live model is interactive:

- Use `ctfctl` from `~/dding-ctf-runner` for setup, sync, board, submit, writeup, and cleanup helpers.
- Start visible Codex sessions yourself with `cd ~/CTF && codex`.
- Every Codex terminal is an autonomous solver. Do not split terminals into controller and solver roles.
- Same-machine duplicate claims are blocked by default.
- Windows WSL can run up to 6 Codex terminals when resources allow.
- MacBook secondary runners should use up to 4 Codex terminals by default.
- Background workers and `contest start-workers` are legacy/advanced, not the default live path.

## 2. Install

Windows WSL primary runner:

```bash
cd ~
git clone <repo-url> dding-ctf-runner
cd ~/dding-ctf-runner

python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e . pytest
./scripts/ctfctl preflight --deep --json
```

Keep the repo on WSL ext4, not `/mnt/c`. Enable Docker Desktop WSL integration for pwn/rev work.

macOS secondary runner:

```bash
cd ~
git clone <repo-url> dding-ctf-runner
cd ~/dding-ctf-runner
python3 -m pip install -e . pytest
```

Keep the existing `~/CTF`, global Codex config, and personal CTF tooling unchanged. For Apple Silicon Docker smoke checks:

```bash
export CTF_DOCKER_WORKSPACE_ROOT="$HOME/.ctf-solver/runner-state/docker-workspaces"
./scripts/ctfctl docker benchmark --image ctf-pwn:latest --json
./scripts/ctfctl docker pool-smoke --contest-id mac-docker-smoke --workers 2 --json
./scripts/ctfctl docker pool-stop --contest-id mac-docker-smoke --json
```

## 3. Profile And Auth

Store platform profiles and secrets outside git:

```text
~/.ctf-solver/platforms/<contest>.yaml
~/.ctf-solver/secrets/<contest>.cookie
~/.ctf-solver/secrets/<contest>.token
~/.ctf-solver/secrets/<contest>.storage_state.json
```

Common auth shapes:

```yaml
auth:
  method: cookie_header_file
  path: "~/.ctf-solver/secrets/<contest>.cookie"
policy:
  allow_live_discovery: true
  allow_live_download: true
  allow_submission: true
  allow_instance_start: false
downloads:
  root: "~/CTF/contests"
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

Validate without printing raw auth:

```bash
./scripts/ctfctl platform profile-check --config ~/.ctf-solver/platforms/<contest>.yaml --json
./scripts/ctfctl auth storage-check --path ~/.ctf-solver/secrets/<contest>.storage_state.json --json
```

Capture browser storage only when needed, by manual login:

```bash
./scripts/ctfctl auth capture-storage \
  --config ~/.ctf-solver/platforms/<contest>.yaml \
  --output ~/.ctf-solver/secrets/<contest>.storage_state.json \
  --live \
  --headed \
  --timeout-sec 300
```

## 4. Interactive Init And Sync

From the runner repo:

```bash
cd ~/dding-ctf-runner
export CONTEST_ID=<contest>
export PROFILE=~/.ctf-solver/platforms/<contest>.yaml
export AGENTS=4

./scripts/ctfctl preflight --deep --json
./scripts/ctfctl platform profile-check --config "$PROFILE" --json
./scripts/ctfctl interactive init --contest-id "$CONTEST_ID" --profile "$PROFILE" --agents "$AGENTS" --json
./scripts/ctfctl interactive sync --contest-id "$CONTEST_ID" --profile "$PROFILE" --live --download --ingest --json
./scripts/ctfctl interactive board --contest-id "$CONTEST_ID" --json
```

If the operator directory does not exist, the first agent or operator runs `interactive init` and creates it.

Generate one prompt per Codex terminal:

```bash
./scripts/ctfctl interactive prompt --contest-id "$CONTEST_ID" --agent agent-1
./scripts/ctfctl interactive prompt --contest-id "$CONTEST_ID" --agent agent-2
./scripts/ctfctl interactive prompt --contest-id "$CONTEST_ID" --agent agent-3
./scripts/ctfctl interactive prompt --contest-id "$CONTEST_ID" --agent agent-4
```

For Windows, use up to six agents:

```bash
./scripts/ctfctl interactive init --contest-id "$CONTEST_ID" --profile "$PROFILE" --agents 6 --json
```

## 5. Start Codex Terminals

In each solver terminal:

```bash
cd ~/CTF
codex
```

Paste a different generated prompt into each Codex session. These are CTF-solving Codex sessions, separate from any Codex you use to develop this repo. Repo development happens in `~/dding-ctf-runner`; challenge solving happens in `~/CTF`.

Each solver should:

- run `interactive solve-loop` to pick or prepare one high-signal canonical challenge and execute the starter harness
- use `prepare-target -> run-attempt -> candidates -> verify-candidate` when manual experiment control is needed
- read the generated target pack, triage summary, and starter before solving
- solve and verify locally
- submit only through `ctfctl interactive submit` or `upload-submit`
- write accepted-only ko/en writeups
- clean safe temporary files
- move to the next challenge unless the user stops the loop, the contest ends, or all challenges are solved/external_solved/stalled-documented
- keep self memos current to prevent context drift

`interactive sync` canonicalizes platform challenge rows before this loop starts. Static shell pages, `-static` slugs, case/spacing variants, and phase metadata are kept under the canonical row in `board.json` as `aliases`, `artifact_sources`, and `source_ids`. Default `interactive next` and `interactive claim` return canonical, claimable rows; `interactive board --json` exposes `canonical_count`, `alias_count`, `skipped_static_count`, and `claimable_count`. `interactive sync --json` also reports `new_count` and `updated_count`.

No background refresh loop runs during a contest. New problems are picked up only when a visible Codex/operator command performs a refresh: `interactive sync --live`, `interactive next --refresh`, or `interactive prepare-target --refresh`.

## 6. Interactive Commands

Board:

```bash
./scripts/ctfctl interactive board --contest-id "$CONTEST_ID" --json
./scripts/ctfctl interactive status --contest-id "$CONTEST_ID" --json
```

Pick and claim the next target:

```bash
ctfctl interactive next --contest-id "$CONTEST_ID" --agent agent-1 --json
ctfctl interactive next --contest-id "$CONTEST_ID" --agent agent-1 --refresh --profile "$PROFILE" --json
```

`next` scores canonical challenges by attachments, remote endpoints, category confidence, existing progress, and clear `next_steps`. It skips alias/static/artifact-source rows, solved/external-solved/stalled-documented challenges, and generic no-file shells. Use `--refresh --profile "$PROFILE"` to run one live sync before ranking; newly discovered challenges become claimable immediately and sync deltas are recorded in metrics. Use `--category <category>` to focus one category, `--dry-run` to inspect the selected target without claiming, and `--allow-duplicate` only for intentional same-machine duplicate solving. The JSON includes `target_pack_path`; the solver should read that file before trying payloads.

Prepare a target for immediate solving:

```bash
ctfctl interactive solve-loop --contest-id "$CONTEST_ID" --agent agent-1 --json
ctfctl interactive solve-loop --contest-id "$CONTEST_ID" --agent agent-1 --challenge-id <id-or-alias> --max-attempts 5 --json
ctfctl interactive prepare-target --contest-id "$CONTEST_ID" --agent agent-1 --json
ctfctl interactive prepare-target --contest-id "$CONTEST_ID" --agent agent-1 --refresh --profile "$PROFILE" --json
ctfctl interactive prepare-target --contest-id "$CONTEST_ID" --agent agent-1 --challenge-id <id-or-alias> --json
```

`solve-loop` is the standard experiment harness. It runs `prepare-target` when needed, executes the starter in the challenge directory, records `attempts/<timestamp>.json`, updates `attempts.md` and `evidence.md`, detects local candidates, verifies format/duplicate/fake-like/previous-wrong guards, and submits only high-confidence candidates through the interactive submit path. If accepted, it writes ko/en writeups, runs safe cleanup, updates metrics, and the solver continues to the next challenge. If no accepted candidate appears after `--max-attempts`, it updates `next_steps.md`, records stalled metrics, creates no writeup, and continues to the next challenge.

`prepare-target` runs the target planner, target pack, local auto-triage, and starter generation as one shell-first step. If `--challenge-id` is omitted, it runs `interactive next`; otherwise it prepares the specified canonical challenge or alias. With `--refresh`, it performs the same one-shot sync path as `next --refresh` first. The JSON returns `target_pack_path`, `triage_summary_path`, `starter_path`, `top_files`, `first_commands`, and `next_steps`. Read the target pack, triage summary, and starter file before manual analysis.

`interactive status` reports `completion_status`: `active`, `needs_sync`, `no_claimable`, `all_solved`, or `all_solved_or_stalled`. `active` means keep solving. `needs_sync` means a profile is configured but the board has not been refreshed. `no_claimable` means no fresh canonical target is currently available, often because work is already claimed locally. `all_solved` and `all_solved_or_stalled` are stop conditions. 대회 중 사용자의 중단 지시, 대회 종료, 모든 문제 solved/stalled-documented 외에는 계속 진행한다.

Generate or refresh the solver launch pack:

```bash
ctfctl interactive target-pack --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --agent agent-1 --json
```

The pack is written under `operator/target-packs/` and includes canonical name, aliases, artifact sources, real challenge/brief/raw/extracted paths, remote connection info, top interesting files, current memory/evidence/attempts/next_steps/operator_notes summaries, recommended first commands, a category playbook, stall criteria, and accepted-only writeup/cleanup reminders. It does not include raw auth material, cookies, tokens, sessions, browser storage, or private keys.

Run local auto-triage and create a starter explicitly:

```bash
ctfctl interactive triage --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --agent agent-1 --json
ctfctl interactive starter --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --category <category> --json
```

`triage` never connects to external CTF services. It reads local raw/handout/extracted files, `brief.md`, manifests, and memos, then writes `triage/summary.md`, `triage/files.json`, `triage/commands.jsonl`, and `triage/findings.jsonl`. It updates `memory.md`, `evidence.md`, `attempts.md`, `next_steps.md`, and `operator_notes.md`. `starter` creates a category-specific skeleton such as `solve_web.py`, `exploit.py`, `solve_rev.py`, `solve_crypto.py`, or `solve_misc.py`, and records the path in board/operator metadata. These commands do not create writeups; writeups remain accepted-only.

Run and verify manual experiments:

```bash
ctfctl interactive run-attempt --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --script <path> --timeout 120 --json
ctfctl interactive run-attempt --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --command "python3 solve.py" --json
ctfctl interactive candidates --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --json
ctfctl interactive verify-candidate --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --json
```

`run-attempt` executes from the challenge directory and stores raw local stdout/stderr/returncode/runtime in `attempts/`. It appends compact attempt/evidence notes and records `attempt_started`/`attempt_completed` metrics. Raw candidates are allowed in local terminal output and `candidates.jsonl`; public-safe snapshots use only hash, length, source, status, confidence, and timestamp.

Compact current-target status:

```bash
ctfctl interactive brief --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --json
```

Use `brief` when the user asks "지금 뭐 하고 있음?" so the solver can answer from local state and continue the loop.

Manual claim remains available:

```bash
ctfctl interactive claim --contest-id "$CONTEST_ID" --agent agent-1 --json
```

The returned `challenge_id`, name, path, memos, and writeup paths are canonical even when the platform also published static or alias rows for the same task.

Claim a specific challenge:

```bash
ctfctl interactive claim --contest-id "$CONTEST_ID" --agent agent-1 --challenge <id> --json
```

Allow intentional same-machine duplicate solving:

```bash
ctfctl interactive claim --contest-id "$CONTEST_ID" --agent agent-2 --challenge <id> --allow-duplicate --json
```

Release a claim when abandoning a live attempt:

```bash
ctfctl interactive release --contest-id "$CONTEST_ID" --agent agent-1 --challenge <id> --reason "switching tasks" --json
```

Record self memo:

```bash
ctfctl interactive memo --contest-id "$CONTEST_ID" --challenge-id <id> --kind memory --append "known fact" --json
ctfctl interactive memo --contest-id "$CONTEST_ID" --challenge-id <id> --kind evidence --append "local evidence path or result" --json
ctfctl interactive memo --contest-id "$CONTEST_ID" --challenge-id <id> --kind attempts --append "tried X, result Y" --json
ctfctl interactive memo --contest-id "$CONTEST_ID" --challenge-id <id> --kind next_steps --append "next concrete action" --json
ctfctl interactive memo --contest-id "$CONTEST_ID" --challenge-id <id> --kind operator_notes --append "operator hint" --json
```

Submit a flag from a local file:

```bash
ctfctl interactive submit --contest-id "$CONTEST_ID" --challenge-id <id> --flag-file <path> --confirm --json
```

Submit an upload artifact:

```bash
ctfctl interactive submit-config --contest-id "$CONTEST_ID" --challenge-id <id> --submit-type artifact_upload --endpoint https://example.invalid/submit --field-name file --json
ctfctl interactive upload-submit --contest-id "$CONTEST_ID" --challenge-id <id> --artifact <path> --confirm --json
```

Artifact upload challenges, including rfc1149b-like wasm tasks, are metadata-first. Store the challenge submit metadata under the local operator state, then upload only to the official endpoint:

```bash
ctfctl interactive submit-config --contest-id "$CONTEST_ID" --challenge-id rfc1149b --submit-type artifact_upload --endpoint https://example.invalid/submit --field-name file --status-url https://example.invalid/status/rfc1149b --json
ctfctl interactive upload-submit --contest-id "$CONTEST_ID" --challenge-id rfc1149b --artifact ./solution.wasm --confirm --json
```

The endpoint must be HTTP/HTTPS, must not embed credentials or secret-bearing query parameters, and must match the origin of the configured platform profile `base_url`. If metadata and `--endpoint` are both missing, `upload-submit` records a planned/blocked local submission and does not perform live network traffic. Successful and failed upload attempts append public-safe local records to `submissions.jsonl` with artifact SHA-256, size, submit timestamp, response status, and active status.

Mark stalled:

```bash
ctfctl interactive stalled --contest-id "$CONTEST_ID" --agent agent-1 --challenge <id> --reason "short blocker and next step" --json
```

Record a challenge solved outside this machine:

```bash
ctfctl interactive external-solved --contest-id "$CONTEST_ID" --challenge <id> --json
```

`external-solved` accepts a canonical ID, canonical name, alias, static slug, or artifact source. It resolves to the canonical challenge, marks it `external_solved`/`solved_by_external`, writes local `external_solved.txt` entries, and releases any claim locks for the canonical challenge and aliases. Use this when a teammate solves a problem and the platform sync does not automatically expose team-solved state.

Write accepted-only writeups:

```bash
ctfctl interactive writeup --contest-id "$CONTEST_ID" --challenge-id <id> --category <category> --languages ko,en --include-code --json
```

Safe cleanup:

```bash
ctfctl interactive cleanup --contest-id "$CONTEST_ID" --challenge-id <id> --safe --json
```

## 7. Giving Solvers New Information

When the user/operator learns something mid-contest, update the local memos rather than relying on chat history:

```bash
ctfctl interactive memo --contest-id "$CONTEST_ID" --challenge-id <id> --kind operator_notes --append "Hint from organizer: <short sanitized note>" --json
ctfctl interactive memo --contest-id "$CONTEST_ID" --challenge-id <id> --kind next_steps --append "Use the new hint to test <action>" --json
```

Then paste the short sanitized note into the affected Codex terminal. Local terminal output may include flags, solver output, and exploit output when needed for solving and verification, but do not paste cookies, tokens, sessions, browser storage, private keys, auth material, flags, writeups, or exploits into public chats, public pastes, issue trackers, public repositories, or external writeup locations during the contest.

## 8. Writeup Policy

Only write a writeup after an accepted solve is confirmed. For each accepted challenge, create two files:

```text
[category]ChallengeNameWriteup.ko.md
[category]ChallengeNameWriteup.en.md
```

If solver or exploit code exists, include the complete code in fenced markdown blocks. Do not write a public-style writeup for unsolved, skipped, or stalled problems. For unsolved problems, leave only local `memory`, `evidence`, `attempts`, `next_steps`, `operator_notes`, and `stalled` records.

## 8.1. Interactive Metrics

Each operator root has local-only metrics files:

```text
metrics/events.jsonl
metrics/sessions.jsonl
metrics/challenge_metrics.jsonl
metrics/tool_benchmarks.jsonl
metrics/summary.json
metrics/regression_report.md
```

Use `ctfctl interactive metrics record` for manual observations, including optional token usage:

```bash
ctfctl interactive metrics record --contest-id "$CONTEST_ID" --event usage_observed --data-json '{"tokens_used": 1234}' --json
ctfctl interactive metrics summary --contest-id "$CONTEST_ID" --json
ctfctl interactive metrics report --contest-id "$CONTEST_ID" --json
```

Metrics are for local performance tracking across updates. Local raw metrics are private operator state and must not be copied into public repos during an active contest.

GitHub metrics are public-safe snapshots only. Use:

```bash
ctfctl interactive metrics baseline --name before-change --json
ctfctl interactive metrics publish-snapshot --contest-id "$CONTEST_ID" --contest-ended --json
ctfctl interactive metrics dashboard --json
ctfctl interactive metrics compare-public --before old-summary.public.json --after metrics/contests/$CONTEST_ID/summary.public.json --json
```

`publish-snapshot` writes `summary.public.json`, `solved.public.md`, `stalled.public.md`, `approaches.public.md`, and `regression.public.md`. These files include counts, elapsed times, high-level approaches, stalled blockers, cleanup/writeup counts, observed token totals when present, candidate hash/length/source/status metadata, and artifact upload SHA-256/size/status when present. They must not include raw candidates, raw flags, writeup bodies, exploit bodies, artifact contents, upload endpoints, local artifact paths, cookies, sessions, browser storage, private keys, raw responses, or auth material.

During an active contest, public snapshot export is blocked unless both `--allow-active-contest` and `--confirm-public-safe` are provided. The normal flow is: accepted solve -> submit or accepted/active artifact upload -> ko/en writeup -> cleanup -> metrics update -> next challenge. For stalled challenges: attempts/next_steps -> stalled metrics update -> next challenge. At contest end: publish-snapshot -> dashboard -> optional git commit.

## 9. Callback, Docker, Submit, And Cleanup Helpers

The interactive workflow still uses runner helpers for live platform operations:

```bash
./scripts/ctfctl docker pool-start --contest-id "$CONTEST_ID" --workers 4 --image ctf-pwn:latest --json
./scripts/ctfctl docker pool-status --contest-id "$CONTEST_ID" --json
./scripts/ctfctl docker pool-stop --contest-id "$CONTEST_ID" --json
```

```bash
./scripts/ctfctl callback start --contest-id "$CONTEST_ID" --challenge-id <id> --worker-id agent-1 --json
./scripts/ctfctl tunnel start --contest-id "$CONTEST_ID" --challenge-id <id> --worker-id agent-1 --listener-id <listener> --provider auto --allow-public --json
./scripts/ctfctl contest cleanup-resources --contest-id "$CONTEST_ID" --json
```

Use public tunnels only when a challenge requires them. Do not paste tunnel URLs, callback logs, or payload transcripts into git or public writeups.

## 10. Troubleshooting

Profile/auth failure:

```bash
./scripts/ctfctl platform profile-check --config "$PROFILE" --json
./scripts/ctfctl auth storage-check --path ~/.ctf-solver/secrets/<contest>.storage_state.json --json
```

Board stale or missing:

```bash
./scripts/ctfctl interactive init --contest-id "$CONTEST_ID" --profile "$PROFILE" --agents "$AGENTS" --json
./scripts/ctfctl interactive sync --contest-id "$CONTEST_ID" --profile "$PROFILE" --live --download --ingest --json
./scripts/ctfctl interactive board --contest-id "$CONTEST_ID" --json
```

Duplicate claim:

- Default locks block duplicate claims only on the same computer.
- Use `--allow-duplicate` only when intentionally racing one problem locally.
- Ignore duplicate claims on other computers unless the team wants manual coordination.

Context drift:

```bash
ctfctl interactive memo --contest-id "$CONTEST_ID" --challenge-id <id> --kind memory --append "current state summary" --json
ctfctl interactive memo --contest-id "$CONTEST_ID" --challenge-id <id> --kind next_steps --append "next action" --json
```

Submit blocked:

- Check profile `policy.allow_submission`.
- Confirm `--confirm` was used.
- Inspect the submit JSON for duplicate, cooldown, wrong-limit, confidence, or fake-like guard reasons.

Docker on Windows WSL:

```bash
docker info >/dev/null
./scripts/ctfctl preflight --deep --json
```

macOS Docker:

```bash
export CTF_DOCKER_WORKSPACE_ROOT="$HOME/.ctf-solver/runner-state/docker-workspaces"
./scripts/ctfctl docker pool-smoke --contest-id mac-docker-smoke --workers 2 --json
./scripts/ctfctl docker pool-stop --contest-id mac-docker-smoke --json
```

Interactive E2E before the next contest:

```bash
./scripts/ctfctl interactive e2e-smoke --contest-id fake-interactive-smoke --agents 2 --json
```

This is the current full-loop rehearsal for the interactive swarm. It is
fake/local only and checks accepted-only writeups, full solver code capture,
cleanup, stalled metrics without writeups, metrics summary, next claim, and
same-machine duplicate-claim behavior. Use `--keep-runtime` when inspecting
`~/CTF/contests/fake-interactive-smoke/operator`.

## 11. Legacy Background Workers

The old background flow remains for advanced testing:

```bash
./scripts/init-codex-workers.sh --count 5 --link-auth
./scripts/ctf-worker-1 --dry-run
./scripts/ctfctl contest start-workers --contest-id <contest> --dry-run --json
```

Do not use this as the default live contest workflow. See [docs/contest-operations.md](docs/contest-operations.md) and [docs/worker-loop.md](docs/worker-loop.md) only when intentionally running legacy/advanced automation.

## 12. Public Safety

Before publishing, use the interactive-first release gate:

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

`public-check` exposes the default release commands under `interactive_test_commands`. Background worker full-rehearsal commands are still available, but they are legacy/advanced checks rather than the default release summary.

Do not push public git changes from this repo during active CTF work.
