# Interactive Codex Swarm Operations

This is the default live contest workflow. The operator uses `ctfctl interactive`
to maintain local state, then starts several visible Codex terminals from
`~/CTF`. Every Codex terminal is an autonomous solver. There is no
controller/solver split and no background worker supervisor in the default path.

## Start

From the runner repo:

```bash
cd ~/dding-ctf-runner
export CONTEST_ID=<contest>
export PROFILE=~/.ctf-solver/platforms/<contest>.yaml
export AGENTS=4

./scripts/ctfctl preflight --deep --json
./scripts/ctfctl platform profile-check --config "$PROFILE" --json
./scripts/ctfctl interactive toolchain doctor --json
./scripts/ctfctl interactive e2e-smoke --contest-id fake-interactive-smoke --agents 2 --json
./scripts/ctfctl interactive init --contest-id "$CONTEST_ID" --profile "$PROFILE" --agents "$AGENTS" --json
./scripts/ctfctl interactive capabilities --contest-id "$CONTEST_ID" --json
./scripts/ctfctl interactive sync --contest-id "$CONTEST_ID" --profile "$PROFILE" --live --download --ingest --pull-solved --json
./scripts/ctfctl interactive board --contest-id "$CONTEST_ID" --json
./scripts/ctfctl interactive status --contest-id "$CONTEST_ID" --json
```

Use `--agents 6` for a strong Windows WSL host and `--agents 4` for a MacBook.

`interactive e2e-smoke` is the pre-contest full-loop check for this workflow.
It starts a local fake CTFd fixture, initializes the operator root at
`~/CTF/contests/<contest>/operator`, syncs fake challenges, verifies claim and
duplicate-claim behavior, submits a synthetic accepted solve through the normal
interactive submit path, creates accepted-only ko/en writeups with complete
solver code, runs cleanup, records a stalled fixture without writeups, updates
metrics, and confirms the next claim does not pick the solved challenge. It
never contacts an external CTF. Add `--keep-runtime` only when you need to
inspect generated local files.

Generate one prompt per solver:

```bash
./scripts/ctfctl interactive prompt --contest-id "$CONTEST_ID" --agent agent-1
./scripts/ctfctl interactive prompt --contest-id "$CONTEST_ID" --agent agent-2
```

Then open separate terminals:

```bash
cd ~/CTF
codex
```

Paste one generated prompt into each Codex session.

## Command Reference

Board:

```bash
ctfctl interactive board --contest-id "$CONTEST_ID" --json
ctfctl interactive status --contest-id "$CONTEST_ID" --json
```

Sync and board canonicalization:

- `interactive sync` folds duplicate platform rows into canonical challenges before claim.
- Static shell pages are detected when they have only generic short text and favicon/CSS-style links, or when the row is a `-static` slug.
- Alias rows include case, spacing, slug, and phase metadata variants. They are recorded on the canonical challenge as `aliases`, `artifact_sources`, and `source_ids` instead of becoming default claim targets.
- `board.json` challenge rows include `canonical_id`, `canonical_name`, `aliases`, `artifact_sources`, `source_ids`, `is_static_shell`, `claimable`, `solved_by_platform`, `solved_by_external`, `solved_source`, `solved_synced_at`, and `solved_aliases`.
- `interactive sync --pull-solved --json` reports `canonical_count`, `new_count`, `updated_count`, `alias_count`, `skipped_static_count`, `claimable_count`, `solved_synced_count`, `external_solved_count`, `solved_alias_resolved_count`, and `solved_status_source`.
- Platform solved IDs, aliases, or static names are resolved to the canonical challenge and excluded from `next`/`prepare-target`. If the platform lacks solved/submission state, `--pull-solved` is a safe no-op with `solved_status_source=unavailable`.
- `interactive status --json` reports `completion_status`, `no_useful_work`, canonical/todo/claimed/solved/external_solved/stalled/skipped counts, `solved_by_platform_count`, `solved_by_external_count`, `solved_sync_available`, active local claims, stale claims, alias count, and artifact source count.
- `completion_status` values are `active`, `needs_sync`, `no_claimable`, `all_solved`, and `all_solved_or_stalled`. Platform solved rows count toward completion. Stop only for contest end, explicit user stop, `all_solved`, or `all_solved_or_stalled`.
- There is no background refresh loop. New challenges and teammate solves are discovered only by visible commands: `interactive sync --live --pull-solved`, `interactive next --refresh`, or `interactive prepare-target --refresh`; the refresh paths pull solved status when available.

Target planning and claim:

```bash
ctfctl interactive solve-loop --contest-id "$CONTEST_ID" --agent agent-1 --json
ctfctl interactive solve-loop --contest-id "$CONTEST_ID" --agent agent-1 --challenge-id <id-or-alias> --max-attempts 5 --json
ctfctl interactive prepare-target --contest-id "$CONTEST_ID" --agent agent-1 --json
ctfctl interactive prepare-target --contest-id "$CONTEST_ID" --agent agent-1 --refresh --profile "$PROFILE" --json
ctfctl interactive prepare-target --contest-id "$CONTEST_ID" --agent agent-1 --challenge-id <id-or-alias> --json
ctfctl interactive next --contest-id "$CONTEST_ID" --agent agent-1 --json
ctfctl interactive next --contest-id "$CONTEST_ID" --agent agent-1 --refresh --profile "$PROFILE" --json
ctfctl interactive next --contest-id "$CONTEST_ID" --agent agent-1 --category web --dry-run --json
ctfctl interactive target-pack --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --agent agent-1 --json
ctfctl interactive triage --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --agent agent-1 --json
ctfctl interactive starter --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --category web --json
ctfctl interactive run-attempt --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --script <path> --timeout 120 --json
ctfctl interactive service-config --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --host <host> --port <port> --plain --token-source none --json
ctfctl interactive service-probe --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --timeout 10 --json
ctfctl interactive service-attempt --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --script <path> --timeout 60 --json
ctfctl interactive service-status --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --json
ctfctl interactive candidates --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --json
ctfctl interactive verify-candidate --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --json
ctfctl interactive brief --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --json
ctfctl interactive capabilities --contest-id "$CONTEST_ID" --category forensics/misc --refresh --json
ctfctl interactive fallback --tool cpio --json
ctfctl interactive claim --contest-id "$CONTEST_ID" --agent agent-1 --json
ctfctl interactive claim --contest-id "$CONTEST_ID" --agent agent-1 --challenge <id> --json
```

Default claim returns only canonical rows where `claimable` is true. If a solver requests an alias or static slug with `--challenge`, the claim resolves to the canonical challenge and returns the canonical path/name.

`interactive solve-loop` is the preferred solver entrypoint. It scores or prepares a target, ensures target pack/triage/starter, runs the starter in the challenge directory, records a structured attempt, extracts local candidates, verifies candidate confidence and submit guards, submits only high-confidence candidates, and performs accepted-only writeup plus cleanup when accepted. If it reaches `--max-attempts` without an accepted candidate, it updates attempts/evidence/next steps, records stalled metrics, creates no writeup, and returns the next action so the Codex keeps moving to another problem. If the attempt fails because a tool is missing, it records `missing_tool_observed`, writes the fallback/blocker to attempts and next steps, stalls that target with evidence, and continues by selecting another target on the next loop. 대회 중 사용자의 중단 지시, 대회 종료, 모든 문제 solved/stalled-documented 외에는 계속 진행한다.

Toolchain commands:

- `interactive toolchain doctor --json` checks the global/local machine without requiring a contest.
- `interactive capabilities --contest-id <id> --json` stores `operator/toolchain/capabilities.json` and `.md`, records `toolchain_checked`, and feeds target-pack/triage/starter/solve-loop.
- `interactive fallback --tool ncat --json` returns fallback plans such as `openssl_s_client` for TLS or `nc` for plain TCP; `--tool cpio` returns `bsdtar`, Python parser, and Docker extraction paths.
- Missing tools are not auto-installed. Hints such as Homebrew, apt, pipx, or gem commands are planned operator actions only.
- Reports include category-specific missing high-priority tools, Docker/`ctf-pwn:latest`, and WSL/macOS notes.

`interactive next` scores only canonical claimable rows by practical solve signal. With `--refresh`, it first performs one live sync using the configured profile, records sync deltas, then ranks the refreshed board:

- positive: local attachments or downloaded handout files, detected remote endpoints, confident category, previous memory/evidence/attempts/operator notes, and clear `next_steps`
- negative or excluded: static shell rows, alias/artifact-source rows, generic no-file statements, claimed rows unless `--allow-duplicate`, solved, external-solved, and stalled-documented rows

`prepare-target` is the preferred Codex entrypoint. If `--challenge-id` is omitted, it runs `next`; otherwise it prepares the specified challenge or alias. With `--refresh`, the no-challenge path is identical to `next --refresh` before preparation. It generates the target pack, runs local-only category triage, creates the category starter skeleton, and returns `target_pack_path`, `triage_summary_path`, `starter_path`, `top_files`, `first_commands`, and `next_steps`. If no target remains, it returns `completion_status` and `no_useful_work` instead of starting a background loop.

On success, `next` claims the selected challenge and returns `target_pack_path`. With `--dry-run`, it writes the pack and reports the target without creating a claim lock.

`interactive target-pack` writes `operator/target-packs/<normalized>.md`. The pack includes:

- canonical name, canonical ID, aliases, artifact sources, and source IDs
- category guess and confidence
- challenge path, brief path, raw/handout directories, extracted directories, and manifest paths
- remote connection info detected from board metadata or brief text
- normalized remote service metadata with host, port, TLS/plain/auto transport, token-source metadata, optional PoW helper, and recommended probe/attempt commands
- top interesting files from ingest manifests or local artifact fallback
- available tools, missing critical tools, and recommended fallbacks
- summaries and paths for `memory.md`, `evidence.md`, `attempts.md`, `next_steps.md`, and `operator_notes.md`
- recommended first commands, a short category playbook, wasted-time warnings, stall criteria, and writeup/cleanup reminders

Pack generation redacts auth-like material and excludes raw cookies, tokens, sessions, browser storage, storage state files, passwords, and private keys. Local terminal output may still show raw flags while solving; public upload, public writeup, public paste, and git push of flags or private artifacts remain forbidden during the contest.

`interactive triage` reads only local `raw/`, `handout/`, `extracted/`, `brief.md`, manifest files, and challenge memos. Category handling includes web route/API/sink scans, pwn `file`/`checksec`/`readelf`/`strings`, rev format and string summaries, crypto parameter extraction, forensics metadata/carving helpers, local-only OSINT identifiers, and AI/ML model/dataset hints. Missing tools are skipped or replaced with an available fallback before being recommended as first commands. It writes `triage/summary.md`, `triage/files.json`, `triage/commands.jsonl`, and `triage/findings.jsonl`, then updates `memory.md`, `evidence.md`, `attempts.md`, `next_steps.md`, and `operator_notes.md`. It records `triage_started`, `fallback_selected`, and `triage_completed` metrics.

`interactive starter` creates a category-specific solver skeleton without creating a writeup: `solve_web.py` with requests/urllib fallback, `exploit.py` with optional pwntools plus socket/subprocess fallback, `solve_rev.py` with subprocess and optional z3 hooks, `solve_crypto.py` with parameter parsing, `solve_misc.py` for forensics/misc/OSINT helpers, or `solve_ai_ml.py` for model triage. The starter path is recorded in board and operator metadata, and `starter_created` is written to metrics.

`interactive run-attempt` executes `--command` or `--script` from the challenge directory. It stores raw local stdout/stderr/returncode/runtime in `attempts/<timestamp>.json`, appends compact entries to `attempts.md` and `evidence.md`, records `attempt_started` and `attempt_completed` metrics, and extracts flag-like candidates into `candidates.jsonl`. `interactive candidates` lists the local candidate store with raw values for local solving. `interactive verify-candidate` reads a passed value, candidate file, or latest local candidate, then checks format, duplicate hash, fake-like markers, previous wrong submissions, and confidence before submit.

Remote service commands:

```bash
ctfctl interactive service-config --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --host <host> --port <port> --tls --token-source file --token-file <path> --pow-helper <path> --json
ctfctl interactive service-config --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --host <host> --port <port> --plain --token-source env --token-env <name> --json
ctfctl interactive service-probe --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --timeout 10 --json
ctfctl interactive service-attempt --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --payload-file <path> --timeout 60 --json
ctfctl interactive service-status --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --json
```

`service-config` records service endpoint metadata in operator and board metadata. It stores host, port, endpoint locality, transport (`tls`, `plain`, or `auto`), token source kind, token file path or environment variable name, and optional PoW helper path. It does not read or store token values. If the host differs from the platform profile origin, the command reports a warning and still allows the remote service because CTF service hosts often differ from board/API hosts.

`service-probe` uses Python sockets for plain TCP and Python `ssl` as the TLS fallback for openssl-style services. It collects the banner/prompt, detects service token prompts, PoW prompts, and menu prompts, writes `service/probes/<timestamp>.json`, and records `service_probe_completed`, plus prompt-specific metrics when relevant. The transcript is local-only and sanitized for service secrets.

`service-attempt` connects to the configured service, reads the initial prompt, injects a configured service token only when a token prompt is detected, runs the optional PoW helper with the prompt on stdin, then sends a payload file and/or script stdout. Scripts receive `CTF_SERVICE_HOST`, `CTF_SERVICE_PORT`, `CTF_SERVICE_TRANSPORT`, `CTF_SERVICE_ENDPOINT`, `CTF_SERVICE_TOKEN_SOURCE`, `CTF_SERVICE_TOKEN_FILE`, `CTF_SERVICE_TOKEN_ENV`, and `CTF_SERVICE_POW_HELPER` when configured; they do not receive the token value. Attempt records live under `service/attempts/<timestamp>.json`, candidates are appended to `candidates.jsonl`, and metrics record only hashes/counts/lengths/status. Public-safe snapshots exclude raw transcripts, token values, and raw candidate values.

`solve-loop` uses `service-attempt` when service metadata is available for the target. If a generated or custom starter fails because a tool is missing, the service path still records `missing_tool_observed` and the usual fallback notes.

`interactive brief` prints a compact status view for a target. Use it when the operator asks "지금 뭐 하고 있음?" so a Codex can answer from local state and keep moving.

Release:

```bash
ctfctl interactive release --contest-id "$CONTEST_ID" --agent agent-1 --challenge <id> --reason "switching tasks" --json
```

Memo:

```bash
ctfctl interactive memo --contest-id "$CONTEST_ID" --challenge-id <id> --kind memory --append "fact" --json
ctfctl interactive memo --contest-id "$CONTEST_ID" --challenge-id <id> --kind evidence --append "evidence" --json
ctfctl interactive memo --contest-id "$CONTEST_ID" --challenge-id <id> --kind attempts --append "attempt and result" --json
ctfctl interactive memo --contest-id "$CONTEST_ID" --challenge-id <id> --kind next_steps --append "next action" --json
ctfctl interactive memo --contest-id "$CONTEST_ID" --challenge-id <id> --kind operator_notes --append "operator note" --json
```

Submit:

```bash
ctfctl interactive submit --contest-id "$CONTEST_ID" --challenge-id <id> --flag-file <path> --confirm --json
ctfctl interactive submit-config --contest-id "$CONTEST_ID" --challenge-id <id> --submit-type artifact_upload --endpoint https://example.invalid/submit --field-name file --json
ctfctl interactive upload-submit --contest-id "$CONTEST_ID" --challenge-id <id> --artifact <path> --confirm --json
```

Artifact upload workflow:

```bash
ctfctl interactive submit-config --contest-id "$CONTEST_ID" --challenge-id rfc1149b --submit-type artifact_upload --endpoint https://example.invalid/submit --field-name file --status-url https://example.invalid/status/rfc1149b --json
ctfctl interactive upload-submit --contest-id "$CONTEST_ID" --challenge-id rfc1149b --artifact ./solution.wasm --confirm --json
```

`submit-config` stores challenge submit metadata in local operator state and mirrors it into `board.json` when the challenge is present. The artifact schema is:

```json
{
  "challenge_id": "rfc1149b",
  "submit_type": "artifact_upload",
  "endpoint": "https://example.invalid/submit",
  "method": "multipart",
  "field_name": "file",
  "auth_source": "profile",
  "status_check": "optional"
}
```

`upload-submit` computes artifact SHA-256 and size before any network action. It blocks without uploading when submit metadata and `--endpoint` are both missing, when the endpoint is not an HTTP/HTTPS URL, when credentials or secret-bearing query parameters are embedded in the URL, when the endpoint origin differs from the profile `base_url`, or when profile policy does not allow submission. A local terminal may show the artifact path and output for verification, but auth headers, cookies, tokens, browser storage, private keys, and raw response bodies are not printed.

Accepted upload records are appended to `submissions.jsonl` with artifact SHA-256, size, submit timestamp, response status, and active status. Only accepted/active artifact uploads update `solved.jsonl`, which is the writeup gate. Rejected or blocked uploads get metrics and local records but do not enable ko/en writeup generation.

Stalled and external solves:

```bash
ctfctl interactive stalled --contest-id "$CONTEST_ID" --agent agent-1 --challenge <id> --reason "compact blocker and next action" --json
ctfctl interactive external-solved --contest-id "$CONTEST_ID" --challenge <id> --json
```

`external-solved` accepts a canonical ID/name, alias, static slug, or artifact source. It marks the canonical challenge as `external_solved`, sets `solved_by_external` and `solved_source=external_solved_txt`, appends local `external_solved.txt` entries, records `external_solved_recorded`, and releases claim locks for the canonical ID, aliases, source IDs, and artifact sources. Use this manual fallback when a teammate solves a problem but platform sync does not expose team-solved state. Platform-solved teammate work does not create this agent's accepted writeup; writeups remain accepted-only unless there is local evidence and the user asks.

Writeup and cleanup:

```bash
ctfctl interactive writeup --contest-id "$CONTEST_ID" --challenge-id <id> --category <category> --languages ko,en --include-code --json
ctfctl interactive cleanup --contest-id "$CONTEST_ID" --challenge-id <id> --safe --json
```

E2E smoke:

```bash
ctfctl interactive e2e-smoke --contest-id fake-interactive-smoke --agents 2 --json
ctfctl interactive e2e-smoke --contest-id fake-interactive-smoke --agents 2 --writeup-root /tmp/interactive-writeups --keep-runtime --json
```

## Board And Operator Files

Runtime state lives outside the repo:

```text
~/CTF/contests/<contest>/operator/
```

The operator directory contains:

- `BOARD.md`: human-readable board.
- `board.json`: machine-readable challenge state.
- `operator.json`: local profile/writeup settings and optional challenge submit metadata.
- `solved.jsonl`: accepted local solve records with hash-only flag data.
- `external_solved.txt`: challenge IDs solved outside this local machine.
- `stalled.jsonl`: compact stalled handoffs.
- `submissions.jsonl`: flag hashes or artifact SHA-256/size/status records, with no raw auth material.
- per-challenge `attempts/`: raw local attempt JSON, including stdout/stderr.
- per-challenge `candidates.jsonl`: local raw candidate store with evidence source, command, timestamp, hash, length, and verification status.
- `claims/`: same-machine claim lock files.
- `memos/`: per-challenge memo files.

Each challenge memo set should include:

```text
memory.md
evidence.md
attempts.md
next_steps.md
operator_notes.md
```

If the operator directory does not exist, the first agent or operator should run
`interactive init`.

## Same-Machine Claim Lock

By default, `interactive claim` creates a lock under
`claims/<normalized>.lock` and prevents another Codex session on the same
computer from claiming the same challenge. This avoids local duplicate work.

Use `--allow-duplicate` only when the operator intentionally wants several local
Codex sessions to race or compare approaches on one canonical challenge:

```bash
ctfctl interactive claim --contest-id "$CONTEST_ID" --agent agent-2 --challenge <id> --allow-duplicate --json
```

Locks are local to one computer. Cross-machine duplicate claims are intentionally
not coordinated.

## Self Memo Policy

Solvers should update memos whenever state changes:

- `memory`: durable facts and current understanding.
- `evidence`: local paths, outputs, hashes, and observations.
- `attempts`: tried approaches and results.
- `next_steps`: next concrete actions.
- `operator_notes`: sanitized user or teammate hints.

This prevents context drift when a Codex session gets long or is resumed later.
Local terminal output may include flags, solver output, and exploit output when
needed for solving and verification. Do not put cookies, tokens, sessions,
browser storage, auth headers, private keys, auth material, or secret-bearing
exploit transcripts into memos, and do not publish or upload flags, writeups,
exploits, or auth material to public services, public repositories, public
pastes, issue trackers, or external writeup locations during the contest.

## Writeup Policy

Writeups are accepted-only. A stalled, skipped, or unsolved challenge must not
produce a writeup.

Accepted challenges produce exactly two local files:

```text
[category]ChallengeNameWriteup.ko.md
[category]ChallengeNameWriteup.en.md
```

If a solver or exploit file exists, include the complete code in fenced markdown
blocks. Writeups are local-only during an active contest. Do not publish or
upload flags, auth material, private callback details, or unreviewed local
runtime artifacts during the contest.

## Metrics

`interactive init` creates local-only metrics files under the operator root:

```text
metrics/events.jsonl
metrics/sessions.jsonl
metrics/challenge_metrics.jsonl
metrics/tool_benchmarks.jsonl
metrics/summary.json
metrics/regression_report.md
```

The sync, solved-sync, claim, release, stalled, external-solved, attempt, candidate verification, submit, artifact upload, writeup, and cleanup
commands record events where practical. Manual observations can be appended:

```bash
ctfctl interactive metrics record --contest-id "$CONTEST_ID" --agent agent-1 --event usage_observed --data-json '{"tokens_used": 1234}' --json
ctfctl interactive metrics summary --contest-id "$CONTEST_ID" --json
ctfctl interactive metrics compare --before before-summary.json --after after-summary.json --json
ctfctl interactive metrics report --contest-id "$CONTEST_ID" --json
ctfctl interactive metrics baseline --name before-change --json
ctfctl interactive metrics publish-snapshot --contest-id "$CONTEST_ID" --contest-ended --json
ctfctl interactive metrics dashboard --json
ctfctl interactive metrics compare-public --before old-summary.public.json --after metrics/contests/$CONTEST_ID/summary.public.json --json
```

The summary includes event counts, session count, claimed/attempt/solved/stalled/submit
counts, artifact submitted/accepted/rejected/blocked counts,
accepted/writeup/cleanup counts, observed token totals when present, and average
time to solve when claim and solve timestamps are available.

Local raw metrics are private. GitHub-managed metrics must be generated through
public-safe snapshots only. `publish-snapshot` creates
`summary.public.json`, `solved.public.md`, `stalled.public.md`,
`approaches.public.md`, and `regression.public.md` under
`metrics/contests/<contest-id>` by default. These files may include challenge
names, categories, elapsed times, high-level approach labels, stalled blockers,
counts, observed token totals, candidate hash/length/source/status metadata, and
artifact upload SHA-256/size/status, but must not include raw candidates, raw
flags, cookies, sessions, browser storage, private keys, auth material, artifact
contents, local artifact paths, upload endpoints, raw responses, exploit bodies,
or full writeup bodies.

During an active contest, do not upload contest writeups, flags, exploits, or
private artifacts. Public snapshot export is blocked unless the contest is ended
with `--contest-ended` or the operator explicitly provides both
`--allow-active-contest` and `--confirm-public-safe`. Unsolved challenges get
stalled metrics with memo/attempts/next_steps, not writeups. After an accepted
solve, use submit or accepted/active upload-submit -> writeup ko/en -> cleanup
-> metrics update -> next challenge. After a stall, use
attempts/next_steps -> stalled metrics update -> next challenge. At contest end,
use publish-snapshot -> dashboard -> optional git commit.

## Pre-Release Check

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

These are the default release criteria for the interactive workflow. The active-contest `publish-snapshot` command is expected to be blocked unless the explicit public-safety override flags are present; `release-check.sh` verifies that block.

## Cleanup Policy

Use safe cleanup after a challenge:

```bash
ctfctl interactive cleanup --contest-id "$CONTEST_ID" --challenge-id <id> --safe --json
```

Safe cleanup should remove disposable temp files while preserving useful
evidence, accepted writeups, memos, solve summaries, and artifacts needed for
review. Contest-level callback, tunnel, and Docker resources are cleaned with
the non-interactive helpers:

```bash
ctfctl contest cleanup-resources --contest-id "$CONTEST_ID" --json
ctfctl docker pool-stop --contest-id "$CONTEST_ID" --json
```

## Legacy Worker Flow

`worker_loop`, `worker_supervisor`, `multi_worker`, `ctfctl worker ...`, and
`ctfctl contest start-workers` remain available for advanced rehearsals and
legacy automation tests. They are not the default live contest operation model.
