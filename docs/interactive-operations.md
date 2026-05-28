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
./scripts/ctfctl interactive e2e-smoke --contest-id fake-interactive-smoke --agents 2 --json
./scripts/ctfctl interactive init --contest-id "$CONTEST_ID" --profile "$PROFILE" --agents "$AGENTS" --json
./scripts/ctfctl interactive sync --contest-id "$CONTEST_ID" --profile "$PROFILE" --live --download --ingest --json
./scripts/ctfctl interactive board --contest-id "$CONTEST_ID" --json
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
```

Sync and board canonicalization:

- `interactive sync` folds duplicate platform rows into canonical challenges before claim.
- Static shell pages are detected when they have only generic short text and favicon/CSS-style links, or when the row is a `-static` slug.
- Alias rows include case, spacing, slug, and phase metadata variants. They are recorded on the canonical challenge as `aliases`, `artifact_sources`, and `source_ids` instead of becoming default claim targets.
- `board.json` challenge rows include `canonical_id`, `canonical_name`, `aliases`, `artifact_sources`, `source_ids`, `is_static_shell`, `claimable`, and `solved_by_external`.
- `interactive sync --json` and `interactive board --json` report `canonical_count`, `alias_count`, `skipped_static_count`, and `claimable_count`.

Claim:

```bash
ctfctl interactive claim --contest-id "$CONTEST_ID" --agent agent-1 --json
ctfctl interactive claim --contest-id "$CONTEST_ID" --agent agent-1 --challenge <id> --json
```

Default claim returns only canonical rows where `claimable` is true. If a solver requests an alias or static slug with `--challenge`, the claim resolves to the canonical challenge and returns the canonical path/name.

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

`external-solved` accepts a canonical ID/name, alias, static slug, or artifact source. It marks the canonical challenge as `external_solved`, sets `solved_by_external`, appends local `external_solved.txt` entries, and releases claim locks for the canonical ID and aliases. Use this when a teammate solves a problem but platform sync does not expose team-solved state.

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

The claim, release, stalled, external-solved, submit, artifact upload, writeup, and cleanup
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

The summary includes event counts, session count, claimed/solved/stalled/submit
counts, artifact submitted/accepted/rejected/blocked counts,
accepted/writeup/cleanup counts, observed token totals when present, and average
time to solve when claim and solve timestamps are available.

Local raw metrics are private. GitHub-managed metrics must be generated through
public-safe snapshots only. `publish-snapshot` creates
`summary.public.json`, `solved.public.md`, `stalled.public.md`,
`approaches.public.md`, and `regression.public.md` under
`metrics/contests/<contest-id>` by default. These files may include challenge
names, categories, elapsed times, high-level approach labels, stalled blockers,
counts, observed token totals, and artifact upload SHA-256/size/status, but must
not include raw flags, cookies, sessions, browser storage, private keys, auth
material, artifact contents, local artifact paths, upload endpoints, raw
responses, exploit bodies, or full writeup bodies.

During an active contest, do not upload contest writeups, flags, exploits, or
private artifacts. Public snapshot export is blocked unless the contest is ended
with `--contest-ended` or the operator explicitly provides both
`--allow-active-contest` and `--confirm-public-safe`. Unsolved challenges get
stalled metrics with memo/attempts/next_steps, not writeups. After an accepted
solve, use submit or accepted/active upload-submit -> writeup ko/en -> cleanup
-> metrics update -> next challenge. After a stall, use
memo/attempts/next_steps -> metrics update -> next challenge. At contest end,
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
