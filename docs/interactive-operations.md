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
./scripts/ctfctl interactive init --contest-id "$CONTEST_ID" --profile "$PROFILE" --agents "$AGENTS" --json
./scripts/ctfctl interactive sync --contest-id "$CONTEST_ID" --profile "$PROFILE" --live --download --ingest --json
./scripts/ctfctl interactive board --contest-id "$CONTEST_ID" --json
```

Use `--agents 6` for a strong Windows WSL host and `--agents 4` for a MacBook.

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

Claim:

```bash
ctfctl interactive claim --contest-id "$CONTEST_ID" --agent agent-1 --json
ctfctl interactive claim --contest-id "$CONTEST_ID" --agent agent-1 --challenge <id> --json
```

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
ctfctl interactive upload-submit --contest-id "$CONTEST_ID" --challenge-id <id> --artifact <path> --confirm --json
```

Stalled and external solves:

```bash
ctfctl interactive stalled --contest-id "$CONTEST_ID" --agent agent-1 --challenge <id> --reason "compact blocker and next action" --json
ctfctl interactive external-solved --contest-id "$CONTEST_ID" --challenge <id> --json
```

Writeup and cleanup:

```bash
ctfctl interactive writeup --contest-id "$CONTEST_ID" --challenge-id <id> --category <category> --languages ko,en --include-code --json
ctfctl interactive cleanup --contest-id "$CONTEST_ID" --challenge-id <id> --safe --json
```

## Board And Operator Files

Runtime state lives outside the repo:

```text
~/CTF/contests/<contest>/operator/
```

The operator directory contains:

- `BOARD.md`: human-readable board.
- `board.json`: machine-readable challenge state.
- `solved.jsonl`: accepted local solve records with hash-only flag data.
- `external_solved.txt`: challenge IDs solved outside this local machine.
- `stalled.jsonl`: compact stalled handoffs.
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
Codex sessions to race or compare approaches on one challenge:

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

The claim, release, stalled, external-solved, submit, writeup, and cleanup
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
counts, accepted/writeup/cleanup counts, observed token totals when present, and
average time to solve when claim and solve timestamps are available.

Local raw metrics are private. GitHub-managed metrics must be generated through
public-safe snapshots only. `publish-snapshot` creates
`summary.public.json`, `solved.public.md`, `stalled.public.md`,
`approaches.public.md`, and `regression.public.md` under
`metrics/contests/<contest-id>` by default. These files may include challenge
names, categories, elapsed times, high-level approach labels, stalled blockers,
counts, and observed token totals, but must not include raw flags, cookies,
sessions, browser storage, private keys, auth material, exploit bodies, or full
writeup bodies.

During an active contest, do not upload contest writeups, flags, exploits, or
private artifacts. Public snapshot export is blocked unless the contest is ended
with `--contest-ended` or the operator explicitly provides both
`--allow-active-contest` and `--confirm-public-safe`. Unsolved challenges get
stalled metrics with memo/attempts/next_steps, not writeups. After an accepted
solve, use submit -> writeup ko/en -> cleanup -> metrics update -> next
challenge. After a stall, use memo/attempts/next_steps -> metrics update -> next
challenge. At contest end, use publish-snapshot -> dashboard -> optional git
commit.

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
