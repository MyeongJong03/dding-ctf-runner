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
Do not put raw flags, cookies, tokens, browser storage, auth headers, private
keys, shell history, or exploit transcripts with secrets into memos.

## Writeup Policy

Writeups are accepted-only. A stalled, skipped, or unsolved challenge must not
produce a writeup.

Accepted challenges produce exactly two local files:

```text
[category]ChallengeNameWriteup.ko.md
[category]ChallengeNameWriteup.en.md
```

If a solver or exploit file exists, include the complete code in fenced markdown
blocks. Do not include raw flags, auth material, private callback details, or
unreviewed local runtime artifacts.

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
