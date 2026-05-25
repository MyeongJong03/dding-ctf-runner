# Interactive Codex Swarm Operations

This is the default live contest workflow. It uses multiple visible Codex terminals
as autonomous solvers. There is no controller/solver split and no background queue
supervisor in the default path.

## Start

From the runner repo:

```bash
export CONTEST_ID=<contest>
export PROFILE=~/.ctf-solver/platforms/<contest>.yaml

./scripts/ctfctl preflight --deep --json
./scripts/ctfctl interactive init --contest-id "$CONTEST_ID" --profile "$PROFILE" --agents 4 --json
./scripts/ctfctl interactive sync --contest-id "$CONTEST_ID" --profile "$PROFILE" --live --download --ingest --json
./scripts/ctfctl interactive board --contest-id "$CONTEST_ID" --json
./scripts/ctfctl interactive prompt --contest-id "$CONTEST_ID" --agent agent-1
```

Open separate terminals, `cd ~/CTF`, start plain interactive Codex sessions, and
paste the prompt generated for each agent. On Windows use six terminals when the
machine can handle it. On Mac use four by default.

## Solver Loop

Each agent should repeatedly run:

```bash
ctfctl interactive claim --contest-id "$CONTEST_ID" --agent agent-1 --json
ctfctl interactive memo --contest-id "$CONTEST_ID" --challenge-id <id> --kind memory --append "fact" --json
ctfctl interactive submit --contest-id "$CONTEST_ID" --challenge-id <id> --flag-file <path> --confirm --json
ctfctl interactive writeup --contest-id "$CONTEST_ID" --challenge-id <id> --category <category> --languages ko,en --include-code --json
ctfctl interactive cleanup --contest-id "$CONTEST_ID" --challenge-id <id> --safe --json
```

If a problem stalls:

```bash
ctfctl interactive stalled --contest-id "$CONTEST_ID" --agent agent-1 --challenge <id> --reason "compact blocker" --json
```

If a teammate solves it elsewhere:

```bash
ctfctl interactive external-solved --contest-id "$CONTEST_ID" --challenge <id> --json
```

Same-machine duplicate claims are blocked by default with
`claims/<normalized>.lock`. Use `--allow-duplicate` only when the operator wants
multiple Codex sessions on the same challenge. Locks are local to one computer;
cross-machine duplicate solving is intentionally out of scope.

## Board And Memos

Runtime state lives under:

```text
~/CTF/contests/<contest>/operator/
```

The operator directory contains `BOARD.md`, `board.json`, `solved.jsonl`,
`external_solved.txt`, `stalled.jsonl`, `claims/`, and `memos/`. Each challenge
keeps `memory.md`, `evidence.md`, `attempts.md`, `next_steps.md`, and
`operator_notes.md` to prevent context drift.

## Writeup Policy

Writeups are accepted-only. A stalled, skipped, or unsolved challenge must not
produce a writeup. Accepted challenges produce two files:

```text
[category]ChallengeNameWriteup.ko.md
[category]ChallengeNameWriteup.en.md
```

If a solver or exploit file exists, include the complete code in fenced markdown
blocks. Never include raw flags, cookies, tokens, browser storage, private keys,
real platform URLs, or local-only artifacts intended to stay private.

## Legacy Worker Flow

`worker_loop`, `worker_supervisor`, `multi_worker`, and
`ctfctl contest start-workers` remain available for advanced rehearsals and
legacy automation tests. They are not the default live contest operation model.
