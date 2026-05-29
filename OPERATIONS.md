# Contest-Day Runbook

Default operation is an interactive Codex swarm. Do not start background workers for normal live play.

## 1. Prepare

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

Use `--agents 6` on a strong Windows WSL machine. Use `--agents 4` on MacBook.

The interactive smoke is local-only. It loads fake challenges, exercises claim,
accepted submit, solved/submission records, ko/en accepted-only writeups with
full solver code, cleanup, stalled metrics without writeups, metrics summary,
next claim, and duplicate-claim guards. Use `--keep-runtime` only when you need
to inspect the generated local operator files.

## 2. Start Codex

Generate prompts:

```bash
./scripts/ctfctl interactive prompt --contest-id "$CONTEST_ID" --agent agent-1
./scripts/ctfctl interactive prompt --contest-id "$CONTEST_ID" --agent agent-2
./scripts/ctfctl interactive prompt --contest-id "$CONTEST_ID" --agent agent-3
./scripts/ctfctl interactive prompt --contest-id "$CONTEST_ID" --agent agent-4
```

In each solver terminal:

```bash
cd ~/CTF
codex
```

Paste one prompt per terminal. Every terminal is an autonomous solver: next/claim, read the target pack, solve, verify, submit, writeup, cleanup, next.

## 3. During The Contest

Monitor board:

```bash
./scripts/ctfctl interactive board --contest-id "$CONTEST_ID" --json
```

Board sync is canonical-first. Alias/static shell rows stay in `board.json` under the canonical challenge as `aliases`, `artifact_sources`, and `source_ids`; default claims skip them. Check `canonical_count`, `alias_count`, `skipped_static_count`, and `claimable_count` after sync if the platform publishes duplicate rows.

Pick or prepare the next target:

```bash
ctfctl interactive solve-loop --contest-id "$CONTEST_ID" --agent agent-1 --json
ctfctl interactive solve-loop --contest-id "$CONTEST_ID" --agent agent-1 --challenge-id <id> --max-attempts 5 --json
ctfctl interactive prepare-target --contest-id "$CONTEST_ID" --agent agent-1 --json
ctfctl interactive next --contest-id "$CONTEST_ID" --agent agent-1 --json
ctfctl interactive target-pack --contest-id "$CONTEST_ID" --challenge-id <id> --agent agent-1 --json
ctfctl interactive triage --contest-id "$CONTEST_ID" --challenge-id <id> --agent agent-1 --json
ctfctl interactive starter --contest-id "$CONTEST_ID" --challenge-id <id> --json
ctfctl interactive run-attempt --contest-id "$CONTEST_ID" --challenge-id <id> --script <path> --json
ctfctl interactive candidates --contest-id "$CONTEST_ID" --challenge-id <id> --json
ctfctl interactive verify-candidate --contest-id "$CONTEST_ID" --challenge-id <id> --json
ctfctl interactive brief --contest-id "$CONTEST_ID" --challenge-id <id> --json
```

`solve-loop` is the default Codex harness after prompt startup: it selects or prepares a target, ensures target pack/triage/starter, runs the starter as a structured attempt, extracts local candidates, verifies confidence and submit guards, submits high-confidence candidates, then writes ko/en writeups, runs cleanup, updates metrics, and continues. If it exhausts `--max-attempts`, it updates attempts/next steps, records stalled metrics, creates no writeup, and continues to the next challenge.

`prepare-target` is the manual Codex starter: it runs `next` when needed, generates the target pack, runs local-only category triage, creates a starter skeleton, and returns the key paths plus first commands and next steps. `next` prefers canonical challenges with attachments, remote endpoints, confident categories, existing progress, or stalled `next_steps`. It skips alias/static rows and solved/external-solved work. `target-pack` records the paths, aliases, artifact sources, remote info, memory summaries, recommended commands, and category playbook. `triage` writes `triage/summary.md`, `files.json`, `commands.jsonl`, and `findings.jsonl`, then updates local memos. `starter` creates the category solve skeleton and records it in board/operator metadata. `run-attempt` records raw local stdout/stderr/returncode/runtime in `attempts/`, updates `attempts.md`, extracts candidates into `candidates.jsonl`, and emits attempt metrics. `candidates` displays local raw candidate values; public snapshots include only candidate hash, length, source, status, confidence, and timestamp. Use `brief` to answer a user status question such as "지금 뭐 하고 있음?" without stopping the solve loop.

Add operator information:

```bash
ctfctl interactive memo --contest-id "$CONTEST_ID" --challenge-id <id> --kind operator_notes --append "short sanitized note" --json
ctfctl interactive memo --contest-id "$CONTEST_ID" --challenge-id <id> --kind next_steps --append "next action" --json
```

Intentionally duplicate one local claim:

```bash
ctfctl interactive claim --contest-id "$CONTEST_ID" --agent agent-2 --challenge <id> --allow-duplicate --json
```

Record an outside solve:

```bash
ctfctl interactive external-solved --contest-id "$CONTEST_ID" --challenge <id> --json
```

The `<id>` may be a canonical challenge, alias, static slug, or artifact source. This is the fallback when another teammate solved the challenge but team-solved state did not appear in platform sync.

## 4. Submit And Writeup

Submit flag from a local file:

```bash
ctfctl interactive submit --contest-id "$CONTEST_ID" --challenge-id <id> --flag-file <path> --confirm --json
```

Submit upload artifact:

```bash
ctfctl interactive submit-config --contest-id "$CONTEST_ID" --challenge-id <id> --submit-type artifact_upload --endpoint https://example.invalid/submit --field-name file --json
ctfctl interactive upload-submit --contest-id "$CONTEST_ID" --challenge-id <id> --artifact <path> --confirm --json
```

For rfc1149b-like wasm/file challenges, keep the built artifact local and upload only through `upload-submit`. The command blocks if no official endpoint metadata exists or if the endpoint is outside the profile `base_url` origin. Local records include artifact SHA-256, size, timestamp, response status, and active status.

Writeups are accepted-only:

```bash
ctfctl interactive writeup --contest-id "$CONTEST_ID" --challenge-id <id> --category <category> --languages ko,en --include-code --json
```

Expected filenames:

```text
[category]ChallengeNameWriteup.ko.md
[category]ChallengeNameWriteup.en.md
```

If solver/exploit code exists, include the full code. Do not write writeups for unsolved problems; leave memos and a stalled record.

## 5. Cleanup

Per challenge:

```bash
ctfctl interactive cleanup --contest-id "$CONTEST_ID" --challenge-id <id> --safe --json
```

Contest resources:

```bash
./scripts/ctfctl contest cleanup-resources --contest-id "$CONTEST_ID" --json
./scripts/ctfctl docker pool-stop --contest-id "$CONTEST_ID" --json
```

Final check:

```bash
./scripts/ctfctl interactive board --contest-id "$CONTEST_ID" --json
```

## 6. Windows And Mac Notes

- Windows WSL is the preferred primary runner for pwn/rev-heavy work.
- Keep the repo on WSL ext4, not `/mnt/c`.
- Windows can run up to 6 Codex terminals if CPU/RAM and platform rate limits allow.
- MacBook should default to 4 Codex terminals.
- On macOS, keep Docker workspaces outside `~/CTF`:

```bash
export CTF_DOCKER_WORKSPACE_ROOT="$HOME/.ctf-solver/runner-state/docker-workspaces"
```

## 7. Do Not Leak

Local terminal output may include flags, solver output, and exploit output when needed for solving and verification. During an active contest, do not commit, push, paste publicly, publish, or upload flags, writeups, exploits, cookies, tokens, sessions, browser storage, auth headers, passwords, private keys, callback hits, or downloaded private files. Store submitted flags as hashes in runner state.

Record/update local metrics when comparing runner changes. Local raw metrics are private operator state:

```bash
ctfctl interactive metrics summary --contest-id "$CONTEST_ID" --json
ctfctl interactive metrics report --contest-id "$CONTEST_ID" --json
```

GitHub metrics are public-safe snapshots only. Do not upload contest writeups, flags, exploit bodies, auth material, or private artifacts during an active contest. Unsolved challenges get stalled metrics with compact blockers, not writeups.

Use this operational order:

- Accepted solve: submit -> writeup ko/en -> cleanup -> metrics update -> next challenge.
- Stalled challenge: attempts/next_steps -> stalled metrics update -> next challenge.
- Contest end: `ctfctl interactive metrics publish-snapshot --contest-id "$CONTEST_ID" --contest-ended --json` -> `ctfctl interactive metrics dashboard --json` -> optional git commit.

`publish-snapshot` is blocked during a contest unless both `--allow-active-contest` and `--confirm-public-safe` are explicitly set.

## 8. Legacy Background Workers

`contest start-workers`, `worker_loop`, `worker_supervisor`, `multi_worker`, and `scripts/ctf-worker-*` are legacy/advanced. They are for rehearsals and explicit automation experiments, not the normal contest-day runbook.

## 9. Pre-Release Check

Use the interactive-first release gate before public docs or release changes:

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

`release-check.sh`, `public-check`, and `fresh-clone-check.sh` should center interactive init, e2e smoke, metrics, prompt generation, and active-contest public snapshot blocking. Legacy worker/full-rehearsal coverage may remain, but only as advanced compatibility coverage.
