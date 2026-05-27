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
./scripts/ctfctl interactive init --contest-id "$CONTEST_ID" --profile "$PROFILE" --agents "$AGENTS" --json
./scripts/ctfctl interactive sync --contest-id "$CONTEST_ID" --profile "$PROFILE" --live --download --ingest --json
./scripts/ctfctl interactive board --contest-id "$CONTEST_ID" --json
```

Use `--agents 6` on a strong Windows WSL machine. Use `--agents 4` on MacBook.

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

Paste one prompt per terminal. Every terminal is an autonomous solver: claim, solve, verify, submit, writeup, cleanup, next.

## 3. During The Contest

Monitor board:

```bash
./scripts/ctfctl interactive board --contest-id "$CONTEST_ID" --json
```

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

## 4. Submit And Writeup

Submit flag from a local file:

```bash
ctfctl interactive submit --contest-id "$CONTEST_ID" --challenge-id <id> --flag-file <path> --confirm --json
```

Submit upload artifact:

```bash
ctfctl interactive upload-submit --contest-id "$CONTEST_ID" --challenge-id <id> --artifact <path> --confirm --json
```

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
- Stalled challenge: memo/attempts/next_steps -> metrics update -> next challenge.
- Contest end: `ctfctl interactive metrics publish-snapshot --contest-id "$CONTEST_ID" --contest-ended --json` -> `ctfctl interactive metrics dashboard --json` -> optional git commit.

`publish-snapshot` is blocked during a contest unless both `--allow-active-contest` and `--confirm-public-safe` are explicitly set.

## 8. Legacy Background Workers

`contest start-workers`, `worker_loop`, `worker_supervisor`, `multi_worker`, and `scripts/ctf-worker-*` are legacy/advanced. They are for rehearsals and explicit automation experiments, not the normal contest-day runbook.
