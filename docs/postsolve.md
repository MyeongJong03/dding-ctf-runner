# Postsolve And Writeup Policy

Postsolve output is local-only competition material. It exists for operator
review after an accepted solve, not for public publishing during an active event.

## Interactive Writeups

The interactive workflow writes public-style challenge writeups only after an
accepted solve is confirmed:

```bash
ctfctl interactive writeup --contest-id <contest> --challenge-id <id> --category <category> --languages ko,en --include-code --json
```

Accepted challenges produce two files:

```text
[category]ChallengeNameWriteup.ko.md
[category]ChallengeNameWriteup.en.md
```

If solver or exploit code exists, include the complete code in fenced markdown
blocks. This includes helper scripts and final exploit code needed to reproduce
the solve.

Do not generate writeups for unsolved, skipped, or stalled challenges. For
unsolved work, keep only compact local records:

```text
memory.md
evidence.md
attempts.md
next_steps.md
operator_notes.md
stalled.jsonl
```

## Generated Postsolve Files

Default location:

```text
~/CTF/contests/<contest_id>/<challenge_id>/postsolve/
```

Files:

- `solve_summary.md`: compact accepted-solve record with metadata, source summary, submit status, and flag hash.
- `writeup_draft.md`: private draft for later review.
- `skill_candidate.md`: local candidate for a reusable pattern.
- `artifacts_manifest.json`: paths, sizes, hashes, and archive metadata.
- `timeline.jsonl`: redacted postsolve events.
- `postsolve_summary.json`: machine-readable status and generated paths.

Existing files are preserved with `.bak.<timestamp>` names before a new
canonical file is written.

## Redaction

Raw flags, cookies, tokens, auth headers, storage state, API keys, passwords,
private keys, browser storage values, callback secrets, and shell history must
not be written to postsolve files or printed by postsolve commands.

Flags are represented as SHA-256 hashes or `[REDACTED_FLAG]` placeholders.

## Archive

`ctfctl postsolve archive` copies safe local artifacts into
`postsolve/archive/` by default. It does not delete raw attachments or extracted
files.

Archive copy mode:

- skips oversized files above the default limit
- excludes sensitive filenames such as auth, cookie, token, password, session, private key, and storage-state files
- treats obvious secret-like or flag-like contents as metadata-only
- skips the `postsolve/` tree itself

## Commands

```bash
./scripts/ctfctl postsolve generate --contest-id <contest> --challenge-id <challenge> --json
./scripts/ctfctl postsolve status --contest-id <contest> --challenge-id <challenge> --json
./scripts/ctfctl postsolve archive --contest-id <contest> --challenge-id <challenge> --json
./scripts/ctfctl postsolve skill-candidates --contest-id <contest> --json
./scripts/ctfctl postsolve batch --contest-id <contest> --status solved --json
```

## Review Boundary

After the contest, review drafts locally and remove challenge-specific secrets
before any external publication. Review `skill_candidate.md` manually and
promote only sanitized reusable patterns. The runner does not modify
`~/ctf-solver` or installed skills.

Postsolve directories, archives, timelines, writeups, and local solve summaries
must remain outside this repository. Public docs describe the workflow only; do
not copy generated challenge names, transcripts, candidates, callback details,
or archive manifests into git.
