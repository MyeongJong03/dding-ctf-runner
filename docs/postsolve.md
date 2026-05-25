# Postsolve Workflow

Postsolve output is local-only competition material. It is designed for operator review after a challenge is accepted, not for public publishing during an active event.

The interactive workflow has a stricter writeup rule: `ctfctl interactive writeup`
refuses unsolved challenges and writes two accepted-only files,
`[category]ChallengeNameWriteup.ko.md` and
`[category]ChallengeNameWriteup.en.md`. When solver/exploit code exists, the
complete code must be included in fenced markdown blocks.

## Generated Files

Default location:

```text
~/CTF/contests/<contest_id>/<challenge_id>/postsolve/
```

Files:

- `solve_summary.md`: compact solved-state record with challenge metadata, worker ID, source summary, files used, submit status, and flag hash.
- `writeup_draft.md`: private draft with problem summary, approach, core idea, command summary, script references, and verification notes.
- `skill_candidate.md`: candidate pattern for later manual review before updating personal skills.
- `artifacts_manifest.json`: paths, sizes, hashes, and archive metadata for local artifacts.
- `timeline.jsonl`: redacted postsolve events.
- `postsolve_summary.json`: machine-readable status and generated file paths.

Existing files are preserved with `.bak.<timestamp>` names before a new canonical file is written.

## Redaction Policy

Raw flags, cookies, tokens, auth headers, storage state, API keys, passwords, private keys, and browser storage values must not be written to postsolve files or printed by postsolve CLI commands.

Flags are represented as:

- SHA-256 hash when available.
- `[REDACTED_FLAG]` placeholder in prose.
- Redacted text if a solver summary or local note accidentally includes a flag-like value.

## Archive Policy

`ctfctl postsolve archive` copies safe local artifacts into `postsolve/archive/` by default. It never deletes raw attachments or extracted files.

Archive copy mode:

- Skips oversized files above the default 100MB limit unless future explicit large-file support is enabled.
- Excludes sensitive filenames such as auth, cookie, token, password, session, private key, and storage-state files.
- Treats obvious secret-like or flag-like file contents as metadata-only, so those files appear in manifests but are not copied.
- Skips the `postsolve/` tree itself to avoid archiving generated drafts.

Cleanup is intentionally separate from archive generation and is not enabled by default.

## Skill Candidate Format

`skill_candidate.md` uses this structure:

- pattern title
- category
- trigger signs
- solution sketch
- reusable snippet
- avoid/false positives
- source challenge id

The file is a candidate only. It does not modify `~/ctf-solver` or any installed skill files.

## Commands

```bash
./scripts/ctfctl postsolve generate --contest-id <contest> --challenge-id <challenge> --json
./scripts/ctfctl postsolve status --contest-id <contest> --challenge-id <challenge> --json
./scripts/ctfctl postsolve archive --contest-id <contest> --challenge-id <challenge> --json
./scripts/ctfctl postsolve skill-candidates --contest-id <contest> --json
./scripts/ctfctl postsolve batch --contest-id <contest> --status solved --json
```

## Post-Contest Review

After disarming the contest, review generated drafts locally. Convert `writeup_draft.md` into any required organizer format only after removing challenge-specific secrets and confirming event publication rules. Review `skill_candidate.md` files manually and promote only sanitized reusable patterns after the contest.

## Public Release Boundary

Postsolve directories, archives, timelines, local solve summaries, and generated drafts are runtime outputs. They must remain outside this repository and are rejected by public-check when placed under repo-local runtime paths such as `writeups/`, `downloads/`, `contests/`, or `state/`. Public docs should describe the workflow only; do not copy generated challenge names, solver transcripts, raw candidates, callback details, or archive manifests into git.
