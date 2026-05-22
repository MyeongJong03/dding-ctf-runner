# Submit Policy

Phase 5 implements controlled auto-submit. The runner can plan and execute guarded CTFd submissions, but a live submission must pass local policy, platform policy, and operator confirmation gates.

Confidence tiers:

- `high`: the candidate matches the configured flag regex and came from a trusted solve source such as exploit output, a verified solver path, a known flag source, or an accepted platform response.
- `medium`: the candidate is flag-like, but the context is uncertain.
- `low`: the candidate looks like a placeholder, example, fixture, test value, or common bait.

Guards:

- `duplicate_detection: sha256` compares only flag hashes against previous terminal submissions.
- `max_wrong_per_challenge` blocks after the configured number of rejected attempts.
- `cooldown_seconds` blocks another attempt shortly after a wrong submission.
- `reject_fake_like` blocks fake/test/example/dummy/placeholder-style candidates even when they match the regex.
- `require_high_confidence` blocks medium and low confidence candidates by default.
- `submit_requires_live` keeps platform submit dry-run unless `--live` is present.
- `submit_requires_confirm_or_policy` requires `--confirm` unless the platform config has an explicit unconfirmed-submit policy override.

State and output rules:

- Raw flags are never stored in the submission table, CLI JSON, telemetry, or docs.
- Submission state stores `challenge_id`, `flag_hash`, `submitted_at`, `status`, `confidence`, `result_summary_redacted`, and `worker_id`.
- CLI output runs through `redact_text`; submit helpers also return only a hash and a short redacted preview.

CTFd submit endpoint:

- `POST /api/v1/challenges/attempt`
- Payload fields are `challenge_id` and `submission`.
- Responses are normalized to `accepted`, `rejected`, `rate_limited`, or `unknown`.

Example dry-run:

```bash
ctfctl platform submit --config contests/<id>/platform.local.yaml --challenge-id 123 --flag '<candidate>'
```

Example live submit after policy review:

```bash
ctfctl platform submit --config contests/<id>/platform.local.yaml --challenge-id 123 --flag '<candidate>' --live --confirm
```
