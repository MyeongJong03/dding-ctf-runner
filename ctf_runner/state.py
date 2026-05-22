from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .paths import get_paths
from .redact import redact_text


CHALLENGE_STATUSES = {
    "new",
    "queued",
    "claimed",
    "ingest_ready",
    "solving",
    "submit_planned",
    "solved",
    "stalled",
    "error",
    "blocked_by_mode",
    "abandoned",
}
CLAIMABLE_STATUSES = {"new", "queued", "ingest_ready"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def default_db_path() -> Path:
    return get_paths().db_path


class ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool | None:
        try:
            return super().__exit__(exc_type, exc, tb)
        finally:
            self.close()


def connect(db_path: str | Path | None = None) -> sqlite3.Connection:
    path = Path(db_path).expanduser() if db_path else default_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, factory=ClosingConnection)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS contests (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS challenges (
  id TEXT PRIMARY KEY,
  contest_id TEXT,
  name TEXT NOT NULL,
  category TEXT,
  points INTEGER,
  solves INTEGER,
  status TEXT NOT NULL DEFAULT 'queued',
  source TEXT NOT NULL DEFAULT 'manual',
  metadata TEXT NOT NULL DEFAULT '{}',
  priority INTEGER NOT NULL DEFAULT 100,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(contest_id) REFERENCES contests(id)
);

CREATE TABLE IF NOT EXISTS claims (
  worker_id TEXT NOT NULL,
  challenge_id TEXT NOT NULL UNIQUE,
  claimed_at TEXT NOT NULL,
  heartbeat_at TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'active',
  PRIMARY KEY(worker_id, challenge_id),
  FOREIGN KEY(challenge_id) REFERENCES challenges(id)
);

CREATE TABLE IF NOT EXISTS claim_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  worker_id TEXT NOT NULL,
  challenge_id TEXT NOT NULL,
  claimed_at TEXT NOT NULL,
  heartbeat_at TEXT NOT NULL,
  finished_at TEXT NOT NULL,
  final_state TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL,
  worker_id TEXT,
  challenge_id TEXT,
  event_type TEXT NOT NULL,
  status TEXT NOT NULL,
  details TEXT
);

CREATE TABLE IF NOT EXISTS submissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  challenge_id TEXT NOT NULL,
  flag_hash TEXT NOT NULL,
  submitted_at TEXT NOT NULL,
  status TEXT NOT NULL,
  confidence TEXT,
  result_summary_redacted TEXT,
  worker_id TEXT,
  details TEXT,
  UNIQUE(challenge_id, flag_hash)
);

CREATE TABLE IF NOT EXISTS workers (
  worker_id TEXT PRIMARY KEY,
  role TEXT NOT NULL,
  status TEXT NOT NULL,
  registered_at TEXT NOT NULL,
  heartbeat_at TEXT NOT NULL
);
"""


def init_db(db_path: str | Path | None = None) -> Path:
    path = Path(db_path).expanduser() if db_path else default_db_path()
    with connect(path) as conn:
        conn.executescript(SCHEMA)
        _apply_migrations(conn)
    return path


def _apply_migrations(conn: sqlite3.Connection) -> None:
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(challenges)").fetchall()}
    additions = {
        "points": "ALTER TABLE challenges ADD COLUMN points INTEGER",
        "solves": "ALTER TABLE challenges ADD COLUMN solves INTEGER",
        "source": "ALTER TABLE challenges ADD COLUMN source TEXT NOT NULL DEFAULT 'manual'",
        "metadata": "ALTER TABLE challenges ADD COLUMN metadata TEXT NOT NULL DEFAULT '{}'",
    }
    for column, statement in additions.items():
        if column not in columns:
            conn.execute(statement)
    submission_columns = {row["name"] for row in conn.execute("PRAGMA table_info(submissions)").fetchall()}
    submission_additions = {
        "result_summary_redacted": "ALTER TABLE submissions ADD COLUMN result_summary_redacted TEXT",
        "worker_id": "ALTER TABLE submissions ADD COLUMN worker_id TEXT",
        "details": "ALTER TABLE submissions ADD COLUMN details TEXT",
    }
    for column, statement in submission_additions.items():
        if column not in submission_columns:
            conn.execute(statement)


def record_event(
    event_type: str,
    status: str,
    details: Any | None = None,
    *,
    worker_id: str | None = None,
    challenge_id: str | None = None,
    db_path: str | Path | None = None,
) -> None:
    init_db(db_path)
    payload = redact_text(json.dumps(details or {}, sort_keys=True))
    with connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO events(timestamp, worker_id, challenge_id, event_type, status, details)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (utc_now(), worker_id, challenge_id, event_type, status, payload),
        )


def register_worker(worker_id: str, role: str, db_path: str | Path | None = None) -> dict[str, str]:
    init_db(db_path)
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO workers(worker_id, role, status, registered_at, heartbeat_at)
            VALUES (?, ?, 'idle', ?, ?)
            ON CONFLICT(worker_id) DO UPDATE SET role=excluded.role, status='idle', heartbeat_at=excluded.heartbeat_at
            """,
            (worker_id, role, now, now),
        )
    record_event("worker_register", "ok", {"role": role}, worker_id=worker_id, db_path=db_path)
    return {"worker_id": worker_id, "role": role, "status": "idle"}


def add_manual_challenge(
    challenge_id: str,
    name: str,
    category: str,
    *,
    contest_id: str | None = None,
    priority: int = 100,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    init_db(db_path)
    now = utc_now()
    with connect(db_path) as conn:
        if contest_id:
            conn.execute(
                "INSERT OR IGNORE INTO contests(id, name, created_at) VALUES (?, ?, ?)",
                (contest_id, contest_id, now),
            )
        conn.execute(
            """
            INSERT INTO challenges(id, contest_id, name, category, status, source, priority, created_at, updated_at, metadata)
            VALUES (?, ?, ?, ?, 'queued', 'manual', ?, ?, ?, '{}')
            ON CONFLICT(id) DO UPDATE SET
              name=excluded.name,
              category=excluded.category,
              priority=excluded.priority,
              source='manual',
              updated_at=excluded.updated_at
            """,
            (challenge_id, contest_id, name, category, priority, now, now),
        )
    record_event(
        "challenge_add_manual",
        "ok",
        {"name": name, "category": category},
        challenge_id=challenge_id,
        db_path=db_path,
    )
    return {"challenge_id": challenge_id, "name": name, "category": category, "status": "queued"}


def upsert_platform_challenges(
    challenges: list[dict[str, Any]],
    *,
    contest_id: str | None = None,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    init_db(db_path)
    now = utc_now()
    inserted = 0
    with connect(db_path) as conn:
        if contest_id:
            conn.execute(
                "INSERT OR IGNORE INTO contests(id, name, created_at) VALUES (?, ?, ?)",
                (contest_id, contest_id, now),
            )
        for item in challenges:
            challenge_id = str(item.get("challenge_id") or item.get("id") or "").strip()
            name = str(item.get("name") or "").strip()
            if not challenge_id or not name:
                continue
            metadata = redact_text(json.dumps(item.get("metadata") or item, sort_keys=True))
            conn.execute(
                """
                INSERT INTO challenges(
                  id, contest_id, name, category, points, solves, status, source, metadata, priority, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, 'new', 'platform', ?, 100, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                  contest_id=excluded.contest_id,
                  name=excluded.name,
                  category=excluded.category,
                  points=excluded.points,
                  solves=excluded.solves,
                  metadata=excluded.metadata,
                  updated_at=excluded.updated_at,
                  status=CASE
                    WHEN challenges.source='manual' THEN challenges.status
                    WHEN challenges.status IN ('ingest_ready', 'solving', 'submit_planned', 'solved', 'stalled', 'error', 'abandoned')
                      THEN challenges.status
                    ELSE 'new'
                  END,
                  source=CASE WHEN challenges.source='manual' THEN challenges.source ELSE 'platform' END
                """,
                (
                    challenge_id,
                    contest_id,
                    name,
                    item.get("category"),
                    item.get("points"),
                    item.get("solves"),
                    metadata,
                    now,
                    now,
                ),
            )
            inserted += 1
    record_event(
        "platform_discover_upsert",
        "ok",
        {"count": inserted, "contest_id": contest_id},
        db_path=db_path,
    )
    return {"count": inserted, "contest_id": contest_id}


def update_challenge_ingested(
    challenge_id: str,
    ingest_result: dict[str, Any],
    *,
    worker_id: str | None = None,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    init_db(db_path)
    now = utc_now()
    metadata_update = {
        key: ingest_result.get(key)
        for key in (
            "contest_id",
            "challenge_dir",
            "raw_dir",
            "extracted_dir",
            "manifest_path",
            "scan_path",
            "brief_path",
            "file_count",
            "likely_categories",
        )
        if ingest_result.get(key) not in (None, "", [])
    }
    metadata_update = json.loads(redact_text(json.dumps(metadata_update, sort_keys=True)))
    with connect(db_path) as conn:
        row = conn.execute("SELECT metadata FROM challenges WHERE id=?", (challenge_id,)).fetchone()
        existing: dict[str, Any] = {}
        if row and row["metadata"]:
            try:
                loaded = json.loads(row["metadata"])
                existing = loaded if isinstance(loaded, dict) else {}
            except json.JSONDecodeError:
                existing = {}
        existing.update(metadata_update)
        conn.execute(
            """
            UPDATE challenges
            SET status='ingest_ready', metadata=?, updated_at=?
            WHERE id=?
            """,
            (redact_text(json.dumps(existing, sort_keys=True)), now, challenge_id),
        )
    record_event(
        "challenge_ingested",
        "ok",
        {"challenge_id": challenge_id, "brief_path": ingest_result.get("brief_path"), "file_count": ingest_result.get("file_count")},
        worker_id=worker_id,
        challenge_id=challenge_id,
        db_path=db_path,
    )
    return {"challenge_id": challenge_id, "status": "ingest_ready", "metadata": metadata_update}


def _stale_cutoff(stale_after_sec: int | float | None) -> str | None:
    if stale_after_sec is None:
        return None
    try:
        seconds = float(stale_after_sec)
    except (TypeError, ValueError):
        return None
    if seconds <= 0:
        return None
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()


def _archive_claims(conn: sqlite3.Connection, challenge_id: str, final_state: str, now: str) -> int:
    rows = conn.execute(
        "SELECT worker_id, challenge_id, claimed_at, heartbeat_at FROM claims WHERE challenge_id=?",
        (challenge_id,),
    ).fetchall()
    for row in rows:
        conn.execute(
            """
            INSERT INTO claim_history(worker_id, challenge_id, claimed_at, heartbeat_at, finished_at, final_state)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (row["worker_id"], row["challenge_id"], row["claimed_at"], row["heartbeat_at"], now, final_state),
        )
    conn.execute("DELETE FROM claims WHERE challenge_id=?", (challenge_id,))
    return len(rows)


def _reclaim_stale_claims_conn(conn: sqlite3.Connection, stale_after_sec: int | float | None, now: str) -> list[dict[str, Any]]:
    cutoff = _stale_cutoff(stale_after_sec)
    if cutoff is None:
        return []
    rows = conn.execute(
        """
        SELECT cl.worker_id, cl.challenge_id, cl.claimed_at, cl.heartbeat_at, c.status
        FROM claims cl
        JOIN challenges c ON c.id = cl.challenge_id
        WHERE cl.state='active' AND cl.heartbeat_at < ? AND c.status IN ('claimed', 'solving')
        ORDER BY cl.heartbeat_at ASC
        """,
        (cutoff,),
    ).fetchall()
    reclaimed: list[dict[str, Any]] = []
    for row in rows:
        conn.execute(
            """
            INSERT INTO claim_history(worker_id, challenge_id, claimed_at, heartbeat_at, finished_at, final_state)
            VALUES (?, ?, ?, ?, ?, 'stale')
            """,
            (row["worker_id"], row["challenge_id"], row["claimed_at"], row["heartbeat_at"], now),
        )
        conn.execute("DELETE FROM claims WHERE challenge_id=?", (row["challenge_id"],))
        conn.execute(
            "UPDATE challenges SET status='queued', updated_at=? WHERE id=? AND status IN ('claimed', 'solving')",
            (now, row["challenge_id"]),
        )
        conn.execute(
            "UPDATE workers SET status='stale', heartbeat_at=? WHERE worker_id=?",
            (now, row["worker_id"]),
        )
        reclaimed.append(dict(row))
    return reclaimed


def reclaim_stale_claims(
    *,
    stale_after_sec: int | float = 900,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    init_db(db_path)
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        reclaimed = _reclaim_stale_claims_conn(conn, stale_after_sec, now)
    record_event(
        "claim_reclaim_stale",
        "ok",
        {"count": len(reclaimed), "challenge_ids": [item["challenge_id"] for item in reclaimed]},
        db_path=db_path,
    )
    return {"status": "ok", "count": len(reclaimed), "claims": reclaimed}


def heartbeat_claim(
    worker_id: str,
    challenge_id: str,
    db_path: str | Path | None = None,
) -> dict[str, str]:
    init_db(db_path)
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute(
            "UPDATE claims SET heartbeat_at=? WHERE worker_id=? AND challenge_id=? AND state='active'",
            (now, worker_id, challenge_id),
        )
        conn.execute("UPDATE workers SET heartbeat_at=? WHERE worker_id=?", (now, worker_id))
    return {"worker_id": worker_id, "challenge_id": challenge_id, "heartbeat_at": now}


def claim_next_challenge(
    worker_id: str,
    db_path: str | Path | None = None,
    *,
    stale_after_sec: int | float | None = 900,
) -> dict[str, Any] | None:
    init_db(db_path)
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        _reclaim_stale_claims_conn(conn, stale_after_sec, now)
        conn.execute(
            """
            INSERT INTO workers(worker_id, role, status, registered_at, heartbeat_at)
            VALUES (?, 'helper', 'idle', ?, ?)
            ON CONFLICT(worker_id) DO UPDATE SET heartbeat_at=excluded.heartbeat_at
            """,
            (worker_id, now, now),
        )
        row = conn.execute(
            """
            SELECT c.* FROM challenges c
            LEFT JOIN claims cl ON cl.challenge_id = c.id AND cl.state = 'active'
            WHERE c.status IN ('new', 'queued', 'ingest_ready') AND cl.challenge_id IS NULL
            ORDER BY c.priority ASC, c.created_at ASC
            LIMIT 1
            """
        ).fetchone()
        if row is None:
            conn.execute("UPDATE workers SET status='idle', heartbeat_at=? WHERE worker_id=?", (now, worker_id))
            return None
        conn.execute("UPDATE challenges SET status='claimed', updated_at=? WHERE id=?", (now, row["id"]))
        conn.execute("DELETE FROM claims WHERE challenge_id=? AND state <> 'active'", (row["id"],))
        conn.execute(
            """
            INSERT OR REPLACE INTO claims(worker_id, challenge_id, claimed_at, heartbeat_at, state)
            VALUES (?, ?, ?, ?, 'active')
            """,
            (worker_id, row["id"], now, now),
        )
        conn.execute("UPDATE workers SET status='busy', heartbeat_at=? WHERE worker_id=?", (now, worker_id))
        result = dict(row)
        result["status"] = "claimed"
    record_event("challenge_claim", "ok", {}, worker_id=worker_id, challenge_id=result["id"], db_path=db_path)
    return result


def get_challenge(challenge_id: str, db_path: str | Path | None = None) -> dict[str, Any] | None:
    init_db(db_path)
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM challenges WHERE id=?", (challenge_id,)).fetchone()
    return dict(row) if row else None


def update_challenge_status(
    challenge_id: str,
    status: str,
    *,
    worker_id: str | None = None,
    details: Any | None = None,
    db_path: str | Path | None = None,
) -> dict[str, str]:
    init_db(db_path)
    status = str(status or "").lower()
    if status not in CHALLENGE_STATUSES:
        raise ValueError(f"unsupported challenge status: {status}")
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute("UPDATE challenges SET status=?, updated_at=? WHERE id=?", (status, now, challenge_id))
        if status in {"new", "queued", "ingest_ready", "submit_planned", "solved", "stalled", "error", "blocked_by_mode", "abandoned"}:
            _archive_claims(conn, challenge_id, status, now)
            if worker_id:
                conn.execute("UPDATE workers SET status='idle', heartbeat_at=? WHERE worker_id=?", (now, worker_id))
        elif status in {"claimed", "solving"} and worker_id:
            conn.execute(
                "UPDATE claims SET heartbeat_at=? WHERE worker_id=? AND challenge_id=? AND state='active'",
                (now, worker_id, challenge_id),
            )
            conn.execute("UPDATE workers SET status='busy', heartbeat_at=? WHERE worker_id=?", (now, worker_id))
    record_event(
        "challenge_status_update",
        status,
        details or {},
        worker_id=worker_id,
        challenge_id=challenge_id,
        db_path=db_path,
    )
    return {"challenge_id": challenge_id, "status": status}


def release_claim(
    worker_id: str,
    challenge_id: str,
    state: str = "stalled",
    reason: str = "",
    db_path: str | Path | None = None,
) -> dict[str, str]:
    init_db(db_path)
    if state not in {"queued", "stalled", "abandoned"}:
        raise ValueError("state must be queued, stalled, or abandoned")
    now = utc_now()
    with connect(db_path) as conn:
        _archive_claims(conn, challenge_id, state, now)
        conn.execute("UPDATE challenges SET status=?, updated_at=? WHERE id=?", (state, now, challenge_id))
        conn.execute("UPDATE workers SET status='idle', heartbeat_at=? WHERE worker_id=?", (now, worker_id))
    record_event(
        "challenge_release",
        state,
        {"reason": reason},
        worker_id=worker_id,
        challenge_id=challenge_id,
        db_path=db_path,
    )
    return {"worker_id": worker_id, "challenge_id": challenge_id, "state": state}


TERMINAL_SUBMISSION_STATUSES = {"submitted", "accepted", "rejected", "rate_limited"}
NON_TERMINAL_SUBMISSION_STATUSES = {"planned", "blocked", "duplicate"}
WRONG_SUBMISSION_STATUSES = {"rejected", "wrong", "incorrect"}


def record_submission_attempt(
    *,
    challenge_id: str,
    flag_hash: str,
    status: str,
    confidence: str | None = None,
    result_summary_redacted: str | None = None,
    worker_id: str | None = None,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    init_db(db_path)
    now = utc_now()
    summary = redact_text(result_summary_redacted or "")
    status = str(status or "planned").lower()
    with connect(db_path) as conn:
        existing = conn.execute(
            "SELECT * FROM submissions WHERE challenge_id=? AND flag_hash=?",
            (challenge_id, flag_hash),
        ).fetchone()
        if (
            existing is not None
            and str(existing["status"]).lower() in TERMINAL_SUBMISSION_STATUSES
            and status in NON_TERMINAL_SUBMISSION_STATUSES
        ):
            result = dict(existing)
            result["unchanged"] = True
        elif existing is None:
            conn.execute(
                """
                INSERT INTO submissions(
                  challenge_id, flag_hash, submitted_at, status, confidence, result_summary_redacted, worker_id, details
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (challenge_id, flag_hash, now, status, confidence, summary, worker_id, summary),
            )
            result = {
                "challenge_id": challenge_id,
                "flag_hash": flag_hash,
                "submitted_at": now,
                "status": status,
                "confidence": confidence,
                "result_summary_redacted": summary,
                "worker_id": worker_id,
                "unchanged": False,
            }
        else:
            conn.execute(
                """
                UPDATE submissions
                SET submitted_at=?, status=?, confidence=?, result_summary_redacted=?, worker_id=?, details=?
                WHERE challenge_id=? AND flag_hash=?
                """,
                (now, status, confidence, summary, worker_id, summary, challenge_id, flag_hash),
            )
            result = {
                "challenge_id": challenge_id,
                "flag_hash": flag_hash,
                "submitted_at": now,
                "status": status,
                "confidence": confidence,
                "result_summary_redacted": summary,
                "worker_id": worker_id,
                "unchanged": False,
            }
    record_event(
        "submission_attempt",
        status,
        {"flag_hash": flag_hash, "confidence": confidence, "summary": summary},
        worker_id=worker_id,
        challenge_id=challenge_id,
        db_path=db_path,
    )
    return result


def list_submissions(challenge_id: str, db_path: str | Path | None = None) -> list[dict[str, Any]]:
    init_db(db_path)
    with connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT challenge_id, flag_hash, submitted_at, status, confidence, result_summary_redacted, worker_id
            FROM submissions
            WHERE challenge_id=?
            ORDER BY submitted_at DESC, id DESC
            """,
            (challenge_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def count_wrong_submissions(challenge_id: str, db_path: str | Path | None = None) -> int:
    init_db(db_path)
    placeholders = ",".join("?" for _ in WRONG_SUBMISSION_STATUSES)
    with connect(db_path) as conn:
        row = conn.execute(
            f"""
            SELECT COUNT(*) AS count FROM submissions
            WHERE challenge_id=? AND lower(status) IN ({placeholders})
            """,
            (challenge_id, *sorted(WRONG_SUBMISSION_STATUSES)),
        ).fetchone()
    return int(row["count"] if row else 0)


def has_duplicate_submission(challenge_id: str, flag_hash: str, db_path: str | Path | None = None) -> bool:
    init_db(db_path)
    placeholders = ",".join("?" for _ in TERMINAL_SUBMISSION_STATUSES)
    with connect(db_path) as conn:
        row = conn.execute(
            f"""
            SELECT 1 FROM submissions
            WHERE challenge_id=? AND flag_hash=? AND lower(status) IN ({placeholders})
            LIMIT 1
            """,
            (challenge_id, flag_hash, *sorted(TERMINAL_SUBMISSION_STATUSES)),
        ).fetchone()
    return row is not None


def get_challenge_state(challenge_id: str, db_path: str | Path | None = None) -> dict[str, Any]:
    init_db(db_path)
    with connect(db_path) as conn:
        row = conn.execute("SELECT id, status, updated_at FROM challenges WHERE id=?", (challenge_id,)).fetchone()
    if row is None:
        return {"challenge_id": challenge_id, "status": "unknown", "solved": False}
    data = dict(row)
    data["challenge_id"] = data.pop("id")
    data["solved"] = str(data.get("status") or "").lower() == "solved"
    return data


def update_challenge_solved(
    challenge_id: str,
    *,
    worker_id: str | None = None,
    flag_hash: str | None = None,
    confidence: str | None = None,
    result_summary_redacted: str | None = "accepted",
    db_path: str | Path | None = None,
) -> dict[str, str]:
    init_db(db_path)
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute("UPDATE challenges SET status='solved', updated_at=? WHERE id=?", (now, challenge_id))
        _archive_claims(conn, challenge_id, "solved", now)
        if worker_id:
            conn.execute("UPDATE workers SET status='idle', heartbeat_at=? WHERE worker_id=?", (now, worker_id))
    if flag_hash:
        record_submission_attempt(
            challenge_id=challenge_id,
            flag_hash=flag_hash,
            status="accepted",
            confidence=confidence,
            result_summary_redacted=result_summary_redacted,
            worker_id=worker_id,
            db_path=db_path,
        )
    record_event("challenge_solved", "ok", {"confidence": confidence}, worker_id=worker_id, challenge_id=challenge_id, db_path=db_path)
    return {"challenge_id": challenge_id, "status": "solved"}


def mark_solved(
    challenge_id: str,
    *,
    worker_id: str | None = None,
    flag_hash: str | None = None,
    confidence: str | None = None,
    db_path: str | Path | None = None,
) -> dict[str, str]:
    return update_challenge_solved(
        challenge_id,
        worker_id=worker_id,
        flag_hash=flag_hash,
        confidence=confidence,
        db_path=db_path,
    )


def submission_status(challenge_id: str, db_path: str | Path | None = None) -> dict[str, Any]:
    submissions = list_submissions(challenge_id, db_path)
    return {
        "challenge_id": challenge_id,
        "challenge": get_challenge_state(challenge_id, db_path),
        "wrong_count": count_wrong_submissions(challenge_id, db_path),
        "submissions": submissions,
    }


def list_status(db_path: str | Path | None = None) -> dict[str, Any]:
    init_db(db_path)
    with connect(db_path) as conn:
        challenge_counts = {
            row["status"]: row["count"]
            for row in conn.execute("SELECT status, COUNT(*) AS count FROM challenges GROUP BY status").fetchall()
        }
        workers = [dict(row) for row in conn.execute("SELECT worker_id, role, status, heartbeat_at FROM workers ORDER BY worker_id").fetchall()]
        active_claims = [
            dict(row)
            for row in conn.execute(
                "SELECT worker_id, challenge_id, claimed_at, heartbeat_at FROM claims WHERE state='active'"
            ).fetchall()
        ]
        claim_history_counts = {
            row["final_state"]: row["count"]
            for row in conn.execute("SELECT final_state, COUNT(*) AS count FROM claim_history GROUP BY final_state").fetchall()
        }
        recent_events = [
            dict(row)
            for row in conn.execute(
                "SELECT timestamp, worker_id, challenge_id, event_type, status FROM events ORDER BY id DESC LIMIT 10"
            ).fetchall()
        ]
    return {
        "db_path": str(Path(db_path).expanduser() if db_path else default_db_path()),
        "challenge_counts": challenge_counts,
        "workers": workers,
        "active_claims": active_claims,
        "claim_history_counts": claim_history_counts,
        "recent_events": recent_events,
    }
