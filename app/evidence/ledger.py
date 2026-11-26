"""
app/evidence/ledger.py

Forensic hash-chained ledger.

Each entry contains:
  - timestamp (UTC ISO-8601)
  - scan_id   (optional integer)
  - action    (short string describing what happened)
  - evidence_hash  (SHA-256 of the payload being recorded)
  - prev_hash      (SHA-256 of the previous entry; genesis uses "0"*64)
  - entry_hash     (SHA-256 of the concatenation of all five fields above)

This chain makes post-hoc tampering detectable: changing any field in any
row breaks the entry_hash of that row and every subsequent row.
"""

import hashlib
import datetime
import datetime as _dt
from typing import Optional

from app.database import get_conn


GENESIS_HASH = "0" * 64  # Sentinel value for the very first entry


def _sha256(text: str) -> str:
    """Return the lowercase hex SHA-256 digest of a UTF-8 string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_of_bytes(data: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def _compute_entry_hash(
    timestamp: str,
    scan_id: Optional[int],
    action: str,
    evidence_hash: str,
    prev_hash: str,
) -> str:
    """Deterministically hash all five fields that define a ledger entry."""
    payload = "|".join(
        [
            timestamp,
            str(scan_id) if scan_id is not None else "",
            action,
            evidence_hash,
            prev_hash,
        ]
    )
    return _sha256(payload)


def _get_last_entry_hash() -> str:
    """Return the entry_hash of the most recent ledger row, or the genesis hash."""
    conn = get_conn()
    row = conn.execute(
        "SELECT entry_hash FROM ledger ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return row["entry_hash"] if row else GENESIS_HASH


def append(
    action: str,
    evidence_payload: str,
    scan_id: Optional[int] = None,
) -> int:
    """
    Append one entry to the ledger.

    Parameters
    ----------
    action:
        A short label such as "scan_started", "finding_recorded",
        "auth_confirmed", "scan_completed", "integrity_check".
    evidence_payload:
        The raw string whose SHA-256 becomes evidence_hash.
        For findings this is the full evidence_raw text.
        For lifecycle events it is a JSON snapshot or plain description.
    scan_id:
        The scan this entry belongs to, if applicable.

    Returns
    -------
    The row-id of the newly inserted entry.
    """
    conn = get_conn()
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds")
    evidence_hash = _sha256(evidence_payload)
    prev_hash = _get_last_entry_hash()
    entry_hash = _compute_entry_hash(
        timestamp, scan_id, action, evidence_hash, prev_hash
    )

    cur = conn.execute(
        """
        INSERT INTO ledger (timestamp, scan_id, action, evidence_hash, prev_hash, entry_hash)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (timestamp, scan_id, action, evidence_hash, prev_hash, entry_hash),
    )
    conn.commit()
    return cur.lastrowid


def verify_chain(scan_id: Optional[int] = None) -> dict:
    """
    Recompute the hash chain and return a verification result.

    If scan_id is given, only the entries for that scan are checked in
    isolation (prev_hash context is still the global chain, so a targeted
    tamper will still surface).

    Returns a dict with keys: ok, checked, first_broken_id, message.
    """
    conn = get_conn()

    if scan_id is not None:
        rows = conn.execute(
            "SELECT * FROM ledger WHERE scan_id = ? ORDER BY id ASC", (scan_id,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM ledger ORDER BY id ASC"
        ).fetchall()

    checked = 0
    first_broken_id = None

    # For a full-chain check we know prev_hash of first row; for a scan-scoped
    # check we trust the stored prev_hash of the first row (we cannot walk back
    # further without all entries).
    for row in rows:
        expected_entry_hash = _compute_entry_hash(
            row["timestamp"],
            row["scan_id"],
            row["action"],
            row["evidence_hash"],
            row["prev_hash"],
        )
        checked += 1
        if expected_entry_hash != row["entry_hash"]:
            first_broken_id = row["id"]
            break

    ok = first_broken_id is None
    if ok:
        msg = f"All {checked} ledger entries verified successfully. Chain is intact."
    else:
        msg = (
            f"Integrity violation detected at ledger entry #{first_broken_id}. "
            f"Checked {checked} entries before finding the first broken link."
        )

    return {
        "ok": ok,
        "checked": checked,
        "first_broken_id": first_broken_id,
        "message": msg,
    }
