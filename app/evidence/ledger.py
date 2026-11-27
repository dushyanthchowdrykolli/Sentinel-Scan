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

    Verifies:
      1. Every ledger row's entry_hash matches its fields.
      2. Continuity: each row's prev_hash matches the previous row's entry_hash (genesis for row 1).
      3. Cross-verification: every finding row's evidence_raw re-hashes to evidence_hash,
         and matches a corresponding ledger entry with that evidence_hash.
    """
    conn = get_conn()

    # 1. Cross-verify findings table evidence
    if scan_id is not None:
        finding_rows = conn.execute("SELECT id, evidence_raw, evidence_hash FROM findings WHERE scan_id = ? ORDER BY id ASC", (scan_id,)).fetchall()
    else:
        finding_rows = conn.execute("SELECT id, evidence_raw, evidence_hash FROM findings ORDER BY id ASC").fetchall()

    for f_row in finding_rows:
        recomputed_hash = _sha256(f_row["evidence_raw"])
        if recomputed_hash != f_row["evidence_hash"]:
            msg = f"Integrity violation detected in findings table at finding #{f_row['id']}: stored evidence text does not match evidence_hash."
            return {
                "ok": False,
                "checked": 0,
                "first_broken_id": f_row["id"],
                "message": msg,
            }
        # Ensure it exists in ledger
        ledger_match = conn.execute("SELECT id FROM ledger WHERE evidence_hash = ?", (f_row["evidence_hash"],)).fetchone()
        if not ledger_match:
            msg = f"Integrity violation detected: finding #{f_row['id']} has no matching entry in forensic ledger."
            return {
                "ok": False,
                "checked": 0,
                "first_broken_id": f_row["id"],
                "message": msg,
            }

    # 2. Verify ledger entries and continuity
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
    expected_prev = GENESIS_HASH

    for idx, row in enumerate(rows):
        # Continuity check (for global chain check, or sequential within list)
        if scan_id is None:
            if row["prev_hash"] != expected_prev:
                first_broken_id = row["id"]
                msg = f"Integrity violation detected at ledger entry #{first_broken_id}: prev_hash does not match preceding entry_hash (chain broken or row deleted)."
                return {
                    "ok": False,
                    "checked": checked,
                    "first_broken_id": first_broken_id,
                    "message": msg,
                }
        else:
            # For scan-scoped check: verify first entry links to a known ledger entry or genesis
            if idx == 0:
                if row["prev_hash"] != GENESIS_HASH:
                    prev_exists = conn.execute("SELECT id FROM ledger WHERE entry_hash = ?", (row["prev_hash"],)).fetchone()
                    if not prev_exists:
                        first_broken_id = row["id"]
                        msg = f"Integrity violation detected at ledger entry #{first_broken_id}: prev_hash does not match any valid preceding ledger entry."
                        return {
                            "ok": False,
                            "checked": checked,
                            "first_broken_id": first_broken_id,
                            "message": msg,
                        }

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
            msg = f"Integrity violation detected at ledger entry #{first_broken_id}. Checked {checked} entries before finding the first broken link."
            return {
                "ok": False,
                "checked": checked,
                "first_broken_id": first_broken_id,
                "message": msg,
            }
        expected_prev = row["entry_hash"]

    ok = first_broken_id is None
    if ok:
        msg = f"All {checked} ledger entries verified successfully. Chain is intact."
    else:
        msg = f"Integrity violation detected at ledger entry #{first_broken_id}."

    return {
        "ok": ok,
        "checked": checked,
        "first_broken_id": first_broken_id,
        "message": msg,
    }
