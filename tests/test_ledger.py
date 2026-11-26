"""
tests/test_ledger.py

Unit tests for the hash-chained forensic ledger.

Tests:
  - Appending entries builds a valid chain
  - verify_chain passes on an untouched chain
  - Manually editing an entry_hash in the DB causes verify_chain to fail and
    report the correct first_broken_id
  - The genesis hash is correct for the first entry
  - Multiple appends are ordered correctly
"""

import pytest
import sys
import os
import tempfile
import threading

# Point the database at a fresh temp file for each test session
_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["SENTINEL_TEST_DB"] = _tmp.name

# Patch DB_PATH before importing app modules
import importlib

# We need to patch app.database.DB_PATH before it is used
import pathlib
import app.database as db_module

db_module.DB_PATH = pathlib.Path(_tmp.name)
# Reset thread-local so a fresh connection is made
db_module._local = threading.local()

from app.database import init_db, get_conn
from app.evidence import ledger
from app.evidence.ledger import GENESIS_HASH, _compute_entry_hash, _sha256


@pytest.fixture(autouse=True)
def fresh_db(tmp_path):
    """
    Each test gets a clean, isolated SQLite database.
    We re-point DB_PATH to a new temp file and reinitialise.
    """
    db_file = tmp_path / "test_sentinel.db"
    db_module.DB_PATH = db_file
    db_module._local = threading.local()
    init_db()
    yield
    # Cleanup handled by tmp_path fixture


class TestLedgerAppend:
    def test_first_entry_uses_genesis_hash(self):
        """The first ledger entry must reference GENESIS_HASH as prev_hash."""
        ledger.append("test_action", "payload one")
        conn = get_conn()
        row = conn.execute("SELECT * FROM ledger ORDER BY id ASC LIMIT 1").fetchone()
        assert row["prev_hash"] == GENESIS_HASH

    def test_second_entry_references_first(self):
        """Each entry's prev_hash must equal the entry_hash of the previous row."""
        ledger.append("action_a", "first payload")
        ledger.append("action_b", "second payload")

        conn = get_conn()
        rows = conn.execute("SELECT * FROM ledger ORDER BY id ASC").fetchall()
        assert len(rows) == 2
        assert rows[1]["prev_hash"] == rows[0]["entry_hash"]

    def test_entry_hash_is_deterministic(self):
        """Recomputing entry_hash from stored fields must match stored value."""
        ledger.append("det_action", "deterministic payload", scan_id=42)
        conn = get_conn()
        row = conn.execute("SELECT * FROM ledger").fetchone()

        expected = _compute_entry_hash(
            row["timestamp"],
            row["scan_id"],
            row["action"],
            row["evidence_hash"],
            row["prev_hash"],
        )
        assert row["entry_hash"] == expected

    def test_evidence_hash_is_sha256_of_payload(self):
        """evidence_hash must equal SHA-256 of the payload string."""
        payload = "my evidence payload string"
        ledger.append("ev_action", payload)
        conn = get_conn()
        row = conn.execute("SELECT evidence_hash FROM ledger").fetchone()
        assert row["evidence_hash"] == _sha256(payload)

    def test_multiple_appends_chain_correctly(self):
        """Ten consecutive entries must form a valid chain."""
        for i in range(10):
            ledger.append(f"action_{i}", f"payload {i}", scan_id=i % 3)

        conn = get_conn()
        rows = conn.execute("SELECT * FROM ledger ORDER BY id ASC").fetchall()
        assert len(rows) == 10

        # First entry must use genesis
        assert rows[0]["prev_hash"] == GENESIS_HASH

        # Each subsequent entry's prev_hash == previous entry's entry_hash
        for idx in range(1, len(rows)):
            assert rows[idx]["prev_hash"] == rows[idx - 1]["entry_hash"], (
                f"Chain broken between entry {rows[idx-1]['id']} and {rows[idx]['id']}"
            )

    def test_returns_row_id(self):
        """append() must return the integer row id of the new entry."""
        row_id = ledger.append("action", "payload")
        assert isinstance(row_id, int)
        assert row_id >= 1


class TestLedgerVerify:
    def test_empty_ledger_passes(self):
        """verify_chain on an empty ledger should pass with 0 entries checked."""
        result = ledger.verify_chain()
        assert result["ok"] is True
        assert result["checked"] == 0
        assert result["first_broken_id"] is None

    def test_valid_chain_passes(self):
        """A freshly built chain should verify successfully."""
        for i in range(5):
            ledger.append(f"ev_{i}", f"data {i}")
        result = ledger.verify_chain()
        assert result["ok"] is True
        assert result["checked"] == 5
        assert result["first_broken_id"] is None

    def test_tampered_entry_hash_detected(self):
        """
        Directly altering entry_hash in the database must cause verify_chain
        to fail and report the correct first_broken_id.
        """
        ledger.append("action_1", "payload 1")
        ledger.append("action_2", "payload 2")
        ledger.append("action_3", "payload 3")

        conn = get_conn()
        rows = conn.execute("SELECT id FROM ledger ORDER BY id ASC").fetchall()
        tamper_id = rows[1]["id"]  # Tamper the second entry

        # Corrupt the entry_hash
        conn.execute(
            "UPDATE ledger SET entry_hash = 'deadbeef' || entry_hash WHERE id = ?",
            (tamper_id,),
        )
        conn.commit()

        result = ledger.verify_chain()
        assert result["ok"] is False
        assert result["first_broken_id"] == tamper_id

    def test_tampered_evidence_hash_detected(self):
        """
        Altering evidence_hash (without updating entry_hash) also causes
        verify_chain to report a broken entry.
        """
        ledger.append("action_x", "original payload")
        conn = get_conn()
        row = conn.execute("SELECT id FROM ledger").fetchone()

        conn.execute(
            "UPDATE ledger SET evidence_hash = ? WHERE id = ?",
            ("00" * 32, row["id"]),
        )
        conn.commit()

        result = ledger.verify_chain()
        assert result["ok"] is False
        assert result["first_broken_id"] == row["id"]

    def test_scan_scoped_verify(self):
        """verify_chain(scan_id=N) only checks entries for that scan."""
        ledger.append("a1", "d1", scan_id=1)
        ledger.append("a2", "d2", scan_id=2)
        ledger.append("a3", "d3", scan_id=1)

        # Tamper scan_id=2 entry
        conn = get_conn()
        row = conn.execute("SELECT id FROM ledger WHERE scan_id=2").fetchone()
        conn.execute(
            "UPDATE ledger SET entry_hash='tampered' WHERE id=?", (row["id"],)
        )
        conn.commit()

        # Full chain fails
        full = ledger.verify_chain()
        assert full["ok"] is False

        # Scan 1 isolated check passes (only checks scan 1 entries)
        scan1 = ledger.verify_chain(scan_id=1)
        assert scan1["ok"] is True
        assert scan1["checked"] == 2
