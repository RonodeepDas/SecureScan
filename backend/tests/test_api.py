"""
tests/test_api.py — FastAPI integration tests.

Covers:
  - POST /api/scan: auth gate (403), invalid target (422), port cap (422)
  - POST /api/password/history: saves metadata, rejects bad scores
  - ORM roundtrip: PasswordHistory + ScanHistory rows encrypt/decrypt correctly
"""

import binascii
import json
import os
import pytest
from fastapi.testclient import TestClient

# Must be set before any app import so crypto_utils loads correctly
os.environ["ENCRYPTION_KEY"] = binascii.hexlify(os.urandom(32)).decode()

# Use an in-memory SQLite DB for tests (no file left behind)
os.environ["DATABASE_URL"] = "sqlite://"  # in-memory fallback handled in conftest

from main import app  # noqa: E402
from models import (  # noqa: E402
    Base,
    PasswordHistory,
    ScanHistory,
    SessionLocal,
    engine,
)
from crypto_utils import encrypt, decrypt  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_db():
    """Create tables before each test, drop after."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


client = TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# POST /api/scan — security gates
# ---------------------------------------------------------------------------

def test_scan_rejected_without_authorization():
    resp = client.post("/api/scan", json={
        "target": "127.0.0.1",
        "ports": [9999],
        "authorized": False,
    })
    assert resp.status_code == 403
    assert "authorization" in resp.json()["detail"].lower()


def test_scan_rejected_with_invalid_target():
    resp = client.post("/api/scan", json={
        "target": "bad host; rm -rf /",
        "ports": [80],
        "authorized": True,
    })
    assert resp.status_code == 422


def test_scan_rejected_with_too_many_ports():
    ports = list(range(1, 1026))  # 1025 ports → over cap
    resp = client.post("/api/scan", json={
        "target": "127.0.0.1",
        "ports": ports,
        "authorized": True,
    })
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    # May be a list of dicts (pydantic) or a string
    detail_str = json.dumps(detail)
    assert "1024" in detail_str


def test_scan_succeeds_against_localhost():
    resp = client.post("/api/scan", json={
        "target": "127.0.0.1",
        "ports": [9999, 9998],  # almost certainly closed, but the call should succeed
        "authorized": True,
        "timeout": 0.5,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "results" in data
    assert len(data["results"]) == 2


# ---------------------------------------------------------------------------
# POST /api/password/history — metadata only
# ---------------------------------------------------------------------------

def test_save_password_metadata_valid():
    resp = client.post("/api/password/history", json={
        "score": 3,
        "crack_time": "centuries",
    })
    assert resp.status_code == 201
    assert "id" in resp.json()


def test_save_password_metadata_out_of_range_score():
    resp = client.post("/api/password/history", json={
        "score": 9,
        "crack_time": "centuries",
    })
    assert resp.status_code == 422


def test_save_password_metadata_empty_crack_time():
    resp = client.post("/api/password/history", json={
        "score": 2,
        "crack_time": "  ",
    })
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# ORM roundtrip — encrypted field integrity
# ---------------------------------------------------------------------------

def test_password_history_orm_roundtrip():
    """
    Insert a PasswordHistory row and read it back.
    Decrypted values must match what was written.
    """
    db = SessionLocal()
    try:
        score_val = 4
        crack_time_val = "3 million years"

        row = PasswordHistory(
            score_enc=encrypt(str(score_val)),
            crack_time_enc=encrypt(crack_time_val),
        )
        db.add(row)
        db.commit()
        db.refresh(row)

        fetched = db.query(PasswordHistory).filter_by(id=row.id).first()
        assert fetched is not None
        assert int(decrypt(fetched.score_enc)) == score_val
        assert decrypt(fetched.crack_time_enc) == crack_time_val
    finally:
        db.close()


def test_scan_history_orm_roundtrip():
    """
    Insert a ScanHistory row and read it back.
    Decrypted JSON fields must match the originals.
    """
    db = SessionLocal()
    try:
        target = "192.168.1.10"
        open_ports = [22, 80, 443]
        banners = {"22": "SSH-2.0-OpenSSH_9.0", "80": "HTTP/1.1 200 OK"}

        row = ScanHistory(
            target_enc=encrypt(target),
            open_ports_enc=encrypt(json.dumps(open_ports)),
            banners_enc=encrypt(json.dumps(banners)),
        )
        db.add(row)
        db.commit()
        db.refresh(row)

        fetched = db.query(ScanHistory).filter_by(id=row.id).first()
        assert fetched is not None
        assert decrypt(fetched.target_enc) == target
        assert json.loads(decrypt(fetched.open_ports_enc)) == open_ports
        assert json.loads(decrypt(fetched.banners_enc)) == banners
    finally:
        db.close()
