"""
main.py — FastAPI backend for SecureScan.

Security design:
  - All routes served over HTTPS (self-signed dev cert, auto-generated on startup).
  - POST /api/scan is rate-limited (slowapi, 5 req/min) and rejects:
      • missing/false `authorized` flag → 403
      • invalid target → 422
      • > 1024 unique ports → 422
  - A FilteredAccessLogMiddleware strips /api/scan lines from uvicorn's
    access log so the target hostname never appears in log output.
  - Passwords are NEVER accepted by any endpoint.
  - Encrypted fields use AES-256-GCM (crypto_utils.py).
"""

import json
import logging
import os
import ssl
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator, model_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session

from crypto_utils import decrypt, encrypt
from models import PasswordHistory, ScanHistory, get_db, init_db
from scanner import DEFAULT_PORTS, scan_ports, validate_target

import datetime as dt

# ---------------------------------------------------------------------------
# Logging — filtered so /api/scan target never appears in access logs
# ---------------------------------------------------------------------------

class _ScanRouteFilter(logging.Filter):
    """Drop uvicorn access-log records that contain '/api/scan'."""
    def filter(self, record: logging.LogRecord) -> bool:
        return "/api/scan" not in record.getMessage()


_access_logger = logging.getLogger("uvicorn.access")
_access_logger.addFilter(_ScanRouteFilter())

# ---------------------------------------------------------------------------
# App + rate limiter
# ---------------------------------------------------------------------------

limiter = Limiter(key_func=get_remote_address, default_limits=[])

app = FastAPI(
    title="SecureScan API",
    description="Password metadata history and port scanning with encrypted storage.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
init_db()

allowed_origins = [
    "https://localhost:5173",
    "https://localhost:3000",
    "http://localhost:5173",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    "https://127.0.0.1:5173",
    "https://ronodeepdas.github.io",
    "https://www.ronodeepdas.github.io",
]
extra_origins = os.getenv("CORS_ORIGINS", "")
if extra_origins:
    allowed_origins.extend(
        origin.strip() for origin in extra_origins.split(",") if origin.strip()
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=r"https://.*\.github\.io$|https?://localhost(:\d+)?$|https?://127\.0\.0\.1(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Startup: DB init + optional TLS setup
# ---------------------------------------------------------------------------

CERT_FILE = Path(os.getenv("SECURESCAN_TLS_CERT", "cert.pem"))
KEY_FILE = Path(os.getenv("SECURESCAN_TLS_KEY", "key.pem"))


def _generate_self_signed_cert() -> None:
    """Generate a local self-signed cert only when explicitly enabled."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureScan Dev"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + dt.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    CERT_FILE.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    KEY_FILE.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    print("[SecureScan] Generated self-signed dev cert for explicit local HTTPS testing.")


@app.on_event("startup")
def startup_event():
    init_db()
    if os.getenv("SECURESCAN_ALLOW_SELF_SIGNED", "false").lower() == "true":
        if not CERT_FILE.exists() or not KEY_FILE.exists():
            _generate_self_signed_cert()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class PasswordMetadata(BaseModel):
    """Only score + crack_time reach the server — never the password."""
    score: int                    # 0-4
    crack_time: str               # human-readable estimate, e.g. "3 years"
    timestamp: datetime | None = None

    @field_validator("score")
    @classmethod
    def score_range(cls, v: int) -> int:
        if not (0 <= v <= 4):
            raise ValueError("score must be 0-4")
        return v

    @field_validator("crack_time")
    @classmethod
    def crack_time_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("crack_time must not be empty")
        if len(v) > 200:
            raise ValueError("crack_time too long")
        return v


class ScanRequest(BaseModel):
    target: str
    ports: list[int] | None = None
    authorized: bool = False
    timeout: float = 1.0

    @field_validator("target")
    @classmethod
    def target_valid(cls, v: str) -> str:
        if not validate_target(v.strip()):
            raise ValueError(
                "target must be a valid hostname or IP address "
                "(no shell-special characters allowed)"
            )
        return v.strip()

    @field_validator("ports", mode="before")
    @classmethod
    def ports_valid(cls, v) -> list[int] | None:
        if v is None:
            return None
        if len(v) > 1024:
            raise ValueError("Cannot scan more than 1024 ports per request")
        for p in v:
            if not (0 < int(p) <= 65535):
                raise ValueError(f"Invalid port number: {p}")
        return [int(p) for p in v]

    @field_validator("timeout")
    @classmethod
    def timeout_range(cls, v: float) -> float:
        if not (0.1 <= v <= 10.0):
            raise ValueError("timeout must be between 0.1 and 10.0 seconds")
        return v


# ---------------------------------------------------------------------------
# Password history endpoints
# ---------------------------------------------------------------------------

@app.post("/api/password/history", status_code=status.HTTP_201_CREATED)
def save_password_metadata(
    meta: PasswordMetadata,
    db: Annotated[Session, Depends(get_db)],
):
    """
    Save ONLY score + crack_time + timestamp to the DB.
    The password itself is never sent, accepted, or stored.
    """
    ts = meta.timestamp or datetime.now(timezone.utc)
    row = PasswordHistory(
        score_enc=encrypt(str(meta.score)),
        crack_time_enc=encrypt(meta.crack_time),
        timestamp=ts,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"id": row.id, "timestamp": row.timestamp.isoformat()}


@app.get("/api/password/history")
def get_password_history(db: Annotated[Session, Depends(get_db)]):
    """
    Return decrypted password-check metadata records.
    NOTE: No authentication — local single-user dev only.
    """
    rows = db.query(PasswordHistory).order_by(PasswordHistory.timestamp.desc()).all()
    return [
        {
            "id": r.id,
            "score": int(decrypt(r.score_enc)),
            "crack_time": decrypt(r.crack_time_enc),
            "timestamp": r.timestamp.isoformat(),
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Port scanner endpoints
# ---------------------------------------------------------------------------

@app.post("/api/scan")
@limiter.limit("5/minute")
def run_scan(
    request: Request,  # required by slowapi
    scan_req: ScanRequest,
    db: Annotated[Session, Depends(get_db)],
):
    """
    Execute a TCP port scan.

    Security gates (all enforced before scanning):
      1. `authorized` must be True (legal consent from the user).
      2. `target` must pass validate_target().
      3. `ports` must not exceed 1024 entries.
    The target never appears in the uvicorn access log (filtered middleware).
    """
    if not scan_req.authorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Scan rejected: you must confirm authorization before scanning.",
        )

    ports_to_scan = scan_req.ports if scan_req.ports else DEFAULT_PORTS
    # Deduplicate and re-validate count after dedup
    ports_to_scan = list(dict.fromkeys(ports_to_scan))
    if len(ports_to_scan) > 1024:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Cannot scan more than 1024 unique ports per request.",
        )

    try:
        results = scan_ports(
            target=scan_req.target,
            ports=ports_to_scan,
            timeout=scan_req.timeout,
            max_workers=min(50, len(ports_to_scan)),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    open_ports = [r["port"] for r in results if r["open"]]
    banners = {str(r["port"]): r["banner"] for r in results if r["open"] and r["banner"]}

    return {
        "results": results,
        "open_ports": open_ports,
        "total_scanned": len(ports_to_scan),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/scan/save")
def save_scan_result(
    scan_req: ScanRequest,
    payload: dict,
    db: Annotated[Session, Depends(get_db)],
):
    """Save a completed scan result to encrypted history."""
    open_ports = payload.get("open_ports", [])
    banners = payload.get("banners", {})

    row = ScanHistory(
        target_enc=encrypt(scan_req.target),
        open_ports_enc=encrypt(json.dumps(open_ports)),
        banners_enc=encrypt(json.dumps(banners)),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"id": row.id, "timestamp": row.timestamp.isoformat()}


@app.post("/api/scan/save-result")
def save_scan_result_v2(
    body: dict,
    db: Annotated[Session, Depends(get_db)],
):
    """
    Save a completed scan result to encrypted history.
    Body: {target, open_ports, banners}
    """
    target = body.get("target", "")
    if not validate_target(target):
        raise HTTPException(status_code=422, detail="Invalid target in save request")

    open_ports = body.get("open_ports", [])
    banners = body.get("banners", {})

    row = ScanHistory(
        target_enc=encrypt(target),
        open_ports_enc=encrypt(json.dumps(open_ports)),
        banners_enc=encrypt(json.dumps(banners)),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"id": row.id, "timestamp": row.timestamp.isoformat()}


@app.get("/api/scan/history")
def get_scan_history(db: Annotated[Session, Depends(get_db)]):
    """
    Return decrypted scan history.
    NOTE: No authentication — local single-user dev only.
    """
    rows = db.query(ScanHistory).order_by(ScanHistory.timestamp.desc()).all()
    return [
        {
            "id": r.id,
            "target": decrypt(r.target_enc),
            "open_ports": json.loads(decrypt(r.open_ports_enc)),
            "banners": json.loads(decrypt(r.banners_enc)),
            "timestamp": r.timestamp.isoformat(),
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Entry point (run directly: python main.py)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cert_path = os.getenv("SECURESCAN_TLS_CERT")
    key_path = os.getenv("SECURESCAN_TLS_KEY")

    if cert_path and key_path:
        uvicorn.run(
            "main:app",
            host="0.0.0.0",
            port=8000,
            ssl_keyfile=key_path,
            ssl_certfile=cert_path,
            log_level="info",
            reload=False,
        )
    elif os.getenv("SECURESCAN_ALLOW_SELF_SIGNED", "false").lower() == "true":
        if not CERT_FILE.exists() or not KEY_FILE.exists():
            _generate_self_signed_cert()
        uvicorn.run(
            "main:app",
            host="0.0.0.0",
            port=8000,
            ssl_keyfile=str(KEY_FILE),
            ssl_certfile=str(CERT_FILE),
            log_level="info",
            reload=False,
        )
    else:
        uvicorn.run(
            "main:app",
            host="0.0.0.0",
            port=8000,
            log_level="info",
            reload=False,
        )
