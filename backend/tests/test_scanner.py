"""
tests/test_scanner.py — validate_target() and scan_ports() tests.
"""

import binascii
import os
import pytest

os.environ["ENCRYPTION_KEY"] = binascii.hexlify(os.urandom(32)).decode()

from scanner import validate_target, scan_ports  # noqa: E402


# ---------------------------------------------------------------------------
# validate_target tests
# ---------------------------------------------------------------------------

VALID_TARGETS = [
    "localhost",
    "127.0.0.1",
    "192.168.1.1",
    "10.0.0.1",
    "::1",
    "example.com",
    "sub.domain.example.org",
    "my-host-01",
]

INVALID_TARGETS = [
    "",
    " ",
    "bad host",          # space
    "host;rm -rf /",    # shell injection
    "host|cat /etc/passwd",
    "host&&whoami",
    "$(evil)",
    "`evil`",
    "host\nnewline",
    "a" * 254,           # too long
    "192.168.1.1; DROP TABLE",
    "../etc/passwd",
    "host>file",
]


@pytest.mark.parametrize("target", VALID_TARGETS)
def test_validate_target_accepts_valid(target):
    assert validate_target(target) is True, f"Expected valid: {target!r}"


@pytest.mark.parametrize("target", INVALID_TARGETS)
def test_validate_target_rejects_invalid(target):
    assert validate_target(target) is False, f"Expected invalid: {target!r}"


# ---------------------------------------------------------------------------
# scan_ports smoke test (localhost only)
# ---------------------------------------------------------------------------

def test_scan_ports_returns_list():
    """scan_ports must return a list with one entry per port."""
    results = scan_ports("127.0.0.1", [9999, 9998], timeout=0.5, max_workers=2)
    assert isinstance(results, list)
    assert len(results) == 2


def test_scan_ports_sorted_by_port():
    results = scan_ports("127.0.0.1", [9000, 8000, 7000], timeout=0.5, max_workers=3)
    ports = [r["port"] for r in results]
    assert ports == sorted(ports)


def test_scan_ports_closed_ports_not_open():
    """High ephemeral ports are almost certainly closed on localhost."""
    results = scan_ports("127.0.0.1", [59990, 59991], timeout=0.5, max_workers=2)
    for r in results:
        assert r["open"] is False


def test_scan_ports_bad_hostname():
    with pytest.raises(ValueError, match="Cannot resolve"):
        scan_ports("this.hostname.does.not.exist.invalid", [80], timeout=0.5, max_workers=1)
