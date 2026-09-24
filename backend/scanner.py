"""
scanner.py — Network port scanning with banner grabbing.

Security properties:
  - validate_target() rejects shell-injection characters and malformed input.
  - Per-port socket timeout prevents indefinite hangs.
  - ThreadPoolExecutor bounds concurrency; a scan cap on port count is enforced
    in main.py (max 1024 ports per request).
  - The target string is NEVER written to any log inside this module.
"""

import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Only printable ASCII, letters, digits, dots, hyphens, and brackets (IPv6).
_SAFE_HOSTNAME_RE = re.compile(
    r"^(?:"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"  # labels
    r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"          # TLD / single label
    r"|"
    r"\[?[0-9a-fA-F:\.]+\]?"                                     # IPv4 / IPv6
    r")$"
)
_MAX_HOSTNAME_LEN = 253
_BANNER_SIZE = 1024          # bytes to read for banner grab
_BANNER_RECV_TIMEOUT = 2.0  # seconds to wait for banner data after connect

# Common service-port list — used as the default when none is specified
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080]


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

def validate_target(target: str) -> bool:
    """
    Return True iff *target* is a well-formed IPv4, IPv6, or hostname string.

    Rejects:
      - Empty strings
      - Input that's too long (> 253 chars)
      - Anything containing shell-special characters (;, |, &, $, `, >, <, \\n, …)
      - Labels that don't conform to RFC 1123 hostname syntax
    """
    if not target or len(target) > _MAX_HOSTNAME_LEN:
        return False

    # Reject shell-injection characters outright
    forbidden = set(';|&$`><!\n\r\\\'\"(){}[]%@#^*+=,~')
    if any(c in forbidden for c in target):
        return False

    # Try parsing as a literal IP address first (most restrictive / safest)
    try:
        ipaddress.ip_address(target.strip("[]"))
        return True
    except ValueError:
        pass

    # Fall back to hostname regex
    return bool(_SAFE_HOSTNAME_RE.match(target))


# ---------------------------------------------------------------------------
# Banner grabbing
# ---------------------------------------------------------------------------

def _grab_banner(ip: str, port: int, timeout: float) -> Optional[str]:
    """
    Attempt to receive a service banner from *ip*:*port*.
    Returns the decoded banner string, or None on failure.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            sock.settimeout(_BANNER_RECV_TIMEOUT)
            # Some services (HTTP) need a nudge to send a banner
            try:
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            except OSError:
                pass
            raw = sock.recv(_BANNER_SIZE)
            banner = raw.decode("utf-8", errors="replace").strip()
            # Limit to first line to keep output clean
            return banner.splitlines()[0] if banner else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------

def _probe_port(ip: str, port: int, timeout: float) -> dict:
    """
    Probe a single TCP port.
    Returns a dict: {port, open, banner}.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            is_open = result == 0
    except Exception:
        is_open = False

    banner = None
    if is_open:
        banner = _grab_banner(ip, port, timeout)

    return {"port": port, "open": is_open, "banner": banner or ""}


def scan_ports(
    target: str,
    ports: list[int],
    timeout: float = 1.0,
    max_workers: int = 50,
) -> list[dict]:
    """
    Scan *ports* on *target* concurrently.

    Parameters
    ----------
    target      : hostname or IP string (must pass validate_target() before calling)
    ports       : list of port numbers to probe
    timeout     : per-socket connect timeout in seconds
    max_workers : thread-pool size

    Returns
    -------
    List of result dicts sorted by port number:
        [{"port": int, "open": bool, "banner": str}, ...]
    """
    # Resolve hostname to IP once (avoids repeated DNS lookups per thread)
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve target '{target}': {exc}") from exc

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=min(max_workers, len(ports))) as executor:
        futures = {
            executor.submit(_probe_port, ip, port, timeout): port
            for port in ports
        }
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                port = futures[future]
                results.append({"port": port, "open": False, "banner": ""})

    results.sort(key=lambda r: r["port"])
    return results
