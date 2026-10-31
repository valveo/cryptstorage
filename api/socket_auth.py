"""
socket_auth.py - HMAC authentication for the daemon socket.

SINGLE SOURCE OF TRUTH: this file is used by the daemon and copied verbatim
to api/socket_auth.py (see ansible/setup-files.sh). tests/test_socket_auth.py
fails if the two copies differ, so the signing and verifying sides can never
silently diverge again.

Problem: any process that can reach the socket could send commands.
Solution: the API container and the daemon share a secret key
(DAEMON_AUTH_KEY, or /etc/cryptdaemon/auth.key on the host). Every command
carries an HMAC-SHA256 over the *whole* command.

Protocol (one JSON object per line, newline-terminated, in both directions):
  request:  {"action": ..., "user_id": ..., ..., "ts": <unix>, "nonce": "<32 hex>", "auth": "<hex>"}
  MAC:      HMAC-SHA256(key, canonical_json(command without "auth"))
            canonical_json = sorted keys, compact separators, ASCII only
  Replay:   "ts" must be within TIMESTAMP_TOLERANCE seconds of daemon time and the
            random "nonce" must not have been seen before (ReplayCache), so a
            captured command cannot be replayed even inside that window.

Covering every field (including master_key, ssh_public_key, quota_bytes)
means an attacker who captures one valid command cannot alter any part of it.
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from collections import OrderedDict

AUTH_KEY_PATH = "/etc/cryptdaemon/auth.key"
TIMESTAMP_TOLERANCE = 30  # seconds
NONCE_TTL = 2 * TIMESTAMP_TOLERANCE + 5
MAX_NONCES = 10_000

_NONCE_PATTERN = re.compile(r"[0-9a-f]{32}")


class AuthError(Exception):
    pass


def load_auth_key() -> bytes:
    """Load the shared auth key from DAEMON_AUTH_KEY or the key file (hex)."""
    key_hex = os.getenv("DAEMON_AUTH_KEY")
    if key_hex:
        return bytes.fromhex(key_hex.strip())
    try:
        with open(AUTH_KEY_PATH, "r") as f:
            return bytes.fromhex(f.read().strip())
    except FileNotFoundError:
        raise AuthError(
            f"Auth key not found. Create {AUTH_KEY_PATH} or set DAEMON_AUTH_KEY."
        )


def _canonical(command: dict) -> bytes:
    body = {k: v for k, v in command.items() if k != "auth"}
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def compute_mac(key: bytes, command: dict) -> str:
    """HMAC-SHA256 (hex) over the canonical form of the command."""
    return hmac.new(key, _canonical(command), hashlib.sha256).hexdigest()


class ReplayCache:
    """Remembers recently used nonces. Thread-safe, bounded in size and time."""

    def __init__(self, ttl: float = NONCE_TTL, max_entries: int = MAX_NONCES, clock=time.time):
        self._ttl = ttl
        self._max = max_entries
        self._clock = clock
        self._seen: "OrderedDict[str, float]" = OrderedDict()
        self._lock = threading.Lock()

    def check_and_store(self, nonce: str) -> None:
        """Raise AuthError if the nonce was already used; otherwise remember it."""
        now = self._clock()
        with self._lock:
            # Entries are in insertion order and all share one TTL, so the oldest come first
            while self._seen:
                oldest = next(iter(self._seen))
                if self._seen[oldest] > now:
                    break
                self._seen.popitem(last=False)
            if nonce in self._seen:
                raise AuthError("Replay detected.")
            if len(self._seen) >= self._max:
                raise AuthError("Too many recent requests.")
            self._seen[nonce] = now + self._ttl


def sign_command(command: dict, auth_key: bytes) -> dict:
    """Return a new dict with "ts", "nonce" and "auth" added."""
    cmd = dict(command)
    cmd["ts"] = int(time.time())
    cmd["nonce"] = secrets.token_hex(16)
    cmd["auth"] = compute_mac(auth_key, cmd)
    return cmd


def verify_command(command: dict, auth_key: bytes, replay_cache: "ReplayCache | None" = None) -> None:
    """
    Verify timestamp, MAC and (when a cache is given) nonce freshness.
    Raises AuthError on any problem, including malformed fields (wrong types
    must never raise anything else).
    """
    if not isinstance(command, dict):
        raise AuthError("Command must be a JSON object.")

    auth_hex = command.get("auth")
    ts = command.get("ts")
    nonce = command.get("nonce")

    if not isinstance(auth_hex, str) or not auth_hex:
        raise AuthError("Missing or invalid auth field.")
    if isinstance(ts, bool) or not isinstance(ts, int):
        raise AuthError("Missing or invalid ts field.")
    if not isinstance(nonce, str) or not _NONCE_PATTERN.fullmatch(nonce):
        raise AuthError("Missing or invalid nonce field.")

    delta = abs(int(time.time()) - ts)
    if delta > TIMESTAMP_TOLERANCE:
        raise AuthError(f"Timestamp out of range (delta={delta}s).")

    expected = compute_mac(auth_key, command)
    # compare bytes: compare_digest raises TypeError on non-ASCII str input
    if not hmac.compare_digest(auth_hex.encode("utf-8"), expected.encode("utf-8")):
        raise AuthError("Invalid auth signature.")

    # Only after the MAC is valid: someone without the key must not be able to
    # fill the cache.
    if replay_cache is not None:
        replay_cache.check_and_store(nonce)


def generate_auth_key() -> str:
    """Generate a new 256-bit auth key (hex)."""
    return os.urandom(32).hex()
