"""
totp.py - Time-based one-time passwords (RFC 6238) as a second factor.

The algorithm is the standard HMAC-SHA1, 6-digit, 30-second TOTP that every authenticator
app understands. Nothing here is a new cryptographic construction; the module only uses
hmac, hashlib and AES-GCM from `cryptography`.

What the server stores per user:
  - the TOTP secret, encrypted with AES-256-GCM under a key derived from TOTP_ENCRYPTION_KEY
    (an instance key kept outside the database, so a database dump alone does not reveal it),
    with the user id as associated data so a blob cannot be moved to another account;
  - the last accepted time step, so a code works only once (replay protection);
  - keyed hashes of the single-use backup codes.

A second factor protects online logins. It does not protect against an attacker who holds a
copy of the database: the master key is wrapped with the password (see SECURITY.md).
"""

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import struct
import time
from typing import Optional
from urllib.parse import quote

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DIGITS = 6
PERIOD = 30
SECRET_BYTES = 20        # 160 bits, the size RFC 4226 recommends
WINDOW = 1               # accept the previous and next 30-second step (clock drift)
BACKUP_CODE_COUNT = 10

_CODE_RE = re.compile(r"\d{6}")
_BACKUP_RE = re.compile(r"[A-Z2-7]{10}")


class TotpNotConfigured(RuntimeError):
    """TOTP_ENCRYPTION_KEY is not set, so secrets cannot be stored."""


def _instance_key() -> bytes:
    value = os.getenv("TOTP_ENCRYPTION_KEY", "").strip()
    if not value:
        raise TotpNotConfigured("TOTP_ENCRYPTION_KEY is not set.")
    return bytes.fromhex(value)


def is_configured() -> bool:
    return bool(os.getenv("TOTP_ENCRYPTION_KEY", "").strip())


def _subkey(label: bytes) -> bytes:
    """Separate keys for encryption and for hashing backup codes, derived from one secret.

    The "secdisk-totp:" prefix is from the product's earlier name and stays: stored secrets depend on it.
    """
    return hmac.new(_instance_key(), b"secdisk-totp:" + label, hashlib.sha256).digest()


# --- The algorithm (RFC 4226 / RFC 6238) ---

def generate_secret() -> str:
    """Random secret as base32 text, the form authenticator apps expect."""
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode("ascii").rstrip("=")


def _decode_secret(secret_b32: str) -> bytes:
    padded = secret_b32.upper() + "=" * (-len(secret_b32) % 8)
    return base64.b32decode(padded)


def code_for_step(secret_b32: str, step: int) -> str:
    digest = hmac.new(_decode_secret(secret_b32), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(number % (10 ** DIGITS)).zfill(DIGITS)


def current_step(now: Optional[float] = None) -> int:
    return int((time.time() if now is None else now) // PERIOD)


def verify(secret_b32: str, code: str, last_step: Optional[int] = None,
           now: Optional[float] = None) -> Optional[int]:
    """Return the matching time step if `code` is valid, otherwise None.

    A step that is not newer than `last_step` is refused, so a code (for example one
    seen over a shoulder) cannot be used twice.
    """
    code = (code or "").strip().replace(" ", "")
    if not _CODE_RE.fullmatch(code):
        return None
    step_now = current_step(now)
    matched = None
    for candidate in range(step_now - WINDOW, step_now + WINDOW + 1):
        # Compare every candidate so the time taken does not reveal which one matched
        if hmac.compare_digest(code_for_step(secret_b32, candidate), code):
            matched = candidate
    if matched is None or (last_step is not None and matched <= last_step):
        return None
    return matched


def provisioning_uri(secret_b32: str, account: str, issuer: str) -> str:
    """The otpauth:// URI that authenticator apps import (also what a QR code encodes)."""
    label = quote(f"{issuer}:{account}", safe="")
    return (f"otpauth://totp/{label}?secret={secret_b32}&issuer={quote(issuer, safe='')}"
            f"&algorithm=SHA1&digits={DIGITS}&period={PERIOD}")


# --- Storing the secret ---

def encrypt_secret(secret_b32: str, user_id: str) -> str:
    nonce = os.urandom(12)
    blob = nonce + AESGCM(_subkey(b"enc")).encrypt(nonce, secret_b32.encode("ascii"),
                                                    user_id.encode("utf-8"))
    return blob.hex()


def decrypt_secret(blob_hex: str, user_id: str) -> str:
    blob = bytes.fromhex(blob_hex)
    plain = AESGCM(_subkey(b"enc")).decrypt(blob[:12], blob[12:], user_id.encode("utf-8"))
    return plain.decode("ascii")


# --- Backup codes ---

def generate_backup_codes() -> list[str]:
    """Ten single-use codes of 50 random bits each, formatted ABCDE-FGHIJ."""
    codes = []
    for _ in range(BACKUP_CODE_COUNT):
        raw = base64.b32encode(secrets.token_bytes(7)).decode("ascii")[:10]
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


def normalize_backup_code(code: str) -> Optional[str]:
    cleaned = re.sub(r"[\s-]", "", code or "").upper()
    return cleaned if _BACKUP_RE.fullmatch(cleaned) else None


def _hash_backup_code(normalized: str) -> str:
    return hmac.new(_subkey(b"backup"), normalized.encode("ascii"), hashlib.sha256).hexdigest()


def hash_backup_codes(codes: list[str]) -> str:
    return json.dumps([_hash_backup_code(normalize_backup_code(c)) for c in codes])


def consume_backup_code(stored_json: Optional[str], code: str) -> Optional[str]:
    """Return the stored list without `code` if it matches one, otherwise None."""
    normalized = normalize_backup_code(code)
    if normalized is None or not stored_json:
        return None
    hashes = json.loads(stored_json)
    wanted = _hash_backup_code(normalized)
    remaining = [h for h in hashes if not hmac.compare_digest(h, wanted)]
    if len(remaining) == len(hashes):
        return None
    return json.dumps(remaining)


# --- E-mail code for turning the second factor on ---
# Derived from the pending (encrypted) secret, so nothing extra is stored and a new setup makes
# the old code useless. Guessing is limited by the same per-account counter as TOTP codes.

def enrolment_code(user_id: str, secret_enc: str) -> str:
    mac = hmac.new(_subkey(b"enrol"), f"{user_id}|{secret_enc}".encode(), hashlib.sha256).digest()
    return f"{int.from_bytes(mac[:8], 'big') % 10**8:08d}"


def check_enrolment_code(user_id: str, secret_enc: str, code: str) -> bool:
    return hmac.compare_digest(enrolment_code(user_id, secret_enc), re.sub(r"\s", "", code or ""))
