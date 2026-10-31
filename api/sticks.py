"""
sticks.py - The server's half of the USB stick's key.

The SSH key on the stick is encrypted with a key derived from the password AND a random 256-bit stick
secret that only the server holds (cryptclient/stickkey). The server hands the secret out only to a
session that passed the full login, password and second factor. Someone who finds or copies a stick can
then no longer guess the password offline: every guess has to go through the login, which is throttled
and audited. Deleting a stick's secret makes a lost stick useless.

The secrets are stored encrypted under a key derived from TOTP_ENCRYPTION_KEY, which lives outside the
database, so a database dump alone does not contain them. Without that setting the feature is off and
the client keeps the password-only format.
"""

import hashlib
import hmac
import os
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import totp

SECRET_BYTES = 32
MAX_PER_USER = 10


def is_configured() -> bool:
    return totp.is_configured()


def _key() -> bytes:
    # the label is from the product's earlier name and stays: stored stick secrets are encrypted with it
    return hmac.new(totp._instance_key(), b"secdisk-stick:enc", hashlib.sha256).digest()


def server_id() -> "str | None":
    """This server's public identity, which the client stores on a stick to tell servers apart.

    It is derived from TOTP_ENCRYPTION_KEY, the same key the stick secrets are encrypted with, so it
    changes exactly when every stick on this server stops opening anyway: a reinstall that restores the key
    keeps it, a new address keeps it, and an SSH host key that changed does not touch it. The HMAC output
    reveals nothing about the key. None when stick secrets are off.
    """
    if not is_configured():
        return None
    d = hmac.new(totp._instance_key(), b"cryptstorage/server-id/v1", hashlib.sha256).hexdigest()[:32]
    return f"{d[0:8]}-{d[8:12]}-{d[12:16]}-{d[16:20]}-{d[20:32]}"


def new_secret() -> bytes:
    return secrets.token_bytes(SECRET_BYTES)


def encrypt(secret: bytes, user_id: str, stick_id: str) -> str:
    nonce = os.urandom(12)
    return (nonce + AESGCM(_key()).encrypt(nonce, secret, f"{user_id}/{stick_id}".encode())).hex()


def decrypt(blob_hex: str, user_id: str, stick_id: str) -> bytes:
    blob = bytes.fromhex(blob_hex)
    return AESGCM(_key()).decrypt(blob[:12], blob[12:], f"{user_id}/{stick_id}".encode())
