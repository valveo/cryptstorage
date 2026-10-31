"""
ssh_keys.py - Validation of user-supplied OpenSSH public keys.

The key ends up in authorized_keys inside the user's container, and holding the
matching private key is what grants access to the decrypted files. So the value
must be exactly one key line: no newlines, no options (command="..."), a
well-formed key blob, and a modern size.
"""

import base64
import binascii
import re
import struct

ALLOWED_TYPES = ("ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256")
MAX_LENGTH = 2048
MIN_RSA_BITS = 3072

_LINE = re.compile(
    r"(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256) "
    r"([A-Za-z0-9+/]{20,}={0,3})"
    r"(?: ([\x21-\x7e][\x20-\x7e]{0,127}))?"
)


class InvalidSSHKey(ValueError):
    pass


def _read_string(buf: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(buf):
        raise InvalidSSHKey("Truncated SSH key.")
    (length,) = struct.unpack(">I", buf[offset:offset + 4])
    offset += 4
    if offset + length > len(buf):
        raise InvalidSSHKey("Truncated SSH key.")
    return buf[offset:offset + length], offset + length


def validate_ssh_public_key(key: str) -> str:
    """Return the normalized key line or raise InvalidSSHKey."""
    if not isinstance(key, str):
        raise InvalidSSHKey("SSH key must be a string.")
    key = key.strip()
    if len(key) > MAX_LENGTH:
        raise InvalidSSHKey("SSH key is too long.")

    m = _LINE.fullmatch(key)
    if not m:
        raise InvalidSSHKey(
            "SSH key must be a single line: ssh-ed25519, ssh-rsa or "
            "ecdsa-sha2-nistp256, followed by the key and an optional comment."
        )
    key_type, b64, comment = m.groups()

    try:
        blob = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        raise InvalidSSHKey("SSH key is not valid base64.")

    inner_type, off = _read_string(blob, 0)
    if inner_type.decode("ascii", "replace") != key_type:
        raise InvalidSSHKey("SSH key type does not match its contents.")

    if key_type == "ssh-rsa":
        _e, off = _read_string(blob, off)
        n, off = _read_string(blob, off)
        bits = int.from_bytes(n, "big").bit_length()
        if bits < MIN_RSA_BITS:
            raise InvalidSSHKey(f"RSA keys must be at least {MIN_RSA_BITS} bits (got {bits}).")
    elif key_type == "ssh-ed25519":
        raw, off = _read_string(blob, off)
        if len(raw) != 32:
            raise InvalidSSHKey("Invalid ed25519 key.")

    return f"{key_type} {b64}" + (f" {comment}" if comment else "")
