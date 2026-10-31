#!/usr/bin/env python3
"""Operator tool for the organisation's recovery (escrow) key. Run it on a trusted machine, not on the server.

  escrow.py keygen                     make a key pair: keep the private key offline, put the public key
                                       in ESCROW_PUBLIC_KEY (ansible: escrow_public_key)
  escrow.py recovery-code <blob-hex>   open one user's escrow blob (private key read from the
                                       ESCROW_PRIVATE_KEY environment variable, never from an argument)
                                       and print the user's recovery code, to hand to the user safely

Blob format: ephemeral public (32) | nonce (12) | AES-256-GCM ciphertext+tag, hex. See cryptclient/e2ee/escrow.go.
"""
import base64, hashlib, os, sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

RAW = serialization.Encoding.Raw, serialization.PublicFormat.Raw


def keygen():
    priv = X25519PrivateKey.generate()
    print("ESCROW_PRIVATE_KEY=" + priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                                      serialization.NoEncryption()).hex())
    print("ESCROW_PUBLIC_KEY=" + priv.public_key().public_bytes(*RAW).hex())
    print("\nKeep the private key offline and backed up. Anyone who has it can read EVERY user's data.", file=sys.stderr)


def open_blob(blob_hex: str, private_hex: str) -> bytes:
    blob = bytes.fromhex(blob_hex)
    if len(blob) != 92:
        raise ValueError("bad blob length")
    priv = X25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex))
    eph, nonce, ct = blob[:32], blob[32:44], blob[44:]
    shared = priv.exchange(X25519PublicKey.from_public_bytes(eph))
    mine = priv.public_key().public_bytes(*RAW)
    key = HKDF(hashes.SHA256(), 32, eph + mine, b"secdisk/escrow/v1").derive(shared)
    return AESGCM(key).decrypt(nonce, ct, eph + mine)


def recovery_code(master_key: bytes) -> str:
    """Same format as cryptclient/e2ee/recovery.go: key + 4-byte checksum, base32, groups of six."""
    chk = hashlib.sha256(b"secdisk/recovery/v1\x00" + master_key).digest()[:4]
    s = base64.b32encode(master_key + chk).decode().rstrip("=")
    return "-".join(s[i:i + 6] for i in range(0, len(s), 6))


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "keygen":
        keygen()
    elif len(sys.argv) == 3 and sys.argv[1] == "recovery-code":
        priv = os.environ.get("ESCROW_PRIVATE_KEY")
        if not priv:
            sys.exit("Set ESCROW_PRIVATE_KEY in the environment.")
        print(recovery_code(open_blob(sys.argv[2], priv)))
    else:
        sys.exit(__doc__)
