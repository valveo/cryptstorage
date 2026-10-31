"""
models.py - SQLAlchemy database models.
"""

import uuid
from datetime import datetime
from sqlalchemy import BigInteger, Column, String, DateTime, Boolean, Integer, Text
from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, index=True)       # UUID
    username = Column(String(32), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)

    # Slow hash of the recovery proof (the recovery verifier, docs/design-e2ee.md). The column keeps its
    # old name from the removed server-side mode so existing databases need no rename.
    recovery_encrypted_master_key = Column(String(255), nullable=True)

    # SSH public key for SSHFS access
    ssh_public_key = Column(Text, nullable=True)

    # Email verification
    email_verified = Column(Boolean, default=False, nullable=False)

    # Storage status (the SFTP account exists)
    storage_created = Column(Boolean, default=False, nullable=False)

    # Quota in bytes (default 10GB)
    # BigInteger: the 10 GB default exceeds MariaDB INT (max 2147483647)
    quota_bytes = Column(BigInteger, default=10 * 1024 * 1024 * 1024, nullable=False)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login = Column(DateTime, nullable=True)
    # Bumped on password change; access tokens carry the version they were issued
    # under and are rejected once it no longer matches.
    token_version = Column(Integer, nullable=False, default=0, server_default="0")

    # Second factor (TOTP, see totp.py). The secret is stored encrypted; last_step makes a
    # code usable only once; backup codes are keyed hashes in a JSON list.
    # End-to-end mode: master key sealed to the organisation's escrow key (opaque to the server)
    escrow_blob        = Column(Text, nullable=True)
    totp_secret_enc    = Column(String(255), nullable=True)
    totp_enabled       = Column(Boolean, default=False, nullable=False, server_default="0")
    totp_last_step     = Column(BigInteger, nullable=True)
    totp_backup_hashes = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)

    def __repr__(self):
        return f"<User id={self.id} username={self.username}>"


class RefreshToken(Base):
    """
    Persistent refresh token store for rotation and revocation.

    Flow:
      - Login creates a new token family (family_id = random UUID)
      - Each /auth/refresh invalidates the old token and issues a new one
        in the same family
      - If a revoked token is presented (theft detection), the entire
        family is revoked and a security alert email is sent
    """
    __tablename__ = "refresh_tokens"

    id          = Column(String(36), primary_key=True)   # UUID, stable identifier
    token_hash  = Column(String(64), unique=True, index=True, nullable=False)  # SHA256 hex
    user_id     = Column(String(36), index=True, nullable=False)
    family_id   = Column(String(36), index=True, nullable=False)  # rotation family
    revoked     = Column(Boolean, default=False, nullable=False)
    created_at  = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at  = Column(DateTime, nullable=False)
    replaced_by = Column(String(36), nullable=True)  # id of successor token


class SecurityEvent(Base):
    """
    Audit log for security-relevant events.
    Written on: refresh token reuse, failed login bursts, account deletion.
    """
    __tablename__ = "security_events"

    id         = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id    = Column(String(36), index=True, nullable=True)
    event_type = Column(String(64), nullable=False)
    detail     = Column(String(1024), nullable=True)
    ip_address = Column(String(45), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class PendingChange(Base):
    """
    A new SSH key or an account deletion waiting for its delay to pass. The owner is
    told at request time and can cancel with the link in that e-mail (only its HMAC is
    stored, like refresh tokens) or from a signed-in session. The old key keeps working.
    """
    __tablename__ = "pending_changes"

    id             = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id        = Column(String(36), index=True, nullable=False)
    kind           = Column(String(16), nullable=False)          # "ssh_key", "delete" or "stick"
    ssh_public_key = Column(Text, nullable=True)
    cancel_hash    = Column(String(64), unique=True, nullable=False)
    state          = Column(String(16), nullable=False, default="pending")   # pending/applied/cancelled
    created_at     = Column(DateTime, default=datetime.utcnow, nullable=False)
    due_at         = Column(DateTime, index=True, nullable=False)
    ip_address     = Column(String(45), nullable=True)


class SyncLock(Base):
    """
    One synchronisation at a time per volume (docs/design-features.md section 5.1): two clients
    running rclone bisync against the same volume at once lose files without a conflict copy.
    The lock is held by one client installation (holder) and lapses at expires_at unless renewed.
    """
    __tablename__ = "sync_locks"

    user_id     = Column(String(36), primary_key=True)
    volume      = Column(String(64), primary_key=True)      # "personal"; shared folders later
    holder      = Column(String(64), nullable=False)
    holder_name = Column(String(64), nullable=True)         # shown to the user who has to wait
    expires_at  = Column(DateTime, nullable=False)


class WebAuthnCredential(Base):
    """A passkey or FIDO2 key registered as a second factor (passkeys.py)."""
    __tablename__ = "webauthn_credentials"

    id              = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id         = Column(String(36), index=True, nullable=False)
    credential_id   = Column(Text, nullable=False)                          # base64url
    credential_hash = Column(String(64), unique=True, nullable=False)       # SHA-256 of credential_id
    public_key      = Column(Text, nullable=False)                          # COSE key, base64url
    sign_count      = Column(BigInteger, nullable=False, default=0)
    transports      = Column(String(255), nullable=True)
    name            = Column(String(64), nullable=False)
    created_at      = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_used_at    = Column(DateTime, nullable=True)


class EscrowSeal(Base):
    """
    Which escrow key a user's master key was sealed to (docs/design-e2ee.md section 14, "Escrow").
    The blob itself stays in users.escrow_blob; this records the key's fingerprint, so the user can
    see that a copy exists for that key even after the operator changes it.
    """
    __tablename__ = "escrow_seals"

    user_id         = Column(String(36), primary_key=True)
    key_fingerprint = Column(String(64), nullable=False)
    sealed_at       = Column(DateTime, default=datetime.utcnow, nullable=False)


class ConfigLog(Base):
    """
    Hash-chained record of the escrow settings, one row per change seen at start-up.
    entry_hash = SHA-256 over the previous hash and this row's fields, so editing or deleting
    a row breaks the chain. It cannot stop the operator, who could rewrite the whole chain:
    the client's own record on the stick is the protection against that.
    """
    __tablename__ = "config_log"

    seq                    = Column(Integer, primary_key=True, autoincrement=False)
    created_at             = Column(DateTime, nullable=False)
    recovery_policy        = Column(String(16), nullable=False)
    escrow_key_fingerprint = Column(String(64), nullable=True)
    prev_hash              = Column(String(64), nullable=False)
    entry_hash             = Column(String(64), nullable=False)


class StickLock(Base):
    """A locked stick: its secret is not released until the owner unlocks it from the app with
    the full sign-in. Locking is immediate and can be done from the web UI, for a stick that is lost;
    removing it for good waits like other destructive changes (removal_change_id, pending.py)."""
    __tablename__ = "stick_locks"

    stick_id          = Column(String(36), primary_key=True)
    user_id           = Column(String(36), index=True, nullable=False)
    locked_at         = Column(DateTime, default=datetime.utcnow, nullable=False)
    removal_change_id = Column(String(36), index=True, nullable=True)


class StickSecret(Base):
    """The server's half of a USB stick's key (sticks.py). The id is also written on the stick."""
    __tablename__ = "stick_secrets"

    id           = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id      = Column(String(36), index=True, nullable=False)
    secret_enc   = Column(Text, nullable=False)          # AES-GCM under a key from TOTP_ENCRYPTION_KEY
    name         = Column(String(64), nullable=False)    # the computer that prepared it, for the list
    created_at   = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_used_at = Column(DateTime, nullable=True)
