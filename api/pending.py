"""
pending.py - Delayed SSH key replacement, account deletion and stick removal.

The SSH key is what opens the SFTP account, so replacing it is the step that turns a stolen
password (and code) into the user's ciphertext. Deleting the account destroys everything. Both
therefore wait CHANGE_DELAY_HOURS before they take effect. So does removing a USB stick for good: the
stick is locked at once (models.StickLock), but only the delay makes it permanent, so that someone who got
hold of a passkey cannot lock the owner out of the data for good without the owner hearing of it.

  1. The request is stored here and the owner is told at once, with a cancel link.
  2. Until the delay has passed the old key keeps working and nothing is deleted.
  3. A background thread (and /storage/e2ee, for the user who is connecting) applies what is due.

The cancel link carries <id>.<random>; only an HMAC of it is stored (like refresh tokens).
"""

import logging
import secrets
import threading
import time
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session

import config
from audit import log as audit_log
from auth import _hash_token
from email_verification import BASE_URL, send_security_notice_email
from models import EscrowSeal, PendingChange, StickLock, StickSecret, SyncLock, User, WebAuthnCredential
from socket_client import DaemonError, daemon_e2ee_delete, daemon_e2ee_provision

logger = logging.getLogger(__name__)

KINDS = ("ssh_key", "delete", "stick")
_WHAT = {
    "ssh_key": "A new SSH key was requested for your account. It replaces the key on your USB stick",
    "delete": "Deletion of your account and all its data was requested. It will happen",
    "stick": "Removal of a USB stick from your account was requested. The stick is locked now; "
             "it will be removed for good, so that its key can never be opened again,",
}


class NoticeFailed(Exception):
    """The owner could not be told about the request, so it was not stored."""


def schedule(db: Session, user: User, kind: str, ip: Optional[str],
             ssh_public_key: Optional[str] = None) -> PendingChange:
    """Store a delayed change and tell the owner. Replaces an earlier request of the same kind (each
    stick removal stands on its own: the caller links it to the stick's lock)."""
    assert kind in KINDS
    for old in (_pending(db, user.id, kind) if kind != "stick" else []):
        old.state = "cancelled"
    raw = secrets.token_urlsafe(32)
    change = PendingChange(
        user_id=user.id, kind=kind, ssh_public_key=ssh_public_key,
        cancel_hash=_hash_token(raw), state="pending",
        due_at=datetime.utcnow() + timedelta(hours=config.change_delay_hours()), ip_address=ip,
    )
    db.add(change)
    db.flush()
    link = f"{BASE_URL}/cancel.php?token={change.id}.{raw}"
    try:
        send_security_notice_email(
            user.email, user.username,
            f"{_WHAT[kind]} on {change.due_at:%Y-%m-%d %H:%M} UTC.",
            f"To stop it, open this link before then:\n{link}",
        )
    except Exception as e:
        db.rollback()
        logger.error(f"Could not send the change notice to user {user.id}: {e}")
        raise NoticeFailed() from e
    db.commit()
    audit_log(db, f"{kind}_change_requested", user_id=user.id, ip_address=ip,
              detail=f"change={change.id} due={change.due_at:%Y-%m-%dT%H:%M}")
    return change


def list_pending(db: Session, user_id: str) -> list[PendingChange]:
    return _pending(db, user_id)


def cancel(db: Session, user_id: str, change_id: str, ip: Optional[str]) -> bool:
    """Cancel from a signed-in session."""
    change = db.query(PendingChange).filter(
        PendingChange.id == change_id, PendingChange.user_id == user_id,
    ).first()
    return _cancel(db, change, ip, "session")


def cancel_by_token(db: Session, token: str, ip: Optional[str]) -> bool:
    """Cancel with the link from the e-mail. No sign-in needed: the token is the proof."""
    change_id, _, raw = (token or "").partition(".")
    change = db.query(PendingChange).filter(PendingChange.id == change_id).first() if raw else None
    if change is None or not secrets.compare_digest(change.cancel_hash, _hash_token(raw)):
        return False
    return _cancel(db, change, ip, "link")


def _cancel(db: Session, change: Optional[PendingChange], ip: Optional[str], how: str) -> bool:
    if change is None:
        return False
    changed = db.query(PendingChange).filter(
        PendingChange.id == change.id, PendingChange.state == "pending",
    ).update({PendingChange.state: "cancelled"}, synchronize_session=False)
    db.commit()
    if changed:
        audit_log(db, f"{change.kind}_change_cancelled", user_id=change.user_id, ip_address=ip,
                  detail=f"change={change.id} via={how}")
    return changed == 1


def apply_due(db: Session, user_id: Optional[str] = None) -> int:
    """Apply every change whose delay has passed. Safe to run from several processes at once."""
    q = db.query(PendingChange).filter(
        PendingChange.state == "pending", PendingChange.due_at <= datetime.utcnow(),
    )
    if user_id:
        q = q.filter(PendingChange.user_id == user_id)
    done = 0
    for change in q.order_by(PendingChange.due_at).all():
        # Claim it, so two workers never apply the same change
        claimed = db.query(PendingChange).filter(
            PendingChange.id == change.id, PendingChange.state == "pending",
        ).update({PendingChange.state: "applying"}, synchronize_session=False)
        db.commit()
        if not claimed:
            continue
        try:
            _apply(db, change)
        except DaemonError as e:
            logger.error(f"Could not apply change {change.id}, retrying later: {e}")
            db.rollback()
            db.query(PendingChange).filter(PendingChange.id == change.id).update(
                {PendingChange.state: "pending"}, synchronize_session=False)
            db.commit()
            continue
        done += 1
    return done


def _apply(db: Session, change: PendingChange) -> None:
    user = db.query(User).filter(User.id == change.user_id).first()
    if user is None:
        change.state = "cancelled"
        db.commit()
        return
    if change.kind == "ssh_key":
        daemon_e2ee_provision(user.username, change.ssh_public_key, user.quota_bytes)
        user.ssh_public_key = change.ssh_public_key
        user.storage_created = True
        change.state = "applied"
        db.commit()
        audit_log(db, "ssh_key_updated", user_id=user.id, detail=f"change={change.id}")
        _tell(user, "The new SSH key on your account is now active; the old one no longer works.")
    elif change.kind == "stick":
        lock = db.query(StickLock).filter(StickLock.removal_change_id == change.id).first()
        name = None
        if lock is not None:
            stick = db.query(StickSecret).filter(StickSecret.id == lock.stick_id).first()
            if stick is not None:
                name = stick.name
                db.delete(stick)
            db.delete(lock)
        change.state = "applied"
        db.commit()
        if name is not None:
            audit_log(db, "stick_removed", user_id=user.id, detail=f"stick={lock.stick_id} change={change.id}")
            _tell(user, f"The USB stick ({name}) was removed from your account. Its key can no longer be opened.")
    else:
        daemon_e2ee_delete(user.username)
        db.query(PendingChange).filter(
            PendingChange.user_id == user.id, PendingChange.state == "pending",
        ).update({PendingChange.state: "cancelled"}, synchronize_session=False)
        change.state = "applied"
        email, username, user_id = user.email, user.username, user.id
        db.query(SyncLock).filter(SyncLock.user_id == user.id).delete(synchronize_session=False)
        db.query(EscrowSeal).filter(EscrowSeal.user_id == user.id).delete(synchronize_session=False)
        db.query(WebAuthnCredential).filter(WebAuthnCredential.user_id == user.id).delete(synchronize_session=False)
        db.query(StickSecret).filter(StickSecret.user_id == user.id).delete(synchronize_session=False)
        db.query(StickLock).filter(StickLock.user_id == user.id).delete(synchronize_session=False)
        db.delete(user)
        db.commit()
        audit_log(db, "account_deleted", user_id=user_id, detail=f"change={change.id}")
        try:
            send_security_notice_email(email, username, "Your account and all its data were deleted.")
        except Exception as e:
            logger.error(f"Could not send the deletion notice for user {user_id}: {e}")


def expire_accounts(db: Session) -> int:
    """Demo/trial servers (ACCOUNT_LIFETIME_HOURS): schedule the deletion of accounts that have
    reached their lifetime, due at once, so they go through the same path as a user's own deletion."""
    hours = config.account_lifetime_hours()
    if hours <= 0:
        return 0
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    waiting = {c.user_id for c in db.query(PendingChange).filter(
        PendingChange.kind == "delete", PendingChange.state.in_(("pending", "applying")))}
    n = 0
    now = datetime.utcnow()
    for user in db.query(User).filter(User.created_at <= cutoff).all():
        if user.id in waiting:
            # a deletion the user asked for waits for its delay; the lifetime does not. One that is already
            # due (or being applied, or retried after a daemon error) is left alone, so a deletion that keeps
            # failing does not add an "account_expired" line to the audit log at every round of the worker.
            moved = db.query(PendingChange).filter(
                PendingChange.user_id == user.id, PendingChange.kind == "delete",
                PendingChange.state == "pending", PendingChange.due_at > now,
            ).update({PendingChange.due_at: now}, synchronize_session=False)
            if not moved:
                continue
        else:
            db.add(PendingChange(user_id=user.id, kind="delete", state="pending",
                                 cancel_hash=_hash_token(secrets.token_urlsafe(32)),
                                 due_at=now))
        audit_log(db, "account_expired", user_id=user.id, detail=f"lifetime={hours:g}h")
        n += 1
    db.commit()
    return n


def _tell(user: User, what: str) -> None:
    try:
        send_security_notice_email(user.email, user.username, what)
    except Exception as e:
        logger.error(f"Could not send security notice to user {user.id}: {e}")


def _pending(db: Session, user_id: str, kind: Optional[str] = None) -> list[PendingChange]:
    q = db.query(PendingChange).filter(PendingChange.user_id == user_id, PendingChange.state == "pending")
    if kind:
        q = q.filter(PendingChange.kind == kind)
    return q.order_by(PendingChange.due_at).all()


def start_worker(session_factory, interval: float) -> Optional[threading.Thread]:
    """Apply due changes every `interval` seconds in a daemon thread. interval <= 0: no thread."""
    if interval <= 0:
        return None

    def loop():
        while True:
            db = session_factory()
            try:
                expire_accounts(db)
                apply_due(db)
            except Exception as e:      # keep the worker alive whatever happens
                logger.error(f"Applying pending changes failed: {e}")
            finally:
                db.close()
            time.sleep(interval)

    t = threading.Thread(target=loop, name="pending-changes", daemon=True)
    t.start()
    return t
