"""
escrow_state.py - What the escrow settings are, and whether they changed.

At start-up the current policy and escrow key are compared with the last row of the
hash-chained config_log. A change is appended, written to the audit log and mailed to every
user. A broken chain (a row edited or deleted) is reported the same way. This catches another
admin or an intruder; it cannot catch the operator, who can rewrite the chain. The client's own
record on the stick is the protection against that (docs/design-e2ee.md section 14, "Escrow").
"""

import hashlib
import logging
from datetime import datetime
from typing import Callable, Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

import config
from audit import log as audit_log
from models import ConfigLog

logger = logging.getLogger("cryptstorage.escrow")

GENESIS = "0" * 64

# Result of the last start-up check, shown to users: {"chain_ok", "changed_at"}
status = {"chain_ok": True, "changed_at": None}


def key_fingerprint(public_hex: Optional[str]) -> Optional[str]:
    """SHA-256 of the raw X25519 public key, hex. The client computes the same value."""
    if not public_hex:
        return None
    return hashlib.sha256(bytes.fromhex(public_hex)).hexdigest()


def current() -> tuple[str, Optional[str]]:
    policy = config.recovery_policy()
    return policy, key_fingerprint(config.escrow_public_key()) if policy != "user" else None


def _entry_hash(prev: str, seq: int, at: datetime, policy: str, fp: Optional[str]) -> str:
    data = "|".join([prev, str(seq), at.strftime("%Y-%m-%dT%H:%M:%S"), policy, fp or ""])
    return hashlib.sha256(data.encode()).hexdigest()


def verify_chain(rows: list[ConfigLog]) -> bool:
    prev = GENESIS
    for i, r in enumerate(rows):
        if r.seq != i + 1 or r.prev_hash != prev or \
                r.entry_hash != _entry_hash(prev, r.seq, r.created_at, r.recovery_policy, r.escrow_key_fingerprint):
            return False
        prev = r.entry_hash
    return True


def check_at_startup(db: Session, notify_all: Callable[[str], None]) -> dict:
    """Verify the chain, append the current settings if they changed, and tell the users.
    Several API workers start at once: the one that loses the race for the next seq reads again."""
    try:
        return _check(db, notify_all)
    except IntegrityError:
        db.rollback()
        return _check(db, lambda what: None)


def _check(db: Session, notify_all: Callable[[str], None]) -> dict:
    rows = db.query(ConfigLog).order_by(ConfigLog.seq).all()
    chain_ok = verify_chain(rows)
    policy, fp = current()
    last = rows[-1] if rows else None
    changed_at = last.created_at if last else None
    if not chain_ok:
        logger.error("config_log hash chain is broken: escrow settings history was edited")
        audit_log(db, "escrow_config_log_broken")
        notify_all("The record of this server's escrow settings has been tampered with. "
                   "Ask your administrator what changed.")
    if last is None or (last.recovery_policy, last.escrow_key_fingerprint) != (policy, fp):
        at = datetime.utcnow().replace(microsecond=0)
        seq = (last.seq if last else 0) + 1
        prev = last.entry_hash if last else GENESIS
        db.add(ConfigLog(seq=seq, created_at=at, recovery_policy=policy, escrow_key_fingerprint=fp,
                         prev_hash=prev, entry_hash=_entry_hash(prev, seq, at, policy, fp)))
        db.commit()
        if last is not None:
            changed_at = at
            detail = f"{last.recovery_policy}/{last.escrow_key_fingerprint} -> {policy}/{fp}"
            logger.warning(f"escrow settings changed since the last start: {detail}")
            audit_log(db, "escrow_config_changed", detail=detail)
            notify_all(f"This server's recovery setting changed: escrow is now "
                       f"{'OFF' if policy == 'user' else 'ON'} (policy '{policy}'"
                       + (f", organisation key {fp[:16]}..." if fp else "") + "). "
                       "Nothing is sealed for you without your consent; your client will warn you too.")
    status.update(chain_ok=chain_ok, changed_at=changed_at)
    return status
