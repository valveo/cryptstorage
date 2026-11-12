"""
registration.py - Who may create an account, and invitations.

REGISTRATION (config.py) is "open", "invite" or "closed". An invitation is a random code the
administrator makes with admin.py and hands to one person. Only an HMAC of it is stored. It works
once, for a limited time, and only for one e-mail address when the administrator named one.
"""

import secrets
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session

import config
from auth import _hash_token
from models import Invite

CLOSED = "REGISTRATION_CLOSED"
INVITE_REQUIRED = "INVITE_REQUIRED"
INVITE_INVALID = "INVITE_INVALID"
EMAIL_DOMAIN_REFUSED = "EMAIL_DOMAIN_REFUSED"


class Refused(Exception):
    """Registration is not allowed; str() is the code the clients show a message for."""


def _normalize(code: str) -> str:
    return "".join(code.split())


def create_invite(db: Session, email: Optional[str] = None, days: float = 7,
                  note: Optional[str] = None) -> tuple[Invite, str]:
    """A new invitation and its code, which is shown once and not stored."""
    code = secrets.token_urlsafe(18)
    invite = Invite(code_hash=_hash_token(code), email=(email or "").strip().lower() or None,
                    note=(note or "")[:255] or None,
                    expires_at=datetime.utcnow() + timedelta(days=days))
    db.add(invite)
    db.commit()
    db.refresh(invite)
    return invite, code


def check(email: str) -> None:
    """What can be refused before looking at an invitation: the mode and the address."""
    if config.registration() == "closed":
        raise Refused(CLOSED)
    domains = config.registration_email_domains()
    if domains and email.rsplit("@", 1)[-1].lower() not in domains:
        raise Refused(EMAIL_DOMAIN_REFUSED)


def claim_invite(db: Session, code: Optional[str], email: str, user_id: str) -> Optional[Invite]:
    """Use up the invitation for this registration (not committed: it is part of the caller's
    transaction, so a registration that fails leaves the invitation usable). None in open mode."""
    if config.registration() != "invite":
        return None
    if not code or not _normalize(code):
        raise Refused(INVITE_REQUIRED)
    now = datetime.utcnow()
    invite = db.query(Invite).filter(Invite.code_hash == _hash_token(_normalize(code))).first()
    if (invite is None or invite.used_at is not None or invite.expires_at <= now
            or (invite.email and invite.email != email.strip().lower())):
        # one answer for all of these, so a code cannot be probed for the address it belongs to
        raise Refused(INVITE_INVALID)
    # Only the request that marks it used wins, so one code never registers two accounts
    claimed = db.query(Invite).filter(Invite.id == invite.id, Invite.used_at.is_(None)).update(
        {Invite.used_at: now, Invite.used_by: user_id}, synchronize_session=False)
    if claimed != 1:
        raise Refused(INVITE_INVALID)
    return invite
