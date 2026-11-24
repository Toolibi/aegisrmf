"""API-key authentication, role/scope authorization.

Keys look like  aeg_<prefix>_<secret>. Only an HMAC-SHA256(pepper, secret) is stored.
Entra ID (OIDC JWT) sign-in for the web app plugs in at verify_bearer(); see
docs/adr/0004-identity.md. Customer passwords are never stored.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import ApiKey, User

ALL_SCOPES = {
    "read", "evidence:write", "assessment:write", "findings:review", "poam:write",
    "report:export", "assessment:finalize", "admin",
}
ROLE_SCOPES = {
    "owner": set(ALL_SCOPES),
    "assessor": {"read", "evidence:write", "assessment:write", "findings:review", "poam:write",
                 "report:export", "assessment:finalize"},
    "contributor": {"read", "evidence:write", "poam:write"},
    "viewer": {"read"},
    # AI agents: read-only by default. Write scopes may be granted explicitly but an
    # agent can never finalize an assessment, review its own findings, or administer.
    "agent": {"read", "evidence:write", "assessment:write", "poam:write", "report:export"},
}


class AuthError(Exception):
    status = 401


class Forbidden(Exception):
    status = 403


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    user_id: str
    role: str
    scopes: frozenset = field(default_factory=frozenset)
    key_id: str | None = None
    channel: str = "api"

    def require(self, scope: str) -> None:
        if scope not in self.scopes:
            raise Forbidden(f"missing scope '{scope}'")


def _hash(secret: str) -> str:
    return hmac.new(get_settings().key_pepper.encode(), secret.encode(), hashlib.sha256).hexdigest()


def issue_key(db: Session, user: User, scopes: set[str] | None = None, label: str = "") -> str:
    allowed = ROLE_SCOPES[user.role]
    scopes = set(scopes) if scopes is not None else ({"read"} if user.role == "agent" else allowed)
    if not scopes <= allowed:
        raise Forbidden(f"scopes {sorted(scopes - allowed)} not allowed for role {user.role}")
    prefix = secrets.token_hex(6)
    secret = secrets.token_urlsafe(32)
    db.add(ApiKey(tenant_id=user.tenant_id, prefix=prefix, secret_hash=_hash(secret),
                  user_id=user.id, scopes=sorted(scopes), label=label))
    db.flush()
    return f"aeg_{prefix}_{secret}"


def verify_bearer(db: Session, token: str | None, channel: str = "api") -> Principal:
    if not token:
        raise AuthError("missing credentials")
    parts = token.split("_", 2)
    if len(parts) != 3 or parts[0] != "aeg":
        raise AuthError("invalid credentials")
    key = db.scalar(select(ApiKey).where(ApiKey.prefix == parts[1]))
    # Constant-time comparison; same error for every failure mode.
    if key is None:
        hmac.compare_digest(_hash(parts[2]), "0" * 64)
        raise AuthError("invalid credentials")
    if not hmac.compare_digest(key.secret_hash, _hash(parts[2])) or key.revoked:
        raise AuthError("invalid credentials")
    if key.expires_at and key.expires_at.replace(tzinfo=key.expires_at.tzinfo or timezone.utc) < datetime.now(timezone.utc):
        raise AuthError("invalid credentials")
    user = db.get(User, key.user_id)
    if user is None or user.tenant_id != key.tenant_id:
        raise AuthError("invalid credentials")
    scopes = frozenset(set(key.scopes) & ROLE_SCOPES[user.role])
    from ..db import bind_tenant
    bind_tenant(db, key.tenant_id)
    return Principal(tenant_id=key.tenant_id, user_id=user.id, role=user.role, scopes=scopes,
                     key_id=key.id, channel=channel)
