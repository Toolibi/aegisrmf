"""Tamper-evident audit log: each event hashes the previous event's hash (per tenant).
verify_chain() recomputes the chain; any edit or deletion breaks it. In production the
chain head is also anchored to immutable Azure Blob storage (WORM) - see runbooks."""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import AuditEvent

GENESIS = "0" * 64


def _digest(prev: str, body: dict) -> str:
    return hashlib.sha256((prev + json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)).encode()).hexdigest()


def record(db: Session, principal, action: str, entity: str, entity_id: str, data: dict | None = None) -> AuditEvent:
    tenant_id = principal.tenant_id
    last = db.scalar(select(AuditEvent).where(AuditEvent.tenant_id == tenant_id)
                     .order_by(AuditEvent.seq.desc()).limit(1))
    seq = (last.seq + 1) if last else 1
    prev = last.hash if last else GENESIS
    at = datetime.now(timezone.utc).isoformat()
    body = {"tenant_id": tenant_id, "seq": seq, "actor_id": principal.user_id, "channel": principal.channel,
            "action": action, "entity": entity, "entity_id": entity_id, "data": data or {}, "at": at}
    ev = AuditEvent(tenant_id=tenant_id, seq=seq, actor_id=principal.user_id, channel=principal.channel,
                    action=action, entity=entity, entity_id=entity_id, data=data or {}, at=at,
                    prev_hash=prev, hash=_digest(prev, body))
    db.add(ev)
    db.flush()
    return ev


def verify_chain(db: Session, tenant_id: str) -> dict:
    events = db.scalars(select(AuditEvent).where(AuditEvent.tenant_id == tenant_id).order_by(AuditEvent.seq)).all()
    prev = GENESIS
    for i, e in enumerate(events, start=1):
        body = {"tenant_id": e.tenant_id, "seq": e.seq, "actor_id": e.actor_id, "channel": e.channel,
                "action": e.action, "entity": e.entity, "entity_id": e.entity_id, "data": e.data, "at": e.at}
        if e.seq != i or e.prev_hash != prev or e.hash != _digest(prev, body):
            return {"valid": False, "broken_at_seq": e.seq, "events": len(events)}
        prev = e.hash
    return {"valid": True, "events": len(events), "head": prev}


def sign_manifest(manifest: dict) -> str:
    """HMAC-SHA256 over a canonical manifest. Production: swap for Key Vault asymmetric sign."""
    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hmac.new(get_settings().manifest_signing_key.encode(), payload, hashlib.sha256).hexdigest()


def verify_manifest(manifest: dict, signature: str) -> bool:
    return hmac.compare_digest(sign_manifest(manifest), signature)


def count(db: Session, tenant_id: str) -> int:
    return db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.tenant_id == tenant_id))
