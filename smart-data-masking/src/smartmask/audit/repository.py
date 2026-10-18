"""Privacy-conscious audit repository.

Records access events without logging sensitive values (raw card numbers,
passwords, tokens, HMAC secrets, query results or scanner samples).
"""

from __future__ import annotations

import logging
from typing import Optional

from ..database.connection import DatabaseManager
from ..database.models import AccessEvent
from ..schemas import AccessEvent as AccessEventSchema

logger = logging.getLogger(__name__)


class AuditRepository:
    """Persists privacy-conscious access events."""

    def __init__(self, db_manager: DatabaseManager) -> None:
        self._db_manager = db_manager

    def record_event(
        self,
        *,
        principal_user_id: Optional[str] = None,
        principal_role: Optional[str] = None,
        operation: str,
        table_name: Optional[str] = None,
        outcome: str,
        reason: str = "",
        policy_reference: Optional[str] = None,
        scan_reference: Optional[str] = None,
        actor_id: Optional[str] = None,
        database_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> None:
        """Record an access event. Never stores sensitive values."""
        session = self._db_manager.control_session()
        try:
            event = AccessEvent(
                principal_user_id=principal_user_id,
                principal_role=principal_role,
                operation=operation,
                table_name=table_name,
                outcome=outcome,
                reason=reason,
                policy_reference=policy_reference,
                scan_reference=scan_reference,
                actor_id=actor_id or principal_user_id,
                database_id=database_id,
                request_id=request_id,
            )
            session.add(event)
            session.commit()
            logger.debug(
                "Audit event recorded: operation=%s table=%s outcome=%s",
                operation, table_name, outcome,
            )
        except Exception as exc:
            session.rollback()
            logger.error("Failed to persist an audit event; operation must not report success.")
            raise RuntimeError("Audit persistence failed.") from exc
        finally:
            session.close()

    def list_events(self, limit: int = 50, offset: int = 0,
                    database_id: Optional[str] = None) -> list[dict]:
        """List recent access events (newest first)."""
        session = self._db_manager.control_session()
        try:
            from sqlalchemy import desc
            query = session.query(AccessEvent)
            if database_id is not None:
                query = query.filter(AccessEvent.database_id == database_id)
            rows = query.order_by(desc(AccessEvent.id)).offset(max(0, offset)).limit(max(1, min(limit, 1000))).all()
            return [
                {
                    "id": row.id,
                    "actor_id": row.actor_id,
                    "database_id": row.database_id,
                    "request_id": row.request_id,
                    "occurred_at": row.occurred_at.isoformat() if row.occurred_at else None,
                    "principal_user_id": row.principal_user_id,
                    "principal_role": row.principal_role,
                    "operation": row.operation,
                    "table_name": row.table_name,
                    "outcome": row.outcome,
                    "reason": row.reason,
                    "policy_reference": row.policy_reference,
                    "scan_reference": row.scan_reference,
                }
                for row in rows
            ]
        finally:
            session.close()
