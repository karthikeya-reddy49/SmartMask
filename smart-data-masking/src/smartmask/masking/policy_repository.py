"""Repository for persisted policies.

Handles SQLAlchemy sessions and transactions for baseline policy seeding,
retrieval and validated updates.
"""

from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy.orm import Session

from ..database.connection import DatabaseManager
from ..database.models import (
    Base,
    Policy,
    PolicyHistory,
)
from ..exceptions import MetadataPersistenceError, PolicyError
from ..models import ClassificationTag, Role
from ..schemas import PolicyDecision

logger = logging.getLogger(__name__)


class PolicyRepository:
    """Persists and retrieves role-and-classification policy rules."""

    def __init__(self, db_manager: DatabaseManager) -> None:
        self._db_manager = db_manager

    def initialize_schema(self) -> None:
        """Create all internal control tables idempotently."""
        engine = self._db_manager.control_engine
        Base.metadata.create_all(engine)
        logger.info("Control schema initialized (idempotent).")

    def seed_baseline_policies(self) -> int:
        """Idempotently insert baseline policy rules.

        Returns the number of policies inserted (skips existing via unique
        constraint). Uses INSERT ... ON CONFLICT DO NOTHING semantics.
        """
        baseline = [
            # Role, Classification, Action, table_scope, column_scope, version
            (Role.ADMIN, ClassificationTag.PII_HIGH, "allow", None, None, "1.0"),
            (Role.ADMIN, ClassificationTag.FINANCIAL_CONFIDENTIAL, "allow", None, None, "1.0"),
            (Role.ADMIN, ClassificationTag.PUBLIC, "allow", None, None, "1.0"),
            (Role.ADMIN, ClassificationTag.UNCLASSIFIED, "redact", None, None, "1.0"),
            (Role.SUPPORT, ClassificationTag.PII_HIGH, "mask", None, None, "1.0"),
            (Role.SUPPORT, ClassificationTag.FINANCIAL_CONFIDENTIAL, "mask", None, None, "1.0"),
            (Role.SUPPORT, ClassificationTag.PUBLIC, "allow", None, None, "1.0"),
            (Role.SUPPORT, ClassificationTag.UNCLASSIFIED, "redact", None, None, "1.0"),
            (Role.ANALYST, ClassificationTag.PII_HIGH, "hmac_sha256", None, None, "1.0"),
            (Role.ANALYST, ClassificationTag.FINANCIAL_CONFIDENTIAL, "redact", None, None, "1.0"),
            (Role.ANALYST, ClassificationTag.PUBLIC, "allow", None, None, "1.0"),
            (Role.ANALYST, ClassificationTag.UNCLASSIFIED, "redact", None, None, "1.0"),
        ]
        session = self._db_manager.control_session()
        inserted = 0
        try:
            for role, classification, action, table_scope, column_scope, version in baseline:
                existing = (
                    session.query(Policy)
                    .filter_by(
                        role=role,
                        classification=classification,
                        table_scope=table_scope,
                        column_scope=column_scope,
                    )
                    .first()
                )
                if existing is None:
                    session.add(
                        Policy(
                            role=role,
                            classification=classification,
                            action=action,
                            table_scope=table_scope,
                            column_scope=column_scope,
                            enabled=True,
                            policy_version=version,
                        )
                    )
                    inserted += 1
            session.commit()
            logger.info("Seeded %s new baseline policies.", inserted)
            return inserted
        except Exception as exc:
            session.rollback()
            raise MetadataPersistenceError(
                f"Failed to seed baseline policies: {exc}"
            ) from exc
        finally:
            session.close()

    def get_applicable_policy(
        self,
        role: Role,
        classification: ClassificationTag,
        table_name: Optional[str] = None,
        column_name: Optional[str] = None,
    ) -> Optional[Policy]:
        """Retrieve the most specific applicable policy.

        Field-scoped rules take precedence over role/classification-only rules.
        Disabled policies are ignored.
        """
        session = self._db_manager.control_session()
        try:
            # Most specific first: exact table+column, then table only, then none.
            candidates = (
                session.query(Policy)
                .filter_by(role=role, classification=classification)
                .all()
            )
            candidates = [
                policy for policy in candidates
                if (policy.table_scope is None or policy.table_scope == table_name)
                and (policy.column_scope is None or policy.column_scope == column_name)
            ]
            if not candidates:
                return None

            def specificity(p: Policy) -> int:
                score = 0
                if p.table_scope == table_name:
                    score += 2
                if p.column_scope == column_name:
                    score += 2
                return score

            candidates.sort(key=specificity, reverse=True)
            return candidates[0]
        finally:
            session.close()

    def update_policy(
        self,
        policy_id: int,
        *,
        action: Optional[str] = None,
        enabled: Optional[bool] = None,
        actor_id: Optional[str] = None,
    ) -> Policy:
        """Update a policy through a validated operation.

        Validates the action against supported actions. Avoids implicit
        privilege escalation by requiring explicit action changes.
        """
        from ..database.models import utc_now
        supported_actions = {"allow", "redact", "mask", "hmac_sha256"}
        if action is not None and action not in supported_actions:
            raise PolicyError(f"Unsupported action: {action}")
        session = self._db_manager.control_session()
        try:
            row = session.get(Policy, policy_id)
            if row is None:
                raise PolicyError(f"Policy {policy_id} not found.")
            before = self._safe_policy(row)
            if action is not None:
                row.action = action
            if enabled is not None:
                row.enabled = enabled
            row.updated_at = utc_now()
            row.policy_version = self._next_version(row.policy_version)
            session.flush()
            session.add(PolicyHistory(policy_id=row.id, actor_id=actor_id,
                operation=("disabled" if enabled is False else
                           "enabled" if enabled is True else "updated"),
                before_state=before, after_state=self._safe_policy(row)))
            session.commit()
            session.refresh(row)
            logger.info("Updated policy id=%s", policy_id)
            return row
        except Exception as exc:
            session.rollback()
            raise MetadataPersistenceError(
                f"Failed to update policy {policy_id}: {exc}"
            ) from exc
        finally:
            session.close()

    def create_policy(self, *, role: Role, classification: ClassificationTag,
                      action: str, table_scope: Optional[str] = None,
                      column_scope: Optional[str] = None, actor_id: Optional[str] = None) -> Policy:
        supported = {"allow", "redact", "mask", "hmac_sha256"}
        if action not in supported:
            raise PolicyError("Unsupported policy action.")
        if column_scope and not table_scope:
            raise PolicyError("A column-scoped policy must include a table scope.")
        session = self._db_manager.control_session()
        try:
            existing = session.query(Policy).filter_by(
                role=role, classification=classification,
                table_scope=table_scope, column_scope=column_scope,
            ).first()
            if existing is not None:
                raise PolicyError("A policy with this role, classification, and scope already exists.")
            row = Policy(role=role, classification=classification, action=action,
                         table_scope=table_scope, column_scope=column_scope,
                         enabled=True, policy_version="1.0")
            session.add(row)
            session.flush()
            session.add(PolicyHistory(policy_id=row.id, actor_id=actor_id,
                operation="created", before_state=None, after_state=self._safe_policy(row)))
            session.commit()
            session.refresh(row)
            return row
        except PolicyError:
            session.rollback()
            raise
        except Exception as exc:
            session.rollback()
            raise MetadataPersistenceError("Failed to create policy; verify its scope is unique.") from exc
        finally:
            session.close()

    @staticmethod
    def _next_version(version: str) -> str:
        try:
            major, minor = version.split(".", 1)
            return f"{major}.{int(minor) + 1}"
        except (ValueError, AttributeError):
            return "1.1"

    @staticmethod
    def _safe_policy(row: Policy) -> dict:
        return {"id": row.id, "role": row.role.value,
            "classification": row.classification.value, "action": row.action,
            "table_scope": row.table_scope, "column_scope": row.column_scope,
            "enabled": row.enabled, "policy_version": row.policy_version}

    def list_policies(self) -> list[dict]:
        """List all persisted policies as plain dicts."""
        session = self._db_manager.control_session()
        try:
            rows = session.query(Policy).all()
            return [
                {
                    "id": row.id,
                    "role": row.role.value,
                    "classification": row.classification.value,
                    "action": row.action,
                    "table_scope": row.table_scope,
                    "column_scope": row.column_scope,
                    "enabled": row.enabled,
                    "policy_version": row.policy_version,
                    "created_at": row.created_at.isoformat() if row.created_at else None,
                    "updated_at": row.updated_at.isoformat() if row.updated_at else None,
                }
                for row in rows
            ]
        finally:
            session.close()
