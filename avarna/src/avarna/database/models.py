"""Internal control/metadata database tables.

These tables store scan runs, column classifications, role/tag policies, and
access events. Raw customer values are never stored here.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Index,
    JSON,
)
from sqlalchemy.orm import relationship

from .base import Base

from avarna.models import ClassificationTag, ReviewStatus, Role  # noqa: E402


def utc_now() -> datetime:
    """Return the current UTC time, timezone-aware."""
    return datetime.now(timezone.utc)


class ScanRun(Base):
    """A recorded PII scan run."""

    __tablename__ = "scan_runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    database_id = Column(String(50), nullable=False, default="sqlite_demo", index=True)
    status = Column(String, nullable=False, default="running")  # running, completed, failed
    tables_scanned = Column(Integer, nullable=False, default=0)
    columns_classified = Column(Integer, nullable=False, default=0)
    started_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error_summary = Column(Text, nullable=True)

    classifications = relationship(
        "ColumnClassification",
        back_populates="scan_run",
        cascade="all, delete-orphan",
    )


class ColumnClassification(Base):
    """Persisted classification metadata for a table column."""

    __tablename__ = "column_classifications"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_run_id = Column(
        Integer, ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False
    )
    table_name = Column(String, nullable=False, index=True)
    column_name = Column(String, nullable=False, index=True)
    classification = Column(Enum(ClassificationTag), nullable=False)
    effective_classification = Column(Enum(ClassificationTag), nullable=True)
    confidence = Column(Integer, nullable=False)  # stored as int (0-100)
    reasons = Column(Text, nullable=False, default="")  # JSON-ish / pipe-joined reasons
    review_status = Column(Enum(ReviewStatus), nullable=False, default=ReviewStatus.PENDING)
    reviewer = Column(String, nullable=True)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)

    scan_run = relationship("ScanRun", back_populates="classifications")

    __table_args__ = (
        UniqueConstraint(
            "scan_run_id", "table_name", "column_name",
            name="uq_scan_run_table_column",
        ),
        Index("ix_column_classifications_table_column", "table_name", "column_name"),
    )


class Policy(Base):
    """A role-and-classification-based policy rule."""

    __tablename__ = "policies"

    id = Column(Integer, primary_key=True, autoincrement=True)
    role = Column(Enum(Role), nullable=False, index=True)
    classification = Column(Enum(ClassificationTag), nullable=False, index=True)
    action = Column(String, nullable=False)  # allow, redact, mask, hmac_sha256
    table_scope = Column(String, nullable=True)  # optional table name
    column_scope = Column(String, nullable=True)  # optional column name
    enabled = Column(Boolean, nullable=False, default=True)
    policy_version = Column(String, nullable=False, default="1.0")
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)

    __table_args__ = (
        UniqueConstraint(
            "role", "classification", "table_scope", "column_scope",
            name="uq_policy_role_classification_scope",
        ),
    )


class AccessEvent(Base):
    """A privacy-conscious audit access event."""

    __tablename__ = "access_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    actor_id = Column(String(64), nullable=True)
    database_id = Column(String(50), nullable=True, index=True)
    request_id = Column(String(64), nullable=True)
    occurred_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    principal_user_id = Column(String, nullable=True)
    principal_role = Column(String, nullable=True)
    operation = Column(String, nullable=False)
    table_name = Column(String, nullable=True, index=True)
    outcome = Column(String, nullable=False)  # allowed, denied, error
    reason = Column(Text, nullable=False, default="")
    policy_reference = Column(String, nullable=True)
    scan_reference = Column(String, nullable=True)


class User(Base):
    """Persisted API identity. Passwords are always Argon2id hashes."""
    __tablename__ = "users"

    id = Column(String(36), primary_key=True)
    username = Column(String(64), nullable=False, unique=True, index=True)
    password_hash = Column(String(512), nullable=False)
    role = Column(Enum(Role), nullable=False)
    is_active = Column(Boolean, nullable=False, default=True)
    failed_login_count = Column(Integer, nullable=False, default=0)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    token_version = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    grants = relationship("PermissionGrant", back_populates="user", cascade="all, delete-orphan")


class PermissionGrant(Base):
    __tablename__ = "permission_grants"
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    permission = Column(String(64), primary_key=True)
    granted_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    granted_by = Column(String(36), nullable=True)
    user = relationship("User", back_populates="grants")


class PolicyHistory(Base):
    __tablename__ = "policy_history"
    id = Column(Integer, primary_key=True, autoincrement=True)
    policy_id = Column(Integer, nullable=False, index=True)
    actor_id = Column(String(36), nullable=True)
    operation = Column(String(32), nullable=False)
    before_state = Column(JSON, nullable=True)
    after_state = Column(JSON, nullable=False)
    occurred_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
