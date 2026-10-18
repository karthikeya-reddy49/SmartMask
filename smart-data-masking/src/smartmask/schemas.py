"""Structured input/output data types.

Typed dataclasses used across scanner, policy engine, transformations and the
query service so that the system does not pass around unexplained raw strings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from .models import ClassificationTag, MaskingAction, ReviewStatus


@dataclass(frozen=True)
class ColumnClassification:
    """A single column classification result."""

    table_name: str
    column_name: str
    classification: ClassificationTag
    confidence: float
    reasons: list[str] = field(default_factory=list)
    scan_run_id: Optional[int] = None
    scanned_at: Optional[datetime] = None
    review_status: ReviewStatus = ReviewStatus.PENDING
    reviewer: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    classification_id: Optional[int] = None
    machine_classification: Optional[ClassificationTag] = None

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")


@dataclass(frozen=True)
class ScanReport:
    """Structured report of a database scan."""

    scan_run_id: int
    tables_scanned: int
    columns_classified: int
    classifications: list[ColumnClassification]
    errors: list[str] = field(default_factory=list)
    failed: bool = False

    @property
    def success(self) -> bool:
        return not self.failed and not self.errors


@dataclass(frozen=True)
class PolicyDecision:
    """Structured policy evaluation decision."""

    principal_user_id: str
    principal_role: str
    table_name: str
    column_name: str
    classification: ClassificationTag
    action: MaskingAction
    allowed: bool
    matched_rule: Optional[str] = None
    reason: str = ""
    policy_version: Optional[str] = None

    @property
    def deny(self) -> bool:
        return not self.allowed


@dataclass(frozen=True)
class QueryRequest:
    """Controlled query request."""

    table_name: str
    limit: Optional[int] = None
    offset: int = 0

    def __post_init__(self) -> None:
        if self.offset < 0:
            raise ValueError("offset must be non-negative")


@dataclass(frozen=True)
class QueryResult:
    """Controlled query response containing transformed records."""

    table_name: str
    columns: list[str]
    rows: list[dict]
    row_count: int
    principal_user_id: str
    principal_role: str
    decisions_applied: int = 0


@dataclass(frozen=True)
class AccessEvent:
    """A privacy-conscious audit access event."""

    event_id: Optional[int] = None
    principal_user_id: Optional[str] = None
    principal_role: Optional[str] = None
    operation: str = ""
    table_name: Optional[str] = None
    outcome: str = ""
    reason: str = ""
    policy_reference: Optional[str] = None
    scan_reference: Optional[str] = None
    occurred_at: Optional[str] = None
