"""Typed domain models.

Defines the Principal identity model and enumeration types used across the
system. These are intentionally free of framework dependencies so they can be
reused by later phases (API layer, dashboard).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional, FrozenSet


class ClassificationTag(Enum):
    """PII classification labels.

    UNKNOWN fields are never treated as safe by default.
    """
    PII_HIGH = "PII_HIGH"
    FINANCIAL_CONFIDENTIAL = "FINANCIAL_CONFIDENTIAL"
    PUBLIC = "PUBLIC"
    UNCLASSIFIED = "UNCLASSIFIED"


class MaskingAction(Enum):
    """Supported masking actions."""

    ALLOW = "allow"
    REDACT = "redact"
    MASK = "mask"
    HMAC_SHA256 = "hmac_sha256"


class ReviewStatus(Enum):
    """Classification review status."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class Role(str, Enum):
    """Supported platform and banking-sector roles.

    Unknown or missing roles are denied / fail closed and are never treated
    as Admin.
    """
    ADMIN = "Admin"
    SUPPORT = "Support"
    ANALYST = "Analyst"
    COMPLIANCE_OFFICER = "Compliance Officer"
    FRAUD_RISK_ANALYST = "Fraud/Risk Analyst"
    BANKING_OPERATIONS = "Banking Operations"
    INTERNAL_AUDITOR = "Internal Auditor"
    DATA_PROTECTION_OFFICER = "Data Protection Officer"


@dataclass(frozen=True)
class Principal:
    """Typed principal / identity model.

    A stable user identifier plus role information. Part 1 does not implement
    real login or token validation; the CLI role selection is a local
    demonstration mechanism, not secure authentication. Production-facing
    business logic depends on an explicitly supplied Principal object.
    """

    user_id: str
    role: Role
    permissions: FrozenSet[str] = frozenset()
    username: Optional[str] = None

    @property
    def is_admin(self) -> bool:
        return self.role == Role.ADMIN

    @property
    def is_support(self) -> bool:
        return self.role == Role.SUPPORT

    @property
    def is_analyst(self) -> bool:
        return self.role == Role.ANALYST
