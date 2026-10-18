"""Public API schemas. ORM and secret-bearing models are never serialized."""
from __future__ import annotations

from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..models import ClassificationTag, ReviewStatus, Role


class SafeModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TokenResponse(SafeModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class IdentityResponse(SafeModel):
    user_id: str
    username: str
    role: Role
    permissions: list[str]
    is_active: bool = True


class ClassificationResponse(SafeModel):
    classification_id: int
    table_name: str
    column_name: str
    classification: ClassificationTag
    machine_classification: Optional[ClassificationTag] = None
    confidence: float
    reasons: list[str]
    scan_run_id: Optional[int]
    review_status: ReviewStatus
    reviewer: Optional[str]
    reviewed_at: Optional[str]


class ReviewRequest(SafeModel):
    review_status: ReviewStatus
    classification: Optional[ClassificationTag] = None

    @model_validator(mode="after")
    def classification_only_when_approved(self):
        if self.classification is not None and self.review_status != ReviewStatus.APPROVED:
            raise ValueError("Only approved reviews may set an effective classification.")
        return self


class PolicyCreate(SafeModel):
    role: Role
    classification: ClassificationTag
    action: str = Field(pattern="^(allow|redact|mask|hmac_sha256)$")
    table_scope: Optional[str] = Field(default=None, pattern="^[A-Za-z_][A-Za-z0-9_]{0,127}$")
    column_scope: Optional[str] = Field(default=None, pattern="^[A-Za-z_][A-Za-z0-9_]{0,127}$")


class PolicyUpdate(SafeModel):
    action: Optional[str] = Field(default=None, pattern="^(allow|redact|mask|hmac_sha256)$")
    enabled: Optional[bool] = None


class UserRoleUpdate(SafeModel):
    role: Role


class UserPermissionUpdate(SafeModel):
    permission: str = Field(min_length=1, max_length=64)


class RecordResponse(SafeModel):
    database_id: str
    table_name: str
    columns: list[str]
    rows: list[dict[str, Any]]
    row_count: int
    offset: int
    limit: int


class ScanRequest(SafeModel):
    sample_size: Optional[int] = Field(default=None, ge=1)
