"""Thin HTTP routes; all data access flows through existing services."""
from __future__ import annotations

import time
from fastapi import APIRouter, Depends, Query, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import text
from ..auth.auth_service import AuthenticationFailed
from ..auth.user_repository import UserRepository
from ..auth.permissions import PERMISSIONS
from ..database.models import ScanRun
from ..exceptions import InvalidLimitError, UnknownColumnError, UnknownTableError
from ..masking.engine import MaskingEngine
from ..masking.policy_repository import PolicyRepository
from ..models import Principal
from ..scanner.metadata_repository import MetadataRepository
from ..scanner.scanner import Scanner
from ..service.query_service import QueryService
from ..audit.repository import AuditRepository
from .dependencies import error, get_current_principal, get_auth_service, require_permission
from .schemas import (ClassificationResponse, IdentityResponse, PolicyCreate, PolicyUpdate,
                     RecordResponse, ReviewRequest, ScanRequest, TokenResponse,
                     UserPermissionUpdate, UserRoleUpdate)

router = APIRouter()


def _target(request: Request, database_id: str):
    try:
        return request.app.state.registry.get(database_id)
    except KeyError as exc:
        raise error(404, "UNKNOWN_DATABASE", "Configured database was not found.") from exc


def _check_database_access(request: Request, principal: Principal, database_id: str) -> None:
    if "database:select" not in principal.permissions:
        _audit(request, principal, "database_selection", "denied",
               "INSUFFICIENT_PERMISSION", database_id)
        raise error(403, "INSUFFICIENT_PERMISSION", "This operation is not permitted.")


def _audit(request: Request, actor: Principal | None, operation: str, outcome: str,
           reason: str, database_id: str | None = None, table: str | None = None,
           policy_ref: str | None = None, scan_ref: str | None = None) -> None:
    AuditRepository(request.app.state.manager).record_event(
        principal_user_id=actor.user_id if actor else None,
        principal_role=actor.role.value if actor else None,
        operation=operation, outcome=outcome, reason=reason,
        actor_id=actor.user_id if actor else None, database_id=database_id,
        table_name=table, policy_reference=policy_ref, scan_reference=scan_ref,
        request_id=getattr(request.state, "request_id", None),
    )


@router.get("/health")
def health():
    return {"status": "ok"}


@router.get("/ready")
def readiness(request: Request):
    """Check that the API control store can serve authenticated operations."""
    try:
        with request.app.state.manager.control_engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception as exc:
        raise error(503, "CONTROL_STORE_UNAVAILABLE",
                    "The service is not ready to handle requests.") from exc
    return {"status": "ready"}


@router.post("/auth/token", response_model=TokenResponse)
def issue_token(request: Request, form: OAuth2PasswordRequestForm = Depends(), auth=Depends(get_auth_service)):
    now = time.monotonic()
    key = request.client.host if request.client else "unknown"
    with request.app.state.login_lock:
        buckets = request.app.state.login_attempts
        if key not in buckets and len(buckets) >= 2048:
            expired = [ip for ip, values in buckets.items()
                       if not values or now - values[-1] >= 60]
            for ip in expired:
                buckets.pop(ip, None)
            if len(buckets) >= 2048:
                buckets.pop(next(iter(buckets)))
        attempts = buckets.setdefault(key, [])
        attempts[:] = [when for when in attempts if now - when < 60]
        if len(attempts) >= 10:
            raise error(429, "RATE_LIMITED", "Too many login attempts. Try again shortly.")
        attempts.append(now)
    try:
        token, expires, _user = auth.authenticate(
            form.username, form.password,
            request_id=getattr(request.state, "request_id", None))
    except AuthenticationFailed as exc:
        raise error(401, "INVALID_CREDENTIALS", "Invalid username or password.") from exc
    return TokenResponse(access_token=token, expires_in=expires)


@router.get("/auth/me", response_model=IdentityResponse)
def me(principal: Principal = Depends(get_current_principal)):
    return IdentityResponse(user_id=principal.user_id, username=principal.username or "",
        role=principal.role, permissions=sorted(principal.permissions), is_active=True)


@router.get("/permissions")
def list_permissions(principal: Principal = Depends(require_permission("users:manage"))):
    return {"items": sorted(PERMISSIONS)}


@router.get("/users")
def list_users(request: Request,
               principal: Principal = Depends(require_permission("users:manage"))):
    return {"items": UserRepository(request.app.state.manager).list_users()}


def _managed_user(request: Request, user_id: str, principal: Principal):
    if user_id == principal.user_id:
        raise error(400, "SELF_ADMINISTRATION_BLOCKED",
                    "Administrators cannot change their own role or permissions.")
    user = UserRepository(request.app.state.manager).get_by_id(user_id)
    if user is None:
        raise error(404, "USER_NOT_FOUND", "User was not found.")
    return user


@router.patch("/users/{user_id}/role")
def change_user_role(user_id: str, body: UserRoleUpdate, request: Request,
                     principal: Principal = Depends(require_permission("users:manage"))):
    user = _managed_user(request, user_id, principal)
    updated = UserRepository(request.app.state.manager).update(
        user.username, role=body.role, revoke_tokens=True)
    _audit(request, principal, "user_role_changed", "allowed",
           f"USER_ROLE_CHANGED:{updated.id}")
    return {"user_id": updated.id, "username": updated.username,
            "role": updated.role.value, "tokens_revoked": True}


@router.put("/users/{user_id}/permissions")
def grant_user_permission(user_id: str, body: UserPermissionUpdate, request: Request,
                          principal: Principal = Depends(require_permission("users:manage"))):
    user = _managed_user(request, user_id, principal)
    try:
        changed = UserRepository(request.app.state.manager).grant(
            user.username, body.permission, granted_by=principal.user_id)
    except ValueError as exc:
        raise error(400, "INVALID_PERMISSION", "Permission is not supported.") from exc
    _audit(request, principal, "permission_granted", "allowed",
           f"PERMISSION_GRANTED:{user.id}:{body.permission}")
    return {"user_id": user.id, "permission": body.permission, "changed": changed}


@router.delete("/users/{user_id}/permissions")
def revoke_user_permission(user_id: str, body: UserPermissionUpdate, request: Request,
                           principal: Principal = Depends(require_permission("users:manage"))):
    user = _managed_user(request, user_id, principal)
    try:
        changed = UserRepository(request.app.state.manager).revoke(
            user.username, body.permission)
    except ValueError as exc:
        raise error(400, "INVALID_PERMISSION", "Permission is not supported.") from exc
    _audit(request, principal, "permission_revoked", "allowed",
           f"PERMISSION_REVOKED:{user.id}:{body.permission}")
    return {"user_id": user.id, "permission": body.permission, "changed": changed}


@router.post("/auth/logout", status_code=204)
def logout(request: Request, principal: Principal = Depends(get_current_principal),
           auth=Depends(get_auth_service)):
    auth.logout(principal, request_id=getattr(request.state, "request_id", None))


@router.get("/databases")
def list_databases(request: Request,
                   principal: Principal = Depends(require_permission("database:select"))):
    result = request.app.state.registry.list_public()
    _audit(request, principal, "database_registry_read", "allowed", "DATABASE_LISTED")
    return {"items": result}


@router.get("/databases/{database_id}/tables")
def list_tables(database_id: str, request: Request,
                principal: Principal = Depends(require_permission("database:select"))):
    target = _target(request, database_id)
    _check_database_access(request, principal, database_id)
    try:
        tables = target.adapter.list_tables()
    except Exception as exc:
        _audit(request, principal, "table_discovery", "error", "DATABASE_UNAVAILABLE", database_id)
        raise error(503, "DATABASE_UNAVAILABLE", "Configured database is unavailable.") from exc
    _audit(request, principal, "table_discovery", "allowed", "TABLES_LISTED", database_id)
    return {"database_id": database_id, "tables": tables}


@router.post("/databases/{database_id}/scans", status_code=201)
def run_scan(database_id: str, body: ScanRequest, request: Request,
             principal: Principal = Depends(require_permission("scan:run"))):
    target = _target(request, database_id)
    _check_database_access(request, principal, database_id)
    config = request.app.state.config
    sample_size = min(body.sample_size or config.max_sample_rows, config.max_sample_rows)
    repo = MetadataRepository(request.app.state.manager)
    try:
        report = Scanner(target.adapter, repo, sample_size=sample_size,
                         database_id=database_id).scan_database(sample_size=sample_size)
    except Exception as exc:
        _audit(request, principal, "scan", "error", "SCAN_FAILED", database_id)
        raise error(503, "SCAN_FAILED", "The configured database scan failed safely.") from exc
    _audit(request, principal, "scan", "allowed" if not report.failed else "error",
           "SCAN_COMPLETED" if not report.failed else "SCAN_FAILED", database_id,
           scan_ref=str(report.scan_run_id))
    return {"scan_id": report.scan_run_id,
            "status": "failed" if report.failed else "completed",
            "tables_scanned": report.tables_scanned,
            "columns_classified": report.columns_classified,
            "errors": (["One or more eligible tables or columns could not be scanned."]
                       if report.errors else []),
            "classifications": [ClassificationResponse(
                classification_id=c.classification_id or 0, table_name=c.table_name,
                column_name=c.column_name, classification=c.classification,
                machine_classification=c.machine_classification or c.classification,
                confidence=c.confidence, reasons=c.reasons, scan_run_id=c.scan_run_id,
                review_status=c.review_status, reviewer=c.reviewer,
                reviewed_at=c.reviewed_at.isoformat() if c.reviewed_at else None
            ) for c in report.classifications]}


@router.get("/scans/{scan_id}")
def get_scan(scan_id: int, request: Request,
             principal: Principal = Depends(require_permission("scan:read"))):
    with request.app.state.manager.control_session() as session:
        run = session.get(ScanRun, scan_id)
        if run is None:
            raise error(404, "SCAN_NOT_FOUND", "Scan was not found.")
        return {"scan_id": run.id, "database_id": run.database_id, "status": run.status,
                "tables_scanned": run.tables_scanned, "columns_classified": run.columns_classified,
                "started_at": run.started_at.isoformat() if run.started_at else None,
                "completed_at": run.completed_at.isoformat() if run.completed_at else None}


@router.get("/databases/{database_id}/classifications")
def list_classifications(database_id: str, request: Request,
                         limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
                         principal: Principal = Depends(require_permission("scan:read"))):
    _target(request, database_id)
    _check_database_access(request, principal, database_id)
    rows = MetadataRepository(request.app.state.manager).list_classifications(database_id)
    page = rows[offset:offset + limit]
    items = [ClassificationResponse(
        classification_id=c.classification_id or 0, table_name=c.table_name,
        column_name=c.column_name, classification=c.classification, confidence=c.confidence,
        machine_classification=c.machine_classification or c.classification,
        reasons=c.reasons, scan_run_id=c.scan_run_id, review_status=c.review_status,
        reviewer=c.reviewer, reviewed_at=c.reviewed_at.isoformat() if c.reviewed_at else None
    ) for c in page]
    return {"database_id": database_id, "items": items,
            "total": len(rows), "limit": limit, "offset": offset}


@router.patch("/classifications/{classification_id}/review")
def review_classification(classification_id: int, body: ReviewRequest, request: Request,
                          principal: Principal = Depends(require_permission("scan:review"))):
    repo = MetadataRepository(request.app.state.manager)
    try:
        repo.update_review_status(classification_id, review_status=body.review_status,
            reviewer=principal.username, classification=body.classification)
    except Exception as exc:
        raise error(404, "CLASSIFICATION_NOT_FOUND", "Classification review could not be saved.") from exc
    _audit(request, principal, "classification_review", "allowed", "CLASSIFICATION_REVIEWED",
           scan_ref=str(classification_id))
    return {"classification_id": classification_id, "review_status": body.review_status,
            "effective_classification": body.classification}


@router.get("/databases/{database_id}/tables/{table_name}/records", response_model=RecordResponse)
def records(database_id: str, table_name: str, request: Request,
            limit: int = Query(20, ge=1, le=10000),
            offset: int = Query(0, ge=0, le=1000000),
            columns: list[str] | None = Query(default=None, max_length=100),
            principal: Principal = Depends(require_permission("data:read"))):
    target = _target(request, database_id)
    _check_database_access(request, principal, database_id)
    manager, config = request.app.state.manager, request.app.state.config
    service = QueryService(target.adapter, manager, PolicyRepository(manager),
        AuditRepository(manager), MaskingEngine(config), config, database_id=database_id,
        request_id=getattr(request.state, "request_id", None))
    try:
        result = service.query_records(principal, table_name, limit=limit,
                                       offset=offset, columns=columns)
    except UnknownTableError as exc:
        raise error(404, "UNKNOWN_TABLE", "Table was not found in the configured database.") from exc
    except InvalidLimitError as exc:
        raise error(400, "REQUEST_LIMIT_EXCEEDED", "Query limits are invalid.") from exc
    except UnknownColumnError as exc:
        raise error(400, "INVALID_COLUMNS", "One or more requested columns are unavailable.") from exc
    except Exception as exc:
        raise error(503, "POLICY_UNAVAILABLE", "Protected query could not be completed safely.") from exc
    return RecordResponse(database_id=database_id, table_name=result.table_name,
        columns=result.columns, rows=result.rows, row_count=result.row_count,
        offset=offset, limit=min(limit, config.max_query_limit))


@router.get("/databases/{database_id}/tables/{table_name}/columns")
def list_table_columns(database_id: str, table_name: str, request: Request,
                       principal: Principal = Depends(require_permission("database:select"))):
    target = _target(request, database_id)
    try:
        columns = target.adapter.get_columns(table_name)
    except UnknownTableError as exc:
        raise error(404, "UNKNOWN_TABLE", "Table was not found in the configured database.") from exc
    except Exception as exc:
        raise error(503, "DATABASE_UNAVAILABLE", "Column discovery failed safely.") from exc
    _audit(request, principal, "column_discovery", "allowed", "COLUMNS_LISTED",
           database_id, table_name)
    return {"database_id": database_id, "table_name": table_name,
            "columns": [{"name": c["name"], "type": c["type"],
                         "nullable": c["nullable"]} for c in columns]}


@router.get("/policies")
def list_policies(request: Request,
                  principal: Principal = Depends(require_permission("policy:read"))):
    return {"items": PolicyRepository(request.app.state.manager).list_policies()}


@router.post("/policies", status_code=201)
def create_policy(body: PolicyCreate, request: Request,
                  principal: Principal = Depends(require_permission("policy:write"))):
    repo = PolicyRepository(request.app.state.manager)
    try:
        policy = repo.create_policy(role=body.role, classification=body.classification,
            action=body.action, table_scope=body.table_scope,
            column_scope=body.column_scope, actor_id=principal.user_id)
    except Exception as exc:
        raise error(400, "INVALID_POLICY", "Policy is invalid or its scope already exists.") from exc
    _audit(request, principal, "policy_created", "allowed", "POLICY_CREATED", policy_ref=str(policy.id))
    return repo._safe_policy(policy)


@router.patch("/policies/{policy_id}")
def update_policy(policy_id: int, body: PolicyUpdate, request: Request,
                  principal: Principal = Depends(require_permission("policy:write"))):
    if body.action is None and body.enabled is None:
        raise error(422, "INVALID_POLICY", "At least one policy field must be provided.")
    repo = PolicyRepository(request.app.state.manager)
    try:
        policy = repo.update_policy(policy_id, action=body.action, enabled=body.enabled,
                                    actor_id=principal.user_id)
    except Exception as exc:
        raise error(404, "POLICY_NOT_FOUND", "Policy update could not be completed.") from exc
    _audit(request, principal, "policy_updated", "allowed", "POLICY_UPDATED", policy_ref=str(policy.id))
    return repo._safe_policy(policy)


@router.get("/audit-events")
def list_audit_events(request: Request,
                      limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
                      principal: Principal = Depends(require_permission("audit:read"))):
    return {"items": AuditRepository(request.app.state.manager).list_events(limit, offset),
            "limit": limit, "offset": offset}
