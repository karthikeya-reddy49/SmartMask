"""Shared authentication and permission dependencies."""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer

from ..auth.auth_service import AuthService, AuthenticationFailed
from ..models import Principal
from ..auth.token_service import TokenError
from ..audit.repository import AuditRepository
import logging

logger = logging.getLogger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token", auto_error=False)


def error(status: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status, detail={"code": code, "message": message})


def get_auth_service(request: Request) -> AuthService:
    service = getattr(request.app.state, "auth_service", None)
    if service is None:
        raise error(503, "AUTH_UNAVAILABLE", "Authentication service is unavailable.")
    return service


def get_current_principal(token: str | None = Depends(oauth2_scheme),
                          auth: AuthService = Depends(get_auth_service)) -> Principal:
    if not token:
        raise error(401, "INVALID_TOKEN", "Bearer authentication is required.")
    try:
        return auth.current_principal(token)
    except TokenError as exc:
        code = "TOKEN_EXPIRED" if str(exc) == "expired" else "INVALID_TOKEN"
        raise error(401, code, "Access token is invalid or expired.") from exc
    except AuthenticationFailed as exc:
        raise error(401, "INVALID_TOKEN", "Access token is invalid or expired.") from exc


def require_permission(permission: str):
    def dependency(request: Request, principal: Principal = Depends(get_current_principal)) -> Principal:
        if permission not in principal.permissions:
            try:
                AuditRepository(request.app.state.manager).record_event(
                    principal_user_id=principal.user_id,
                    principal_role=principal.role.value,
                    operation="authorization_denied", outcome="denied",
                    reason="INSUFFICIENT_PERMISSION", actor_id=principal.user_id,
                    request_id=getattr(request.state, "request_id", None),
                )
            except Exception as exc:
                logger.error("Could not persist an authorization-denial audit event.")
                raise error(503, "AUDIT_UNAVAILABLE",
                            "The request cannot be completed safely.") from exc
            raise error(403, "INSUFFICIENT_PERMISSION", "This operation is not permitted.")
        return principal
    return dependency
