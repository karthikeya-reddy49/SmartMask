"""Authentication use cases with generic login failures and lockout."""
from __future__ import annotations

from datetime import datetime, timezone
import secrets

from ..audit.repository import AuditRepository
from ..database.models import User
from ..models import Principal
from .password_service import PasswordService
from .token_service import TokenService
from .user_repository import UserRepository


class AuthenticationFailed(Exception):
    pass


class AuthService:
    def __init__(self, users: UserRepository, tokens: TokenService, audit: AuditRepository):
        self.users, self.tokens, self.audit = users, tokens, audit
        self._dummy_hash = PasswordService.hash(secrets.token_urlsafe(24))

    def authenticate(self, username: str, password: str, *,
                    request_id: str | None = None) -> tuple[str, int, User]:
        user = None
        try:
            user = self.users.get_by_username(username)
        except ValueError:
            pass
        encoded = user.password_hash if user else self._dummy_hash
        verified = PasswordService.verify(password, encoded)
        now = datetime.now(timezone.utc)
        locked = bool(user and user.locked_until and user.locked_until.replace(tzinfo=timezone.utc) > now)
        if not user or not verified or not user.is_active or locked:
            self.users.record_login_failure(user.id if user else None)
            self.audit.record_event(
                principal_user_id=user.id if user else None,
                operation="login", outcome="denied", reason="INVALID_CREDENTIALS",
                actor_id=user.id if user else None, request_id=request_id,
            )
            raise AuthenticationFailed("Invalid username or password.")
        self.users.record_login_success(user.id)
        token, expires = self.tokens.issue(user.id, user.token_version)
        self.audit.record_event(principal_user_id=user.id, principal_role=user.role.value,
            operation="login", outcome="allowed", reason="LOGIN_SUCCEEDED", actor_id=user.id,
            request_id=request_id)
        return token, expires, user

    def current_principal(self, token: str) -> Principal:
        claims = self.tokens.decode(token)
        user = self.users.get_by_id(claims["sub"])
        if user is None or not user.is_active or user.token_version != claims["ver"]:
            raise AuthenticationFailed("Invalid access token.")
        return Principal(user_id=user.id, username=user.username, role=user.role,
                         permissions=self.users.permissions(user.id))

    def logout(self, principal: Principal, *, request_id: str | None = None) -> None:
        self.users.update(principal.username or "", revoke_tokens=True)
        self.audit.record_event(principal_user_id=principal.user_id,
            principal_role=principal.role.value, operation="logout", outcome="allowed",
            reason="USER_TOKENS_REVOKED", actor_id=principal.user_id,
            request_id=request_id)
