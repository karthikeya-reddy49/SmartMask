"""Persistence operations for API identities and explicit permission grants."""
from __future__ import annotations

import re
import uuid
from typing import Optional

from sqlalchemy import select

from ..database.connection import DatabaseManager
from ..database.models import PermissionGrant, User, utc_now
from ..models import Role
from .permissions import PERMISSIONS

_USERNAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{2,63}$")


class UserRepository:
    def __init__(self, manager: DatabaseManager):
        self.manager = manager

    @staticmethod
    def normalize(username: str) -> str:
        if not isinstance(username, str) or not _USERNAME.fullmatch(username):
            raise ValueError("Username must be 3-64 letters, numbers, dots, underscores, or hyphens.")
        return username.lower()

    def create(self, username: str, password_hash: str, role: Role) -> User:
        session = self.manager.control_session()
        normalized = self.normalize(username)
        try:
            if session.scalar(select(User).where(User.username == normalized)):
                raise ValueError("Username already exists.")
            user = User(id=str(uuid.uuid4()), username=normalized,
                        password_hash=password_hash, role=role)
            session.add(user)
            session.commit()
            session.refresh(user)
            return user
        finally:
            session.close()

    def get_by_username(self, username: str) -> Optional[User]:
        normalized = self.normalize(username)
        with self.manager.control_session() as session:
            user = session.scalar(select(User).where(User.username == normalized))
            if user is None:
                return None
            # Detached scalar snapshot avoids returning a live ORM identity.
            session.expunge(user)
            return user

    def get_by_id(self, user_id: str) -> Optional[User]:
        with self.manager.control_session() as session:
            user = session.get(User, user_id)
            if user is None:
                return None
            session.expunge(user)
            return user

    def permissions(self, user_id: str) -> frozenset[str]:
        with self.manager.control_session() as session:
            return frozenset(session.scalars(select(PermissionGrant.permission).where(
                PermissionGrant.user_id == user_id)).all())

    def list_users(self) -> list[dict]:
        with self.manager.control_session() as session:
            users = session.scalars(select(User).order_by(User.username)).all()
            grants = session.execute(select(PermissionGrant.user_id,
                                             PermissionGrant.permission)).all()
            permissions: dict[str, list[str]] = {}
            for user_id, permission in grants:
                permissions.setdefault(user_id, []).append(permission)
            return [{"id": u.id, "username": u.username, "role": u.role.value,
                     "is_active": u.is_active, "created_at": u.created_at.isoformat() if u.created_at else None,
                     "permissions": sorted(permissions.get(u.id, []))} for u in users]

    def grant(self, username: str, permission: str, granted_by: Optional[str] = None) -> bool:
        if permission not in PERMISSIONS:
            raise ValueError("Unsupported permission.")
        user = self.get_by_username(username)
        if user is None:
            raise ValueError("User not found.")
        with self.manager.control_session() as session:
            grant = session.get(PermissionGrant, (user.id, permission))
            if grant:
                return False
            session.add(PermissionGrant(user_id=user.id, permission=permission, granted_by=granted_by))
            session.commit()
            return True

    def revoke(self, username: str, permission: str) -> bool:
        if permission not in PERMISSIONS:
            raise ValueError("Unsupported permission.")
        user = self.get_by_username(username)
        if user is None:
            raise ValueError("User not found.")
        with self.manager.control_session() as session:
            grant = session.get(PermissionGrant, (user.id, permission))
            if not grant:
                return False
            session.delete(grant)
            session.commit()
            return True

    def update(self, username: str, *, active: Optional[bool] = None,
               role: Optional[Role] = None, password_hash: Optional[str] = None,
               revoke_tokens: bool = False) -> User:
        user = self.get_by_username(username)
        if user is None:
            raise ValueError("User not found.")
        with self.manager.control_session() as session:
            row = session.get(User, user.id)
            if active is not None:
                row.is_active = active
            if role is not None:
                row.role = role
            if password_hash is not None:
                row.password_hash = password_hash
            if revoke_tokens:
                row.token_version += 1
            row.failed_login_count = 0
            row.locked_until = None
            row.updated_at = utc_now()
            session.commit()
            session.refresh(row)
            session.expunge(row)
            return row

    def record_login_failure(self, user_id: Optional[str], maximum: int = 5) -> None:
        if not user_id:
            return
        with self.manager.control_session() as session:
            row = session.get(User, user_id)
            if row:
                row.failed_login_count += 1
                if row.failed_login_count >= maximum:
                    from datetime import timedelta
                    row.locked_until = utc_now() + timedelta(minutes=15)
                session.commit()

    def record_login_success(self, user_id: str) -> None:
        with self.manager.control_session() as session:
            row = session.get(User, user_id)
            if row:
                row.failed_login_count = 0
                row.locked_until = None
                row.last_login_at = utc_now()
                session.commit()
