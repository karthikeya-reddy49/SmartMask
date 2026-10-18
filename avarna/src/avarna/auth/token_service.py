"""Short-lived HS256 JWT issuance and validation."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import secrets

import jwt

from ..config import AppConfig


class TokenError(ValueError):
    """JWT is invalid, expired, or misconfigured."""


class TokenService:
    ALGORITHM = "HS256"

    def __init__(self, config: AppConfig):
        if config.jwt_algorithm != self.ALGORITHM:
            raise ValueError("Only HS256 is supported.")
        if len(config.jwt_secret.encode("utf-8")) < 32:
            raise ValueError("AVARNA_JWT_SECRET must contain at least 32 bytes for API use.")
        self.config = config

    def issue(self, user_id: str, token_version: int) -> tuple[str, int]:
        now = datetime.now(timezone.utc)
        lifetime = self.config.jwt_lifetime_minutes * 60
        claims = {
            "sub": user_id, "iss": self.config.jwt_issuer,
            "aud": self.config.jwt_audience, "iat": now,
            "exp": now + timedelta(seconds=lifetime),
            "jti": secrets.token_urlsafe(18), "ver": token_version,
        }
        return jwt.encode(claims, self.config.jwt_secret, algorithm=self.ALGORITHM), lifetime

    def decode(self, token: str) -> dict:
        try:
            return jwt.decode(
                token, self.config.jwt_secret, algorithms=[self.ALGORITHM],
                issuer=self.config.jwt_issuer, audience=self.config.jwt_audience,
                options={"require": ["sub", "iss", "aud", "iat", "exp", "jti", "ver"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenError("expired") from exc
        except jwt.InvalidTokenError as exc:
            raise TokenError("invalid") from exc
