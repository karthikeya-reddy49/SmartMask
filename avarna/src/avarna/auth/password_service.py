"""Argon2id password hashing with explicit input bounds."""
from pwdlib import PasswordHash


class PasswordService:
    MIN_LENGTH = 12
    MAX_LENGTH = 128
    _hasher = PasswordHash.recommended()

    @classmethod
    def validate(cls, password: str) -> None:
        if not isinstance(password, str) or not cls.MIN_LENGTH <= len(password) <= cls.MAX_LENGTH:
            raise ValueError(f"Password must be between {cls.MIN_LENGTH} and {cls.MAX_LENGTH} characters.")
        if len(password.encode("utf-8")) > 512:
            raise ValueError("Password is too long when encoded.")

    @classmethod
    def hash(cls, password: str) -> str:
        cls.validate(password)
        return cls._hasher.hash(password)

    @classmethod
    def verify(cls, password: str, encoded: str) -> bool:
        if not isinstance(password, str) or len(password) > cls.MAX_LENGTH:
            return False
        try:
            return cls._hasher.verify(password, encoded)
        except Exception:
            return False
