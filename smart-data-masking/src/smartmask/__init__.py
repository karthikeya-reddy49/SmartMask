"""Smart Data Masking System for PII Protection.

Part 1: Core Engine.

This package provides a privacy-conscious data masking foundation for
discovering likely sensitive columns, classifying them, and applying
role-specific transformations whenever records are retrieved through the system.

The original database values are never altered. All sensitive transformations
operate on retrieved result values only.

Security note: this is an in-process developer prototype. It is not yet a
secure multi-user network application. Real authentication, hardened
server-side authorization and PostgreSQL support belong to later phases.
"""

from .config import AppConfig
from .exceptions import SmartMaskError
from .models import Principal

__all__ = ["AppConfig", "SmartMaskError", "Principal"]

__version__ = "1.0.0"
