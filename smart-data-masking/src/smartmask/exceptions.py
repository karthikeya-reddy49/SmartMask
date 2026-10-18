"""Coherent error model for expected failure cases.

All exceptions carry a human-readable message and avoid leaking internal
secrets or raw customer records.
"""


class SmartMaskError(Exception):
    """Base exception for all Smart Data Masking errors."""


class ConfigurationError(SmartMaskError):
    """Raised when application configuration is invalid or incomplete."""


class DatabaseError(SmartMaskError):
    """Raised when a database cannot be reached or is unavailable."""


class UnknownTableError(SmartMaskError):
    """Raised when a requested table is not present in the schema."""


class UnknownColumnError(SmartMaskError):
    """Raised when a requested column is not present in a table."""


class InvalidLimitError(SmartMaskError):
    """Raised when a row limit is invalid or non-positive."""


class InvalidPrincipalError(SmartMaskError):
    """Raised when a principal is invalid or missing."""


class UnknownRoleError(SmartMaskError):
    """Raised when a role is unknown or unsupported."""


class MissingClassificationError(SmartMaskError):
    """Raised when no classification exists for a table/column."""


class MissingPolicyError(SmartMaskError):
    """Raised when no applicable policy exists for a request."""


class UnsupportedTransformationError(SmartMaskError):
    """Raised when a requested masking action is unsupported."""


class MissingHmacKeyError(SmartMaskError):
    """Raised when an HMAC operation requires a secret that is not configured."""


class ScanError(SmartMaskError):
    """Raised when a PII scan fails for a table or column."""


class MetadataPersistenceError(SmartMaskError):
    """Raised when scan/classification results cannot be persisted."""


class PolicyError(SmartMaskError):
    """Raised when policy evaluation or mutation fails."""


class ValidationError(SmartMaskError):
    """Raised when user-controlled input fails validation."""
