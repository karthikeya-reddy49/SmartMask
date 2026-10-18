"""Coherent error model for expected failure cases.

All exceptions carry a human-readable message and avoid leaking internal
secrets or raw customer records.
"""


class AvarnaError(Exception):
    """Base exception for all Avarna errors."""


class ConfigurationError(AvarnaError):
    """Raised when application configuration is invalid or incomplete."""


class DatabaseError(AvarnaError):
    """Raised when a database cannot be reached or is unavailable."""


class UnknownTableError(AvarnaError):
    """Raised when a requested table is not present in the schema."""


class UnknownColumnError(AvarnaError):
    """Raised when a requested column is not present in a table."""


class InvalidLimitError(AvarnaError):
    """Raised when a row limit is invalid or non-positive."""


class InvalidPrincipalError(AvarnaError):
    """Raised when a principal is invalid or missing."""


class UnknownRoleError(AvarnaError):
    """Raised when a role is unknown or unsupported."""


class MissingClassificationError(AvarnaError):
    """Raised when no classification exists for a table/column."""


class MissingPolicyError(AvarnaError):
    """Raised when no applicable policy exists for a request."""


class UnsupportedTransformationError(AvarnaError):
    """Raised when a requested masking action is unsupported."""


class MissingHmacKeyError(AvarnaError):
    """Raised when an HMAC operation requires a secret that is not configured."""


class ScanError(AvarnaError):
    """Raised when a PII scan fails for a table or column."""


class MetadataPersistenceError(AvarnaError):
    """Raised when scan/classification results cannot be persisted."""


class PolicyError(AvarnaError):
    """Raised when policy evaluation or mutation fails."""


class ValidationError(AvarnaError):
    """Raised when user-controlled input fails validation."""
