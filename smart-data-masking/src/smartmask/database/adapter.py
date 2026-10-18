"""Reusable database adapter interface.

The interface defines the operations the scanner and query service need. It
is deliberately small and implementation-agnostic so a PostgreSQL adapter can
be added in Part 2 without changing the scanner or masking engine.
"""

from __future__ import annotations

from typing import Optional

from ..exceptions import InvalidLimitError


class DatabaseAdapter:
    """Abstract interface for database access.

    Implementations must validate identifiers against reflected metadata and
    must not expose arbitrary raw SQL execution.
    """

    def list_tables(self) -> list[str]:
        """Return the names of eligible user tables."""
        raise NotImplementedError

    def get_columns(self, table_name: str) -> list[dict]:
        """Return column metadata for a table.

        Each dict describes a reflected column with keys such as name, type,
        nullable, and default.
        """
        raise NotImplementedError

    def fetch_column_sample(
        self, table_name: str, column_name: str, limit: int
    ) -> list:
        """Fetch a bounded sample of values from a column.

        Returns a list of Python values (may include None). Never logs values.
        """
        raise NotImplementedError

    def fetch_records(
        self, table_name: str, limit: int, offset: int = 0,
        columns: Optional[list[str]] = None,
    ) -> list[dict]:
        """Fetch a bounded set of records for an allowlisted table.

        Each record is a dict mapping column name to value.
        """
        raise NotImplementedError

    def clamp_limit(self, limit: Optional[int], default: int) -> int:
        """Clamp a requested limit to the configured safe maximum.

        Rejects invalid or non-positive limits.
        """
        raise NotImplementedError

    def dispose(self) -> None:
        """Release resources safely."""
        raise NotImplementedError
