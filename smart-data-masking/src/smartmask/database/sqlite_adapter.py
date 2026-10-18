"""SQLite database adapter using SQLAlchemy 2.x.

Reflects schema at runtime and validates table/column identifiers against
the reflected metadata. Supports bounded sampling and bounded record
retrieval. Never exposes arbitrary SQL execution.
"""

from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy import (
    Column,
    Integer,
    MetaData,
    Table,
    create_engine,
    inspect,
    select,
    text,
    URL,
    make_url,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from .adapter import DatabaseAdapter
from ..exceptions import (
    DatabaseError,
    InvalidLimitError,
    UnknownColumnError,
    UnknownTableError,
)

logger = logging.getLogger(__name__)


class SQLiteAdapter(DatabaseAdapter):
    """SQLite implementation of the database adapter interface.

    Uses SQLAlchemy reflection and bound parameters. Table and column names
    are validated against reflected metadata before any query is built.
    """

    def __init__(self, db_url: str, max_sample_rows: int = 50,
                 max_query_rows: int = 100, read_only: bool = True) -> None:
        self.db_url = db_url
        self.max_sample_rows = max_sample_rows
        self.max_query_rows = max_query_rows
        self.read_only = read_only
        self._engine: Optional[Engine] = None
        self._metadata = MetaData()

    def _ensure_engine(self) -> Engine:
        if self._engine is None:
            try:
                url = make_url(self.db_url)
                if self.read_only and url.database not in (None, ":memory:"):
                    query = dict(url.query)
                    query.update({"mode": "ro", "uri": "true"})
                    # SQLAlchemy's SQLite URI mode requires a ``file:`` path.
                    database = url.database
                    if not database.startswith("file:"):
                        database = f"file:{database}"
                    url = url.set(database=database, query=query)
                self._engine = create_engine(url, pool_pre_ping=True)
                logger.debug("SQLite source engine created.")
            except Exception as exc:  # pragma: no cover - defensive
                raise DatabaseError(
                    "Cannot initialize source database connection; verify the configured SQLite URL and file permissions."
                ) from exc
        return self._engine

    def _validate_table(self, session: Session, table_name: str) -> Table:
        """Validate a table name against reflected metadata.

        Raises UnknownTableError if the table does not exist.
        """
        inspector = inspect(self._ensure_engine())
        table_names = inspector.get_table_names()
        if table_name not in table_names:
            raise UnknownTableError(
                f"Table '{table_name}' does not exist in the source database."
            )
        # Reflect only the requested table to avoid loading system tables.
        table = Table(table_name, self._metadata, autoload_with=self._ensure_engine())
        return table

    def list_tables(self) -> list[str]:
        """Return the names of eligible user tables.

        Excludes SQLite system tables (names starting with 'sqlite_').
        """
        engine = self._ensure_engine()
        inspector = inspect(engine)
        all_tables = inspector.get_table_names()
        return [t for t in all_tables if not t.startswith("sqlite_")]

    def get_columns(self, table_name: str) -> list[dict]:
        """Return column metadata for a table.

        Each dict has keys: name, type, nullable, default.
        """
        engine = self._ensure_engine()
        inspector = inspect(engine)
        table_names = inspector.get_table_names()
        if table_name not in table_names:
            raise UnknownTableError(
                f"Table '{table_name}' does not exist in the source database."
            )
        columns = inspector.get_columns(table_name)
        return [
            {
                "name": col["name"],
                "type": str(col["type"]),
                "nullable": bool(col.get("nullable", True)),
                "default": col.get("default"),
            }
            for col in columns
        ]

    def _validate_column(self, table: Table, column_name: str) -> Column:
        if column_name not in table.c:
            raise UnknownColumnError(
                f"Column '{column_name}' does not exist in table '{table.name}'."
            )
        return table.c[column_name]

    def fetch_column_sample(
        self, table_name: str, column_name: str, limit: int
    ) -> list:
        """Fetch a bounded sample of values from a column.

        Returns a list of Python values (may include None). Values are not
        logged. The limit is clamped to max_sample_rows.
        """
        if limit <= 0:
            raise InvalidLimitError("Sample limit must be a positive integer.")
        clamped = min(limit, self.max_sample_rows)

        with Session(self._ensure_engine()) as session:
            table = self._validate_table(session, table_name)
            column = self._validate_column(table, column_name)
            stmt = select(column).where(column.is_not(None)).limit(clamped)
            rows = session.execute(stmt).scalars().all()
            return list(rows)

    def fetch_records(
        self, table_name: str, limit: int, offset: int = 0,
        columns: Optional[list[str]] = None,
    ) -> list[dict]:
        """Fetch a bounded set of records for an allowlisted table.

        Each record is a dict mapping column name to value. Identifiers are
        validated against reflected metadata.
        """
        if limit <= 0:
            raise InvalidLimitError("Record limit must be a positive integer.")
        if offset < 0:
            raise InvalidLimitError("Offset must be non-negative.")
        bounded_limit = min(limit, self.max_query_rows)

        with Session(self._ensure_engine()) as session:
            table = self._validate_table(session, table_name)
            selected = list(table.c) if columns is None else [
                self._validate_column(table, name) for name in columns
            ]
            if not selected:
                raise InvalidLimitError("At least one column must be selected.")
            stmt = select(*selected).offset(offset).limit(bounded_limit)
            rows = session.execute(stmt).mappings().all()
            return [dict(row) for row in rows]

    def clamp_limit(self, limit: Optional[int], default: int) -> int:
        """Clamp a requested limit to the configured safe maximum.

        Rejects invalid or non-positive limits.
        """
        if limit is None:
            return max(1, min(default, self.max_query_rows))
        if limit <= 0:
            raise InvalidLimitError("Limit must be a positive integer.")
        return max(1, min(limit, self.max_query_rows))

    def dispose(self) -> None:
        """Release engine resources safely."""
        if self._engine is not None:
            self._engine.dispose()
            self._engine = None
