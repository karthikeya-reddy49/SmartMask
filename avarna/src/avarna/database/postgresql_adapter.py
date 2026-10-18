"""Read-only PostgreSQL adapter using SQLAlchemy 2 and psycopg 3."""
from __future__ import annotations

import re
from typing import Optional

from sqlalchemy import MetaData, Table, create_engine, inspect, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from ..exceptions import DatabaseError, InvalidLimitError, UnknownColumnError, UnknownTableError
from .adapter import DatabaseAdapter


class PostgreSQLAdapter(DatabaseAdapter):
    def __init__(self, db_url: str, *, schema: str = "public",
                 max_sample_rows: int = 50, max_query_rows: int = 100,
                 connect_timeout: int = 5) -> None:
        if not db_url.startswith("postgresql+psycopg://"):
            raise ValueError("PostgreSQL URL must use the psycopg 3 driver.")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", schema):
            raise ValueError("Invalid PostgreSQL schema identifier.")
        self.db_url, self.schema = db_url, schema
        self.max_sample_rows, self.max_query_rows = max_sample_rows, max_query_rows
        self.connect_timeout = connect_timeout
        self._engine: Optional[Engine] = None
        self._metadata = MetaData()

    def _engine_for_use(self) -> Engine:
        if self._engine is None:
            try:
                self._engine = create_engine(
                    self.db_url, pool_pre_ping=True,
                    connect_args={"connect_timeout": self.connect_timeout,
                                  "options": "-c default_transaction_read_only=on"},
                )
            except Exception as exc:
                raise DatabaseError("Could not initialize configured PostgreSQL adapter.") from exc
        return self._engine

    def list_tables(self) -> list[str]:
        try:
            return sorted(inspect(self._engine_for_use()).get_table_names(schema=self.schema))
        except Exception as exc:
            raise DatabaseError("PostgreSQL source database is unavailable.") from exc

    def _table(self, table_name: str) -> Table:
        if table_name not in self.list_tables():
            raise UnknownTableError("Requested table does not exist in the configured schema.")
        return Table(table_name, self._metadata, schema=self.schema,
                     autoload_with=self._engine_for_use())

    def get_columns(self, table_name: str) -> list[dict]:
        try:
            table = self._table(table_name)
            return [{"name": col.name, "type": str(col.type), "nullable": col.nullable,
                     "default": col.default} for col in table.columns]
        except UnknownTableError:
            raise
        except Exception as exc:
            raise DatabaseError("Could not inspect configured PostgreSQL table.") from exc

    def _column(self, table: Table, column_name: str):
        if column_name not in table.c:
            raise UnknownColumnError("Requested column does not exist in the selected table.")
        return table.c[column_name]

    def fetch_column_sample(self, table_name: str, column_name: str, limit: int) -> list:
        if limit <= 0:
            raise InvalidLimitError("Sample limit must be positive.")
        table = self._table(table_name)
        column = self._column(table, column_name)
        with Session(self._engine_for_use()) as session:
            session.execute(text("SET TRANSACTION READ ONLY"))
            return list(session.execute(select(column).where(column.is_not(None)).limit(
                min(limit, self.max_sample_rows))).scalars().all())

    def fetch_records(self, table_name: str, limit: int, offset: int = 0,
                      columns: Optional[list[str]] = None) -> list[dict]:
        if limit <= 0 or offset < 0:
            raise InvalidLimitError("Limit must be positive and offset non-negative.")
        table = self._table(table_name)
        selected = list(table.columns) if columns is None else [
            self._column(table, name) for name in columns
        ]
        if not selected:
            raise InvalidLimitError("At least one column must be selected.")
        with Session(self._engine_for_use()) as session:
            session.execute(text("SET TRANSACTION READ ONLY"))
            rows = session.execute(select(*selected).offset(offset).limit(
                min(limit, self.max_query_rows))).mappings().all()
            return [dict(row) for row in rows]

    def clamp_limit(self, limit: Optional[int], default: int) -> int:
        value = default if limit is None else limit
        if value <= 0:
            raise InvalidLimitError("Limit must be positive.")
        return min(value, self.max_query_rows)

    def dispose(self) -> None:
        if self._engine is not None:
            self._engine.dispose()
            self._engine = None
