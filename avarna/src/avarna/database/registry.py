"""Allowlisted, server-configured source database adapters."""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..config import AppConfig
from ..exceptions import UnknownTableError
from .adapter import DatabaseAdapter
from .postgresql_adapter import PostgreSQLAdapter
from .sqlite_adapter import SQLiteAdapter


@dataclass(frozen=True)
class DatabaseTarget:
    database_id: str
    display_name: str
    adapter: DatabaseAdapter


class DatabaseRegistry:
    def __init__(self, config: AppConfig):
        self._targets: dict[str, DatabaseTarget] = {}
        for database_id, url in config.database_registry or (("sqlite_demo", config.source_db_url),):
            if not re.fullmatch(r"[a-z][a-z0-9_-]{1,49}", database_id):
                raise ValueError("Unsafe configured database identifier.")
            if url.startswith("sqlite:"):
                adapter = SQLiteAdapter(url, config.max_sample_rows, config.max_query_limit, read_only=True)
            elif url.startswith("postgresql+psycopg:"):
                adapter = PostgreSQLAdapter(url, schema=config.postgres_schema,
                    max_sample_rows=config.max_sample_rows,
                    max_query_rows=config.max_query_limit,
                    connect_timeout=config.postgres_connect_timeout)
            else:
                raise ValueError("Only configured SQLite and PostgreSQL psycopg URLs are supported.")
            self._targets[database_id] = DatabaseTarget(database_id, database_id, adapter)

    def get(self, database_id: str) -> DatabaseTarget:
        try:
            return self._targets[database_id]
        except KeyError as exc:
            raise KeyError("Unknown configured database identifier.") from exc

    def list_public(self) -> list[dict]:
        return [{"database_id": target.database_id, "display_name": target.display_name,
                 "backend": "PostgreSQL" if isinstance(target.adapter, PostgreSQLAdapter) else "SQLite"}
                for target in self._targets.values()]

    def dispose(self) -> None:
        for target in self._targets.values():
            target.adapter.dispose()
