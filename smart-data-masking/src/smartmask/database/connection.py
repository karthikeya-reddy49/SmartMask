"""Database connection management for source and control databases.

Creates SQLAlchemy engines and sessions. Source and control databases are
logically separate SQLite databases. Initialization is idempotent and does
not overwrite existing user data by default.
"""

from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from ..exceptions import DatabaseError

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manages engines and sessions for source and control databases."""

    def __init__(self, source_db_url: str, control_db_url: str) -> None:
        self.source_db_url = source_db_url
        self.control_db_url = control_db_url
        self._source_engine: Optional[Engine] = None
        self._control_engine: Optional[Engine] = None
        self._source_session_factory: Optional[sessionmaker] = None
        self._control_session_factory: Optional[sessionmaker] = None

    def _mask_url(self, url: str) -> str:
        """Return a logging-safe representation of a database URL.

        Never logs credentials.
        """
        return url.split("://")[-1] if "://" in url else url

    def initialize(self) -> None:
        """Create engines and session factories for both databases.

        Does not create schemas here; schema creation is handled separately
        by the control database initializer and the demo data setup script.
        """
        try:
            self._source_engine = create_engine(self.source_db_url, pool_pre_ping=True)
            self._control_engine = create_engine(self.control_db_url, pool_pre_ping=True)

            # Avoid logging URLs entirely: even a parsed URL may contain
            # private paths, usernames, or backend-specific credentials.
            logger.info("Source database connection initialized.")
            logger.info("Control database connection initialized.")

            self._source_session_factory = sessionmaker(
                bind=self._source_engine, expire_on_commit=False
            )
            self._control_session_factory = sessionmaker(
                bind=self._control_engine, expire_on_commit=False
            )
        except Exception as exc:  # pragma: no cover - defensive
            raise DatabaseError("Failed to initialize database connections; check configured database URLs.") from exc

    @property
    def source_engine(self) -> Engine:
        if self._source_engine is None:
            raise DatabaseError("Source database not initialized. Call initialize() first.")
        return self._source_engine

    @property
    def control_engine(self) -> Engine:
        if self._control_engine is None:
            raise DatabaseError("Control database not initialized. Call initialize() first.")
        return self._control_engine

    def source_session(self) -> Session:
        if self._source_session_factory is None:
            raise DatabaseError("Source database not initialized. Call initialize() first.")
        return self._source_session_factory()

    def control_session(self) -> Session:
        if self._control_session_factory is None:
            raise DatabaseError("Control database not initialized. Call initialize() first.")
        return self._control_session_factory()

    def dispose(self) -> None:
        """Dispose of engine resources safely."""
        if self._source_engine is not None:
            self._source_engine.dispose()
        if self._control_engine is not None:
            self._control_engine.dispose()
