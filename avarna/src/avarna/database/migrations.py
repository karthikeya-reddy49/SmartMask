"""Small additive, idempotent control-schema upgrades for the prototype.

Part 1 did not use a migration runner. This upgrader preserves those tables
and rows, creates newly introduced tables, and adds nullable/defaulted columns
in place. It intentionally has no destructive downgrade path.
"""
from __future__ import annotations

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine

from ..models import Role
from .models import Base, ColumnClassification


def upgrade_control_schema(engine: Engine) -> None:
    """Upgrade Part 1 control stores without dropping or recreating data."""
    Base.metadata.create_all(engine)
    inspector = inspect(engine)
    dialect = engine.dialect.name
    additions = {
        "scan_runs": {"database_id": "VARCHAR(50) NOT NULL DEFAULT 'sqlite_demo'"},
        "column_classifications": {"effective_classification": "VARCHAR(32) NULL"},
        "access_events": {
            "actor_id": "VARCHAR(64) NULL",
            "database_id": "VARCHAR(50) NULL",
            "request_id": "VARCHAR(64) NULL",
        },
    }
    if dialect == "postgresql":
        enum_type = ColumnClassification.__table__.c.effective_classification.type
        additions["column_classifications"]["effective_classification"] = f"{enum_type.name} NULL"
        existing_role_values = {
            value for enum in inspect(engine).get_enums()
            if enum["name"] == "role"
            for value in enum["labels"]
        }
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
            for role in Role:
                if role.name not in existing_role_values:
                    connection.execute(text(
                        f"ALTER TYPE role ADD VALUE IF NOT EXISTS '{role.name}'"
                    ))
    with engine.begin() as connection:
        for table, columns in additions.items():
            existing = {col["name"] for col in inspector.get_columns(table)}
            for name, ddl in columns.items():
                if name not in existing:
                    # Names/DDL are fixed by this migration module, never user input.
                    connection.execute(text(f'ALTER TABLE "{table}" ADD COLUMN "{name}" {ddl}'))
                    existing.add(name)
        # create_all does not add indexes to tables that already existed in
        # Part 1. These additive indexes support database-scoped lookups.
        connection.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_scan_runs_database_id ON scan_runs (database_id)"
        ))
        connection.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_access_events_database_id ON access_events (database_id)"
        ))
