from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from sqlalchemy import create_engine

from avarna.config import AppConfig
from avarna.database.connection import DatabaseManager
from avarna.scanner.metadata_repository import MetadataRepository


@pytest.fixture
def env(tmp_path):
    source = tmp_path / "source.db"
    control = tmp_path / "control.db"
    config = AppConfig(
        source_db_url=f"sqlite:///{source.as_posix()}",
        control_db_url=f"sqlite:///{control.as_posix()}",
        max_sample_rows=5, max_query_limit=10, default_query_limit=5,
        hmac_secret="test-only-secret", log_level="ERROR",
        jwt_secret="test-jwt-secret-that-is-only-for-tests-123456",
    )
    setup_path = Path(__file__).parents[1] / "data" / "setup_demo.py"
    spec = importlib.util.spec_from_file_location("setup_demo_test", setup_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    engine = create_engine(config.source_db_url)
    module.seed(engine)
    engine.dispose()
    manager = DatabaseManager(config.source_db_url, config.control_db_url)
    manager.initialize()
    metadata = MetadataRepository(manager)
    metadata.initialize_schema()
    yield config, manager, metadata
    manager.dispose()
