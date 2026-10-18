from dataclasses import replace
import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy import inspect as sqlalchemy_inspect

from avarna.api.app import create_app
from avarna.auth.password_service import PasswordService
from avarna.auth.user_repository import UserRepository
from avarna.database.migrations import upgrade_control_schema
from avarna.database.postgresql_adapter import PostgreSQLAdapter
from avarna.database.registry import DatabaseRegistry
from avarna.database.sqlite_adapter import SQLiteAdapter
from avarna.models import Role


def _make_user(manager, username, role=Role.SUPPORT, permissions=()):
    users = UserRepository(manager)
    user = users.create(username, PasswordService.hash("safe-password-for-tests-42"), role)
    for permission in permissions:
        users.grant(username, permission, "test")
    return user


def test_credential_errors_are_generic_and_disabled_account_is_rejected(env):
    config, manager, _ = env
    user = _make_user(manager, "lockeduser", permissions={"data:read"})
    app = create_app(replace(config, database_registry=(("sqlite_demo", config.source_db_url),)))
    with TestClient(app) as client:
        wrong_user = client.post("/api/v1/auth/token", data={"username": "unknown", "password": "wrong"})
        wrong_pass = client.post("/api/v1/auth/token", data={"username": "lockeduser", "password": "wrong"})
        assert wrong_user.status_code == wrong_pass.status_code == 401
        assert wrong_user.json() == wrong_pass.json()
        token = client.post("/api/v1/auth/token", data={"username": "lockeduser",
            "password": "safe-password-for-tests-42"}).json()["access_token"]
        UserRepository(manager).update("lockeduser", active=False, revoke_tokens=True)
        response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 401
        assert "password_hash" not in response.text


def test_permission_revocation_is_immediate_and_admin_role_has_no_policy_write(env):
    config, manager, _ = env
    _make_user(manager, "adminop", Role.ADMIN, {"policy:read"})
    app = create_app(replace(config, database_registry=(("sqlite_demo", config.source_db_url),)))
    with TestClient(app) as client:
        token = client.post("/api/v1/auth/token", data={"username": "adminop",
            "password": "safe-password-for-tests-42"}).json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        assert client.get("/api/v1/policies", headers=headers).status_code == 200
        assert client.post("/api/v1/policies", headers=headers, json={
            "role": "Support", "classification": "PII_HIGH", "action": "redact"
        }).status_code == 403
        UserRepository(manager).revoke("adminop", "policy:read")
        assert client.get("/api/v1/policies", headers=headers).status_code == 403


def test_database_classifications_are_isolated_by_registry_id(env):
    config, manager, metadata = env
    one = SQLiteAdapter(config.source_db_url)
    two = SQLiteAdapter(config.source_db_url)
    from avarna.scanner.scanner import Scanner
    first = Scanner(one, metadata, database_id="source_one").scan_database()
    assert first.success
    assert metadata.get_latest_classification("customers", "email", "source_one") is not None
    assert metadata.get_latest_classification("customers", "email", "source_two") is None
    assert len(metadata.list_classifications("source_one")) == 10
    assert metadata.list_classifications("source_two") == []
    one.dispose(); two.dispose()


def test_sqlite_adapter_is_read_only_and_registry_hides_url(env):
    config, _, _ = env
    adapter = SQLiteAdapter(config.source_db_url)
    with pytest.raises(Exception):
        with adapter._ensure_engine().begin() as connection:
            connection.execute(text("UPDATE customers SET name='changed' WHERE id=1"))
    adapter.dispose()
    registry_config = replace(config, database_registry=(
        ("pg_safe", "postgresql+psycopg://demo:secret@localhost/example"),))
    registry = DatabaseRegistry(registry_config)
    public = registry.list_public()
    assert public == [{"database_id": "pg_safe", "display_name": "pg_safe", "backend": "PostgreSQL"}]
    assert "secret" not in str(public)
    registry.dispose()


def test_control_schema_upgrade_preserves_legacy_scan_run(env, tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy import inspect as sqlalchemy_inspect
    path = tmp_path / "legacy-control.db"
    engine = create_engine(f"sqlite:///{path.as_posix()}")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE scan_runs (id INTEGER PRIMARY KEY, status VARCHAR NOT NULL, tables_scanned INTEGER NOT NULL, columns_classified INTEGER NOT NULL, started_at DATETIME NOT NULL, completed_at DATETIME, error_summary TEXT)"))
        connection.execute(text("INSERT INTO scan_runs VALUES (42, 'completed', 1, 8, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, NULL)"))
    upgrade_control_schema(engine)
    with engine.connect() as connection:
        assert connection.execute(text("SELECT id, database_id FROM scan_runs WHERE id=42")).one() == (42, "sqlite_demo")
    assert "users" in sqlalchemy_inspect(engine).get_table_names()
    assert "ix_scan_runs_database_id" in {
        item["name"] for item in sqlalchemy_inspect(engine).get_indexes("scan_runs")
    }
    assert "ix_access_events_database_id" in {
        item["name"] for item in sqlalchemy_inspect(engine).get_indexes("access_events")
    }
    engine.dispose()


def test_duplicate_global_policy_is_rejected(env):
    from avarna.exceptions import PolicyError
    from avarna.masking.policy_repository import PolicyRepository
    from avarna.models import ClassificationTag

    _config, manager, _metadata = env
    repo = PolicyRepository(manager)
    repo.seed_baseline_policies()
    with pytest.raises(PolicyError):
        repo.create_policy(role=Role.SUPPORT,
                           classification=ClassificationTag.PII_HIGH,
                           action="redact")


def test_api_disables_traceback_mode_and_fails_closed_when_denial_audit_fails(
    env, monkeypatch
):
    _config, manager, _metadata = env
    _make_user(manager, "denieduser", Role.SUPPORT, ())
    config = env[0]
    app = create_app(replace(config, api_environment="staging",
                             database_registry=(("sqlite_demo", config.source_db_url),)))
    assert app.debug is False
    with TestClient(app) as client:
        token = client.post("/api/v1/auth/token", data={
            "username": "denieduser", "password": "safe-password-for-tests-42"
        }).json()["access_token"]
        monkeypatch.setattr(
            "avarna.api.dependencies.AuditRepository.record_event",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("audit unavailable")),
        )
        response = client.get("/api/v1/policies", headers={
            "Authorization": f"Bearer {token}"
        })
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "AUDIT_UNAVAILABLE"
        assert "Traceback" not in response.text


def test_postgres_adapter_creation_validates_driver_without_connecting():
    with pytest.raises(ValueError):
        PostgreSQLAdapter("postgres://not-allowed")
    adapter = PostgreSQLAdapter("postgresql+psycopg://user:placeholder@127.0.0.1/testdb")
    adapter.dispose()


@pytest.mark.postgres
def test_optional_postgres_connection_contract(env):
    url = os.environ.get("AVARNA_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("Set AVARNA_TEST_POSTGRES_URL to a dedicated disposable PostgreSQL test database.")
    import uuid
    from sqlalchemy import create_engine
    from avarna.exceptions import UnknownTableError
    from avarna.scanner.metadata_repository import MetadataRepository
    from avarna.scanner.scanner import Scanner

    schema = f"avarna_test_{uuid.uuid4().hex[:12]}"
    engine = create_engine(url)
    adapter = None
    try:
        with engine.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))
            connection.execute(text(
                f'CREATE TABLE "{schema}".customers '
                '(id INTEGER PRIMARY KEY, email TEXT, account_balance NUMERIC)'
            ))
            connection.execute(text(
                f'INSERT INTO "{schema}".customers VALUES '
                "(1, 'one@example.test', 10.5), (2, 'two@example.test', 20.5), "
                "(3, 'three@example.test', 30.5)"
            ))

        adapter = PostgreSQLAdapter(url, schema=schema,
                                    max_sample_rows=2, max_query_rows=2)
        assert adapter.list_tables() == ["customers"]
        assert {column["name"] for column in adapter.get_columns("customers")} == {
            "id", "email", "account_balance"
        }
        assert len(adapter.fetch_column_sample("customers", "email", 100)) == 2
        rows = adapter.fetch_records("customers", 100)
        assert len(rows) == 2
        with pytest.raises(UnknownTableError):
            adapter.fetch_records("missing", 1)

        _config, _manager, metadata = env
        report = Scanner(adapter, metadata, sample_size=2,
                         database_id="postgres_integration").scan_database()
        assert report.success
        assert metadata.get_latest_classification(
            "customers", "email", "postgres_integration"
        ) is not None
        assert metadata.get_latest_classification(
            "customers", "email", "sqlite_demo"
        ) is None
        with engine.connect() as connection:
            after = connection.execute(text(
                f'SELECT * FROM "{schema}".customers ORDER BY id'
            )).all()
        assert after == [
            (1, "one@example.test", 10.5),
            (2, "two@example.test", 20.5),
            (3, "three@example.test", 30.5),
        ]
    finally:
        if adapter is not None:
            adapter.dispose()
        with engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        engine.dispose()


def test_local_cli_prompts_and_never_displays_password(env, monkeypatch, capsys):
    from argparse import Namespace
    from avarna.cli import _Context, cmd_users
    config, manager, _ = env
    context = _Context(config)
    context.db_manager = manager
    answers = iter(["cli-password-for-tests-12", "cli-password-for-tests-12"])
    monkeypatch.setattr("avarna.cli.getpass.getpass", lambda _prompt: next(answers))
    assert cmd_users(Namespace(users_command="create", username="cliuser", role="Support"), context) == 0
    output = capsys.readouterr().out
    assert "Created user cliuser" in output
    assert "cli-password-for-tests-12" not in output
    assert cmd_users(Namespace(users_command="grant", username="cliuser",
                               permission="data:read"), context) == 0
    assert cmd_users(Namespace(users_command="list"), context) == 0
    listing = capsys.readouterr().out
    assert "cliuser\tSupport\tactive\tdata:read" in listing
    assert "$argon2" not in listing
