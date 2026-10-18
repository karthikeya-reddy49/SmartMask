import hashlib
import json
from argparse import Namespace
from dataclasses import replace

from fastapi.testclient import TestClient
from sqlalchemy import text

from smartmask.api.app import create_app
from smartmask.audit.repository import AuditRepository
from smartmask.cli import _Context, cmd_users
from smartmask.database.sqlite_adapter import SQLiteAdapter
from smartmask.masking.policy_repository import PolicyRepository
from smartmask.models import ClassificationTag, Role
from smartmask.scanner.scanner import Scanner


def _source_digest(manager):
    with manager.source_engine.connect() as connection:
        rows = connection.execute(text(
            "SELECT * FROM customers ORDER BY id"
        )).mappings().all()
    encoded = json.dumps([dict(row) for row in rows], sort_keys=True, default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def test_synthetic_support_user_full_workflow_preserves_source(env, monkeypatch, capsys):
    config, manager, metadata = env
    before = _source_digest(manager)

    adapter = SQLiteAdapter(config.source_db_url, max_sample_rows=10)
    report = Scanner(adapter, metadata, sample_size=10).scan_database()
    assert report.success
    assert any(item.column_name == "email" and
               item.classification == ClassificationTag.PII_HIGH
               for item in report.classifications)
    PolicyRepository(manager).seed_baseline_policies()

    context = _Context(config)
    context.db_manager = manager
    password = "synthetic-dashboard-account-42"
    answers = iter([password, password])
    monkeypatch.setattr("smartmask.cli.getpass.getpass", lambda _prompt: next(answers))
    assert cmd_users(Namespace(users_command="create", username="e2esupport",
                               role="Support"), context) == 0
    capsys.readouterr()
    for permission in ("data:read", "database:select", "audit:read"):
        assert cmd_users(Namespace(users_command="grant", username="e2esupport",
                                   permission=permission), context) == 0
    capsys.readouterr()

    app = create_app(replace(config, database_registry=(
        ("sqlite_demo", config.source_db_url),
    )))
    with TestClient(app) as client:
        login = client.post("/api/v1/auth/token", data={
            "username": "e2esupport", "password": password,
        })
        assert login.status_code == 200
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        identity = client.get("/api/v1/auth/me", headers=headers)
        assert identity.status_code == 200
        assert "data:read_raw" not in identity.json()["permissions"]

        response = client.get(
            "/api/v1/databases/sqlite_demo/tables/customers/records"
            "?limit=2&columns=email&columns=credit_card&columns=account_balance",
            headers=headers,
        )
        assert response.status_code == 200
        first = response.json()["rows"][0]
        assert first["email"] == "a***@example.test"
        assert first["credit_card"].endswith("1111")
        assert first["account_balance"] == "[REDACTED]"
        assert "arun@example.test" not in response.text

        denied = client.post("/api/v1/policies", headers=headers, json={
            "role": "Support", "classification": "PII_HIGH", "action": "allow",
        })
        assert denied.status_code == 403
        events = client.get("/api/v1/audit-events", headers=headers)
        assert events.status_code == 200
        assert any(event["operation"] == "query_records"
                   for event in events.json()["items"])
        assert any(event["operation"] == "query_records" and event["request_id"]
                   for event in events.json()["items"])
        assert any(event["operation"] == "login" and event["request_id"]
                   for event in events.json()["items"])
        assert "arun@example.test" not in events.text
        assert "4111111111111111" not in events.text

    assert _source_digest(manager) == before
    adapter.dispose()
    assert AuditRepository(manager).list_events(limit=100)
