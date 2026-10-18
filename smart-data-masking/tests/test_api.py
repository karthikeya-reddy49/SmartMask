from dataclasses import replace

import jwt
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from smartmask.api.app import create_app
from smartmask.auth.password_service import PasswordService
from smartmask.auth.user_repository import UserRepository
from smartmask.auth.token_service import TokenService
from smartmask.database.models import User
from smartmask.masking.policy_repository import PolicyRepository
from smartmask.models import Role
from smartmask.scanner.scanner import Scanner
from smartmask.database.sqlite_adapter import SQLiteAdapter


def _account(env, name="supporter", role=Role.SUPPORT, grants=()):
    config, manager, metadata = env
    user = UserRepository(manager).create(name, PasswordService.hash("correct-horse-battery-7"), role)
    users = UserRepository(manager)
    for permission in grants:
        users.grant(name, permission, granted_by="test")
    return user


def _login(client, name="supporter"):
    response = client.post("/api/v1/auth/token", data={
        "username": name, "password": "correct-horse-battery-7"})
    return response


def test_auth_me_and_permission_enforced_masked_records(env):
    config, manager, metadata = env
    _account(env, grants={"data:read", "database:select", "scan:read"})
    adapter = SQLiteAdapter(config.source_db_url, max_sample_rows=10)
    Scanner(adapter, metadata).scan_database()
    PolicyRepository(manager).seed_baseline_policies()
    config = replace(config, database_registry=(("sqlite_demo", config.source_db_url),))
    app = create_app(config)
    with TestClient(app) as client:
        assert client.get("/api/v1/health").headers["cache-control"] == "no-store"
        assert client.get("/api/v1/ready").json() == {"status": "ready"}
        assert client.get("/api/v1/auth/me").status_code == 401
        token_response = _login(client)
        assert token_response.status_code == 200
        token = token_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        me = client.get("/api/v1/auth/me", headers=headers)
        assert me.status_code == 200
        assert me.json()["role"] == "Support"
        assert "password_hash" not in me.text
        rows = client.get("/api/v1/databases/sqlite_demo/tables/customers/records",
                          headers=headers).json()["rows"][0]
        assert rows["email"] == "a***@example.test"
        assert rows["credit_card"].endswith("1111")
        assert rows["account_balance"] == "[REDACTED]"
        selected = client.get(
            "/api/v1/databases/sqlite_demo/tables/customers/records?limit=1&columns=email",
            headers=headers,
        )
        assert selected.status_code == 200
        assert selected.json()["columns"] == ["email"]
        assert list(selected.json()["rows"][0]) == ["email"]
        invalid = client.get(
            "/api/v1/databases/sqlite_demo/tables/customers/records?columns=email&columns=missing",
            headers=headers,
        )
        assert invalid.status_code == 400
        assert client.post("/api/v1/databases/sqlite_demo/scans", headers=headers,
                           json={}).status_code == 403
        assert client.get("/api/v1/audit-events", headers=headers).status_code == 403
        assert client.patch("/api/v1/policies/1", headers=headers,
                            json={"enabled": False}).status_code == 403
        assert client.get("/api/v1/databases", headers=headers).status_code == 200
        assert client.get("/api/v1/databases/unknown/tables", headers=headers).status_code == 404
        assert client.get("/api/v1/databases/sqlite_demo/tables/customers/records?limit=0",
                          headers=headers).status_code == 422
        assert client.get("/api/v1/databases/sqlite_demo/tables/customers/records",
                          headers={"Authorization": "Bearer bad-token"}).status_code == 401
        assert client.post("/api/v1/auth/logout", headers=headers).status_code == 204
        assert client.get("/api/v1/auth/me", headers=headers).status_code == 401
    adapter.dispose()


def test_admin_role_does_not_imply_raw_permission_and_grants_refresh(env):
    config, manager, metadata = env
    user = _account(env, "adminuser", Role.ADMIN,
                    {"data:read", "database:select"})
    adapter = SQLiteAdapter(config.source_db_url, max_sample_rows=10)
    Scanner(adapter, metadata).scan_database()
    PolicyRepository(manager).seed_baseline_policies()
    app = create_app(replace(config, database_registry=(("sqlite_demo", config.source_db_url),)))
    with TestClient(app) as client:
        token = _login(client, "adminuser").json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        url = "/api/v1/databases/sqlite_demo/tables/customers/records?limit=1"
        masked = client.get(url, headers=headers).json()["rows"][0]
        assert masked["email"] == "a***@example.test"
        UserRepository(manager).grant("adminuser", "data:read_raw", granted_by="test")
        raw = client.get(url, headers=headers).json()["rows"][0]
        assert raw["email"] == "arun@example.test"
    adapter.dispose()


def test_api_review_policy_and_audit_routes(env):
    config, manager, metadata = env
    _account(env, "operator", Role.ADMIN, {"database:select", "scan:run", "scan:read",
        "scan:review", "policy:read", "policy:write", "audit:read"})
    adapter = SQLiteAdapter(config.source_db_url)
    Scanner(adapter, metadata).scan_database()
    PolicyRepository(manager).seed_baseline_policies()
    app = create_app(replace(config, database_registry=(("sqlite_demo", config.source_db_url),)))
    with TestClient(app) as client:
        token = _login(client, "operator").json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        classifications = client.get("/api/v1/databases/sqlite_demo/classifications", headers=headers)
        assert classifications.status_code == 200
        entry = next(x for x in classifications.json()["items"] if x["column_name"] == "name")
        response = client.patch(f"/api/v1/classifications/{entry['classification_id']}/review",
            headers=headers, json={"review_status": "approved", "classification": "PII_HIGH"})
        assert response.status_code == 200
        assert client.get("/api/v1/policies", headers=headers).status_code == 200
        created = client.post("/api/v1/policies", headers=headers, json={
            "role": "Support", "classification": "PII_HIGH", "action": "redact",
            "table_scope": "customers", "column_scope": "email"})
        assert created.status_code == 201
        assert client.patch(f"/api/v1/policies/{created.json()['id']}", headers=headers,
                            json={"enabled": False}).status_code == 200
        events = client.get("/api/v1/audit-events", headers=headers)
        assert events.status_code == 200 and events.json()["items"]
        assert "arun@example.test" not in events.text
        scan = client.post("/api/v1/databases/sqlite_demo/scans", headers=headers,
                           json={"sample_size": 99999})
        assert scan.status_code == 201
        assert scan.json()["status"] == "completed"
        assert "arun@example.test" not in scan.text
    adapter.dispose()


def test_invalid_expired_and_tampered_tokens(env):
    config, manager, _ = env
    _account(env, grants={"data:read"})
    app = create_app(replace(config, database_registry=(("sqlite_demo", config.source_db_url),)))
    with TestClient(app) as client:
        service = TokenService(config)
        valid, _ = service.issue(UserRepository(manager).get_by_username("supporter").id, 0)
        claims = jwt.decode(valid, config.jwt_secret, algorithms=["HS256"],
                            audience=config.jwt_audience, issuer=config.jwt_issuer)
        claims["exp"] = 1
        expired = jwt.encode(claims, config.jwt_secret, algorithm="HS256")
        assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {expired}"}).status_code == 401
        assert client.get("/api/v1/auth/me", headers={"Authorization": "Bearer " + valid[:-2] + "xx"}).status_code == 401


def test_user_administration_requires_permission_and_blocks_self_changes(env):
    config, manager, _metadata = env
    _account(env, "useroperator", Role.ADMIN, {"users:manage"})
    target = _account(env, "manageduser", Role.SUPPORT, {"data:read"})
    app = create_app(replace(config, database_registry=(("sqlite_demo", config.source_db_url),)))
    with TestClient(app) as client:
        user_token = _login(client, "manageduser").json()["access_token"]
        user_headers = {"Authorization": f"Bearer {user_token}"}
        assert client.get("/api/v1/users", headers=user_headers).status_code == 403

        operator = _login(client, "useroperator").json()["access_token"]
        headers = {"Authorization": f"Bearer {operator}"}
        assert client.get("/api/v1/users", headers=headers).status_code == 200
        assert client.get("/api/v1/permissions", headers=headers).status_code == 200
        self_change = client.put("/api/v1/users/" +
            UserRepository(manager).get_by_username("useroperator").id +
            "/permissions", headers=headers, json={"permission":"data:read_raw"})
        assert self_change.status_code == 400
        changed = client.patch(f"/api/v1/users/{target.id}/role", headers=headers,
                               json={"role":"Analyst"})
        assert changed.status_code == 200
        assert changed.json()["tokens_revoked"] is True
        assert client.get("/api/v1/auth/me", headers=user_headers).status_code == 401
        grant = client.put(f"/api/v1/users/{target.id}/permissions", headers=headers,
                           json={"permission":"database:select"})
        assert grant.status_code == 200 and grant.json()["changed"] is True
        assert "password_hash" not in client.get("/api/v1/users", headers=headers).text


def test_password_hashing_and_user_cli_repository(env):
    config, manager, _ = env
    user = _account(env)
    with Session(manager.control_engine) as session:
        persisted = session.get(User, user.id)
        assert persisted.password_hash != "correct-horse-battery-7"
        assert persisted.password_hash.startswith("$argon2id$")
    assert set(UserRepository(manager).permissions(user.id)) == set()
