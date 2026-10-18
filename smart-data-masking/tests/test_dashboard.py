def test_dashboard_login_screen_reports_api_down_without_traceback(monkeypatch):
    from pathlib import Path
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("SMARTMASK_API_BASE_URL", "http://127.0.0.1:1/api/v1")
    app_path = Path(__file__).parents[1] / "dashboard.py"
    app = AppTest.from_file(app_path).run(timeout=15)
    assert not app.exception
    assert any(title.value == "Smart Data Masking System" for title in app.title)
    assert len(app.form) == 1


def test_selected_column_query_returns_only_requested_fields(env):
    from smartmask.audit.repository import AuditRepository
    from smartmask.database.sqlite_adapter import SQLiteAdapter
    from smartmask.masking.engine import MaskingEngine
    from smartmask.masking.policy_repository import PolicyRepository
    from smartmask.models import Principal, Role
    from smartmask.scanner.scanner import Scanner
    from smartmask.service.query_service import QueryService

    config, manager, metadata = env
    adapter = SQLiteAdapter(config.source_db_url, max_query_rows=5)
    Scanner(adapter, metadata).scan_database()
    PolicyRepository(manager).seed_baseline_policies()
    result = QueryService(adapter, manager, PolicyRepository(manager),
        AuditRepository(manager), MaskingEngine(config), config).query_records(
            Principal("dashboard-test", Role.SUPPORT), "customers", limit=1,
            columns=["email"])
    assert result.columns == ["email"]
    assert list(result.rows[0]) == ["email"]
    assert result.rows[0]["email"] == "a***@example.test"
    adapter.dispose()


def test_classification_summary_reads_all_api_pages():
    from smartmask.dashboard.app import _classification_summary

    class FakeAPI:
        def __init__(self):
            self.requests = []

        @staticmethod
        def segment(value):
            return value

        def get(self, _path, *, params):
            self.requests.append(params.copy())
            offset, limit = params["offset"], params["limit"]
            total = 501
            items = [{"classification": "PII_HIGH" if i % 2 else "PUBLIC"}
                     for i in range(offset, min(offset + limit, total))]
            return {"items": items, "total": total}

    api = FakeAPI()
    assert _classification_summary(api, "sample") == (501, 250)
    assert [request["offset"] for request in api.requests] == [0, 100, 200, 300, 400, 500]


def test_dashboard_sign_in_calls_api_and_does_not_retain_password(env, monkeypatch):
    import socket
    import threading
    import time
    from dataclasses import replace
    from pathlib import Path

    import requests
    import uvicorn
    from streamlit.testing.v1 import AppTest

    from smartmask.api.app import create_app
    from smartmask.auth.password_service import PasswordService
    from smartmask.auth.user_repository import UserRepository
    from smartmask.models import Role

    config, manager, _metadata = env
    password = "dashboard-ui-password-42"
    UserRepository(manager).create("dashboardui", PasswordService.hash(password), Role.SUPPORT)
    app = create_app(replace(config, database_registry=(
        ("sqlite_demo", config.source_db_url),
    )))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()
    server = uvicorn.Server(uvicorn.Config(
        app, host="127.0.0.1", port=port, log_level="critical", access_log=False,
    ))
    worker = threading.Thread(target=server.run, daemon=True)
    worker.start()
    try:
        for _ in range(100):
            try:
                if requests.get(f"http://127.0.0.1:{port}/api/v1/health", timeout=0.2).ok:
                    break
            except requests.RequestException:
                time.sleep(0.05)
        monkeypatch.setenv("SMARTMASK_API_BASE_URL", f"http://127.0.0.1:{port}/api/v1")
        app_path = Path(__file__).parents[1] / "dashboard.py"
        ui = AppTest.from_file(app_path).run(timeout=15)
        ui.text_input[0].set_value("dashboardui")
        ui.text_input[1].set_value(password)
        ui.button[0].click().run(timeout=15)
        assert not ui.exception
        assert any("Authenticated as dashboardui" in str(item.value) for item in ui.caption)
        assert "smartmask_token" in ui.session_state
        assert "login_password" not in ui.session_state
    finally:
        server.should_exit = True
        worker.join(timeout=5)
