def test_dashboard_login_screen_reports_api_down_without_traceback(monkeypatch):
    from pathlib import Path
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("AVARNA_API_BASE_URL", "http://127.0.0.1:1/api/v1")
    app_path = Path(__file__).parents[1] / "dashboard.py"
    app = AppTest.from_file(app_path).run(timeout=15)
    assert not app.exception
    assert any("Avarna Data Masking System" in str(markdown.value)
               for markdown in app.markdown)
    assert len(app.form) == 1


def test_selected_column_query_returns_only_requested_fields(env):
    from avarna.audit.repository import AuditRepository
    from avarna.database.sqlite_adapter import SQLiteAdapter
    from avarna.masking.engine import MaskingEngine
    from avarna.masking.policy_repository import PolicyRepository
    from avarna.models import Principal, Role
    from avarna.scanner.scanner import Scanner
    from avarna.service.query_service import QueryService

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
    from avarna.dashboard.app import _classification_summary

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


def test_classification_breakdown_counts_labels_and_pending_reviews():
    from avarna.dashboard.app import _classification_breakdown

    class FakeAPI:
        @staticmethod
        def segment(value):
            return value

        def get(self, _path, *, params):
            assert params == {"limit": 100, "offset": 0}
            return {
                "total": 3,
                "items": [
                    {"classification": "PII_HIGH", "review_status": "pending"},
                    {"classification": "FINANCIAL_CONFIDENTIAL", "review_status": "approved"},
                    {"classification": "UNKNOWN", "review_status": "pending"},
                ],
            }

    counts, pending = _classification_breakdown(FakeAPI(), "sample")
    assert counts == {
        "PII_HIGH": 1,
        "FINANCIAL_CONFIDENTIAL": 1,
        "PUBLIC": 0,
        "UNCLASSIFIED": 1,
    }
    assert pending == 2


def test_echarts_specs_use_only_aggregated_classification_and_audit_values():
    from avarna.dashboard.app import _audit_outcome_chart, _classification_chart

    class_chart = _classification_chart({"PII_HIGH": 4, "PUBLIC": 2})
    class_data = class_chart["series"][0]["data"]
    assert sum(item["value"] for item in class_data) == 6
    assert all("name" in item and "value" in item for item in class_data)

    audit_chart = _audit_outcome_chart([
        {"outcome": "allowed", "reason": "not included"},
        {"outcome": "denied"},
        {"outcome": "denied"},
        {"outcome": "unexpected"},
    ])
    audit_data = audit_chart["series"][0]["data"]
    assert audit_data == [
        {"name": "Allowed", "value": 1},
        {"name": "Denied", "value": 2},
        {"name": "Error", "value": 0},
    ]


def test_native_streamlit_charts_and_badges_render():
    from streamlit.testing.v1 import AppTest

    app = AppTest.from_string(
        """
import streamlit as st

st.echarts_chart({
    "series": [{"type": "pie", "data": [{"name": "Allowed", "value": 1}]}]
}, alt="Audit outcome summary")
st.badge("API available", color="green")
st.pills("Outcome", options=["Allowed", "Denied"], selection_mode="multi")
with st.status("Scan complete", state="complete"):
    st.write("Classification scan finished.")
"""
    ).run()
    assert not app.exception
    assert any("API available" in str(markdown.value) for markdown in app.markdown)
    assert any("Classification scan finished." in str(markdown.value)
               for markdown in app.markdown)


def test_dashboard_sign_in_calls_api_and_does_not_retain_password(env, monkeypatch):
    import socket
    import threading
    import time
    from dataclasses import replace
    from pathlib import Path

    import requests
    import uvicorn
    from streamlit.testing.v1 import AppTest

    from avarna.api.app import create_app
    from avarna.auth.password_service import PasswordService
    from avarna.auth.user_repository import UserRepository
    from avarna.models import Role

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
        monkeypatch.setenv("AVARNA_API_BASE_URL", f"http://127.0.0.1:{port}/api/v1")
        app_path = Path(__file__).parents[1] / "dashboard.py"
        ui = AppTest.from_file(app_path).run(timeout=15)
        ui.text_input[0].set_value("dashboardui")
        ui.text_input[1].set_value("wrong-password")
        ui.button[0].click().run(timeout=15)
        assert not ui.exception
        assert any(
            "Username or password is incorrect" in str(item.value)
            for item in ui.error
        )
        assert "avarna_token" not in ui.session_state
        assert ui.session_state["login_password"] == ""

        ui.text_input[1].set_value(password)
        ui.button[0].click().run(timeout=15)
        assert not ui.exception
        assert any("Authenticated as dashboardui" in str(item.value) for item in ui.caption)
        assert "avarna_token" in ui.session_state
        assert "login_password" not in ui.session_state
    finally:
        server.should_exit = True
        worker.join(timeout=5)
