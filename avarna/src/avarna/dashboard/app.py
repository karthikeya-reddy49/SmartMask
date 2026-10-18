"""Streamlit UI for the authenticated Avarna API.

The dashboard contains no database connection or masking logic. The access
token stays in server-side Streamlit session state and protected results are
fetched on demand without persistent caching.
"""
from __future__ import annotations

from html import escape
import os

import streamlit as st

from ..dashboard_client import DashboardAPI, DashboardAPIError
from ..models import ClassificationTag, Role

DEFAULT_API_BASE = "http://127.0.0.1:8000/api/v1"

_APP_STYLES = """
<style>
    /* Typography: self-hosted IBM Plex families and the application type scale. */
    @font-face {
        font-family: "IBM Plex Sans";
        font-style: normal;
        font-weight: 400 600;
        font-display: swap;
        src: url("/app/static/fonts/ibm-plex-sans-latin.woff2") format("woff2");
    }
    @font-face {
        font-family: "IBM Plex Mono";
        font-style: normal;
        font-weight: 400;
        font-display: swap;
        src: url("/app/static/fonts/ibm-plex-mono-regular-latin.woff2") format("woff2");
    }
    @font-face {
        font-family: "IBM Plex Mono";
        font-style: normal;
        font-weight: 500;
        font-display: swap;
        src: url("/app/static/fonts/ibm-plex-mono-medium-latin.woff2") format("woff2");
    }
    @font-face {
        font-family: "IBM Plex Mono";
        font-style: normal;
        font-weight: 600;
        font-display: swap;
        src: url("/app/static/fonts/ibm-plex-mono-semibold-latin.woff2") format("woff2");
    }
    :root {
        --avarna-caption-size: 13px;
        --avarna-body-size: 15px;
        --avarna-subheading-size: 18px;
        --avarna-heading-size: 24px;
        --avarna-title-size: 36px;
        --avarna-muted: color-mix(in srgb, var(--text-color) 72%, var(--background-color));
        --avarna-blue: var(--primary-color);
        --avarna-line: color-mix(in srgb, var(--text-color) 16%, var(--background-color));
    }
    [data-testid="stAppViewContainer"],
    [data-testid="stSidebar"] {
        font-family: "IBM Plex Sans";
    }
    .stMarkdown p,
    [data-testid="stWidgetLabel"] p,
    [data-testid="stFormSubmitButton"] button,
    [data-testid="stButton"] button,
    input,
    textarea {
        font-size: var(--avarna-body-size);
        font-weight: 400;
        line-height: 1.6;
    }
    .stMarkdown p {
        max-width: 80ch;
    }
    [data-testid="stSidebar"] [data-testid="stCaptionContainer"] p {
        color: var(--text-color);
        font-size: var(--avarna-caption-size);
        line-height: 1.6;
    }
    [data-testid="stSidebar"] [data-testid="stRadio"] label {
        border-radius: 8px;
        padding: 0.2rem 0.35rem;
    }
    [data-testid="stAppViewContainer"] .main .block-container {
        max-width: 1440px;
        padding-top: 2rem;
        padding-bottom: 3rem;
    }
    [data-testid="stMetric"] {
        background: var(--secondary-background-color);
        border: 1px solid var(--avarna-line);
        border-radius: 14px;
        padding: 1rem 1.1rem;
        box-shadow: 0 5px 18px rgba(20, 35, 63, 0.04);
    }
    [data-testid="stMetricLabel"] p {
        color: var(--avarna-muted);
        font-size: var(--avarna-small-size);
        font-weight: 400;
    }
    [data-testid="stMetricValue"] {
        color: var(--text-color);
        font-size: var(--avarna-heading-size);
        font-weight: 600;
    }
    [data-testid="stDataFrame"],
    [data-testid="stTable"] {
        border: 1px solid var(--avarna-line);
        border-radius: 12px;
        overflow: hidden;
    }
    [data-testid="stForm"] {
        background: var(--secondary-background-color);
        border: 1px solid var(--avarna-line);
        border-radius: 14px;
        padding: 1.25rem;
    }
    .avarna-hero {
        background: linear-gradient(120deg, #14233f 0%, #243d75 58%, #3157d5 100%);
        border-radius: 20px;
        color: #ffffff;
        padding: 1.6rem 1.8rem;
        margin: 0.3rem 0 1.6rem;
        box-shadow: 0 12px 30px rgba(29, 52, 103, 0.16);
    }
    .avarna-hero .eyebrow {
        color: #c7d5ff;
        font-size: var(--avarna-caption-size);
        font-weight: 400;
        letter-spacing: normal;
        text-transform: none;
        margin-bottom: 0.45rem;
    }
    .avarna-hero h1 {
        color: #ffffff;
        font-size: var(--avarna-title-size);
        font-weight: 600;
        margin: 0;
        line-height: 1.2;
        letter-spacing: -0.02em;
    }
    .avarna-hero p {
        color: #e0e8ff;
        font-size: var(--avarna-body-size);
        font-weight: 400;
        line-height: 1.55;
        margin: 0.65rem 0 0;
        max-width: 70ch;
    }
    .avarna-login-panel {
        background: linear-gradient(145deg, #14233f, #294a8e);
        border-radius: 20px;
        color: #ffffff;
        min-height: 310px;
        padding: 2rem;
        box-shadow: 0 14px 32px rgba(20, 35, 63, 0.15);
    }
    .avarna-login-panel h2 {
        color: #ffffff;
        font-size: var(--avarna-subheading-size);
        font-weight: 600;
        line-height: 1.2;
        margin: 0.5rem 0 0.7rem;
    }
    .avarna-login-panel p,
    .avarna-login-panel li {
        color: #e0e8ff;
        font-size: var(--avarna-body-size);
        font-weight: 400;
        line-height: 1.6;
    }
    .avarna-login-panel ul {
        padding-left: 1.2rem;
        margin-bottom: 0;
    }
    .avarna-login-mark {
        align-items: center;
        background: rgba(255, 255, 255, 0.12);
        border: 1px solid rgba(255, 255, 255, 0.2);
        border-radius: 12px;
        display: inline-flex;
        font-size: 1.5rem;
        height: 48px;
        justify-content: center;
        width: 48px;
    }
    div.stButton > button[kind="primary"],
    div[data-testid="stFormSubmitButton"] > button[kind="primary"] {
        background: var(--avarna-blue);
        border-color: var(--avarna-blue);
        border-radius: 9px;
        font-size: var(--avarna-body-size);
        font-weight: 600;
        min-height: 2.7rem;
    }
    h1, h2, h3 {
        color: var(--text-color);
        font-weight: 600;
        letter-spacing: normal;
    }
    h1 {
        font-size: var(--avarna-heading-size);
        line-height: 1.2;
    }
    h2 {
        font-size: var(--avarna-heading-size);
        line-height: 1.2;
    }
    h3 {
        font-size: var(--avarna-subheading-size);
        line-height: 1.2;
    }
    [data-testid="stCaptionContainer"] p {
        color: var(--text-color);
        font-size: var(--avarna-caption-size);
        font-weight: 400;
        line-height: 1.6;
    }
    code,
    pre,
    [data-testid="stCode"] {
        font-family: "IBM Plex Mono";
    }
    [data-testid="stHeaderActionElements"] {
        display: none;
    }
    @media (max-width: 760px) {
        [data-testid="stAppViewContainer"] .main .block-container {
            padding: 1.2rem 1rem 2rem;
        }
        .avarna-hero {
            padding: 1.3rem;
        }
    }
</style>
"""


def _api_base() -> str:
    return os.environ.get("AVARNA_API_BASE_URL", DEFAULT_API_BASE).rstrip("/")


def _apply_ui_theme() -> None:
    st.markdown(_APP_STYLES, unsafe_allow_html=True)


def _api(token: str | None = None) -> DashboardAPI:
    return DashboardAPI(_api_base(), token)


def _error(exc: DashboardAPIError) -> None:
    st.error(str(exc))


def _has(identity: dict, permission: str) -> bool:
    return permission in identity.get("permissions", [])


def _status() -> tuple[bool, bool]:
    client = _api()
    try:
        health = client.get("/health").get("status") == "ok"
    except DashboardAPIError:
        health = False
    try:
        ready = client.get("/ready").get("status") == "ready"
    except DashboardAPIError:
        ready = False
    return health, ready


def _submit_login() -> None:
    username = st.session_state.get("login_username", "")
    password = st.session_state.get("login_password", "")
    try:
        result = _api().login(username, password)
        st.session_state["avarna_token"] = result["access_token"]
        st.session_state["avarna_api_base"] = _api_base()
        st.session_state.pop("avarna_login_error", None)
    except DashboardAPIError as exc:
        if exc.status_code == 401:
            st.session_state["avarna_login_error"] = (
                "Username or password is incorrect. Try again."
            )
        elif exc.status_code == 429:
            st.session_state["avarna_login_error"] = (
                "Too many sign-in attempts. Wait a moment and try again."
            )
        else:
            st.session_state["avarna_login_error"] = (
                "Could not sign in. Check the API status and try again."
            )
    except KeyError:
        st.session_state["avarna_login_error"] = (
            "Could not sign in. Check the API status and try again."
        )
    finally:
        # This callback runs before the next render, so the widget state is
        # removed without retaining the submitted password in the session.
        st.session_state.pop("login_password", None)


def _login() -> None:
    st.markdown(
        """
        <div class="avarna-hero">
            <div class="eyebrow">Avarna · Data protection workspace</div>
            <h1>Avarna Data Masking System</h1>
            <p>Discover sensitive fields, review classifications, and explore data
            protected by your organization's policies.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    login_col, info_col = st.columns([1, 0.9], gap="large")
    with login_col:
        st.subheader("Sign in")
        st.caption("Use your provisioned Avarna account.")
        with st.form("login_form"):
            st.text_input("Username", max_chars=64, key="login_username")
            st.text_input("Password", type="password", max_chars=128,
                          key="login_password")
            st.form_submit_button("Sign in", type="primary", on_click=_submit_login,
                                  use_container_width=True)
    with info_col:
        st.markdown(
            """
            <div class="avarna-login-panel">
                <div class="avarna-login-mark">
                    <svg viewBox="0 0 24 24" width="28" height="28" fill="none"
                         xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                        <path d="M12 3 20 6v5c0 5.1-3.4 8.8-8 10-4.6-1.2-8-4.9-8-10V6l8-3Z"
                              stroke="currentColor" stroke-width="1.8"
                              stroke-linejoin="round"/>
                        <path d="m8.5 12 2.2 2.2 4.8-4.8"
                              stroke="currentColor" stroke-width="1.8"
                              stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                </div>
                <h2>Privacy-aware by design</h2>
                <p>Access is permission-controlled, and sensitive values are
                transformed by the API before they reach the dashboard.</p>
                <ul>
                    <li>Review scan evidence and classifications</li>
                    <li>Explore records through stored masking policies</li>
                    <li>Monitor service and control-store status</li>
                </ul>
            </div>
            """,
            unsafe_allow_html=True,
        )
    login_error = st.session_state.get("avarna_login_error")
    if login_error:
        st.error(login_error)
    health, ready = _status()
    status_col, _ = st.columns([1, 1.9])
    with status_col:
        st.caption(
            f"Dashboard is running · API {'available' if health else 'unavailable'} · "
            f"Control store {'ready' if ready else 'not ready'}"
        )


def _clear_session() -> None:
    for key in tuple(st.session_state.keys()):
        if key.startswith("avarna_") or key == "login_password":
            del st.session_state[key]


def _database_selector(api: DashboardAPI, identity: dict) -> str | None:
    if not _has(identity, "database:select"):
        st.sidebar.caption("Database selection requires database:select.")
        return None
    try:
        databases = api.get("/databases").get("items", [])
    except DashboardAPIError as exc:
        st.sidebar.error(str(exc))
        return None
    if not databases:
        st.sidebar.info("No configured databases are available.")
        return None
    ids = [item["database_id"] for item in databases]
    prior = st.session_state.get("avarna_database")
    index = ids.index(prior) if prior in ids else 0
    selected = st.sidebar.selectbox("Registered database", ids, index=index)
    st.session_state["avarna_database"] = selected
    backends = {item["database_id"]: item.get("backend", "Configured") for item in databases}
    st.sidebar.caption(f"Backend: {backends.get(selected, 'Configured')}")
    return selected


def _load_tables(api: DashboardAPI, database_id: str) -> list[str]:
    result = api.get(f"/databases/{api.segment(database_id)}/tables")
    return result.get("tables", [])


def _load_classifications(api: DashboardAPI, database_id: str, *,
                          offset: int = 0, limit: int = 100) -> tuple[list[dict], int]:
    result = api.get(f"/databases/{api.segment(database_id)}/classifications",
                     params={"limit": limit, "offset": offset})
    return result.get("items", []), int(result.get("total", 0))


def _classification_summary(api: DashboardAPI, database_id: str) -> tuple[int, int]:
    """Return total and sensitive classification counts across every API page."""
    counts, _pending = _classification_breakdown(api, database_id)
    total = sum(counts.values())
    sensitive = sum(
        count for tag, count in counts.items()
        if tag not in {
            ClassificationTag.PUBLIC.value,
            ClassificationTag.UNCLASSIFIED.value,
        }
    )
    return total, sensitive


def _classification_breakdown(
    api: DashboardAPI,
    database_id: str,
) -> tuple[dict[str, int], int]:
    counts = {tag.value: 0 for tag in ClassificationTag}
    pending = 0
    total = 0
    offset = 0
    while True:
        items, reported_total = _load_classifications(api, database_id, offset=offset)
        total = reported_total
        for item in items:
            classification = item.get("classification", ClassificationTag.UNCLASSIFIED.value)
            if classification not in counts:
                classification = ClassificationTag.UNCLASSIFIED.value
            counts[classification] += 1
            pending += item.get("review_status") == "pending"
        offset += len(items)
        if not items or offset >= reported_total:
            return counts, pending


def _classification_chart(counts: dict[str, int]) -> dict:
    colors = {
        ClassificationTag.PII_HIGH.value: "#C43D4D",
        ClassificationTag.FINANCIAL_CONFIDENTIAL.value: "#C47716",
        ClassificationTag.PUBLIC.value: "#21835A",
        ClassificationTag.UNCLASSIFIED.value: "#718096",
    }
    return {
        "tooltip": {"trigger": "item", "formatter": "{b}: {c} ({d}%)"},
        "legend": {"bottom": 0, "left": "center"},
        "color": [colors[tag.value] for tag in ClassificationTag],
        "series": [{
            "name": "Column classifications",
            "type": "pie",
            "radius": ["46%", "70%"],
            "center": ["50%", "44%"],
            "avoidLabelOverlap": True,
            "itemStyle": {"borderRadius": 5, "borderColor": "transparent", "borderWidth": 2},
            "label": {"show": False},
            "emphasis": {"scale": True, "scaleSize": 8},
            "data": [
                {"name": tag.value, "value": counts.get(tag.value, 0)}
                for tag in ClassificationTag
            ],
        }],
    }


def _audit_outcome_chart(events: list[dict]) -> dict:
    counts = {"allowed": 0, "denied": 0, "error": 0}
    for event in events:
        outcome = event.get("outcome", "")
        if outcome in counts:
            counts[outcome] += 1
    colors = {"allowed": "#21835A", "denied": "#C47716", "error": "#C43D4D"}
    return {
        "tooltip": {"trigger": "item", "formatter": "{b}: {c} ({d}%)"},
        "legend": {"bottom": 0, "left": "center"},
        "color": [colors[outcome] for outcome in counts],
        "series": [{
            "name": "Audit outcomes on this page",
            "type": "pie",
            "radius": ["46%", "70%"],
            "center": ["50%", "44%"],
            "label": {"show": False},
            "emphasis": {"scale": True, "scaleSize": 8},
            "data": [
                {"name": outcome.title(), "value": count}
                for outcome, count in counts.items()
            ],
        }],
    }


def _overview(api: DashboardAPI, identity: dict, database_id: str | None) -> None:
    st.header("Overview")
    health, ready = _status()
    st.caption(f"API {'available' if health else 'unavailable'} · "
               f"Control store {'ready' if ready else 'not ready'}")
    database_count: int | str = "No access"
    table_count: int | str = "No selection"
    scanned_count: int | str = "No access"
    pii_count: int | str = "No access"
    classification_counts: dict[str, int] | None = None
    pending_reviews = 0
    if _has(identity, "database:select"):
        try:
            databases = api.get("/databases").get("items", [])
            database_count = len(databases)
        except DashboardAPIError as exc:
            st.warning(f"Database registry unavailable: {exc}")
    if database_id:
        if _has(identity, "database:select"):
            try:
                table_count = len(_load_tables(api, database_id))
            except DashboardAPIError as exc:
                st.warning(f"Database is unavailable: {exc}")
        if _has(identity, "scan:read"):
            try:
                classification_counts, pending_reviews = _classification_breakdown(
                    api, database_id
                )
                scanned_count = sum(classification_counts.values())
                pii_count = sum(
                    count for tag, count in classification_counts.items()
                    if tag not in {
                        ClassificationTag.PUBLIC.value,
                        ClassificationTag.UNCLASSIFIED.value,
                    }
                )
            except DashboardAPIError as exc:
                st.info(f"Scan counts require completed scan metadata: {exc}")
        else:
            scanned_count = "No access"
            pii_count = "No access"
    metrics = st.columns(4)
    metrics[0].metric("Registered databases", database_count)
    metrics[1].metric("Tables discovered", table_count)
    metrics[2].metric("Scanned columns", scanned_count)
    metrics[3].metric("PII-classified", pii_count)
    if classification_counts is not None:
        chart_col, review_col = st.columns([1.5, 1])
        with chart_col:
            st.subheader("Classification breakdown")
            if sum(classification_counts.values()):
                st.echarts_chart(
                    _classification_chart(classification_counts),
                    height=360,
                    alt="Interactive breakdown of classified columns by sensitivity category.",
                    key="overview-classification-breakdown",
                )
            else:
                st.info("Run a scan to see classification results.")
        with review_col:
            st.subheader("Review queue")
            st.metric("Pending reviews", pending_reviews)
            st.caption("Classifications awaiting a reviewer decision.")
    st.subheader("Masking policies")
    if _has(identity, "policy:read"):
        try:
            policies = api.get("/policies").get("items", [])
            st.metric("Configured rules", len(policies))
        except DashboardAPIError as exc:
            st.warning(str(exc))
    else:
        st.caption("Policy count requires policy:read.")
    st.subheader("Recent audit activity")
    if _has(identity, "audit:read"):
        try:
            events = api.get("/audit-events", params={"limit": 10, "offset": 0}).get("items", [])
            st.dataframe(events, use_container_width=True, hide_index=True)
        except DashboardAPIError as exc:
            st.warning(str(exc))
    else:
        st.caption("Audit events require audit:read.")


def _connections(api: DashboardAPI, identity: dict, database_id: str | None) -> None:
    st.header("Registered database connections")
    if not _has(identity, "database:select"):
        st.warning("This account cannot select registered databases.")
        return
    try:
        items = api.get("/databases").get("items", [])
        st.dataframe(items, use_container_width=True, hide_index=True)
        if database_id:
            tables = _load_tables(api, database_id)
            st.success(f"{database_id} is reachable; discovered {len(tables)} table(s).")
            st.write(tables)
    except DashboardAPIError as exc:
        st.error(f"Connection check failed: {exc}")


def _scanner(api: DashboardAPI, identity: dict, database_id: str | None) -> None:
    st.header("PII scanner")
    if not database_id:
        st.info("Select a registered database with database:select.")
        return
    if _has(identity, "scan:run") and st.button("Scan schema and bounded samples", type="primary"):
        with st.status("Scanning schema and bounded samples...", expanded=True) as scan_status:
            try:
                result = api.post(f"/databases/{api.segment(database_id)}/scans", {})
                if result.get("status") == "completed":
                    scan_status.update(
                        label=f"Scan {result['scan_id']} completed",
                        state="complete",
                    )
                    st.success(f"{result['tables_scanned']} table(s), "
                               f"{result['columns_classified']} column(s) classified.")
                else:
                    scan_status.update(
                        label=f"Scan {result.get('scan_id')} finished with errors",
                        state="error",
                    )
                    st.warning("Review the scan report for columns that could not be scanned.")
                if result.get("errors"):
                    st.warning("One or more eligible columns could not be scanned.")
            except DashboardAPIError as exc:
                scan_status.update(label="Scan failed", state="error")
                st.error(f"Scan failed: {exc}")
    elif not _has(identity, "scan:run"):
        st.info("Starting scans requires scan:run.")

    if not _has(identity, "scan:read"):
        st.info("Viewing persisted classifications requires scan:read.")
        return
    try:
        _first_page, total = _load_classifications(api, database_id)
        page_size = st.select_slider("Classifications per page", options=[25, 50, 100, 250, 500], value=100)
        max_offset = max(0, ((total - 1) // page_size) * page_size)
        offset = st.number_input("Classification offset", min_value=0, max_value=max_offset,
                                 value=0, step=page_size, disabled=max_offset == 0)
        items, total = _load_classifications(api, database_id, offset=int(offset), limit=page_size)
        selected_tags = st.pills(
            "Filter by classification",
            options=[tag.value for tag in ClassificationTag],
            selection_mode="multi",
            key="classification-tag-filter",
            help="Choose one or more labels, or clear the selection to show every result.",
        )
        visible_items = [
            item for item in items
            if not selected_tags or item.get("classification") in selected_tags
        ]
        st.dataframe(
            visible_items,
            use_container_width=True,
            hide_index=True,
            column_config={
                "confidence": st.column_config.ProgressColumn(
                    "Confidence",
                    min_value=0,
                    max_value=1,
                    format="percent",
                ),
            },
        )
        st.caption(f"Showing {len(items)} of {total} classifications from offset {int(offset)}.")
    except DashboardAPIError as exc:
        st.warning(str(exc))
        return

    uncertain = [item for item in items if item.get("confidence", 1.0) < 0.7]
    if uncertain:
        st.caption(f"{len(uncertain)} classification(s) have confidence below 0.70.")
    if visible_items and _has(identity, "scan:review"):
        st.subheader("Review a classification")
        labels = {
            f"{x['table_name']}.{x['column_name']} · {x['classification']} · {x['confidence']:.2f}": x
            for x in visible_items
        }
        label = st.selectbox("Column", list(labels), key="review_column")
        selected = labels[label]
        status = st.selectbox("Decision", ["approved", "rejected"], key="review_status")
        options = [tag.value for tag in ClassificationTag]
        effective = st.selectbox("Effective classification", options,
                                 index=options.index(selected["classification"]),
                                 disabled=status != "approved")
        if st.button("Save review"):
            body = {"review_status": status}
            if status == "approved":
                body["classification"] = effective
            try:
                api.patch(f"/classifications/{selected['classification_id']}/review", body)
                st.success("Classification review saved.")
                st.rerun()
            except DashboardAPIError as exc:
                st.error(str(exc))


def _explorer(api: DashboardAPI, identity: dict, database_id: str | None) -> None:
    st.header("Masked-data explorer")
    st.caption("The API applies the persisted classification and policy before returning any row.")
    if not _has(identity, "data:read"):
        st.warning("Record previews require data:read.")
        return
    if not database_id or not _has(identity, "database:select"):
        st.info("Select a registered database with database:select.")
        return
    try:
        tables = _load_tables(api, database_id)
    except DashboardAPIError as exc:
        st.error(f"Database is unavailable: {exc}")
        return
    if not tables:
        st.info("No tables are available in this connection.")
        return
    table = st.selectbox("Table", tables)
    try:
        schema = api.get(f"/databases/{api.segment(database_id)}/tables/"
                         f"{api.segment(table)}/columns").get("columns", [])
    except DashboardAPIError as exc:
        st.error(f"Column discovery failed: {exc}")
        return
    names = [column["name"] for column in schema]
    default = ["id"] if "id" in names else names[:1]
    chosen = st.multiselect("Columns to preview", names, default=default)
    limit = st.number_input("Maximum rows", min_value=1, max_value=100,
                            value=10, step=1)
    if st.button("Load protected preview", type="primary", disabled=not chosen):
        try:
            result = api.get(
                f"/databases/{api.segment(database_id)}/tables/{api.segment(table)}/records",
                params={"limit": int(limit), "columns": chosen},
            )
            st.success(f"Received {result['row_count']} row(s) through the server-side policy service.")
            if _has(identity, "data:read_raw"):
                st.warning("This account has data:read_raw. Fields allowed by stored policy may be shown in full.")
            else:
                st.info("Restricted view: sensitive fields are transformed by the backend policy.")
            st.dataframe(result["rows"], use_container_width=True, hide_index=True)
        except DashboardAPIError as exc:
            if exc.status_code == 403:
                st.error("Access denied by the server. No protected response was displayed.")
            else:
                st.error(str(exc))


def _policies(api: DashboardAPI, identity: dict) -> None:
    st.header("Masking policies")
    if not _has(identity, "policy:read"):
        st.warning("Policy inspection requires policy:read.")
        return
    try:
        policies = api.get("/policies").get("items", [])
        st.dataframe(policies, use_container_width=True, hide_index=True)
    except DashboardAPIError as exc:
        st.error(str(exc))
        return
    if not _has(identity, "policy:write"):
        return
    roles = [role.value for role in Role]
    tags = [tag.value for tag in ClassificationTag]
    with st.expander("Create a scoped policy"):
        with st.form("create_policy"):
            role = st.selectbox("Role", roles)
            classification = st.selectbox("Classification", tags)
            action = st.selectbox("Action", ["allow", "mask", "redact", "hmac_sha256"])
            table_scope = st.text_input("Table scope (optional)", max_chars=128)
            column_scope = st.text_input("Column scope (optional)", max_chars=128)
            submit = st.form_submit_button("Create policy")
        if submit:
            body = {"role": role, "classification": classification, "action": action,
                    "table_scope": table_scope or None, "column_scope": column_scope or None}
            try:
                api.post("/policies", body)
                st.success("Policy created and recorded in policy history.")
                st.rerun()
            except DashboardAPIError as exc:
                st.error(str(exc))
    if policies:
        by_id = {f"{p['id']} · {p['role']} · {p['classification']} · {p['action']}": p
                 for p in policies}
        choice = st.selectbox("Policy to update", list(by_id))
        policy = by_id[choice]
        with st.form("update_policy"):
            action = st.selectbox("New action", ["allow", "mask", "redact", "hmac_sha256"],
                                  index=["allow", "mask", "redact", "hmac_sha256"].index(policy["action"]))
            enabled = st.checkbox("Enabled", value=policy["enabled"])
            submit = st.form_submit_button("Save policy")
        if submit:
            try:
                api.patch(f"/policies/{policy['id']}", {"action": action, "enabled": enabled})
                st.success("Policy updated; the change is effective on the next query.")
                st.rerun()
            except DashboardAPIError as exc:
                st.error(str(exc))


def _users(api: DashboardAPI, identity: dict) -> None:
    st.header("Users and permissions")
    if not _has(identity, "users:manage"):
        st.warning("User administration requires users:manage.")
        return
    try:
        users = api.get("/users").get("items", [])
        permissions = api.get("/permissions").get("items", [])
    except DashboardAPIError as exc:
        st.error(str(exc))
        return
    st.dataframe(users, use_container_width=True, hide_index=True)
    if not users:
        return
    user_by_label = {f"{user['username']} · {user['role']} · {user['id']}": user for user in users}
    chosen = user_by_label[st.selectbox("Account", list(user_by_label))]
    current_permissions = chosen.get("permissions", [])
    st.caption("Role or permission changes apply server-side. Role changes revoke that account’s current tokens.")
    if chosen["id"] == identity["user_id"]:
        st.info("The API prevents administrators from changing their own role or permissions.")
        return
    with st.form("change_role"):
        role = st.selectbox("New role", [item.value for item in Role],
                            index=[item.value for item in Role].index(chosen["role"]))
        submit = st.form_submit_button("Change role")
    if submit:
        try:
            api.patch(f"/users/{api.segment(chosen['id'])}/role", {"role": role})
            st.success("Role changed and existing account tokens revoked.")
            st.rerun()
        except DashboardAPIError as exc:
            st.error(str(exc))
    available = [permission for permission in permissions if permission not in current_permissions]
    with st.form("grant_permission"):
        grant = st.selectbox("Grant permission", available, disabled=not available)
        submit_grant = st.form_submit_button("Grant", disabled=not available)
    if submit_grant:
        try:
            api.put(f"/users/{api.segment(chosen['id'])}/permissions", {"permission": grant})
            st.success("Permission granted.")
            st.rerun()
        except DashboardAPIError as exc:
            st.error(str(exc))
    if current_permissions:
        with st.form("revoke_permission"):
            revoke = st.selectbox("Revoke permission", current_permissions)
            submit_revoke = st.form_submit_button("Revoke")
        if submit_revoke:
            try:
                api.delete(f"/users/{api.segment(chosen['id'])}/permissions",
                           {"permission": revoke})
                st.success("Permission revoked.")
                st.rerun()
            except DashboardAPIError as exc:
                st.error(str(exc))


def _audit(api: DashboardAPI, identity: dict) -> None:
    st.header("Audit viewer")
    if not _has(identity, "audit:read"):
        st.warning("Audit event access requires audit:read.")
        return
    limit = st.select_slider("Page size", options=[25, 50, 100, 250], value=100)
    offset = st.number_input("Offset", min_value=0, max_value=1_000_000,
                             value=0, step=limit)
    search = st.text_input("Filter this page", placeholder="actor, operation, outcome, or resource")
    try:
        result = api.get("/audit-events", params={"limit": limit, "offset": int(offset)})
        events = result.get("items", [])
        outcomes = st.pills(
            "Filter by outcome",
            options=["Allowed", "Denied", "Error"],
            selection_mode="multi",
            key="audit-outcome-filter",
            help="Choose outcomes to show, or clear the selection to show every result.",
        )
        if outcomes:
            selected_outcomes = {outcome.lower() for outcome in outcomes}
            events = [
                event for event in events
                if str(event.get("outcome", "")).lower() in selected_outcomes
            ]
        if search:
            needle = search.casefold()
            events = [event for event in events
                      if needle in " ".join(str(value) for value in event.values()).casefold()]
        st.subheader("Outcome summary for this page")
        if any(event.get("outcome") in {"allowed", "denied", "error"} for event in events):
            st.echarts_chart(
                _audit_outcome_chart(events),
                height=300,
                alt="Interactive chart of allowed, denied, and error outcomes in the current audit page.",
                key="audit-outcome-summary",
            )
        else:
            st.info("No outcome data is available on this page.")
        st.dataframe(events, use_container_width=True, hide_index=True)
        st.caption(f"Showing {len(events)} event(s) from the requested page. Audit records are read-only.")
    except DashboardAPIError as exc:
        st.error(str(exc))


def _status_page(api: DashboardAPI, identity: dict, database_id: str | None) -> None:
    st.header("API and database status")
    health, ready = _status()
    left, right = st.columns(2)
    left.metric("API process", "Available" if health else "Unavailable")
    right.metric("Control store", "Ready" if ready else "Not ready")
    st.badge(
        "API available" if health else "API unavailable",
        icon=":material/check_circle:" if health else ":material/error:",
        color="green" if health else "red",
    )
    st.badge(
        "Control store ready" if ready else "Control store not ready",
        icon=":material/check_circle:" if ready else ":material/error:",
        color="green" if ready else "red",
    )
    st.caption("Dashboard availability does not imply that the API or every source database is healthy.")
    if database_id and _has(identity, "database:select"):
        try:
            tables = _load_tables(api, database_id)
            st.success(f"{database_id}: reachable ({len(tables)} table(s) discovered).")
        except DashboardAPIError as exc:
            st.error(f"{database_id}: unavailable ({exc}).")


def main() -> None:
    st.set_page_config(page_title="Avarna", page_icon=":material/shield_lock:", layout="wide")
    _apply_ui_theme()
    st.sidebar.title("Avarna")
    st.sidebar.caption("PII discovery and policy-controlled data access")
    prior_api_base = st.session_state.get("avarna_api_base")
    if prior_api_base and prior_api_base != _api_base():
        _clear_session()
    token = st.session_state.get("avarna_token")
    if not token:
        health, ready = _status()
        st.sidebar.caption(f"API {'available' if health else 'unavailable'} · "
                           f"Control store {'ready' if ready else 'not ready'}")
        _login()
        return

    api = _api(token)
    try:
        identity = api.get("/auth/me")
    except DashboardAPIError as exc:
        if exc.status_code == 401:
            _clear_session()
            st.warning("Your session expired or is no longer valid. Please sign in again.")
            st.rerun()
            return
        st.error(f"Could not load the authenticated identity: {exc}")
        return

    st.sidebar.markdown("### Workspace")
    st.sidebar.write(f"**{identity['username']}**")
    st.sidebar.caption(f"{identity['role']} · {len(identity.get('permissions', []))} permissions")
    if st.sidebar.button("Log out"):
        try:
            api.post("/auth/logout")
        except DashboardAPIError:
            pass
        _clear_session()
        st.rerun()

    database_id = _database_selector(api, identity)
    pages = ["Overview", "Connections", "PII scanner", "Masked-data explorer",
             "Policies", "Users and permissions", "Audit viewer", "API status"]
    page = st.sidebar.radio("Workspace", pages)
    safe_username = escape(str(identity["username"]))
    safe_role = escape(str(identity["role"]))
    st.markdown(
        f"""
        <div class="avarna-hero">
            <div class="eyebrow">Secure data governance</div>
            <h1>{page}</h1>
            <p>Signed in as {safe_username} · role: {safe_role}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.caption(f"Authenticated as {identity['username']} ({identity['role']})")

    if page == "Overview":
        _overview(api, identity, database_id)
    elif page == "Connections":
        _connections(api, identity, database_id)
    elif page == "PII scanner":
        _scanner(api, identity, database_id)
    elif page == "Masked-data explorer":
        _explorer(api, identity, database_id)
    elif page == "Policies":
        _policies(api, identity)
    elif page == "Users and permissions":
        _users(api, identity)
    elif page == "Audit viewer":
        _audit(api, identity)
    else:
        _status_page(api, identity, database_id)


if __name__ == "__main__":
    main()
