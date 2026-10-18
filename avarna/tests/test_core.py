from sqlalchemy import select
from sqlalchemy import text
from sqlalchemy.orm import Session
import pytest

from avarna.audit.repository import AuditRepository
from avarna.database.sqlite_adapter import SQLiteAdapter
from avarna.masking.engine import MaskingEngine
from avarna.masking.policy_repository import PolicyRepository
from avarna.models import Principal, Role, ClassificationTag
from avarna.scanner.scanner import Scanner
from avarna.database.models import ColumnClassification, AccessEvent, Policy
from avarna.service.query_service import QueryService


def test_scan_metadata_privacy_and_limits(env):
    config, manager, metadata = env
    adapter = SQLiteAdapter(config.source_db_url, max_sample_rows=2)
    assert adapter.list_tables() == ["customers"]
    assert len(adapter.fetch_column_sample("customers", "email", 99)) <= 2
    before = adapter.fetch_records("customers", 10)
    report = Scanner(adapter, metadata, sample_size=99).scan_database()
    assert report.success and report.columns_classified == 10
    assert all(item.scan_run_id == report.scan_run_id for item in report.classifications)
    assert metadata.list_classifications()
    assert len(metadata.list_classifications()) == 10
    assert adapter.fetch_records("customers", 10) == before
    with Session(manager.control_engine) as session:
        saved = " ".join(row.reasons for row in session.scalars(select(ColumnClassification)))
        assert "arun@example.test" not in saved
        run_count = len(list(session.scalars(select(ColumnClassification))))
        assert run_count == 10
    adapter.dispose()


def test_role_query_fails_closed_and_preserves_source(env):
    config, manager, metadata = env
    adapter = SQLiteAdapter(config.source_db_url, max_sample_rows=10)
    Scanner(adapter, metadata).scan_database()
    policies = PolicyRepository(manager)
    policies.seed_baseline_policies()
    service = QueryService(adapter, manager, policies, AuditRepository(manager),
                           MaskingEngine(config), config)
    support = service.query_records(Principal("support", Role.SUPPORT), "customers", 1)
    row = support.rows[0]
    assert row["email"].startswith("a***@")
    assert row["account_balance"] == "[REDACTED]"
    assert row["credit_card"] == "XXXX-XXXX-XXXX-1111"
    analyst = service.query_records(Principal("analyst", Role.ANALYST), "customers", 1)
    assert len(analyst.rows[0]["email"]) == 64
    admin = service.query_records(Principal("admin", Role.ADMIN,
        permissions=frozenset({"data:read_raw"})), "customers", 1)
    assert admin.rows[0]["email"] == "arun@example.test"
    with Session(manager.source_engine) as session:
        assert session.execute(text("SELECT email FROM customers LIMIT 1")).scalar_one() == "arun@example.test"
    with Session(manager.control_engine) as session:
        events = list(session.scalars(select(AccessEvent)))
        assert events and all("arun@example.test" not in event.reason for event in events)
    with pytest.raises(Exception):
        service.query_records(Principal("support", Role.SUPPORT), "unknown", 1)
    adapter.dispose()


def test_cli_help_and_commands(env, monkeypatch):
    from avarna.cli import build_parser
    assert "seed-policies" in build_parser().format_help()


def test_missing_policy_and_unknown_role_fail_closed(env):
    from avarna.exceptions import InvalidPrincipalError
    from avarna.models import Principal
    from avarna.masking.policy_repository import PolicyRepository
    from avarna.masking.engine import MaskingEngine
    from avarna.audit.repository import AuditRepository
    from avarna.service.query_service import QueryService

    config, manager, _ = env
    adapter = SQLiteAdapter(config.source_db_url, max_sample_rows=10)
    service = QueryService(adapter, manager, PolicyRepository(manager),
                           AuditRepository(manager), MaskingEngine(config), config)
    result = service.query_records(Principal("x", Role.ANALYST), "customers", 1)
    assert all(value == "[REDACTED]" for value in result.rows[0].values())
    with pytest.raises(InvalidPrincipalError):
        service.query_records(Principal("x", "Root"), "customers", 1)
    adapter.dispose()


def test_review_status_is_persisted(env):
    from avarna.models import ReviewStatus
    config, manager, metadata = env
    adapter = SQLiteAdapter(config.source_db_url)
    Scanner(adapter, metadata).scan_database()
    entry = metadata.list_classifications()[0]
    metadata.update_review_status(entry.classification_id,
                                  review_status=ReviewStatus.APPROVED,
                                  reviewer="reviewer-1")
    reviewed = metadata.get_latest_classification(entry.table_name, entry.column_name)
    assert reviewed.review_status == ReviewStatus.APPROVED
    assert reviewed.reviewer == "reviewer-1"


def test_disabled_field_policy_overrides_general_allow_and_fails_closed(env):
    from avarna.models import MaskingAction
    config, manager, metadata = env
    adapter = SQLiteAdapter(config.source_db_url, max_sample_rows=10,
                            max_query_rows=config.max_query_limit)
    Scanner(adapter, metadata).scan_database()
    policies = PolicyRepository(manager)
    policies.seed_baseline_policies()
    with Session(manager.control_engine) as session:
        session.add(Policy(role=Role.SUPPORT, classification=ClassificationTag.PII_HIGH,
            action="allow", table_scope="customers", column_scope="email", enabled=False,
            policy_version="1.0"))
        session.commit()
    service = QueryService(adapter, manager, policies, AuditRepository(manager),
                           MaskingEngine(config), config)
    result = service.query_records(Principal("support", Role.SUPPORT), "customers", 1)
    assert result.rows[0]["email"] == "[REDACTED]"
    adapter.dispose()


def test_banking_roles_have_explicit_fail_safe_baseline_policies(env):
    from avarna.masking.policy import PolicyEngine

    _config, manager, _metadata = env
    repository = PolicyRepository(manager)
    repository.seed_baseline_policies()
    assert repository.seed_baseline_policies() == 0
    engine = PolicyEngine(repository)
    expected = {
        Role.COMPLIANCE_OFFICER: ("mask", "mask"),
        Role.FRAUD_RISK_ANALYST: ("hmac_sha256", "mask"),
        Role.BANKING_OPERATIONS: ("mask", "mask"),
        Role.INTERNAL_AUDITOR: ("redact", "redact"),
        Role.DATA_PROTECTION_OFFICER: ("mask", "mask"),
    }

    for role, (pii_action, financial_action) in expected.items():
        pii = engine.evaluate_policy(
            "user", role, "customers", "email", ClassificationTag.PII_HIGH
        )
        financial = engine.evaluate_policy(
            "user", role, "customers", "account_balance",
            ClassificationTag.FINANCIAL_CONFIDENTIAL,
        )
        assert pii.action.value == pii_action
        assert financial.action.value == financial_action


def test_cli_accepts_banking_role_names():
    from avarna.cli import build_parser

    parser = build_parser()
    for role in (
        "Compliance Officer",
        "Fraud/Risk Analyst",
        "Banking Operations",
        "Internal Auditor",
        "Data Protection Officer",
    ):
        parsed = parser.parse_args(["users", "create", "--username", "bankuser", "--role", role])
        assert parsed.role == role
