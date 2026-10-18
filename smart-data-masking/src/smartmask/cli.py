"""Basic, honest developer CLI for the Smart Data Masking System.

Commands:
    smartmask --help
    smartmask init
    smartmask seed-demo
    smartmask scan
    smartmask classifications
    smartmask seed-policies
    smartmask demo --role Admin
    smartmask demo --role Support
    smartmask demo --role Analyst

Role selection in the CLI is a local demonstration mechanism, NOT secure
authentication. This is a developer prototype.

The CLI returns meaningful exit codes and produces useful error messages
without stack traces by default. Use --debug for developer traces that avoid
leaking secrets or record contents.
"""

from __future__ import annotations

import argparse
import logging
import getpass
import sys
import traceback
from typing import Optional, Sequence

from .config import AppConfig
from .database.connection import DatabaseManager
from .database.sqlite_adapter import SQLiteAdapter
from .exceptions import SmartMaskError
from .masking.engine import MaskingEngine
from .masking.policy_repository import PolicyRepository
from .masking.transformations import REDACTED
from .models import Principal, Role
from .scanner.metadata_repository import MetadataRepository
from .scanner.scanner import Scanner
from .service.query_service import QueryService
from .audit.repository import AuditRepository
from .auth.password_service import PasswordService
from .auth.user_repository import UserRepository

logger = logging.getLogger("smartmask.cli")


class _Context:
    """Holds wired-up components for a CLI invocation."""

    def __init__(self, config: AppConfig, debug: bool = False) -> None:
        self.config = config
        self.debug = debug
        self.db_manager: Optional[DatabaseManager] = None


def _setup_logging(level: str, debug: bool) -> None:
    """Configure logging without sensitive data."""
    log_level = "DEBUG" if debug else level
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _build_context(config: AppConfig, debug: bool = False) -> _Context:
    ctx = _Context(config, debug=debug)
    ctx.db_manager = DatabaseManager(config.source_db_url, config.control_db_url)
    ctx.db_manager.initialize()
    return ctx


def _require_db(ctx: _Context) -> DatabaseManager:
    if ctx.db_manager is None:
        raise RuntimeError("Database manager not initialized.")
    return ctx.db_manager


def _adapter(ctx: _Context) -> SQLiteAdapter:
    return SQLiteAdapter(
        ctx.config.source_db_url, max_sample_rows=ctx.config.max_sample_rows,
        max_query_rows=ctx.config.max_query_limit,
    )


def cmd_init(args: argparse.Namespace, ctx: _Context) -> int:
    """Initialize the control database and required metadata schema safely."""
    db_manager = _require_db(ctx)
    metadata_repo = MetadataRepository(db_manager)
    try:
        metadata_repo.initialize_schema()
        print("Control database initialized successfully.")
        return 0
    except SmartMaskError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        if ctx.debug:
            traceback.print_exc()
        return 1


def cmd_seed_demo(args: argparse.Namespace, ctx: _Context) -> int:
    """Create the demo source schema and insert fictional data repeatably."""
    # Import here to avoid requiring the setup script at module import time.
    import importlib.util
    from pathlib import Path

    setup_path = Path(__file__).resolve().parent.parent.parent / "data" / "setup_demo.py"
    spec = importlib.util.spec_from_file_location("setup_demo", setup_path)
    if spec is None or spec.loader is None:
        print("ERROR: Could not locate demo setup script.", file=sys.stderr)
        return 1
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        print(f"ERROR: Failed to load demo setup script: {exc}", file=sys.stderr)
        if ctx.debug:
            traceback.print_exc()
        return 1

    try:
        module.main(["--db-url", ctx.config.source_db_url])
        return 0
    except SystemExit as exc:
        return int(exc.code or 0)


def cmd_scan(args: argparse.Namespace, ctx: _Context) -> int:
    """Run the PII scanner, persist classifications and report the outcome."""
    db_manager = _require_db(ctx)
    metadata_repo = MetadataRepository(db_manager)
    adapter = _adapter(ctx)

    scanner = Scanner(
        adapter=adapter,
        metadata_repository=metadata_repo,
        sample_size=ctx.config.max_sample_rows,
    )

    try:
        report = scanner.scan_database(
            sample_size=ctx.config.max_sample_rows
        )
    except SmartMaskError as exc:
        print(f"ERROR: Scan failed: {exc}", file=sys.stderr)
        if ctx.debug:
            traceback.print_exc()
        return 1

    print(f"Scan run {report.scan_run_id}: {'FAILED' if report.failed else 'completed'}")
    print(f"Tables scanned: {report.tables_scanned}")
    print(f"Columns classified: {report.columns_classified}")
    if report.errors:
        print("Errors:")
        for err in report.errors:
            print(f"  - {err}")
    if report.classifications:
        print("Classifications:")
        for cls in report.classifications:
            print(
                f"  {cls.table_name}.{cls.column_name:20s} "
                f"{cls.classification.value:24s} conf={cls.confidence}"
            )
    return 1 if report.failed else 0


def cmd_classifications(args: argparse.Namespace, ctx: _Context) -> int:
    """Display a readable classification table without sample values."""
    db_manager = _require_db(ctx)
    metadata_repo = MetadataRepository(db_manager)
    try:
        rows = metadata_repo.list_classifications()
    except SmartMaskError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        if ctx.debug:
            traceback.print_exc()
        return 1

    if not rows:
        print("No classifications found. Run 'smartmask scan' first.")
        return 0

    print(f"{'ID':<5} {'Table':<12} {'Column':<22} {'Classification':<24} {'Confidence':<10} {'Review'}")
    print("-" * 88)
    for cls in rows:
        print(
            f"{(cls.classification_id or ''):<5} {cls.table_name:<12} {cls.column_name:<22} "
            f"{cls.classification.value:<24} {cls.confidence:<10.2f} "
            f"{cls.review_status.value}"
        )
    return 0


def cmd_seed_policies(args: argparse.Namespace, ctx: _Context) -> int:
    """Create the baseline policies idempotently."""
    db_manager = _require_db(ctx)
    policy_repo = PolicyRepository(db_manager)
    try:
        inserted = policy_repo.seed_baseline_policies()
        print(f"Baseline policies seeded. {inserted} new rule(s) added.")
        return 0
    except SmartMaskError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        if ctx.debug:
            traceback.print_exc()
        return 1


def cmd_review(args: argparse.Namespace, ctx: _Context) -> int:
    """Record an explicit human review decision for a classification."""
    repo = MetadataRepository(_require_db(ctx))
    try:
        from .models import ReviewStatus
        status = ReviewStatus.APPROVED if args.approve else ReviewStatus.REJECTED
        repo.update_review_status(args.classification_id, review_status=status,
                                  reviewer=args.reviewer)
        print(f"Classification {args.classification_id} marked {status.value}.")
        return 0
    except SmartMaskError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


def cmd_users(args: argparse.Namespace, ctx: _Context) -> int:
    """Provision accounts locally; passwords are only accepted interactively."""
    manager = _require_db(ctx)
    MetadataRepository(manager).initialize_schema()
    users, audit = UserRepository(manager), AuditRepository(manager)
    username = getattr(args, "username", None)
    try:
        if args.users_command == "create":
            first = getpass.getpass("New password (12-128 characters): ")
            second = getpass.getpass("Confirm password: ")
            if first != second:
                raise ValueError("Passwords do not match.")
            user = users.create(username, PasswordService.hash(first), Role(args.role))
            audit.record_event(principal_user_id=user.id, operation="user_created",
                outcome="allowed", reason="LOCAL_USER_CREATED", actor_id="local-cli")
            print(f"Created user {user.username} ({user.id}) with role {user.role.value}.")
        elif args.users_command == "list":
            for user in users.list_users():
                print(f"{user['username']}\t{user['role']}\t{'active' if user['is_active'] else 'inactive'}\t{','.join(user['permissions'])}")
        elif args.users_command == "grant":
            changed = users.grant(username, args.permission, granted_by="local-cli")
            target = users.get_by_username(username)
            audit.record_event(principal_user_id=target.id, operation="permission_granted", outcome="allowed",
                reason=f"PERMISSION_GRANT:{args.permission}", actor_id="local-cli")
            print("Permission granted." if changed else "Permission already granted.")
        elif args.users_command == "revoke":
            changed = users.revoke(username, args.permission)
            target = users.get_by_username(username)
            audit.record_event(principal_user_id=target.id, operation="permission_revoked", outcome="allowed",
                reason=f"PERMISSION_REVOKE:{args.permission}", actor_id="local-cli")
            print("Permission revoked." if changed else "Permission was not granted.")
        elif args.users_command in {"activate", "deactivate"}:
            active = args.users_command == "activate"
            user = users.update(username, active=active, revoke_tokens=not active)
            audit.record_event(principal_user_id=user.id, operation=f"user_{args.users_command}",
                outcome="allowed", reason=f"USER_{args.users_command.upper()}", actor_id="local-cli")
            print(f"User {username} {'activated' if active else 'deactivated'}.")
        elif args.users_command == "set-role":
            user = users.update(username, role=Role(args.role), revoke_tokens=True)
            audit.record_event(principal_user_id=user.id, operation="user_role_changed",
                outcome="allowed", reason=f"ROLE_CHANGED:{user.role.value}", actor_id="local-cli")
            print(f"Updated role for {username} to {user.role.value}.")
        elif args.users_command == "reset-password":
            first = getpass.getpass("New password (12-128 characters): ")
            second = getpass.getpass("Confirm password: ")
            if first != second:
                raise ValueError("Passwords do not match.")
            user = users.update(username, password_hash=PasswordService.hash(first), revoke_tokens=True)
            audit.record_event(principal_user_id=user.id, operation="password_reset",
                outcome="allowed", reason="PASSWORD_RESET", actor_id="local-cli")
            print(f"Password reset for {username}; prior tokens revoked.")
        return 0
    except (ValueError, SmartMaskError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


def _demo_role(role_str: str) -> Principal:
    """Build a demonstration principal. NOT secure authentication."""
    try:
        role = Role(role_str)
    except ValueError:
        raise SystemExit(f"Unknown role: {role_str}. Supported: {[r.value for r in Role]}")
    return Principal(user_id=f"demo-{role_str.lower()}", role=role)


def cmd_demo(args: argparse.Namespace, ctx: _Context) -> int:
    """Retrieve records through the controlled query service using a demo identity.

    Role selection is a local demonstration mechanism, not real authentication.
    """
    principal = _demo_role(args.role)
    db_manager = _require_db(ctx)
    adapter = _adapter(ctx)
    policy_repo = PolicyRepository(db_manager)
    audit_repo = AuditRepository(db_manager)
    masking_engine = MaskingEngine(ctx.config)
    service = QueryService(
        adapter=adapter,
        db_manager=db_manager,
        policy_repository=policy_repo,
        audit_repository=audit_repo,
        masking_engine=masking_engine,
        config=ctx.config,
    )

    table_name = getattr(args, "table", "customers")
    limit = getattr(args, "limit", ctx.config.default_query_limit)

    try:
        result = service.query_records(
            principal=principal,
            table_name=table_name,
            limit=limit,
        )
    except SmartMaskError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        if ctx.debug:
            traceback.print_exc()
        return 1

    print(f"Demo as role '{principal.role.value}' (user {principal.user_id})")
    print(f"Table: {result.table_name} | Rows returned: {result.row_count}")
    if result.columns:
        header = " | ".join(result.columns)
        print(header)
        print("-" * len(header))
        for row in result.rows:
            print(" | ".join(
                str(row.get(col, "")) if row.get(col) is not None else "NULL"
                for col in result.columns
            ))
    else:
        print("(no rows)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="smartmask",
        description="Smart Data Masking System - developer CLI (Part 1 prototype).",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Show developer tracebacks (avoid leaking secrets/record contents).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Initialize the control database schema.")

    sub.add_parser(
        "seed-demo",
        help="Create the demo source schema and insert fictional data.",
    )

    sub.add_parser("scan", help="Run the PII scanner and persist classifications.")

    sub.add_parser(
        "classifications",
        help="Display the classification table (no sample values).",
    )

    sub.add_parser(
        "seed-policies",
        help="Seed baseline role-and-classification policies.",
    )

    review_parser = sub.add_parser("review", help="Approve or reject a classification.")
    review_parser.add_argument("classification_id", type=int)
    review_group = review_parser.add_mutually_exclusive_group(required=True)
    review_group.add_argument("--approve", action="store_true")
    review_group.add_argument("--reject", action="store_true")
    review_parser.add_argument("--reviewer", required=True)

    users_parser = sub.add_parser("users", help="Provision API users through the local CLI.")
    users_sub = users_parser.add_subparsers(dest="users_command", required=True)
    create_user = users_sub.add_parser("create")
    create_user.add_argument("--username", required=True)
    create_user.add_argument("--role", choices=[r.value for r in Role], required=True)
    users_sub.add_parser("list")
    for command in ("grant", "revoke"):
        item = users_sub.add_parser(command)
        item.add_argument("--username", required=True)
        item.add_argument("--permission", required=True)
    for command in ("activate", "deactivate", "reset-password"):
        item = users_sub.add_parser(command)
        item.add_argument("--username", required=True)
    set_role = users_sub.add_parser("set-role")
    set_role.add_argument("--username", required=True)
    set_role.add_argument("--role", choices=[r.value for r in Role], required=True)

    demo_parser = sub.add_parser(
        "demo",
        help="Run a role-based demonstration query.",
    )
    demo_parser.add_argument(
        "--role",
        required=True,
        choices=[r.value for r in Role],
        help="Demo role (local demonstration mechanism, not real authentication).",
    )
    demo_parser.add_argument(
        "--table",
        default="customers",
        help="Table to query (default: customers).",
    )
    demo_parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum rows to return (clamped to configured max).",
    )

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Configure logging first so errors are captured.
    try:
        config = AppConfig.from_env()
    except ValueError as exc:
        print(f"ERROR: Invalid configuration: {exc}", file=sys.stderr)
        return 1

    _setup_logging(config.log_level, args.debug)

    ctx = _build_context(config, debug=args.debug)

    commands = {
        "init": cmd_init,
        "seed-demo": cmd_seed_demo,
        "scan": cmd_scan,
        "classifications": cmd_classifications,
        "seed-policies": cmd_seed_policies,
        "review": cmd_review,
        "users": cmd_users,
        "demo": cmd_demo,
    }

    handler = commands.get(args.command)
    if handler is None:
        print(f"ERROR: Unknown command: {args.command}", file=sys.stderr)
        return 1

    try:
        return handler(args, ctx)
    except SmartMaskError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        if args.debug:
            traceback.print_exc()
        return 1
    except Exception as exc:  # pragma: no cover - defensive top-level
        # Never leak secrets or record contents in the default message.
        print(f"ERROR: Unexpected failure: {exc}", file=sys.stderr)
        if args.debug:
            traceback.print_exc()
        return 1
    finally:
        if ctx.db_manager is not None:
            ctx.db_manager.dispose()


if __name__ == "__main__":
    sys.exit(main())
