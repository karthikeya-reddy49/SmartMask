"""Controlled query service.

Integrates the adapter, classification repository, policy repository, masking
engine and audit repository. Results are transformed before they leave the
service. No arbitrary SQL execution is supported.
"""

from __future__ import annotations

import logging
from typing import Optional

from ..audit.repository import AuditRepository
from ..database.adapter import DatabaseAdapter
from ..database.connection import DatabaseManager
from ..exceptions import (
    DatabaseError,
    InvalidLimitError,
    InvalidPrincipalError,
    UnknownColumnError,
    UnknownTableError,
)
from ..masking.engine import MaskingEngine
from ..masking.policy import PolicyEngine
from ..masking.policy_repository import PolicyRepository
from ..models import ClassificationTag, MaskingAction, Principal, Role
from ..schemas import (
    PolicyDecision,
    QueryRequest,
    QueryResult,
)
from ..scanner.metadata_repository import MetadataRepository

logger = logging.getLogger(__name__)


class QueryService:
    """Controlled read-only query service with role-based masking."""

    def __init__(
        self,
        adapter: DatabaseAdapter,
        db_manager: DatabaseManager,
        policy_repository: PolicyRepository,
        audit_repository: AuditRepository,
        masking_engine: MaskingEngine,
        config,
        database_id: str = "sqlite_demo",
        request_id: Optional[str] = None,
    ) -> None:
        self._adapter = adapter
        self._db_manager = db_manager
        self._policy_repository = policy_repository
        self._audit_repository = audit_repository
        self._masking_engine = masking_engine
        self._config = config
        self._database_id = database_id
        self._request_id = request_id
        self._policy_engine = PolicyEngine(policy_repository)
        self._metadata_repository = MetadataRepository(db_manager)

    def query_records(
        self,
        principal: Principal,
        table_name: str,
        limit: Optional[int] = None,
        offset: int = 0,
        columns: Optional[list[str]] = None,
    ) -> QueryResult:
        """Retrieve and transform records for a principal.

        Steps:
          1. Validate the principal and role.
          2. Validate the requested table against schema metadata.
          3. Enforce a reasonable result limit.
          4. Retrieve only the requested supported records.
          5. Obtain the applicable classification for each returned column.
          6. Evaluate the policy for every field and the requesting principal.
          7. Apply the selected transformation.
          8. Return the transformed result.
          9. Record a basic access event without logging sensitive values.

        Fail-closed: if a field is unclassified, a policy is missing, or a
        transformation/security dependency fails, raw values are not returned.
        """
        # 1. Validate principal and role.
        if principal is None or not principal.user_id:
            raise InvalidPrincipalError("A valid principal is required.")
        try:
            normalized_role = Role(principal.role)
        except ValueError as exc:
            raise InvalidPrincipalError(
                f"Unknown or unsupported role: {principal.role}"
            ) from exc
        if principal.role is not normalized_role:
            principal = Principal(user_id=principal.user_id, role=normalized_role,
                                  username=principal.username,
                                  permissions=principal.permissions)

        # 2. Validate the requested table against actual schema metadata.
        try:
            tables = self._adapter.list_tables()
        except Exception as exc:
            self._audit_repository.record_event(
                principal_user_id=principal.user_id,
                principal_role=principal.role.value,
                operation="query_records",
                table_name=table_name,
                outcome="error",
                reason="Failed to list configured tables.",
                actor_id=principal.user_id, database_id=self._database_id,
                request_id=self._request_id,
            )
            raise DatabaseError("Unable to access source database schema.") from exc

        if table_name not in tables:
            self._audit_repository.record_event(
                principal_user_id=principal.user_id,
                principal_role=principal.role.value,
                operation="query_records",
                table_name=table_name,
                outcome="denied",
                reason="Unknown table.",
                actor_id=principal.user_id, database_id=self._database_id,
                request_id=self._request_id,
            )
            raise UnknownTableError(
                f"Table '{table_name}' does not exist or is not accessible."
            )

        if columns is not None:
            available = {item["name"] for item in self._adapter.get_columns(table_name)}
            if (not columns or len(columns) > 100 or len(set(columns)) != len(columns)
                    or any(not isinstance(name, str) or name not in available for name in columns)):
                raise UnknownColumnError("One or more requested columns are unavailable.")

        # 3. Enforce a reasonable result limit.
        try:
            effective_limit = self._adapter.clamp_limit(
                limit, self._config.default_query_limit
            )
            effective_limit = min(effective_limit, self._config.max_query_limit)
        except InvalidLimitError as exc:
            self._audit_repository.record_event(
                principal_user_id=principal.user_id,
                principal_role=principal.role.value,
                operation="query_records",
                table_name=table_name,
                outcome="denied",
                reason=str(exc),
                actor_id=principal.user_id, database_id=self._database_id,
                request_id=self._request_id,
            )
            raise

        # 4. Retrieve only the requested supported records.
        try:
            raw_rows = self._adapter.fetch_records(table_name, effective_limit, offset, columns)
        except Exception as exc:
            self._audit_repository.record_event(
                principal_user_id=principal.user_id,
                principal_role=principal.role.value,
                operation="query_records",
                table_name=table_name,
                outcome="error",
                reason="Failed to retrieve source records.",
                actor_id=principal.user_id, database_id=self._database_id,
                request_id=self._request_id,
            )
            raise DatabaseError("Failed to retrieve source records.") from exc

        if not raw_rows:
            self._audit_repository.record_event(
                principal_user_id=principal.user_id,
                principal_role=principal.role.value,
                operation="query_records",
                table_name=table_name,
                outcome="allowed",
                reason="No rows returned.",
                actor_id=principal.user_id, database_id=self._database_id,
                request_id=self._request_id,
            )
            return QueryResult(
                table_name=table_name,
                columns=[],
                rows=[],
                row_count=0,
                principal_user_id=principal.user_id,
                principal_role=principal.role.value,
                decisions_applied=0,
            )

        columns = list(raw_rows[0].keys())

        # 5-7. Classify, evaluate policy, transform each field.
        transformed_rows = []
        decisions_applied = 0
        failed_closed_fields = 0

        for row in raw_rows:
            transformed_row = {}
            for column_name in columns:
                # Obtain classification for this column.
                classification = self._get_classification(table_name, column_name)
                if classification is None:
                    # Missing classification -> fail closed: treat as unknown,
                    # not safe. Redact for non-admin.
                    classification = ClassificationTag.UNCLASSIFIED

                # Evaluate policy.
                try:
                    decision = self._policy_engine.evaluate_policy(
                        principal_user_id=principal.user_id,
                        principal_role=principal.role,
                        table_name=table_name,
                        column_name=column_name,
                        classification=classification,
                    )
                    if (decision.action.value == "allow"
                            and classification != ClassificationTag.PUBLIC
                            and "data:read_raw" not in principal.permissions):
                        decision = PolicyDecision(
                            principal_user_id=decision.principal_user_id,
                            principal_role=decision.principal_role,
                            table_name=decision.table_name,
                            column_name=decision.column_name,
                            classification=decision.classification,
                            action=MaskingAction.MASK,
                            allowed=False,
                            matched_rule=decision.matched_rule,
                            reason="Raw-data permission is not granted; applying a safe mask.",
                            policy_version=decision.policy_version,
                        )
                except Exception as exc:
                    # Policy evaluation failure -> fail closed.
                    logger.error("Policy evaluation failed for %s.%s; failing closed.",
                                 table_name, column_name)
                    self._audit_repository.record_event(
                        principal_user_id=principal.user_id,
                        principal_role=principal.role.value,
                        operation="query_records",
                        table_name=table_name,
                        outcome="denied",
                        reason="Policy evaluation failure; field redacted.",
                        actor_id=principal.user_id, database_id=self._database_id,
                        request_id=self._request_id,
                    )
                    transformed_row[column_name] = self._masking_engine.redact_for_failure(
                        row.get(column_name)
                    )
                    failed_closed_fields += 1
                    decisions_applied += 1
                    continue

                # Apply transformation.
                try:
                    transformed_value = self._masking_engine.apply(
                        row.get(column_name), decision, principal
                    )
                except Exception as exc:
                    # Transformation or missing-secret failure -> fail closed.
                    logger.error("Transformation failed for %s.%s; failing closed.",
                                 table_name, column_name)
                    transformed_value = self._masking_engine.redact_for_failure(
                        row.get(column_name)
                    )
                    failed_closed_fields += 1
                    decision = PolicyDecision(
                        principal_user_id=decision.principal_user_id,
                        principal_role=decision.principal_role,
                        table_name=decision.table_name,
                        column_name=decision.column_name,
                        classification=decision.classification,
                        action=decision.action,
                        allowed=False,
                        matched_rule=decision.matched_rule,
                        reason="Transformation failure; field redacted.",
                        policy_version=decision.policy_version,
                    )

                transformed_row[column_name] = transformed_value
                decisions_applied += 1

            transformed_rows.append(transformed_row)

        # 9. Record a basic access event without logging sensitive values.
        reason = f"Returned {len(transformed_rows)} rows with {decisions_applied} field decisions; fail_closed_fields={failed_closed_fields}."
        self._audit_repository.record_event(
            principal_user_id=principal.user_id,
            principal_role=principal.role.value,
            operation="query_records",
            table_name=table_name,
            outcome="error" if failed_closed_fields else "allowed",
            reason=reason,
            actor_id=principal.user_id, database_id=self._database_id,
            request_id=self._request_id,
        )

        return QueryResult(
            table_name=table_name,
            columns=columns,
            rows=transformed_rows,
            row_count=len(transformed_rows),
            principal_user_id=principal.user_id,
            principal_role=principal.role.value,
            decisions_applied=decisions_applied,
        )

    def _get_classification(
        self, table_name: str, column_name: str
    ) -> Optional[ClassificationTag]:
        """Retrieve the applicable classification for a table/column."""
        try:
            result = self._metadata_repository.get_latest_classification(
                table_name, column_name
                , database_id=self._database_id
            )
            if result is None:
                return None
            return result.classification
        except Exception as exc:
            logger.warning("Could not load classification for %s.%s; treating it as unclassified.",
                           table_name, column_name)
            return None
