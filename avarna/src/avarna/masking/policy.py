"""Role-based policy engine.

Determines the permitted masking action for a principal, table, column and
classification. Separate from the scanner and database adapter.
"""

from __future__ import annotations

import logging
from typing import Optional

from ..database.models import Policy
from ..exceptions import MissingPolicyError, PolicyError
from ..models import ClassificationTag, MaskingAction, Role
from ..schemas import PolicyDecision
from .policy_repository import PolicyRepository

logger = logging.getLogger(__name__)


class PolicyEngine:
    """Evaluates role-and-classification-based policies.

    Field-level explicit deny takes precedence over a broad allow rule.
    Missing policies and unknown roles fail closed.
    """

    def __init__(self, policy_repository: PolicyRepository) -> None:
        self._policy_repository = policy_repository

    def evaluate_policy(
        self,
        principal_user_id: str,
        principal_role: Role,
        table_name: str,
        column_name: str,
        classification: ClassificationTag,
    ) -> PolicyDecision:
        """Return a structured policy decision.

        Never returns an unexplained raw string. The decision includes the
        selected action, result, matched rule and reason.
        """
        # Unknown role is handled before this point by the caller/query service,
        # but defend here too: never treat unknown as Admin.
        if principal_role not in tuple(Role):
            return PolicyDecision(
                principal_user_id=principal_user_id,
                principal_role=principal_role.value,
                table_name=table_name,
                column_name=column_name,
                classification=classification,
                action=MaskingAction.REDACT,
                allowed=False,
                matched_rule=None,
                reason="Unknown or unsupported role. Fail closed.",
                policy_version=None,
            )

        # Try field-scoped policy first (table + column), then broader.
        policy = self._policy_repository.get_applicable_policy(
            principal_role, classification, table_name=table_name, column_name=column_name
        )

        if policy is None or not policy.enabled:
            # Missing or disabled policy -> fail closed (redact/deny).
            return PolicyDecision(
                principal_user_id=principal_user_id,
                principal_role=principal_role.value,
                table_name=table_name,
                column_name=column_name,
                classification=classification,
                action=MaskingAction.REDACT,
                allowed=False,
                matched_rule=None,
                reason=(
                    f"No applicable enabled policy for role '{principal_role.value}' "
                    f"and classification '{classification.value}'. Fail closed."
                ),
                policy_version=None,
            )

        action = self._parse_action(policy.action)
        allowed = action != MaskingAction.REDACT  # redact => not allowed raw

        return PolicyDecision(
            principal_user_id=principal_user_id,
            principal_role=principal_role.value,
            table_name=table_name,
            column_name=column_name,
            classification=classification,
            action=action,
            allowed=allowed,
            matched_rule=f"policy id={policy.id} (version {policy.policy_version})",
            reason=self._decision_reason(principal_role, classification, action, policy),
            policy_version=policy.policy_version,
        )

    def _parse_action(self, action_value: str) -> MaskingAction:
        try:
            return MaskingAction(action_value)
        except ValueError as exc:
            raise PolicyError(f"Unsupported policy action: {action_value}") from exc

    def _decision_reason(
        self,
        role: Role,
        classification: ClassificationTag,
        action: MaskingAction,
        policy: Policy,
    ) -> str:
        if action == MaskingAction.ALLOW:
            return (
                f"Explicit policy permits raw view for role '{role.value}' on "
                f"'{classification.value}'."
            )
        if action == MaskingAction.HMAC_SHA256:
            return (
                f"Policy authorizes HMAC-SHA-256 pseudonymization for role "
                f"'{role.value}' on '{classification.value}'."
            )
        if action == MaskingAction.MASK:
            return (
                f"Policy authorizes partial masking for role '{role.value}' on "
                f"'{classification.value}'."
            )
        return (
            f"Policy redacts '{classification.value}' for role '{role.value}'. "
            "Raw value not disclosed."
        )
