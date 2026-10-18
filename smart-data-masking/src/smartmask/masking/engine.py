"""Masking engine: applies transformations based on policy decisions.

Separates authorization decisions (policy engine) from transformation
execution. Never returns restricted values unchanged when a transformation
or policy dependency is invalid; fails closed.
"""

from __future__ import annotations

import logging
from typing import Optional

from ..config import AppConfig
from ..exceptions import MissingHmacKeyError, UnsupportedTransformationError
from ..models import ClassificationTag, MaskingAction, Principal
from ..schemas import PolicyDecision
from .transformations import apply_transformation, REDACTED

logger = logging.getLogger(__name__)


class MaskingEngine:
    """Applies masking transformations to record field values.

    Depends on an explicitly supplied AppConfig for the HMAC secret. The
    secret is injected from configuration and never hard-coded.
    """

    def __init__(self, config: AppConfig) -> None:
        self._config = config

    def apply(
        self,
        value,
        decision: PolicyDecision,
        principal: Principal,
    ):
        """Apply the transformation selected by a policy decision.

        Returns the transformed value. On transformation or policy failure,
        fails closed: returns [REDACTED] for non-admin and denies raw access.

        Raises:
            MissingHmacKeyError: if HMAC is required but no secret configured.
            UnsupportedTransformationError: if the action is invalid.
        """
        action = decision.action

        if action == MaskingAction.ALLOW:
            if not decision.allowed:
                # Explicit deny: never return raw value.
                return REDACTED
            return value

        if action == MaskingAction.REDACT:
            return REDACTED if value is not None else None

        if action == MaskingAction.MASK:
            return apply_transformation(
                value,
                MaskingAction.MASK,
                classification=decision.classification,
                column_name=decision.column_name,
            )

        if action == MaskingAction.HMAC_SHA256:
            if not self._config.hmac_configured():
                raise MissingHmacKeyError(
                    "HMAC-SHA-256 pseudonymization requires a configured "
                    "SMARTMASK_HMAC_SECRET."
                )
            return apply_transformation(
                value,
                MaskingAction.HMAC_SHA256,
                secret_key=self._config.hmac_key_bytes(),
            )

        # Unknown action -> fail closed.
        raise UnsupportedTransformationError(
            f"Unsupported masking action: {action}"
        )

    def redact_for_failure(self, value) -> str:
        """Safe redaction used when a security dependency fails."""
        return REDACTED if value is not None else None
