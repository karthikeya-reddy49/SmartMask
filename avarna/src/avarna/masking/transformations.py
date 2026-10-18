"""Independent, tested masking transformation functions.

All transformations operate on retrieved result values and never alter the
source database. Null values are preserved as null by default.

Available actions:
  - allow: return the value only when policy explicitly permits it
  - redact: replace with [REDACTED]
  - mask: field-appropriate partial masking (credit card, email, phone, SSN, name)
  - hmac_sha256: HMAC-SHA-256 pseudonymization (requires a configured secret)
"""

from __future__ import annotations

import hmac
import hashlib
import re
from typing import Optional

from ..exceptions import MissingHmacKeyError, UnsupportedTransformationError
from ..models import ClassificationTag, MaskingAction

REDACTED = "[REDACTED]"

# ---- Credit card ----

_CARD_DIGIT_RE = re.compile(r"\d")


def _card_digits(value: str) -> str:
    return "".join(_CARD_DIGIT_RE.findall(value))


def mask_credit_card(value: Optional[str]) -> Optional[str]:
    """Partially mask a credit card number.

    Retains only the last four digits. Separators are stripped before masking
    so no extra digits leak through. Output format is XXXX-XXXX-XXXX-1111.

    Null values are preserved as null. Short or malformed values are redacted.
    """
    if value is None:
        return None
    digits = _card_digits(str(value))
    if not 13 <= len(digits) <= 19:
        return REDACTED
    last4 = digits[-4:]
    return f"XXXX-XXXX-XXXX-{last4}"


# ---- Email ----

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def mask_email(value: Optional[str]) -> Optional[str]:
    """Mask an email address.

    Preserves the first character and the domain: a***@example.test.
    Invalid email-like values are fully redacted.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not _EMAIL_RE.match(text):
        return REDACTED
    local, _, domain = text.partition("@")
    if len(local) <= 1:
        masked_local = local
    else:
        masked_local = local[0] + "***"  # deterministic
    return f"{masked_local}@{domain}"


# ---- Telephone ----

_PHONE_DIGIT_RE = re.compile(r"\d")


def mask_telephone(value: Optional[str]) -> Optional[str]:
    """Mask a telephone number.

    Preserves at most the last four digits; obscures the rest. Supports common
    separators and optional country-code formatting. Short/malformed values are
    redacted.
    """
    if value is None:
        return None
    text = str(value).strip()
    digits = _PHONE_DIGIT_RE.findall(text)
    if not 7 <= len(digits) <= 15 or not re.fullmatch(r"[+()\d.\- ]+", text):
        return REDACTED
    last4 = "".join(digits[-4:])
    return f"XXX-XXX-{last4}"


# ---- SSN / national identifier ----

_SSN_RE = re.compile(r"^(\d{3})[- ]?(\d{2})[- ]?(\d{4})$")


def mask_ssn(value: Optional[str]) -> Optional[str]:
    """Mask an SSN-shaped national identifier.

    XXX-XX-3456 format. Unexpected formats are redacted rather than guessed.
    """
    if value is None:
        return None
    text = str(value).strip()
    match = _SSN_RE.match(text)
    if not match:
        return REDACTED
    return f"XXX-XX-{match.group(3)}"


# ---- Name ----

_NAME_WORD_RE = re.compile(r"[A-Za-z]+")


def mask_name(value: Optional[str]) -> Optional[str]:
    """Conservative name masking.

    Keeps the first letter of each name part and replaces the rest with *.
    Deterministic. Null preserved as null.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return REDACTED
    parts = _NAME_WORD_RE.findall(text)
    if not parts:
        return REDACTED
    masked_parts = []
    for part in parts:
        if len(part) <= 1:
            masked_parts.append(part)
        else:
            masked_parts.append(part[0] + "*" * (len(part) - 1))
    return " ".join(masked_parts)


# ---- Full redaction ----

def redact_value(value) -> str:
    """Full redaction: replace a non-null restricted value with [REDACTED]."""
    return REDACTED


# ---- HMAC pseudonymization ----

def hmac_pseudonymize(
    value: Optional[str], secret_key: bytes
) -> Optional[str]:
    """HMAC-SHA-256 pseudonymization.

    Takes the secret key as an injected dependency. Never hard-codes a secret.
    Stable output for the same value and key; different keys produce different
    outputs. Null values are preserved as null.

    This is pseudonymization, NOT encryption, and NOT anonymization.
    """
    if value is None:
        return None
    if not secret_key:
        raise MissingHmacKeyError(
            "HMAC secret key is required for pseudonymization but was not provided."
        )
    digest = hmac.new(secret_key, str(value).encode("utf-8"), hashlib.sha256).hexdigest()
    return digest


# ---- Central dispatch ----

def _mask_by_classification(
    value, classification: Optional[ClassificationTag] = None,
    column_name: Optional[str] = None, **kwargs
):
    """Apply a field-appropriate partial mask based on its reflected name."""
    if value is None:
        return None
    normalized = re.sub(r"[^a-z0-9]", "", (column_name or "").lower())
    if normalized in {"email", "emailaddress"}:
        return mask_email(str(value))
    if normalized in {"phone", "mobile", "telephone"}:
        return mask_telephone(str(value))
    if normalized in {"ssn", "socialsecuritynumber", "nationalid"}:
        return mask_ssn(str(value))
    if normalized in {"name", "fullname"}:
        return mask_name(str(value))
    if normalized in {"creditcard", "cardnumber", "cardpan"}:
        return mask_credit_card(str(value))
    # Financial values such as balances and account numbers are fully
    # redacted unless a dedicated, reviewed transformation is configured.
    if classification in (
        ClassificationTag.PII_HIGH,
        ClassificationTag.UNCLASSIFIED,
        ClassificationTag.FINANCIAL_CONFIDENTIAL,
    ):
        return REDACTED
    return REDACTED if classification != ClassificationTag.PUBLIC else value


def _hmac_dispatch(
    value, secret_key: Optional[bytes] = None, **kwargs
):
    if secret_key is None or not secret_key:
        raise MissingHmacKeyError(
            "HMAC secret key is required but not configured."
        )
    return hmac_pseudonymize(
        str(value) if value is not None else None, secret_key
    )


_ACTION_DISPATCH: dict[MaskingAction, callable] = {
    MaskingAction.ALLOW: lambda value, **kwargs: value,
    MaskingAction.REDACT: lambda value, **kwargs: REDACTED if value is not None else None,
    MaskingAction.MASK: _mask_by_classification,
    MaskingAction.HMAC_SHA256: _hmac_dispatch,
}


def apply_transformation(
    value,
    action: MaskingAction,
    *,
    classification: Optional[ClassificationTag] = None,
    column_name: Optional[str] = None,
    secret_key: Optional[bytes] = None,
):
    """Central, maintainable transformation dispatch.

    Accepts a value, action, optional classification and optional secret key.

    If an action or classification is missing, invalid or unsupported, the
    operation fails closed: it does NOT return restricted values unchanged.
    """
    if action is None:
        raise UnsupportedTransformationError(
            "No masking action specified. Failing closed."
        )

    try:
        action_enum = MaskingAction(action) if not isinstance(action, MaskingAction) else action
    except ValueError as exc:
        raise UnsupportedTransformationError(
            f"Unsupported masking action: {action}"
        ) from exc

    handler = _ACTION_DISPATCH.get(action_enum)
    if handler is None:
        raise UnsupportedTransformationError(
            f"No handler for masking action: {action_enum}"
        )

    # ALLOW returns the value; callers must have already authorized it via policy.
    if action_enum == MaskingAction.ALLOW:
        return handler(value)

    # HMAC requires a configured secret; fail closed if missing.
    if action_enum == MaskingAction.HMAC_SHA256:
        if secret_key is None or not secret_key:
            raise MissingHmacKeyError(
                "HMAC-SHA-256 requires a configured secret key."
            )
        return handler(value, secret_key=secret_key)

    # MASK / REDACT use classification context.
    return handler(value, classification=classification, column_name=column_name)
