"""Column-name and sample-value detection signals for PII classification.

The scanner combines multiple signals instead of relying solely on regular
expressions. All detection is deterministic and offline; no sample values are
transmitted to external services.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from ..models import ClassificationTag

# ---- Column name normalization ----

_NAME_NORMALIZATION_RE = re.compile(r"[^a-z0-9]")


def normalize_name(name: str) -> str:
    """Normalize a column name for comparison.

    Lowercases, and removes spaces, underscores and other separators so that
    camelCase, snake_case and kebab-case variants all normalize alike.
    """
    lowered = name.lower()
    return _NAME_NORMALIZATION_RE.sub("", lowered)


# Known sensitive column-name signals -> (tag, base confidence)
NAME_SIGNALS: dict[str, tuple[ClassificationTag, float]] = {
    "name": (ClassificationTag.PII_HIGH, 0.85),
    "fullname": (ClassificationTag.PII_HIGH, 0.9),
    "email": (ClassificationTag.PII_HIGH, 0.9),
    "emailaddress": (ClassificationTag.PII_HIGH, 0.95),
    "phone": (ClassificationTag.PII_HIGH, 0.85),
    "mobile": (ClassificationTag.PII_HIGH, 0.85),
    "telephone": (ClassificationTag.PII_HIGH, 0.85),
    "ssn": (ClassificationTag.PII_HIGH, 0.9),
    "socialsecuritynumber": (ClassificationTag.PII_HIGH, 0.95),
    "nationalid": (ClassificationTag.PII_HIGH, 0.9),
    "creditcard": (ClassificationTag.FINANCIAL_CONFIDENTIAL, 0.95),
    "cardnumber": (ClassificationTag.FINANCIAL_CONFIDENTIAL, 0.95),
    "cardpan": (ClassificationTag.FINANCIAL_CONFIDENTIAL, 0.95),
    "bankaccount": (ClassificationTag.FINANCIAL_CONFIDENTIAL, 0.9),
    "accountnumber": (ClassificationTag.FINANCIAL_CONFIDENTIAL, 0.9),
    "accountbalance": (ClassificationTag.FINANCIAL_CONFIDENTIAL, 0.85),
    "routingnumber": (ClassificationTag.FINANCIAL_CONFIDENTIAL, 0.85),
}

# Columns explicitly treated as harmless/demo-safe (public).
PUBLIC_SIGNALS: dict[str, ClassificationTag] = {
    "accountstatus": ClassificationTag.PUBLIC,
    "status": ClassificationTag.PUBLIC,
    "createdat": ClassificationTag.PUBLIC,
    "updatedat": ClassificationTag.PUBLIC,
}

# Ambiguous identifier columns: conservative, reviewable.
AMBIGUOUS_ID_SIGNALS = {"id", "customerid", "userid", "accountid"}


@dataclass(frozen=True)
class NameSignal:
    """Result of column-name signal analysis."""

    matched: bool
    tag: Optional[ClassificationTag]
    confidence: float
    reason: str


def analyze_column_name(name: str) -> NameSignal:
    """Analyze a column name for PII signals.

    Returns a NameSignal. Unknown names return matched=False with
    UNCLASSIFIED and low confidence (conservative).
    """
    normalized = normalize_name(name)

    # Exact public-signal match takes precedence for clearly harmless fields.
    if normalized in PUBLIC_SIGNALS:
        return NameSignal(
            matched=True,
            tag=PUBLIC_SIGNALS[normalized],
            confidence=0.7,
            reason=f"Column name '{name}' matches a known public signal.",
        )

    if normalized in NAME_SIGNALS:
        tag, confidence = NAME_SIGNALS[normalized]
        return NameSignal(
            matched=True,
            tag=tag,
            confidence=confidence,
            reason=f"Column name '{name}' matches a known {tag.value} signal.",
        )

    # Ambiguous identifiers are handled conservatively (reviewable).
    if normalized in AMBIGUOUS_ID_SIGNALS:
        return NameSignal(
            matched=True,
            tag=ClassificationTag.UNCLASSIFIED,
            confidence=0.3,
            reason=(
                f"Column name '{name}' is an ambiguous identifier; "
                "treated as UNCLASSIFIED pending review."
            ),
        )

    return NameSignal(
        matched=False,
        tag=ClassificationTag.UNCLASSIFIED,
        confidence=0.2,
        reason=f"Column name '{name}' has no recognized PII signal.",
    )


# ---- Sample-value signals ----

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
_PHONE_DIGIT_RE = re.compile(r"\d")
_SSN_RE = re.compile(r"^\d{3}[- ]?\d{2}[- ]?\d{4}$")


def _digits_only(value: str) -> str:
    return "".join(_PHONE_DIGIT_RE.findall(value))


def luhn_check(card_number: str) -> bool:
    """Validate a credit-card candidate with the Luhn algorithm.

    Returns True if the Luhn checksum passes. Matching the Luhn check does
    NOT establish that a card number is real or valid for use; it is only a
    structural validity check.
    """
    digits = _digits_only(card_number)
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    reverse_digits = digits[::-1]
    for i, ch in enumerate(reverse_digits):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


@dataclass(frozen=True)
class ValueSignal:
    """Result of sample-value signal analysis."""

    tag: ClassificationTag
    confidence: float
    reasons: list[str]


def analyze_samples(
    samples: list,
    column_name: str,
    name_signal: NameSignal,
) -> ValueSignal:
    """Analyze bounded sample values for PII patterns.

    samples: list of Python values (may include None). Nulls are skipped.
    Does not log or store raw values.
    """
    non_null = [s for s in samples if s is not None]
    reasons: list[str] = [name_signal.reason]

    if not non_null:
        return ValueSignal(
            tag=name_signal.tag or ClassificationTag.UNCLASSIFIED,
            confidence=name_signal.confidence or 0.2,
            reasons=reasons + ["No non-null sample values available."],
        )

    total = len(non_null)
    email_like = 0
    phone_like = 0
    ssn_like = 0
    card_like = 0
    card_luhn_pass = 0

    for value in non_null:
        text = str(value).strip()
        if not text:
            continue
        if _EMAIL_RE.match(text):
            email_like += 1
        # Phone-like: at least 7 digits after stripping separators.
        digits = _digits_only(text)
        has_phone_separators = bool(re.search(r"[+()\- ]", text))
        if (10 <= len(digits) <= 15 or
                (7 <= len(digits) <= 15 and has_phone_separators)) and not re.search(r"\.\d", text):
            phone_like += 1
        if _SSN_RE.match(text):
            ssn_like += 1
        if 13 <= len(digits) <= 19 and luhn_check(text):
            card_like += 1
            card_luhn_pass += 1

    # Determine dominant value-based signal.
    best_tag = name_signal.tag or ClassificationTag.UNCLASSIFIED
    best_conf = name_signal.confidence or 0.2
    value_reasons = []

    if email_like > 0 and email_like >= max(phone_like, ssn_like, card_like):
        ratio = email_like / total
        best_tag = ClassificationTag.PII_HIGH
        best_conf = min(0.95, 0.6 + 0.35 * ratio)
        value_reasons.append(f"{email_like}/{total} samples look like email addresses.")
    elif ssn_like > 0 and ssn_like >= max(phone_like, card_like):
        ratio = ssn_like / total
        best_tag = ClassificationTag.PII_HIGH
        best_conf = min(0.95, 0.6 + 0.35 * ratio)
        value_reasons.append(f"{ssn_like}/{total} samples look like SSN-style identifiers.")
    elif card_like > 0 and card_like >= max(email_like, phone_like, ssn_like):
        ratio = card_like / total
        best_tag = ClassificationTag.FINANCIAL_CONFIDENTIAL
        best_conf = min(0.95, 0.6 + 0.35 * ratio)
        value_reasons.append(
            f"{card_like}/{total} samples pass Luhn-style credit-card check "
            f"({card_luhn_pass} Luhn-valid). Luhn match does not imply a real card."
        )
    elif phone_like > 0:
        ratio = phone_like / total
        best_tag = ClassificationTag.PII_HIGH
        best_conf = min(0.90, 0.55 + 0.35 * ratio)
        value_reasons.append(f"{phone_like}/{total} samples look like telephone numbers.")

    # Combine name and value evidence. When they conflict, preserve uncertainty:
    # take the higher-risk tag and do not silently downgrade a high-risk field.
    combined_tag = _higher_risk_tag(best_tag, name_signal.tag or ClassificationTag.UNCLASSIFIED)
    combined_conf = max(best_conf, name_signal.confidence or 0.2)

    if combined_tag != best_tag:
        value_reasons.append(
            f"Name signal suggests {name_signal.tag.value}; "
            f"preserving higher-risk classification {combined_tag.value}."
        )

    return ValueSignal(
        tag=combined_tag,
        confidence=round(min(1.0, combined_conf), 2),
        reasons=reasons + value_reasons,
    )


def _higher_risk_tag(a: ClassificationTag, b: ClassificationTag) -> ClassificationTag:
    """Return the higher-risk classification tag (conservative)."""
    risk = {
        ClassificationTag.PII_HIGH: 3,
        ClassificationTag.FINANCIAL_CONFIDENTIAL: 2,
        ClassificationTag.PUBLIC: 0,
        ClassificationTag.UNCLASSIFIED: 1,
    }
    return a if risk[a] >= risk[b] else b
