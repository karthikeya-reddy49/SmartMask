"""PII classifier: combines name and value signals into a classification.

Scoring rules are deterministic and documented. Confidence values are derived
from signal strength, not arbitrarily chosen.
"""

from __future__ import annotations

from typing import Optional

from ..models import ClassificationTag
from .rules import NameSignal, ValueSignal, analyze_column_name, analyze_samples


def classify_column(
    column_name: str,
    samples: list,
    name_signal: Optional[NameSignal] = None,
) -> tuple[ClassificationTag, float, list[str]]:
    """Classify a single column.

    Returns (tag, confidence, reasons).

    When column-name evidence and sample evidence conflict, the higher-risk
    tag is preserved and the uncertainty is documented in the reasons. Unknown
    fields default to UNCLASSIFIED and are never treated as safe.
    """
    if name_signal is None:
        name_signal = analyze_column_name(column_name)

    value_signal = analyze_samples(samples, column_name, name_signal)

    return value_signal.tag, value_signal.confidence, value_signal.reasons
