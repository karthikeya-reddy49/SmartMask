import pytest

from smartmask.exceptions import MissingHmacKeyError, UnsupportedTransformationError
from smartmask.masking.transformations import (
    REDACTED, apply_transformation, hmac_pseudonymize, mask_credit_card,
    mask_email, mask_name, mask_ssn, mask_telephone,
)
from smartmask.models import ClassificationTag, MaskingAction


def test_masks_common_pii_and_card_separators():
    assert mask_credit_card("4111-1111-1111-1111").endswith("1111")
    assert mask_credit_card("123") == REDACTED
    assert mask_email("arun@example.test") == "a***@example.test"
    assert mask_email("bad") == REDACTED
    assert mask_telephone("+1 (555) 010-2222").endswith("2222")
    assert mask_ssn("111-22-3333") == "XXX-XX-3333"
    assert mask_name("Arun Kumar") == "A*** K****"


def test_null_redaction_and_hmac():
    assert mask_email(None) is None
    assert apply_transformation("x", MaskingAction.REDACT) == REDACTED
    assert hmac_pseudonymize("same", b"key") == hmac_pseudonymize("same", b"key")
    assert hmac_pseudonymize("same", b"key") != hmac_pseudonymize("same", b"other")
    with pytest.raises(MissingHmacKeyError):
        apply_transformation("x", MaskingAction.HMAC_SHA256)
    with pytest.raises(UnsupportedTransformationError):
        apply_transformation("x", "not-supported")


def test_mask_action_is_field_appropriate():
    assert apply_transformation("arun@example.test", MaskingAction.MASK,
        classification=ClassificationTag.PII_HIGH, column_name="email") == "a***@example.test"
    assert apply_transformation(85000, MaskingAction.MASK,
        classification=ClassificationTag.FINANCIAL_CONFIDENTIAL,
        column_name="account_balance") == REDACTED
