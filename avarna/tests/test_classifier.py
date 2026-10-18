from avarna.models import ClassificationTag as Tag
from avarna.scanner.classifier import classify_column
from avarna.scanner.rules import (
    analyze_column_name,
    iban_check,
    luhn_check,
    normalize_name,
)


def test_name_signals_and_ambiguity():
    assert classify_column("EmailAddress", ["a@example.test"])[0] == Tag.PII_HIGH
    assert classify_column("mobile_phone", ["555-010-1234"])[0] == Tag.PII_HIGH
    assert classify_column("ssn", ["111-22-3333"])[0] == Tag.PII_HIGH
    assert classify_column("credit_card", ["4111111111111111"])[0] == Tag.FINANCIAL_CONFIDENTIAL
    assert classify_column("account_balance", [100.0])[0] == Tag.FINANCIAL_CONFIDENTIAL
    assert classify_column("billingAddress", ["1 Main Street"])[0] == Tag.PII_HIGH
    assert classify_column("date_of_birth", ["1990-01-01"])[0] == Tag.PII_HIGH
    assert classify_column("passport_number", ["example"])[0] == Tag.PII_HIGH
    assert classify_column("swift_code", ["example"])[0] == Tag.FINANCIAL_CONFIDENTIAL
    assert analyze_column_name("phonebook").tag == Tag.UNCLASSIFIED
    assert classify_column("id", [1])[0] == Tag.UNCLASSIFIED
    assert classify_column("mystery", ["anything"])[0] == Tag.UNCLASSIFIED
    assert analyze_column_name("accountStatus").tag == Tag.PUBLIC
    assert normalize_name("Email_Address") == "emailaddress"


def test_value_signals_and_luhn():
    assert luhn_check("4111 1111 1111 1111")
    assert not luhn_check("4111 1111 1111 1112")
    assert iban_check("GB82 WEST 1234 5698 7654 32")
    assert not iban_check("GB82 WEST 1234 5698 7654 31")
    assert classify_column("misc", ["a@example.test", None])[0] == Tag.PII_HIGH
    assert classify_column("misc", ["9876543210"])[0] == Tag.PII_HIGH
    assert classify_column("misc", ["GB82WEST12345698765432"])[0] == Tag.FINANCIAL_CONFIDENTIAL
    tag, confidence, reasons = classify_column("misc", ["a@example.test", "", None])
    assert tag == Tag.PII_HIGH and confidence == 0.95
    assert any("1/1 nonblank samples" in reason for reason in reasons)
    assert classify_column("misc", [None])[0] == Tag.UNCLASSIFIED
    assert classify_column("misc", ["", None])[0] == Tag.UNCLASSIFIED
    assert classify_column("misc", ["bad", "also bad"])[0] == Tag.UNCLASSIFIED
    tag, confidence, _ = classify_column("email", [])
    assert tag == Tag.PII_HIGH and 0 <= confidence <= 1
