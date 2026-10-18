from smartmask.models import ClassificationTag as Tag
from smartmask.scanner.classifier import classify_column
from smartmask.scanner.rules import analyze_column_name, luhn_check, normalize_name


def test_name_signals_and_ambiguity():
    assert classify_column("EmailAddress", ["a@example.test"])[0] == Tag.PII_HIGH
    assert classify_column("mobile_phone", ["555-010-1234"])[0] == Tag.PII_HIGH
    assert classify_column("ssn", ["111-22-3333"])[0] == Tag.PII_HIGH
    assert classify_column("credit_card", ["4111111111111111"])[0] == Tag.FINANCIAL_CONFIDENTIAL
    assert classify_column("account_balance", [100.0])[0] == Tag.FINANCIAL_CONFIDENTIAL
    assert classify_column("id", [1])[0] == Tag.UNCLASSIFIED
    assert classify_column("mystery", ["anything"])[0] == Tag.UNCLASSIFIED
    assert analyze_column_name("accountStatus").tag == Tag.PUBLIC
    assert normalize_name("Email_Address") == "emailaddress"


def test_value_signals_and_luhn():
    assert luhn_check("4111 1111 1111 1111")
    assert not luhn_check("4111 1111 1111 1112")
    assert classify_column("misc", ["a@example.test", None])[0] == Tag.PII_HIGH
    assert classify_column("misc", ["9876543210"])[0] == Tag.PII_HIGH
    assert classify_column("misc", [None])[0] == Tag.UNCLASSIFIED
    assert classify_column("misc", ["bad", "also bad"])[0] == Tag.UNCLASSIFIED
    tag, confidence, _ = classify_column("email", [])
    assert tag == Tag.PII_HIGH and 0 <= confidence <= 1
