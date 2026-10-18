"""Synthetic demonstration data setup script.

Creates a sample `customers` table in the source database with fictional
customer records. Repeatable: re-running does not create duplicate rows and
does not destroy an existing database unless --drop is explicitly supplied.

Sample data is synthetic and for demonstration only. It does not represent
actual customer records.
"""

from __future__ import annotations

import argparse
import os
import sys

from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    create_engine,
    inspect,
    text,
)

from sqlalchemy.orm import DeclarativeBase, Session


class Base(DeclarativeBase):
    pass


class Customer(Base):
    __tablename__ = "customers"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=True)
    email = Column(String, nullable=True)
    phone = Column(String, nullable=True)
    ssn = Column(String, nullable=True)
    credit_card = Column(String, nullable=True)
    account_balance = Column(Float, nullable=True)
    account_status = Column(String, nullable=True)
    nickname = Column(String, nullable=True)
    external_ref = Column(String, nullable=True)


# Synthetic fictional customer data. .test emails and clearly synthetic
# identifiers. Not real customer records.
SAMPLE_ROWS = [
    {
        "name": "Arun Kumar",
        "email": "arun@example.test",
        "phone": "9876543210",
        "ssn": "000-12-3456",
        "credit_card": "4111111111111111",
        "account_balance": 85000.00,
        "account_status": "active",
        "nickname": "Sunrise",
        "external_ref": "X-1001",
    },
    {
        "name": "Priya Mehta",
        "email": "priya.mehta@example.test",
        "phone": "+1-555-010-2222",
        "ssn": "111-22-3333",
        "credit_card": "5500000000000004",
        "account_balance": 12450.75,
        "account_status": "active",
        "nickname": None,
        "external_ref": "X-1002",
    },
    {
        "name": "Samir Patel",
        "email": None,
        "phone": "5550103333",
        "ssn": None,
        "credit_card": "370000000000002",
        "account_balance": None,
        "account_status": "suspended",
        "nickname": "Bluebird",
        "external_ref": "X-1003",
    },
    {
        "name": "Lakshmi Devi",
        "email": "lakshmi.d@example.test",
        "phone": None,
        "ssn": "222-33-4444",
        "credit_card": "6011000000000000",
        "account_balance": 33000.00,
        "account_status": "closed",
        "nickname": "Lotus",
        "external_ref": "X-1004",
    },
    {
        "name": "Rohan Singh",
        "email": "rohan.singh@example.test",
        "phone": "9988776655",
        "ssn": "333-44-5555",
        "credit_card": "not-a-card",
        "account_balance": 7150.50,
        "account_status": "active",
        "nickname": "Comet",
        "external_ref": "X-1005",
    },
]

DEMO_CARD_NUMBERS = (
    "4111111111111111",
    "5500000000000004",
    "370000000000002",
    "6011000000000000",
)


def generated_row(index: int) -> dict:
    """Build a deterministic, clearly fictional row for scale demonstrations."""
    return {
        "name": f"Demo Customer {index:06d}",
        "email": f"demo.customer.{index:06d}@example.test",
        "phone": f"555{index:07d}",
        "ssn": f"900-00-{index % 10000:04d}",
        "credit_card": DEMO_CARD_NUMBERS[index % len(DEMO_CARD_NUMBERS)],
        "account_balance": round(((index * 7919) % 2500000) / 100, 2),
        "account_status": ("active", "suspended", "closed")[index % 3],
        "nickname": f"Demo-{index:06d}" if index % 4 else None,
        "external_ref": f"DEMO-{index:08d}",
    }


def create_schema(engine) -> None:
    Base.metadata.create_all(engine)
    # SQLAlchemy create_all intentionally does not migrate existing demo tables.
    # These additive columns keep rerunning this seed safe for older demo DBs.
    inspector = inspect(engine)
    existing = {column["name"] for column in inspector.get_columns("customers")}
    with engine.begin() as connection:
        for name in ("nickname", "external_ref"):
            if name not in existing:
                connection.execute(text(f'ALTER TABLE customers ADD COLUMN "{name}" VARCHAR'))


def table_exists(engine, table_name: str) -> bool:
    inspector = inspect(engine)
    return table_name in inspector.get_table_names()


def row_count(session: Session) -> int:
    return session.query(Customer).count()


def seed(engine, drop: bool = False, rows: int = len(SAMPLE_ROWS)) -> None:
    if not 1 <= rows <= 1_000_000:
        raise ValueError("The requested row count must be between 1 and 1,000,000.")

    if drop:
        with Session(engine) as session:
            session.execute(text("DROP TABLE IF EXISTS customers"))
            session.commit()
        Base.metadata.create_all(engine)

    create_schema(engine)

    with Session(engine) as session:
        existing = row_count(session)
        if existing >= rows:
            print(
                f"Demo data already present ({existing} rows; target {rows}). Skipping seed."
            )
            return

        # Preserve the original five hand-authored examples on first setup.
        for row in SAMPLE_ROWS[:min(rows, len(SAMPLE_ROWS))]:
            already = (
                session.query(Customer)
                .filter_by(name=row["name"], email=row["email"])
                .first()
            )
            if already is None:
                session.add(Customer(**row))
        session.commit()
        current = row_count(session)

        # Commit bounded batches so larger demo sets do not need to be held as
        # one ORM transaction, while keeping generation repeatable.
        while current < rows:
            stop = min(current + 1000, rows)
            session.add_all(
                Customer(**generated_row(index))
                for index in range(current + 1, stop + 1)
            )
            session.commit()
            current = row_count(session)

        print(f"Seeded demo data. Total: {current} customer row(s); target: {rows}.")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Set up the synthetic demo source database."
    )
    parser.add_argument(
        "--db-url",
        default=os.environ.get("AVARNA_DEMO_SETUP_DB_URL", "sqlite:///./data/demo_source.db"),
        help="Source database URL (default: sqlite:///./data/demo_source.db)",
    )
    parser.add_argument(
        "--drop",
        action="store_true",
        help="DESTRUCTIVE: drop the customers table before seeding.",
    )
    parser.add_argument(
        "--rows",
        type=int,
        default=10_000,
        help="Target number of synthetic customer rows (default: 10000; maximum: 1000000).",
    )
    args = parser.parse_args(argv)

    try:
        engine = create_engine(args.db_url)
        seed(engine, drop=args.drop, rows=args.rows)
    except Exception as exc:  # pragma: no cover - CLI defensive
        print(f"ERROR: Failed to set up demo data: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
