"""PII scanner workflow.

Discovers eligible tables, retrieves schema metadata, inspects bounded
samples, classifies each eligible column, saves results and returns a
structured report.
"""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import Optional

from ..database.adapter import DatabaseAdapter
from ..database.connection import DatabaseManager
from ..exceptions import DatabaseError, ScanError
from ..models import ClassificationTag, ReviewStatus
from ..schemas import (
    ColumnClassification,
    ScanReport,
)
from .classifier import classify_column
from .metadata_repository import MetadataRepository
from .rules import analyze_column_name

logger = logging.getLogger(__name__)


class Scanner:
    """Automated PII scanner."""

    def __init__(
        self,
        adapter: DatabaseAdapter,
        metadata_repository: MetadataRepository,
        sample_size: int = 50,
        database_id: str = "sqlite_demo",
    ) -> None:
        self.adapter = adapter
        self.metadata_repository = metadata_repository
        self.sample_size = sample_size
        self.database_id = database_id

    def scan_database(
        self,
        *,
        sample_size: Optional[int] = None,
    ) -> ScanReport:
        """Run the full PII scan.

        Steps:
          1. Discover eligible tables.
          2. Retrieve schema metadata.
          3. Inspect bounded samples.
          4. Classify each eligible column.
          5. Save results and scan metadata.
          6. Return a structured report.

        A failure affecting one table/column is recorded but does not cause
        the whole scan to be silently declared safe. Errors are reported in
        the ScanReport.
        """
        effective_sample_size = sample_size if sample_size is not None else self.sample_size
        scan_run = None
        errors: list[str] = []
        classifications: list[ColumnClassification] = []
        tables_scanned = 0
        failed = False

        try:
            scan_run = self.metadata_repository.create_scan_run(self.database_id)
        except Exception as exc:
            # Cannot persist scan metadata at all -> hard failure.
            raise ScanError(f"Failed to create scan run: {exc}") from exc

        try:
            tables = self.adapter.list_tables()
            tables_scanned = len(tables)
            logger.info("Discovered %s eligible tables.", tables_scanned)

            for table_name in tables:
                try:
                    self._scan_table(table_name, effective_sample_size, classifications)
                except Exception as exc:
                    failed = True
                    msg = f"Failed to scan table '{table_name}': {exc}"
                    logger.error(msg)
                    errors.append(msg)
                    # Do NOT silently declare the table safe. Record it as failed.

            # Persist all successfully-classified columns in one transaction.
            if classifications:
                classifications = [
                    replace(item, scan_run_id=scan_run.id)
                    for item in classifications
                ]
                try:
                    self.metadata_repository.save_classifications(
                        scan_run.id, classifications
                    )
                except Exception as exc:
                    failed = True
                    msg = f"Failed to persist classifications: {exc}"
                    logger.error(msg)
                    errors.append(msg)

            overall_status = "failed" if failed else "completed"
            self.metadata_repository.complete_scan_run(
                scan_run.id,
                status=overall_status,
                tables_scanned=tables_scanned,
                columns_classified=len(classifications),
                error_summary=" | ".join(errors) if errors else None,
            )

        except Exception as exc:
            failed = True
            errors.append(f"Scan workflow error: {exc}")
            try:
                self.metadata_repository.complete_scan_run(
                    scan_run.id,
                    status="failed",
                    tables_scanned=tables_scanned,
                    columns_classified=len(classifications),
                    error_summary=" | ".join(errors) if errors else None,
                )
            except Exception as persist_exc:  # pragma: no cover - defensive
                logger.error("Failed to record scan failure: %s", persist_exc)
            raise ScanError(
                f"Scan failed: {exc}"
            ) from exc

        return ScanReport(
            scan_run_id=scan_run.id,
            tables_scanned=tables_scanned,
            columns_classified=len(classifications),
            classifications=classifications,
            errors=errors,
            failed=failed,
        )

    def _scan_table(
        self,
        table_name: str,
        sample_size: int,
        classifications: list,
    ) -> None:
        """Scan a single table: classify each column and collect results."""
        columns = self.adapter.get_columns(table_name)
        for col in columns:
            column_name = col["name"]
            try:
                # Fetch bounded sample; nulls excluded inside classifier.
                samples = self.adapter.fetch_column_sample(
                    table_name, column_name, sample_size
                )
            except Exception as exc:
                # A column sampling failure must not silently mark data safe.
                raise ScanError(
                    f"Failed to sample column '{table_name}.{column_name}': {exc}"
                ) from exc

            name_signal = analyze_column_name(column_name)
            tag, confidence, reasons = classify_column(
                column_name, samples, name_signal=name_signal
            )

            classifications.append(
                ColumnClassification(
                    table_name=table_name,
                    column_name=column_name,
                    classification=tag,
                    confidence=confidence,
                    reasons=reasons,
                    scan_run_id=None,  # set after scan run created; filled by repository
                    review_status=ReviewStatus.PENDING,
                )
            )
