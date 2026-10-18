"""Repository for scan runs and column classifications.

Handles SQLAlchemy sessions and transactions for persisted scan metadata.
Raw customer values are never stored here.
"""

from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy.orm import Session
from sqlalchemy import case

from ..database.connection import DatabaseManager
from ..database.models import (
    Base,
    ColumnClassification,
    ScanRun,
)
from ..database.migrations import upgrade_control_schema
from ..exceptions import MetadataPersistenceError
from ..models import ClassificationTag, ReviewStatus
from ..schemas import ColumnClassification as ColumnClassificationSchema

logger = logging.getLogger(__name__)


class MetadataRepository:
    """Persists and retrieves scan runs and column classifications."""

    def __init__(self, db_manager: DatabaseManager) -> None:
        self._db_manager = db_manager

    def initialize_schema(self) -> None:
        """Create all internal control tables idempotently.

        Safe to run repeatedly. Does not touch the source database.
        """
        engine = self._db_manager.control_engine
        upgrade_control_schema(engine)
        logger.info("Control schema initialized (idempotent).")

    def create_scan_run(self, database_id: str = "sqlite_demo") -> ScanRun:
        """Create a new scan run with status 'running'."""
        session = self._db_manager.control_session()
        try:
            scan_run = ScanRun(status="running", database_id=database_id)
            session.add(scan_run)
            session.commit()
            session.refresh(scan_run)
            logger.info("Created scan run id=%s", scan_run.id)
            return scan_run
        except Exception as exc:
            session.rollback()
            raise MetadataPersistenceError(
                f"Failed to create scan run: {exc}"
            ) from exc
        finally:
            session.close()

    def complete_scan_run(
        self,
        scan_run_id: int,
        *,
        status: str,
        tables_scanned: int,
        columns_classified: int,
        error_summary: Optional[str] = None,
    ) -> None:
        """Mark a scan run as completed or failed.

        Uses a transaction so partially saved results never look successful.
        """
        session = self._db_manager.control_session()
        try:
            scan_run = session.get(ScanRun, scan_run_id)
            if scan_run is None:
                raise MetadataPersistenceError(
                    f"Scan run {scan_run_id} not found."
                )
            scan_run.status = status
            scan_run.tables_scanned = tables_scanned
            scan_run.columns_classified = columns_classified
            scan_run.error_summary = error_summary
            from ..database.models import utc_now
            scan_run.completed_at = utc_now()
            session.commit()
            logger.info(
                "Completed scan run id=%s status=%s tables=%s columns=%s",
                scan_run_id, status, tables_scanned, columns_classified,
            )
        except Exception as exc:
            session.rollback()
            raise MetadataPersistenceError(
                f"Failed to complete scan run {scan_run_id}: {exc}"
            ) from exc
        finally:
            session.close()

    def save_classifications(
        self,
        scan_run_id: int,
        classifications: list[ColumnClassificationSchema],
    ) -> None:
        """Save classification results within a single transaction.

        All classifications for a scan run are saved together; on failure the
        whole batch is rolled back so partial results never look complete.
        """
        session = self._db_manager.control_session()
        try:
            entities = []
            for cls in classifications:
                entity = ColumnClassification(
                    scan_run_id=scan_run_id,
                    table_name=cls.table_name,
                    column_name=cls.column_name,
                    classification=cls.classification,
                    confidence=int(round(cls.confidence * 100)),
                    reasons=" | ".join(cls.reasons),
                    review_status=ReviewStatus.PENDING,
                )
                entities.append(entity)
            session.add_all(entities)
            session.commit()
            logger.info(
                "Saved %s classifications for scan run %s", len(entities), scan_run_id
            )
        except Exception as exc:
            session.rollback()
            raise MetadataPersistenceError(
                f"Failed to save classifications for scan run {scan_run_id}: {exc}"
            ) from exc
        finally:
            session.close()

    def get_latest_classification(
        self,
        table_name: str,
        column_name: str,
        database_id: str = "sqlite_demo",
    ) -> Optional[ColumnClassificationSchema]:
        """Retrieve the latest applicable classification for a table/column.

        Prefers approved classifications, then the most recent pending one.
        """
        session = self._db_manager.control_session()
        try:
            row = (
                session.query(ColumnClassification)
                .join(ScanRun, ColumnClassification.scan_run_id == ScanRun.id)
                .filter(ColumnClassification.table_name == table_name,
                        ColumnClassification.column_name == column_name)
                .filter(ScanRun.database_id == database_id)
                .order_by(
                    case((ColumnClassification.review_status == ReviewStatus.APPROVED, 0), else_=1),
                    ColumnClassification.created_at.desc(),
                    ColumnClassification.id.desc(),
                )
                .first()
            )
            if row is None:
                return None
            return ColumnClassificationSchema(
                table_name=row.table_name,
                column_name=row.column_name,
                classification=row.effective_classification or row.classification,
                machine_classification=row.classification,
                confidence=row.confidence / 100.0,
                reasons=[r for r in row.reasons.split(" | ") if r],
                scan_run_id=row.scan_run_id,
                scanned_at=row.created_at,
                review_status=row.review_status,
                reviewer=row.reviewer,
                reviewed_at=row.reviewed_at,
                classification_id=row.id,
            )
        finally:
            session.close()

    def list_classifications(self, database_id: str = "sqlite_demo") -> list[ColumnClassificationSchema]:
        """List all persisted classifications."""
        session = self._db_manager.control_session()
        try:
            rows = session.query(ColumnClassification).join(
                ScanRun, ColumnClassification.scan_run_id == ScanRun.id
            ).filter(ScanRun.database_id == database_id).order_by(
                case((ColumnClassification.review_status == ReviewStatus.APPROVED, 0), else_=1),
                ColumnClassification.created_at.desc(),
                ColumnClassification.id.desc(),
            ).all()
            latest = {}
            for row in rows:
                latest.setdefault((row.table_name, row.column_name), row)
            return [
                ColumnClassificationSchema(
                    table_name=row.table_name,
                    column_name=row.column_name,
                    classification=row.effective_classification or row.classification,
                    machine_classification=row.classification,
                    confidence=row.confidence / 100.0,
                    reasons=[r for r in row.reasons.split(" | ") if r],
                    scan_run_id=row.scan_run_id,
                    scanned_at=row.created_at,
                    review_status=row.review_status,
                    reviewer=row.reviewer,
                    reviewed_at=row.reviewed_at,
                    classification_id=row.id,
                )
                for row in latest.values()
            ]
        finally:
            session.close()

    def update_review_status(
        self,
        classification_id: int,
        *,
        review_status: ReviewStatus,
        reviewer: Optional[str] = None,
        classification: Optional[ClassificationTag] = None,
    ) -> None:
        """Update the review status of a classification safely."""
        from ..database.models import utc_now
        session = self._db_manager.control_session()
        try:
            row = session.get(ColumnClassification, classification_id)
            if row is None:
                raise MetadataPersistenceError(
                    f"Classification {classification_id} not found."
                )
            row.review_status = review_status
            row.effective_classification = (
                classification if review_status == ReviewStatus.APPROVED else None
            )
            row.reviewer = reviewer
            row.reviewed_at = utc_now()
            session.commit()
            logger.info(
                "Updated classification %s review_status=%s reviewer=%s",
                classification_id, review_status.value, reviewer,
            )
        except Exception as exc:
            session.rollback()
            raise MetadataPersistenceError(
                f"Failed to update classification {classification_id}: {exc}"
            ) from exc
        finally:
            session.close()
