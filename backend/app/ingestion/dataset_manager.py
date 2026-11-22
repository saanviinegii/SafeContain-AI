"""SafeContain AI — Dynamic Dataset Lifecycle & Metadata Registry.

Provides ACID-compliant SQLite and in-memory registry for uploaded and demo datasets:
- Generates deterministic/unique dataset identifiers (UUID)
- Tracks provenance metadata (source file, type, timestamp, node/edge counts)
- Manages active dataset state for multi-tenant and multi-dataset graph visualization
- Provides dataset-scoped entity tracking for safe, non-destructive deletion
"""

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.app.core.config import settings

logger = logging.getLogger(__name__)


class DatasetMetadata(BaseModel):
    """Structured metadata record for an individual ingested dataset."""
    dataset_id: str = Field(description="Unique dataset identifier, e.g. ds-7a8f9c1b2d")
    name: str = Field(description="Human-readable dataset or scenario name")
    source_filename: str = Field(default="", description="Original CSV filename or scenario identifier")
    source_type: str = Field(default="CSV", description="CSV_NODES | CSV_RELATIONSHIPS | CIC_IDS2017_FLOWS | DEMO_SCENARIO")
    node_count: int = Field(default=0)
    edge_count: int = Field(default=0)
    node_ids: List[str] = Field(default_factory=list)
    edge_ids: List[str] = Field(default_factory=list)
    is_active: bool = Field(default=False)
    is_demo: bool = Field(default=False)
    uploaded_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    neo4j_synced: bool = Field(default=False)
    neo4j_status: str = Field(default="OFFLINE_FALLBACK")
    description: Optional[str] = Field(default=None)
    filename: Optional[str] = Field(default=None)
    csv_type: Optional[str] = Field(default=None)
    total_rows: Optional[int] = Field(default=0)
    created_at: Optional[Any] = Field(default=None)

    def model_post_init(self, __context: Any) -> None:
        if self.filename and not self.source_filename:
            self.source_filename = self.filename
        if not self.filename and self.source_filename:
            self.filename = self.source_filename
        if self.csv_type and self.source_type == "CSV":
            self.source_type = self.csv_type
        if not self.csv_type and self.source_type:
            self.csv_type = self.source_type


class DatasetManager:
    """Manages the full lifecycle of ingested datasets, persistence, and active states."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = Path(db_path or settings.SQLITE_DB_PATH)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Initializes SQLite schema for persistent dataset metadata tracking."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS app_datasets (
                    dataset_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    source_filename TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    node_count INTEGER NOT NULL DEFAULT 0,
                    edge_count INTEGER NOT NULL DEFAULT 0,
                    node_ids_json TEXT NOT NULL DEFAULT '[]',
                    edge_ids_json TEXT NOT NULL DEFAULT '[]',
                    is_active INTEGER NOT NULL DEFAULT 0,
                    is_demo INTEGER NOT NULL DEFAULT 0,
                    uploaded_at TEXT NOT NULL,
                    neo4j_synced INTEGER NOT NULL DEFAULT 0,
                    neo4j_status TEXT NOT NULL DEFAULT 'OFFLINE_FALLBACK',
                    description TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_datasets_active ON app_datasets(is_active)")
            conn.commit()

    @staticmethod
    def generate_dataset_id() -> str:
        """Generates a clean, unique dataset identifier."""
        return f"ds-{uuid.uuid4().hex[:12]}"

    def register_dataset(self, metadata: DatasetMetadata) -> DatasetMetadata:
        """Persists a new or updated dataset record, optionally setting it as active."""
        with self._get_connection() as conn:
            if metadata.is_active:
                # Mark all other datasets as inactive
                conn.execute("UPDATE app_datasets SET is_active = 0")

            conn.execute("""
                INSERT INTO app_datasets (
                    dataset_id, name, source_filename, source_type,
                    node_count, edge_count, node_ids_json, edge_ids_json,
                    is_active, is_demo, uploaded_at, neo4j_synced, neo4j_status, description
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(dataset_id) DO UPDATE SET
                    name = excluded.name,
                    node_count = excluded.node_count,
                    edge_count = excluded.edge_count,
                    node_ids_json = excluded.node_ids_json,
                    edge_ids_json = excluded.edge_ids_json,
                    is_active = excluded.is_active,
                    neo4j_synced = excluded.neo4j_synced,
                    neo4j_status = excluded.neo4j_status,
                    description = excluded.description
            """, (
                metadata.dataset_id,
                metadata.name,
                metadata.source_filename,
                metadata.source_type,
                metadata.node_count,
                metadata.edge_count,
                json.dumps(metadata.node_ids),
                json.dumps(metadata.edge_ids),
                1 if metadata.is_active else 0,
                1 if metadata.is_demo else 0,
                metadata.uploaded_at,
                1 if metadata.neo4j_synced else 0,
                metadata.neo4j_status,
                metadata.description
            ))
            conn.commit()

        logger.info(
            "Registered dataset '%s' (ID: %s, %d nodes, %d edges, active=%s)",
            metadata.name, metadata.dataset_id, metadata.node_count, metadata.edge_count, metadata.is_active
        )
        return metadata

    def get_dataset(self, dataset_id: str) -> Optional[DatasetMetadata]:
        """Retrieves an individual dataset record by identifier."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM app_datasets WHERE dataset_id = ?", (dataset_id,)).fetchone()
            if not row:
                return None
            return self._row_to_metadata(row)

    def list_datasets(self) -> List[DatasetMetadata]:
        """Lists all registered datasets ordered by upload timestamp descending."""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM app_datasets ORDER BY uploaded_at DESC").fetchall()
            return [self._row_to_metadata(r) for r in rows]

    def get_active_dataset(self) -> Optional[DatasetMetadata]:
        """Returns the currently active dataset, if any."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM app_datasets WHERE is_active = 1 LIMIT 1").fetchone()
            if row:
                return self._row_to_metadata(row)
            # If none explicitly active, return most recently uploaded if available
            row_recent = conn.execute("SELECT * FROM app_datasets ORDER BY uploaded_at DESC LIMIT 1").fetchone()
            if row_recent:
                return self._row_to_metadata(row_recent)
            return None

    def set_active_dataset(self, dataset_id: str) -> Optional[DatasetMetadata]:
        """Sets the designated dataset as the active dataset."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM app_datasets WHERE dataset_id = ?", (dataset_id,)).fetchone()
            if not row:
                return None
            conn.execute("UPDATE app_datasets SET is_active = 0")
            conn.execute("UPDATE app_datasets SET is_active = 1 WHERE dataset_id = ?", (dataset_id,))
            conn.commit()
            return self.get_dataset(dataset_id)

    def delete_dataset(self, dataset_id: str) -> bool:
        """Removes dataset metadata from persistent registry."""
        with self._get_connection() as conn:
            cur = conn.execute("DELETE FROM app_datasets WHERE dataset_id = ?", (dataset_id,))
            conn.commit()
            return cur.rowcount > 0

    def clear_all(self) -> None:
        """Clears all dataset records from registry."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM app_datasets")
            conn.commit()

    @staticmethod
    def _row_to_metadata(row: sqlite3.Row) -> DatasetMetadata:
        return DatasetMetadata(
            dataset_id=row["dataset_id"],
            name=row["name"],
            source_filename=row["source_filename"],
            source_type=row["source_type"],
            node_count=row["node_count"],
            edge_count=row["edge_count"],
            node_ids=json.loads(row["node_ids_json"]),
            edge_ids=json.loads(row["edge_ids_json"]),
            is_active=bool(row["is_active"]),
            is_demo=bool(row["is_demo"]),
            uploaded_at=row["uploaded_at"],
            neo4j_synced=bool(row["neo4j_synced"]),
            neo4j_status=row["neo4j_status"],
            description=row["description"],
        )


# Global Singleton DatasetManager
dataset_manager = DatasetManager()
