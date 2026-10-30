"""Ingestion Contracts, Base Connector Interface, and Validation Models."""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from backend.app.models.domain import DataProvenance, GraphEdge, GraphNode


class IngestionError(BaseModel):
    """Structured error detail for rejected or malformed records."""
    record_index: int
    field: Optional[str] = None
    error_type: str
    message: str
    raw_snippet: Optional[Dict[str, Any]] = None


class IngestionBatch(BaseModel):
    """Raw telemetry payload submitted for ingestion."""
    source_name: str = Field(description="Connector name e.g. 'crowdstrike_edr', 'splunk_siem', 'synthetic_generator'")
    provenance: DataProvenance = Field(default=DataProvenance.LIVE_TELEMETRY)
    sync_mode: str = Field(default="INCREMENTAL", description="FULL | INCREMENTAL")
    records: List[Dict[str, Any]] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IngestionResult(BaseModel):
    """Result summary of an ingestion operation with full audit counts."""
    source_name: str
    provenance: DataProvenance
    total_received: int
    nodes_created: int
    edges_created: int
    duplicates_skipped: int
    errors_encountered: int
    is_success: bool
    processed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    errors: List[IngestionError] = Field(default_factory=list)


class BaseConnector(ABC):
    """Abstract base class for all security telemetry connectors."""

    def __init__(self, name: str, provenance: DataProvenance = DataProvenance.LIVE_TELEMETRY):
        self.name = name
        self.provenance = provenance
        self._seen_event_hashes: set = set()

    @abstractmethod
    def ingest(self, raw_payload: List[Dict[str, Any]]) -> IngestionResult:
        """Validate, deduplicate, and normalize raw telemetry into graph entities."""
        pass
