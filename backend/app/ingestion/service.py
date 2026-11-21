"""SafeContain AI — CSV Ingestion & Telemetry Processing Service.

Provides robust, incremental, and idempotent CSV upload ingestion with:
- Multipart/form-data parsing with file-size and row-count constraints
- Header validation, schema auto-detection, and row-level data type checking
- Safe error collection per row without failing valid records
- Strict provenance tracking (DataProvenance.CSV)
- Incremental, non-destructive graph upsert (preserving existing graph data)
- Parameterized Cypher & MERGE for live Neo4j persistence with graceful fallback
- Structured audit logging and detailed ingestion summary reporting
"""

import csv
import io
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from backend.app.core.config import settings
from backend.app.graph.engine import GraphEngine
from backend.app.ingestion.contracts import IngestionError
from backend.app.ingestion.synthetic_enterprise_loader import SyntheticEnterpriseLoader
from backend.app.models.domain import (
    DataProvenance,
    EvidenceStatus,
    GraphEdge,
    GraphNode,
    NodeType,
    RelationshipType,
)

logger = logging.getLogger(__name__)

# Configurable Ingestion Safeguards
MAX_CSV_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB limit
MAX_CSV_ROW_COUNT = 10_000                  # 10,000 rows limit


class CSVIngestionSummary(BaseModel):
    """Structured response summary for CSV upload operations."""
    upload_id: str = Field(description="Unique batch identifier for audit attribution")
    filename: str
    csv_type: str = Field(description="NODES | RELATIONSHIPS | UNKNOWN")
    total_rows: int = Field(default=0)
    accepted_rows: int = Field(default=0)
    rejected_rows: int = Field(default=0)
    duplicate_rows: int = Field(default=0)
    nodes_created: int = Field(default=0)
    nodes_updated: int = Field(default=0)
    relationships_created: int = Field(default=0)
    relationships_updated: int = Field(default=0)
    neo4j_synced: bool = Field(default=False)
    neo4j_status: str = Field(default="OFFLINE_FALLBACK")
    neo4j_details: Dict[str, Any] = Field(default_factory=dict)
    validation_errors: List[Dict[str, Any]] = Field(default_factory=list)
    status: str = Field(default="SUCCESS", description="SUCCESS | PARTIAL_SUCCESS | FAILED")
    message: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CSVIngestionParser:
    """Robust CSV stream parser and schema validator."""

    @staticmethod
    def parse_and_validate_raw_csv(
        raw_bytes: bytes,
        filename: str
    ) -> Tuple[List[Dict[str, str]], List[Dict[str, Any]], str]:
        """Validates file extension, byte limits, row bounds, and parses CSV content.
        
        Returns:
            Tuple of (valid_rows, malformed_row_errors, detected_schema_type)
        """
        # 1. Extension check
        lower_name = filename.lower()
        if not lower_name.endswith(".csv"):
            raise ValueError(f"Invalid file extension for '{filename}'. Only .csv files are supported.")

        # 2. File size limit
        if len(raw_bytes) > MAX_CSV_FILE_SIZE_BYTES:
            raise ValueError(
                f"File size exceeds maximum allowable limit of {MAX_CSV_FILE_SIZE_BYTES // (1024 * 1024)}MB "
                f"({len(raw_bytes)} bytes provided)."
            )

        if not raw_bytes or not raw_bytes.strip():
            raise ValueError("Uploaded CSV file is completely empty.")

        # 3. Decode content
        try:
            text = raw_bytes.decode("utf-8-sig")
        except UnicodeDecodeError:
            try:
                text = raw_bytes.decode("latin-1")
            except Exception as e:
                raise ValueError(f"Unable to decode CSV with UTF-8 or Latin-1 encoding: {str(e)}")

        # 4. Parse rows
        stream = io.StringIO(text.strip())
        reader = csv.reader(stream)
        rows_raw = list(reader)

        if not rows_raw:
            raise ValueError("CSV contains no rows.")

        headers_raw = rows_raw[0]
        headers = [h.strip().lower() for h in headers_raw if h.strip()]

        if not headers:
            raise ValueError("CSV header row contains no valid column names.")

        # Determine schema type
        schema_type = "UNKNOWN"
        has_node_id = any(h in headers for h in ("node_id", "id"))
        has_source = any(h in headers for h in ("source_id", "source", "source_node_id"))
        has_target = any(h in headers for h in ("target_id", "target", "target_node_id"))

        if has_source and has_target:
            schema_type = "RELATIONSHIPS"
        elif has_node_id:
            schema_type = "NODES"
        else:
            raise ValueError(
                f"Unrecognized CSV header structure. Found headers: {headers}. "
                "Expected either 'node_id'/'id' for nodes, or 'source_id'/'source' and 'target_id'/'target' for relationships."
            )

        # 5. Row-count check
        data_rows = rows_raw[1:]
        if len(data_rows) > MAX_CSV_ROW_COUNT:
            raise ValueError(
                f"CSV row count ({len(data_rows)}) exceeds maximum batch limit of {MAX_CSV_ROW_COUNT} rows."
            )

        expected_col_count = len(headers_raw)
        parsed_records: List[Dict[str, str]] = []
        errors: List[Dict[str, Any]] = []

        for row_idx, row in enumerate(data_rows, start=2):  # 1-based, row 1 is header
            if not row or all(not cell.strip() for cell in row):
                continue  # Skip blank lines safely

            if len(row) != expected_col_count:
                errors.append({
                    "row": row_idx,
                    "field": None,
                    "error": "MALFORMED_ROW",
                    "message": f"Row has {len(row)} columns, expected {expected_col_count} matching header.",
                    "raw_line": ",".join(row)
                })
                continue

            # Clean and map to normalized headers
            record_dict = {}
            for h_clean, cell in zip(headers, row):
                record_dict[h_clean] = cell.strip()

            parsed_records.append({"_row_number": row_idx, **record_dict})

        return parsed_records, errors, schema_type


class TelemetryIngestionService:
    """Enterprise Ingestion Service orchestrating CSV validation and incremental Neo4j upserts."""

    def __init__(self, loader: Optional[SyntheticEnterpriseLoader] = None):
        self.loader = loader or SyntheticEnterpriseLoader()

    def ingest_csv_payload(
        self,
        raw_bytes: bytes,
        filename: str,
        engine: GraphEngine,
        override_provenance: Optional[DataProvenance] = None
    ) -> CSVIngestionSummary:
        """Processes and incrementally ingests CSV data into the SafeContain AI graph.
        
        Guarantees:
        - NEVER resets, clears, or deletes existing graph entities.
        - Idempotent upserts via parameterized Cypher and MERGE when Neo4j is live.
        - Full provenance tagging with DataProvenance.CSV (or caller override).
        - Detailed row-by-row validation error collection.
        """
        upload_id = f"csv-batch-{uuid.uuid4().hex[:10]}"
        provenance = override_provenance or DataProvenance.CSV

        try:
            records, parse_errors, schema_type = CSVIngestionParser.parse_and_validate_raw_csv(
                raw_bytes=raw_bytes,
                filename=filename
            )
        except ValueError as ve:
            return CSVIngestionSummary(
                upload_id=upload_id,
                filename=filename,
                csv_type="UNKNOWN",
                total_rows=0,
                status="FAILED",
                message=str(ve),
                validation_errors=[{"row": 1, "field": "header", "error": "PARSING_FAILED", "message": str(ve)}]
            )

        total_rows = len(records) + len(parse_errors)
        accepted_rows = 0
        rejected_rows = len(parse_errors)
        duplicate_rows = 0
        nodes_created = 0
        nodes_updated = 0
        relationships_created = 0
        relationships_updated = 0
        validation_errors = list(parse_errors)

        # Process based on detected schema
        if schema_type == "NODES":
            for rec in records:
                row_num = rec.get("_row_number", 0)
                node_id = rec.get("node_id") or rec.get("id")

                if not node_id:
                    validation_errors.append({
                        "row": row_num,
                        "field": "node_id",
                        "error": "MISSING_PRIMARY_KEY",
                        "message": "Node record lacks required 'node_id' or 'id'"
                    })
                    rejected_rows += 1
                    continue

                name = rec.get("name") or rec.get("label") or node_id
                raw_type = rec.get("node_type") or rec.get("type") or "HOST"
                node_type = self.loader._map_node_type(raw_type)

                # Validate numeric criticality
                crit_val = 0.5
                if "criticality" in rec and rec["criticality"]:
                    try:
                        crit_val = float(rec["criticality"])
                        if not (0.0 <= crit_val <= 1.0):
                            raise ValueError()
                    except ValueError:
                        validation_errors.append({
                            "row": row_num,
                            "field": "criticality",
                            "error": "INVALID_NUMERIC_RANGE",
                            "message": f"Criticality value '{rec['criticality']}' must be a float between 0.0 and 1.0."
                        })
                        rejected_rows += 1
                        continue

                # Validate booleans
                is_crown = self._parse_bool(rec.get("is_crown_jewel", "false")) or (crit_val >= 0.95)
                is_compromised = self._parse_bool(rec.get("is_compromised", "false")) or (rec.get("security_status", "").upper() == "COMPROMISED")

                # Validate business value
                b_val = 0.0
                if "business_value" in rec and rec["business_value"]:
                    try:
                        b_val = float(rec["business_value"])
                    except ValueError:
                        b_val = 0.0

                properties = {
                    "hostname": rec.get("hostname", ""),
                    "ip_address": rec.get("ip_address", ""),
                    "environment": rec.get("environment", "Production"),
                    "department": rec.get("department", ""),
                    "owner": rec.get("owner", ""),
                    "business_value": b_val,
                    "exposure": rec.get("exposure", ""),
                    "security_status": rec.get("security_status", "ACTIVE"),
                    "tags": rec.get("tags", ""),
                    "description": rec.get("description", ""),
                    "vulnerabilities": rec.get("vulnerabilities", ""),
                    "upload_batch_id": upload_id,
                }

                new_node = GraphNode(
                    id=node_id,
                    name=name,
                    type=node_type,
                    criticality=crit_val,
                    is_compromised=is_compromised,
                    is_crown_jewel=is_crown,
                    properties=properties,
                    provenance=provenance
                )

                # Incremental Upsert check (Never clear graph!)
                existing = engine.get_node(node_id)
                if existing:
                    # Compare content to identify exact duplicate
                    if (
                        existing.name == new_node.name and
                        existing.type == new_node.type and
                        abs(existing.criticality - new_node.criticality) < 1e-4 and
                        existing.is_compromised == new_node.is_compromised and
                        existing.is_crown_jewel == new_node.is_crown_jewel
                    ):
                        duplicate_rows += 1
                    else:
                        nodes_updated += 1
                else:
                    nodes_created += 1

                engine.add_node(new_node)
                accepted_rows += 1

                # Incremental Neo4j persistence via MERGE
                if engine.is_neo4j_live:
                    engine.create_or_update_node_in_neo4j(new_node)

        elif schema_type == "RELATIONSHIPS":
            for rec in records:
                row_num = rec.get("_row_number", 0)
                src = rec.get("source_id") or rec.get("source") or rec.get("source_node_id")
                tgt = rec.get("target_id") or rec.get("target") or rec.get("target_node_id")

                if not src or not tgt:
                    validation_errors.append({
                        "row": row_num,
                        "field": "source/target",
                        "error": "MISSING_RELATIONSHIP_ENDPOINTS",
                        "message": f"Relationship requires both source and target endpoints. (src='{src}', tgt='{tgt}')"
                    })
                    rejected_rows += 1
                    continue

                raw_rel_type = rec.get("relationship_type") or rec.get("type") or "CONNECTED_TO"
                rel_type = self.loader._map_rel_type(raw_rel_type)

                rel_id = rec.get("relationship_id") or rec.get("rel_id") or rec.get("id")
                if not rel_id:
                    rel_id = f"rel-{src}-{tgt}-{rel_type.value.lower()}"

                # Validate confidence
                conf_val = 0.95
                if "confidence" in rec and rec["confidence"]:
                    try:
                        conf_val = float(rec["confidence"])
                        if not (0.0 <= conf_val <= 1.0):
                            raise ValueError()
                    except ValueError:
                        validation_errors.append({
                            "row": row_num,
                            "field": "confidence",
                            "error": "INVALID_CONFIDENCE_RANGE",
                            "message": f"Confidence value '{rec['confidence']}' must be a float between 0.0 and 1.0."
                        })
                        rejected_rows += 1
                        continue

                # Validate weight / risk
                risk_val = 20.0
                if "risk_score" in rec and rec["risk_score"]:
                    try:
                        risk_val = float(rec["risk_score"])
                    except ValueError:
                        risk_val = 20.0

                weight_val = max(1.0, 100.0 - risk_val)
                if "weight" in rec and rec["weight"]:
                    try:
                        weight_val = float(rec["weight"])
                    except ValueError:
                        pass

                is_active = self._parse_bool(rec.get("is_active", "true"))

                ev_status_raw = rec.get("evidence_status", "").upper()
                if ev_status_raw == "CONFIRMED" or conf_val >= 0.8:
                    ev_status = EvidenceStatus.CONFIRMED
                elif ev_status_raw == "SUSPECTED":
                    ev_status = EvidenceStatus.SUSPECTED
                elif ev_status_raw == "UNKNOWN":
                    ev_status = EvidenceStatus.UNKNOWN
                else:
                    ev_status = EvidenceStatus.CONFIRMED if conf_val >= 0.8 else EvidenceStatus.SUSPECTED

                edge = GraphEdge(
                    id=rel_id,
                    source=src,
                    target=tgt,
                    type=rel_type,
                    evidence_status=ev_status,
                    confidence=conf_val,
                    weight=weight_val,
                    is_active=is_active,
                    properties={
                        "port": rec.get("port", ""),
                        "protocol": rec.get("protocol", "TCP"),
                        "privilege_level": rec.get("privilege_level", "USER"),
                        "risk_score": risk_val,
                        "discovered_by": rec.get("discovered_by", "CSV_INGESTION"),
                        "description": rec.get("description", ""),
                        "upload_batch_id": upload_id,
                    },
                    provenance=provenance
                )

                # Ensure stub nodes exist in graph so edges do not dangle
                if not engine.get_node(src):
                    stub_s = GraphNode(
                        id=src,
                        name=src,
                        type=NodeType.HOST,
                        criticality=0.5,
                        provenance=provenance
                    )
                    engine.add_node(stub_s)
                    if engine.is_neo4j_live:
                        engine.create_or_update_node_in_neo4j(stub_s)
                    nodes_created += 1

                if not engine.get_node(tgt):
                    stub_t = GraphNode(
                        id=tgt,
                        name=tgt,
                        type=NodeType.HOST,
                        criticality=0.5,
                        provenance=provenance
                    )
                    engine.add_node(stub_t)
                    if engine.is_neo4j_live:
                        engine.create_or_update_node_in_neo4j(stub_t)
                    nodes_created += 1

                # Incremental Upsert check
                existing_edge = engine.get_edge(rel_id)
                if existing_edge:
                    if (
                        existing_edge.source == edge.source and
                        existing_edge.target == edge.target and
                        existing_edge.type == edge.type and
                        abs(existing_edge.confidence - edge.confidence) < 1e-4 and
                        existing_edge.is_active == edge.is_active
                    ):
                        duplicate_rows += 1
                    else:
                        relationships_updated += 1
                else:
                    relationships_created += 1

                engine.add_edge(edge)
                accepted_rows += 1

                # Incremental Neo4j persistence via MERGE
                if engine.is_neo4j_live:
                    engine.create_or_update_edge_in_neo4j(edge)

        # Sync diagnostic reporting
        neo4j_synced = False
        neo4j_status = "OFFLINE_FALLBACK"
        if engine.is_neo4j_live:
            neo4j_synced = True
            neo4j_status = "CONNECTED"
            neo4j_details = {
                "database": engine.active_database,
                "synced_nodes": nodes_created + nodes_updated,
                "synced_relationships": relationships_created + relationships_updated,
            }
        else:
            neo4j_details = {
                "mode": "in_memory_networkx",
                "message": "Neo4j is not connected or in fallback mode. Upserted to in-memory graph.",
                "last_error": engine.last_connection_error
            }

        # Overall Status
        if rejected_rows == 0:
            final_status = "SUCCESS"
            msg = f"Successfully processed {accepted_rows} rows from '{filename}'. ({nodes_created} nodes created, {relationships_created} edges created)."
        elif accepted_rows > 0:
            final_status = "PARTIAL_SUCCESS"
            msg = f"Processed {accepted_rows} valid rows from '{filename}'; {rejected_rows} invalid rows rejected."
        else:
            final_status = "FAILED"
            msg = f"All {rejected_rows} rows in '{filename}' failed validation."

        return CSVIngestionSummary(
            upload_id=upload_id,
            filename=filename,
            csv_type=schema_type,
            total_rows=total_rows,
            accepted_rows=accepted_rows,
            rejected_rows=rejected_rows,
            duplicate_rows=duplicate_rows,
            nodes_created=nodes_created,
            nodes_updated=nodes_updated,
            relationships_created=relationships_created,
            relationships_updated=relationships_updated,
            neo4j_synced=neo4j_synced,
            neo4j_status=neo4j_status,
            neo4j_details=neo4j_details,
            validation_errors=validation_errors,
            status=final_status,
            message=msg,
        )

    @staticmethod
    def _parse_bool(val: Any) -> bool:
        if isinstance(val, bool):
            return val
        s = str(val).strip().lower()
        return s in ("true", "1", "yes", "t", "y")
