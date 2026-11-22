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
from backend.app.ingestion.dataset_manager import DatasetManager, DatasetMetadata, dataset_manager
from backend.app.ingestion.synthetic_enterprise_loader import SyntheticEnterpriseLoader
from backend.app.ingestion.cic_ids_adapter import CICIDS2017Adapter, detect_cic_ids_headers
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
MAX_CSV_FILE_SIZE_BYTES = 250 * 1024 * 1024  # 250 MB limit
MAX_CSV_ROW_COUNT = 10_000                  # 10,000 rows default limit for standard entity batches
MAX_FLOW_CSV_ROW_COUNT = 10_000             # 10,000 flows limit for optimal memory and response time in cloud containers


class CSVIngestionSummary(BaseModel):
    """Structured response summary for CSV upload operations."""
    upload_id: str = Field(description="Unique batch identifier for audit attribution")
    dataset_id: Optional[str] = Field(default=None, description="Unique dataset identifier for lifecycle tracking")
    filename: str
    csv_type: str = Field(description="NODES | RELATIONSHIPS | CIC_IDS2017_FLOWS | UNKNOWN")
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
    is_sampled: bool = Field(default=False)
    processing_duration_ms: Optional[float] = Field(default=None)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CSVIngestionParser:
    """Robust, streaming CSV parser and schema validator."""

    @staticmethod
    def parse_and_validate_raw_csv(
        raw_bytes: Any,
        filename: str
    ) -> Tuple[List[Dict[str, str]], List[Dict[str, Any]], str, int]:
        """Validates file extension, byte limits, row bounds, and parses CSV content with minimal memory.
        
        Supports both bytes buffer and file-like stream objects.
        Returns:
            Tuple of (valid_records, malformed_row_errors, detected_schema_type, total_file_data_rows)
        """
        # 1. Extension check
        lower_name = filename.lower()
        if not lower_name.endswith(".csv"):
            raise ValueError(f"Invalid file extension for '{filename}'. Only .csv files are supported.")

        # 2. File size limit & stream normalization
        if isinstance(raw_bytes, (bytes, bytearray)):
            byte_len = len(raw_bytes)
            stream = io.BytesIO(raw_bytes)
        elif hasattr(raw_bytes, "read"):
            stream = raw_bytes
            stream.seek(0, io.SEEK_END)
            byte_len = stream.tell()
            stream.seek(0)
        else:
            raise ValueError(f"Unsupported payload input type: {type(raw_bytes)}")

        if byte_len > MAX_CSV_FILE_SIZE_BYTES:
            raise ValueError(
                f"File size exceeds maximum allowable limit of {MAX_CSV_FILE_SIZE_BYTES // (1024 * 1024)}MB "
                f"({byte_len} bytes provided)."
            )

        if byte_len == 0:
            raise ValueError("Uploaded CSV file is completely empty.")

        # 3. Auto-detect delimiter from first chunk without full decode
        sample_chunk = stream.read(16384)
        if not sample_chunk or not sample_chunk.strip():
            raise ValueError("Uploaded CSV file contains no readable content.")

        sample_text = sample_chunk.decode("utf-8-sig", errors="replace").replace("\x00", "")
        delimiter = ","
        semis = sample_text.count(";")
        commas = sample_text.count(",")
        tabs = sample_text.count("\t")
        if semis > commas and semis > 3:
            delimiter = ";"
        elif tabs > commas and tabs > 3:
            delimiter = "\t"

        stream.seek(0)

        # 4. Stream rows line-by-line with null-byte sanitization
        text_stream = io.TextIOWrapper(stream, encoding="utf-8-sig", errors="replace")

        def sanitized_line_generator():
            for line in text_stream:
                if "\x00" in line:
                    yield line.replace("\x00", "")
                else:
                    yield line

        reader = csv.reader(sanitized_line_generator(), delimiter=delimiter)

        headers_raw: List[str] = []
        header_row_num = 1
        for row in reader:
            if not row or not any(c.strip() for c in row):
                header_row_num += 1
                continue
            if row[0].strip().startswith("#"):
                header_row_num += 1
                continue
            headers_raw = [c.strip() for c in row if c is not None]
            break

        if not headers_raw or not any(headers_raw):
            raise ValueError("CSV header row contains no valid column names.")

        headers = [h.strip().lower() for h in headers_raw if h.strip()]

        # Determine schema type
        schema_type = "UNKNOWN"
        has_node_id = any(h in headers for h in ("node_id", "id"))
        has_source = any(h in headers for h in ("source_id", "source", "source_node_id"))
        has_target = any(h in headers for h in ("target_id", "target", "target_node_id"))
        cic_map = detect_cic_ids_headers(headers_raw, filename=filename)

        if has_source and has_target:
            schema_type = "RELATIONSHIPS"
        elif has_node_id:
            schema_type = "NODES"
        elif cic_map is not None or any(term in lower_name for term in ("portscan", "pcap", "cic", "ids2017", "flow", "ddos", "dos", "attack")):
            schema_type = "CIC_IDS2017_FLOWS"
        else:
            raise ValueError(
                f"Unrecognized CSV header structure. Found headers: {headers[:8]}... "
                "Expected either 'node_id'/'id' for nodes, 'source_id'/'target_id' for relationships, or network flow columns for CIC-IDS2017 datasets."
            )

        # 5. Stream and bound data rows safely without memory spikes
        max_allowed_rows = MAX_FLOW_CSV_ROW_COUNT if schema_type == "CIC_IDS2017_FLOWS" else MAX_CSV_ROW_COUNT
        parsed_records: List[Dict[str, str]] = []
        errors: List[Dict[str, Any]] = []
        expected_col_count = len(headers_raw)
        total_data_row_count = 0

        for row_idx, row in enumerate(reader, start=header_row_num + 1):
            if not row or not any(c.strip() for c in row):
                continue
            total_data_row_count += 1

            # Once capped for processing, quickly count remainder without dict allocations
            if len(parsed_records) >= max_allowed_rows:
                continue

            if len(row) != expected_col_count:
                # Tolerant recovery: pad or slice minor discrepancy of +/- 2 columns
                if abs(len(row) - expected_col_count) <= 2:
                    if len(row) < expected_col_count:
                        row = row + [""] * (expected_col_count - len(row))
                    else:
                        row = row[:expected_col_count]
                else:
                    errors.append({
                        "row": row_idx,
                        "field": None,
                        "error": "MALFORMED_ROW",
                        "message": f"Row has {len(row)} columns, expected {expected_col_count} matching header.",
                        "raw_line": ",".join(row[:5]) + "..."
                    })
                    continue

            # Store only cleaned keys to avoid memory overhead
            record_dict = {"_row_number": row_idx}
            for h_clean, cell in zip(headers, row):
                record_dict[h_clean] = cell.strip()

            parsed_records.append(record_dict)

        if total_data_row_count == 0:
            raise ValueError("CSV contains a header row but 0 data rows.")

        if schema_type != "CIC_IDS2017_FLOWS" and total_data_row_count > max_allowed_rows:
            raise ValueError(
                f"CSV row count ({total_data_row_count}) exceeds maximum batch limit of {max_allowed_rows} rows."
            )

        return parsed_records, errors, schema_type, total_data_row_count


class TelemetryIngestionService:
    """Enterprise Ingestion Service orchestrating CSV validation and incremental Neo4j upserts."""

    def __init__(self, loader: Optional[SyntheticEnterpriseLoader] = None):
        self.loader = loader or SyntheticEnterpriseLoader()

    def ingest_csv_payload(
        self,
        raw_bytes: Any,
        filename: str,
        engine: GraphEngine,
        override_provenance: Optional[DataProvenance] = None,
        dataset_id: Optional[str] = None
    ) -> CSVIngestionSummary:
        """Processes and incrementally ingests CSV data into the SafeContain AI graph.
        
        Guarantees:
        - NEVER resets, clears, or deletes existing graph entities.
        - Idempotent upserts via parameterized Cypher and MERGE when Neo4j is live.
        - Full provenance tagging with DataProvenance.CSV (or caller override).
        - Detailed row-by-row validation error collection.
        """
        upload_id = f"csv-batch-{uuid.uuid4().hex[:10]}"
        dataset_id = dataset_id or DatasetManager.generate_dataset_id()
        provenance = override_provenance or DataProvenance.CSV
        created_node_ids: Set[str] = set()
        created_edge_ids: Set[str] = set()

        try:
            records, parse_errors, schema_type, total_file_rows = CSVIngestionParser.parse_and_validate_raw_csv(
                raw_bytes=raw_bytes,
                filename=filename
            )
        except Exception as ve:
            neo4j_status = "CONNECTED" if engine.is_neo4j_live else "OFFLINE_FALLBACK"
            neo4j_details = {
                "database": getattr(engine, "active_database", None) if engine.is_neo4j_live else None,
                "message": "Parsing failed prior to graph sync. 0 rows ingested." if engine.is_neo4j_live else "Neo4j is offline. Ingestion was not performed due to parse error."
            }
            return CSVIngestionSummary(
                upload_id=upload_id,
                dataset_id=dataset_id,
                filename=filename,
                csv_type="UNKNOWN",
                total_rows=0,
                status="FAILED",
                message=str(ve),
                neo4j_synced=False,
                neo4j_status=neo4j_status,
                neo4j_details=neo4j_details,
                validation_errors=[{"row": 1, "field": "header", "error": "PARSING_FAILED", "message": str(ve)}]
            )

        total_rows = total_file_rows
        accepted_rows = 0
        rejected_rows = len(parse_errors)
        duplicate_rows = 0
        nodes_created = 0
        nodes_updated = 0
        relationships_created = 0
        relationships_updated = 0
        validation_errors = list(parse_errors)
        is_sampled = False
        processing_duration_ms = None

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
                    "dataset_id": dataset_id,
                    "source_file": filename,
                }

                new_node = GraphNode(
                    id=node_id,
                    name=name,
                    type=node_type,
                    criticality=crit_val,
                    is_compromised=is_compromised,
                    is_crown_jewel=is_crown,
                    properties=properties,
                    provenance=provenance,
                    dataset_id=dataset_id,
                    source_file=filename,
                    ingestion_batch_id=upload_id,
                    is_demo=False
                )

                # Incremental Upsert check (Never clear graph!)
                existing = engine.get_node(node_id)
                if existing:
                    if dataset_id and not existing.dataset_id:
                        existing.dataset_id = dataset_id
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
                created_node_ids.add(node_id)
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
                        "dataset_id": dataset_id,
                        "source_file": filename,
                    },
                    provenance=provenance,
                    dataset_id=dataset_id,
                    source_file=filename,
                    ingestion_batch_id=upload_id,
                    is_demo=False
                )

                # Ensure stub nodes exist in graph so edges do not dangle
                if not engine.get_node(src):
                    stub_s = GraphNode(
                        id=src,
                        name=src,
                        type=NodeType.HOST,
                        criticality=0.5,
                        provenance=provenance,
                        dataset_id=dataset_id,
                        source_file=filename,
                        ingestion_batch_id=upload_id,
                        is_demo=False
                    )
                    engine.add_node(stub_s)
                    created_node_ids.add(src)
                    if engine.is_neo4j_live:
                        engine.create_or_update_node_in_neo4j(stub_s)
                    nodes_created += 1

                if not engine.get_node(tgt):
                    stub_t = GraphNode(
                        id=tgt,
                        name=tgt,
                        type=NodeType.HOST,
                        criticality=0.5,
                        provenance=provenance,
                        dataset_id=dataset_id,
                        source_file=filename,
                        ingestion_batch_id=upload_id,
                        is_demo=False
                    )
                    engine.add_node(stub_t)
                    created_node_ids.add(tgt)
                    if engine.is_neo4j_live:
                        engine.create_or_update_node_in_neo4j(stub_t)
                    nodes_created += 1

                # Incremental Upsert check
                existing_edge = engine.get_edge(rel_id)
                if existing_edge:
                    if dataset_id and not existing_edge.dataset_id:
                        existing_edge.dataset_id = dataset_id
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
                created_edge_ids.add(rel_id)
                accepted_rows += 1

                # Incremental Neo4j persistence via MERGE
                if engine.is_neo4j_live:
                    engine.create_or_update_edge_in_neo4j(edge)

        elif schema_type == "CIC_IDS2017_FLOWS":
            adapter_result = CICIDS2017Adapter.process_records(
                records=records,
                filename=filename,
                engine=engine,
                upload_id=upload_id,
                provenance=provenance,
                total_file_rows=total_file_rows,
                max_rows=MAX_FLOW_CSV_ROW_COUNT,
                dataset_id=dataset_id
            )
            accepted_rows = adapter_result["accepted_rows"]
            rejected_rows += adapter_result["rejected_rows"]
            duplicate_rows = adapter_result["duplicate_rows"]
            nodes_created = adapter_result["nodes_created"]
            nodes_updated = adapter_result["nodes_updated"]
            relationships_created = adapter_result["relationships_created"]
            relationships_updated = adapter_result["relationships_updated"]
            validation_errors.extend(adapter_result["validation_errors"])
            is_sampled = adapter_result["is_sampled"]
            processing_duration_ms = adapter_result["duration_ms"]
            created_node_ids.update(adapter_result.get("created_node_ids", []))
            created_edge_ids.update(adapter_result.get("created_edge_ids", []))

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

        # Dataset lifecycle registration
        if accepted_rows > 0:
            dataset_meta = DatasetMetadata(
                dataset_id=dataset_id,
                name=filename,
                filename=filename,
                csv_type=schema_type,
                total_rows=total_rows,
                node_count=len(created_node_ids) if created_node_ids else (nodes_created + nodes_updated),
                edge_count=len(created_edge_ids) if created_edge_ids else (relationships_created + relationships_updated),
                is_active=True,
                created_at=datetime.now(timezone.utc),
                node_ids=list(created_node_ids),
                edge_ids=list(created_edge_ids),
            )
            dataset_manager.register_dataset(dataset_meta)

        # Overall Status
        if rejected_rows == 0:
            final_status = "SUCCESS"
            if is_sampled:
                msg = (
                    f"Successfully ingested {accepted_rows} network flow records from '{filename}' "
                    f"(sampled from {total_rows:,} total flows for graph responsiveness). "
                    f"({nodes_created} nodes, {relationships_created} flow edges created)."
                )
            else:
                msg = f"Successfully processed {accepted_rows} rows from '{filename}'. ({nodes_created} nodes created, {relationships_created} edges created)."
        elif accepted_rows > 0:
            final_status = "PARTIAL_SUCCESS"
            if is_sampled:
                msg = f"Processed {accepted_rows} valid flows from '{filename}' (sampled from {total_rows:,} total rows); {rejected_rows} invalid rows rejected."
            else:
                msg = f"Processed {accepted_rows} valid rows from '{filename}'; {rejected_rows} invalid rows rejected."
        else:
            final_status = "FAILED"
            msg = f"All {rejected_rows} rows in '{filename}' failed validation."

        return CSVIngestionSummary(
            upload_id=upload_id,
            dataset_id=dataset_id,
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
            is_sampled=is_sampled,
            processing_duration_ms=processing_duration_ms,
        )

    @staticmethod
    def _parse_bool(val: Any) -> bool:
        if isinstance(val, bool):
            return val
        s = str(val).strip().lower()
        return s in ("true", "1", "yes", "t", "y")
