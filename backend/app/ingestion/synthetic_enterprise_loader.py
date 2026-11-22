"""SafeContain AI — Synthetic Enterprise Dataset Loader & Graph Synchronizer.

Loads, validates, and populates the complete 12-file synthetic enterprise dataset
into SafeContain AI's Dual Graph Engine (Neo4j if live, NetworkX fallback),
Business Continuity Twin, and Response Planning modules.
"""

import csv
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from backend.app.core.config import settings
from backend.app.graph.engine import GraphEngine
from backend.app.business.twin import BusinessContinuityTwin
from backend.app.ingestion.dataset_manager import DatasetMetadata, dataset_manager
from backend.app.ingestion.dataset_validator import DatasetValidator
from backend.app.models.domain import (
    BusinessWorkflow,
    DataProvenance,
    EvidenceStatus,
    GraphEdge,
    GraphNode,
    NodeType,
    RelationshipType,
    WorkflowCriticality,
)

logger = logging.getLogger(__name__)

DEFAULT_DATASET_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data", "synthetic_enterprise")


class SyntheticEnterpriseLoader:
    """Enterprise-grade, idempotent CSV dataset loader for SafeContain AI."""

    def __init__(self, dataset_dir: str = DEFAULT_DATASET_DIR):
        self.dataset_dir = os.path.abspath(dataset_dir)
        self.validator = DatasetValidator(self.dataset_dir)

    def _read_csv(self, filename: str) -> List[Dict[str, str]]:
        path = os.path.join(self.dataset_dir, filename)
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Required dataset file missing: {path}")
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            return list(reader)

    def get_dataset_metadata(self) -> Dict[str, Any]:
        """Returns catalog information, record counts, and validation status."""
        val_report = self.validator.validate()
        return {
            "dataset_name": "SafeContain AI Enterprise Cyber Defense Synthetic Dataset",
            "version": "2.0.0",
            "provenance": "SYNTHETIC",
            "dataset_directory": self.dataset_dir,
            "validation_status": val_report.get("validation_status", "UNKNOWN"),
            "file_counts": val_report.get("total_records_per_csv", {}),
            "summary_metrics": val_report.get("summary_metrics", {}),
            "files": [
                "nodes.csv", "relationships.csv", "assets.csv", "users.csv",
                "vulnerabilities.csv", "security_alerts.csv", "evidence.csv",
                "attack_paths.csv", "interventions.csv", "asset_dependencies.csv",
                "business_impact.csv", "threat_scenarios.csv"
            ]
        }

    def get_threat_scenarios(self) -> List[Dict[str, Any]]:
        """Reads all scenarios from threat_scenarios.csv."""
        return self._read_csv("threat_scenarios.csv")

    def _map_node_type(self, raw_type: str) -> NodeType:
        t = raw_type.upper().strip()
        if t in ("USER", "EMPLOYEE", "ADMIN"):
            return NodeType.USER
        elif t in ("SERVICE_ACCOUNT", "SERVICE"):
            return NodeType.SERVICE_ACCOUNT
        elif t in ("ENDPOINT", "LAPTOP", "WORKSTATION"):
            return NodeType.ENDPOINT
        elif t in ("SERVER", "WEB_SERVER", "HOST"):
            return NodeType.SERVER
        elif t in ("DATABASE", "DB"):
            return NodeType.DATABASE
        elif t in ("APPLICATION", "APP", "MICROSERVICE"):
            return NodeType.APPLICATION
        elif t in ("FIREWALL", "WAF", "SECURITY_TOOL"):
            return NodeType.SECURITY_CONTROL
        elif t in ("CLOUD_RESOURCE", "STORAGE", "BACKUP_SYSTEM"):
            return NodeType.CLOUD_RESOURCE
        elif t in ("NETWORK", "SUBNET"):
            return NodeType.NETWORK
        return NodeType.HOST

    def _map_rel_type(self, raw_type: str) -> RelationshipType:
        t = raw_type.upper().strip()
        if t in ("USES_DEVICE", "USES"):
            return RelationshipType.USES_DEVICE
        elif t in ("AUTHENTICATES_TO", "LOGS_INTO"):
            return RelationshipType.AUTHENTICATES_TO
        elif t in ("HAS_ACCESS", "HAS_ACCESS_TO"):
            return RelationshipType.HAS_ACCESS_TO
        elif t in ("ADMIN_ACCESS", "MANAGES", "OWNS"):
            return RelationshipType.CAN_ACCESS
        elif t in ("CONNECTS_TO", "COMMUNICATES_WITH", "CAN_REACH"):
            return RelationshipType.CONNECTED_TO
        elif t in ("RUNS_ON", "RUNS"):
            return RelationshipType.RUNS
        elif t in ("HOSTED_ON", "HOSTS"):
            return RelationshipType.HOSTS
        elif t in ("DEPENDS_ON", "BACKED_UP_BY"):
            return RelationshipType.DEPENDS_ON
        elif t in ("CONTROLLED_BY", "PROTECTED_BY"):
            return RelationshipType.CONTROLLED_BY
        elif t in ("EXPOSED_TO", "MEMBER_OF"):
            return RelationshipType.EXPOSED_TO
        return RelationshipType.CONNECTED_TO

    def load_scenario_into_platform(
        self,
        engine: GraphEngine,
        twin: Optional[BusinessContinuityTwin] = None,
        scenario_id: Optional[str] = "SCEN-001"
    ) -> Dict[str, Any]:
        """Idempotently loads nodes, edges, assets, and dependencies into SafeContain AI."""
        # 1. First validate dataset
        val_report = self.validator.validate()
        if val_report["validation_status"] != "PASSED":
            raise ValueError(f"Dataset validation failed with {val_report['integrity_checks']['total_errors']} errors.")

        # 2. Read CSVs
        nodes_raw = self._read_csv("nodes.csv")
        rels_raw = self._read_csv("relationships.csv")
        impact_raw = self._read_csv("business_impact.csv")
        scenarios_raw = self._read_csv("threat_scenarios.csv")

        # Find target scenario
        active_scenario = None
        for s in scenarios_raw:
            if s.get("scenario_id") == scenario_id:
                active_scenario = s
                break
        if not active_scenario and scenarios_raw:
            active_scenario = scenarios_raw[0]

        # 3. Clear existing graph state
        engine.clear()

        # 4. Transform and insert GraphNodes
        entry_node_id = active_scenario.get("entry_node_id") if active_scenario else None
        target_node_id = active_scenario.get("target_node_id") if active_scenario else None

        loaded_nodes = 0
        for r in nodes_raw:
            nid = r["node_id"]
            crit = float(r.get("criticality", 0.5))
            is_compromised = (r.get("security_status") == "COMPROMISED") or (nid == entry_node_id)
            is_crown = (crit >= 0.95) or ("crown_jewel" in r.get("tags", "").lower()) or (nid == target_node_id)

            node = GraphNode(
                id=nid,
                name=r["name"],
                type=self._map_node_type(r.get("node_type", "HOST")),
                criticality=crit,
                is_compromised=is_compromised,
                is_crown_jewel=is_crown,
                properties={
                    "hostname": r.get("hostname", ""),
                    "ip_address": r.get("ip_address", ""),
                    "environment": r.get("environment", ""),
                    "department": r.get("department", ""),
                    "owner": r.get("owner", ""),
                    "business_value": float(r.get("business_value", 0.0)),
                    "exposure": r.get("exposure", ""),
                    "security_status": r.get("security_status", ""),
                    "tags": r.get("tags", ""),
                    "description": r.get("description", ""),
                    "dataset_id": f"DEMO-{scenario_id}",
                    "is_demo": True,
                },
                provenance=DataProvenance.SYNTHETIC,
                dataset_id=f"DEMO-{scenario_id}",
                is_demo=True
            )
            engine.add_node(node)
            loaded_nodes += 1

        # 5. Transform and insert GraphEdges
        loaded_edges = 0
        for r in rels_raw:
            rid = r["relationship_id"]
            src = r["source_id"]
            tgt = r["target_id"]
            risk = float(r.get("risk_score", 20.0))
            conf = float(r.get("confidence", 0.95))

            edge = GraphEdge(
                id=rid,
                source=src,
                target=tgt,
                type=self._map_rel_type(r.get("relationship_type", "CONNECTED_TO")),
                evidence_status=EvidenceStatus.CONFIRMED if conf >= 0.8 else EvidenceStatus.SUSPECTED,
                confidence=conf,
                weight=max(1.0, 100.0 - risk),
                is_active=True,
                properties={
                    "privilege_level": r.get("privilege_level", "USER"),
                    "risk_score": risk,
                    "discovered_by": r.get("discovered_by", ""),
                    "description": r.get("description", ""),
                    "dataset_id": f"DEMO-{scenario_id}",
                    "is_demo": True,
                },
                provenance=DataProvenance.SYNTHETIC,
                dataset_id=f"DEMO-{scenario_id}",
                is_demo=True
            )
            engine.add_edge(edge)
            loaded_edges += 1

        # 6. Populate Business Continuity Twin
        if twin is not None:
            # Register workflows from business_impact.csv
            for imp in impact_raw:
                wf_id = f"wf-{imp['asset_id']}"
                loss = float(imp.get("estimated_hourly_loss", 25000.0))
                score = float(imp.get("impact_score", 70.0))
                
                tier = (
                    WorkflowCriticality.TIER_1_MISSION_CRITICAL if score >= 90.0
                    else (WorkflowCriticality.TIER_2_BUSINESS_CRITICAL if score >= 75.0
                          else WorkflowCriticality.TIER_3_OPERATIONAL)
                )

                wf = BusinessWorkflow(
                    id=wf_id,
                    name=imp.get("business_function", f"Workflow {imp['asset_id']}"),
                    criticality=tier,
                    citizen_facing=("citizen" in imp.get("business_function", "").lower() or "payment" in imp.get("business_function", "").lower()),
                    dependent_asset_ids=[imp["asset_id"]],
                    max_allowable_downtime_hours=0.0 if tier == WorkflowCriticality.TIER_1_MISSION_CRITICAL else 2.0,
                    estimated_hourly_downtime_cost=loss,
                    operational_status="HEALTHY"
                )
                twin.register_workflow(wf)

            # Discover structural dependencies from loaded graph
            twin.discover_dependencies_from_graph(engine)

        # Register demo dataset in dataset manager
        demo_ds_id = f"DEMO-{scenario_id}"
        demo_meta = DatasetMetadata(
            dataset_id=demo_ds_id,
            name=f"{active_scenario.get('scenario_name', 'Enterprise Scenario')} (Demo)",
            filename="nodes.csv & relationships.csv",
            csv_type="DEMO",
            total_rows=loaded_nodes + loaded_edges,
            node_count=loaded_nodes,
            edge_count=loaded_edges,
            is_active=True,
            is_demo=True,
            created_at=datetime.now(timezone.utc),
            node_ids=[r["node_id"] for r in nodes_raw],
            edge_ids=[r["relationship_id"] for r in rels_raw],
        )
        dataset_manager.register_dataset(demo_meta)

        # 7. Sync to Neo4j if live
        neo4j_synced = False
        if engine.is_neo4j_live:
            try:
                engine.sync_to_neo4j()
                neo4j_synced = True
            except Exception as e:
                logger.warning(f"Neo4j sync encountered issue: {e}")

        # 8. Recalculate attack paths and verify reachability
        target_crowns = [nid for nid, n in engine._node_store.items() if n.is_crown_jewel]
        attack_paths = engine.find_attack_paths(max_depth=6)

        return {
            "status": "SUCCESS",
            "scenario_id": active_scenario.get("scenario_id", "SCEN-001") if active_scenario else "ENTERPRISE-CORE",
            "scenario_name": active_scenario.get("scenario_name", "Enterprise Baseline") if active_scenario else "Full Synthetic Enterprise",
            "nodes_loaded": loaded_nodes,
            "edges_loaded": loaded_edges,
            "critical_assets_count": len(target_crowns),
            "attack_paths_discovered": len(attack_paths),
            "neo4j_synced": neo4j_synced,
            "active_backend": "live_neo4j" if engine.is_neo4j_live else "in_memory_networkx",
            "provenance": "SYNTHETIC"
        }
