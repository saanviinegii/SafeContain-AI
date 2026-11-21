#!/usr/bin/env python3
"""SafeContain AI — Synthetic Enterprise Dataset Importer Script.

Executes end-to-end import, validation, graph engine population, and
business twin calibration from the 12 CSV files in backend/data/synthetic_enterprise/.
"""

import sys
import os

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.app.graph.engine import GraphEngine
from backend.app.business.twin import BusinessContinuityTwin
from backend.app.ingestion.synthetic_enterprise_loader import SyntheticEnterpriseLoader


def main():
    print("=" * 80)
    print("      SAFECONTAIN AI — ENTERPRISE DATASET IMPORT & CALIBRATION")
    print("=" * 80)

    loader = SyntheticEnterpriseLoader()

    # Step 1: Check Metadata & Validation
    print("\n[1/4] Validating 12 Synthetic Enterprise CSV Files...")
    meta = loader.get_dataset_metadata()
    print(f"      Dataset Name:      {meta['dataset_name']}")
    print(f"      Validation Status: {meta['validation_status']}")
    if meta['validation_status'] != "PASSED":
        print("[ERROR] Dataset validation failed. Run backend.app.ingestion.dataset_validator for details.")
        sys.exit(1)
    print("      All 12 CSV files verified successfully!")

    # Step 2: Initialize Graph Engine & Business Twin
    print("\n[2/4] Initializing Graph Engine and Business Continuity Twin...")
    engine = GraphEngine()
    twin = BusinessContinuityTwin()
    active_backend = "live_neo4j" if engine.is_neo4j_live else "in_memory_networkx"
    print(f"      Configured Mode: {engine.mode}")
    print(f"      Active Backend:  {active_backend}")
    if not engine.is_neo4j_live:
        print("      [NOTE] Live Neo4j instance not reachable. Seamlessly utilizing in-memory NetworkX engine.")

    # Step 3: Load Scenario & Populate Graph
    scenario_id = sys.argv[1] if len(sys.argv) > 1 else "SCEN-001"
    print(f"\n[3/4] Importing Scenario '{scenario_id}' into Active Engine...")
    result = loader.load_scenario_into_platform(engine, twin, scenario_id=scenario_id)

    print(f"      Scenario Name:       {result['scenario_name']}")
    print(f"      Nodes Ingested:      {result['nodes_loaded']}")
    print(f"      Edges Ingested:      {result['edges_loaded']}")
    print(f"      Critical Assets:     {result['critical_assets_count']}")
    print(f"      Attack Paths Found:  {result['attack_paths_discovered']}")
    print(f"      Neo4j Synchronized:  {result['neo4j_synced']}")

    # Step 4: Verify Final Graph
    print("\n[4/4] Verifying Graph Integrity & Choke Points...")
    paths = engine.find_attack_paths(max_depth=6)
    print(f"      Total Discoverable Multi-Hop Paths: {len(paths)}")
    for idx, p in enumerate(paths[:3]):
        print(f"        Path #{idx+1} ({p.id}): {' -> '.join(p.node_sequence[:4])} -> {p.target_id} [Risk: {p.adjusted_path_risk:.1f}]")

    print("\n" + "=" * 80)
    print("  [SUCCESS] Enterprise Synthetic Dataset successfully loaded and active!")
    print("=" * 80)


if __name__ == "__main__":
    main()
