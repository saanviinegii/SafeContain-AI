"""Data Validation and Quality Assurance for SafeContain AI ML Pipeline.

Verifies schemas, referential integrity, missing values, duplicates,
class distributions, and data consistency across graph and tabular telemetry.
"""

from typing import Any, Dict, List, Optional
import pandas as pd
from backend.app.ml.dataset_loader import DatasetLoader


class DataValidator:
    """Validates data quality, integrity, and class balance for ML modeling."""

    def __init__(self, loader: Optional[DatasetLoader] = None):
        self.loader = loader or DatasetLoader()

    def validate_dataset_quality(self) -> Dict[str, Any]:
        """Performs comprehensive data quality audit across enterprise datasets."""
        issues: List[str] = []
        warnings: List[str] = []

        # 1. Load core tables
        try:
            nodes_df = self.loader.load_table("nodes.csv")
            rels_df = self.loader.load_table("relationships.csv")
            assets_df = self.loader.load_table("assets.csv")
            vulns_df = self.loader.load_table("vulnerabilities.csv")
            alerts_df = self.loader.load_table("security_alerts.csv")
            evid_df = self.loader.load_table("evidence.csv")
        except FileNotFoundError as e:
            return {
                "validation_status": "FAILED",
                "critical_error": str(e),
                "issues": [str(e)],
                "warnings": [],
            }

        # 2. Check Primary Key Uniqueness
        pk_checks = [
            ("nodes.csv", nodes_df, "node_id"),
            ("relationships.csv", rels_df, "relationship_id"),
            ("assets.csv", assets_df, "asset_id"),
            ("vulnerabilities.csv", vulns_df, "vulnerability_id"),
            ("security_alerts.csv", alerts_df, "alert_id"),
            ("evidence.csv", evid_df, "evidence_id"),
        ]

        duplicate_counts: Dict[str, int] = {}
        for fname, df, pk in pk_checks:
            dup_pks = df[pk].duplicated().sum()
            duplicate_counts[fname] = int(dup_pks)
            if dup_pks > 0:
                issues.append(f"{fname} contains {dup_pks} duplicate primary key ({pk}) values.")

        # 3. Check Referential Integrity
        node_ids = set(nodes_df["node_id"])

        orphan_sources = ~rels_df["source_id"].isin(node_ids)
        orphan_targets = ~rels_df["target_id"].isin(node_ids)
        if orphan_sources.sum() > 0:
            issues.append(f"relationships.csv has {orphan_sources.sum()} source_ids not present in nodes.csv")
        if orphan_targets.sum() > 0:
            issues.append(f"relationships.csv has {orphan_targets.sum()} target_ids not present in nodes.csv")

        asset_node_orphans = ~assets_df["node_id"].isin(node_ids)
        if asset_node_orphans.sum() > 0:
            issues.append(f"assets.csv has {asset_node_orphans.sum()} node_ids not present in nodes.csv")

        asset_ids = set(assets_df["asset_id"])
        vuln_asset_orphans = ~vulns_df["asset_id"].isin(asset_ids)
        if vuln_asset_orphans.sum() > 0:
            issues.append(f"vulnerabilities.csv has {vuln_asset_orphans.sum()} asset_ids not present in assets.csv")

        alert_src_orphans = ~alerts_df["source_node_id"].isin(node_ids)
        alert_dst_orphans = ~alerts_df["target_node_id"].isin(node_ids)
        if alert_src_orphans.sum() > 0:
            issues.append(f"security_alerts.csv has {alert_src_orphans.sum()} source_node_ids not in nodes.csv")
        if alert_dst_orphans.sum() > 0:
            issues.append(f"security_alerts.csv has {alert_dst_orphans.sum()} target_node_ids not in nodes.csv")

        # 4. Check Missing Values in Essential Modeling Attributes
        core_null_checks = [
            ("nodes.csv", nodes_df, ["node_id", "node_type", "environment", "exposure", "criticality", "security_status"]),
            ("relationships.csv", rels_df, ["source_id", "target_id", "relationship_type", "privilege_level"]),
        ]
        missing_value_summary: Dict[str, Dict[str, int]] = {}
        for fname, df, cols in core_null_checks:
            col_nulls = {col: int(df[col].isnull().sum()) for col in cols if col in df.columns}
            missing_value_summary[fname] = col_nulls
            for col, count in col_nulls.items():
                if count > 0:
                    issues.append(f"Essential column '{col}' in {fname} has {count} null values.")

        # 5. Check Target Variable Distributions
        status_counts = nodes_df["security_status"].value_counts().to_dict()
        total_nodes = len(nodes_df)
        healthy_count = status_counts.get("HEALTHY", 0)
        at_risk_count = total_nodes - healthy_count

        if total_nodes < 30:
            warnings.append(f"Small dataset size: {total_nodes} nodes is below standard statistical recommendation (>100).")
        if at_risk_count < 5:
            issues.append(f"Severe positive class sparsity: only {at_risk_count} non-healthy nodes found.")
        elif at_risk_count < 15:
            warnings.append(f"Minor positive class size ({at_risk_count}/{total_nodes}): requires stratified K-fold CV.")

        status = "PASSED" if len(issues) == 0 else "FAILED"

        return {
            "validation_status": status,
            "total_nodes": total_nodes,
            "total_relationships": len(rels_df),
            "total_assets": len(assets_df),
            "total_vulnerabilities": len(vulns_df),
            "total_alerts": len(alerts_df),
            "total_evidence": len(evid_df),
            "duplicate_counts": duplicate_counts,
            "missing_values": missing_value_summary,
            "target_distribution": {
                "security_status_breakdown": {k: int(v) for k, v in status_counts.items()},
                "binary_healthy_count": int(healthy_count),
                "binary_at_risk_count": int(at_risk_count),
                "at_risk_prevalence": round(at_risk_count / total_nodes, 4) if total_nodes > 0 else 0.0,
            },
            "issues": issues,
            "warnings": warnings,
        }
