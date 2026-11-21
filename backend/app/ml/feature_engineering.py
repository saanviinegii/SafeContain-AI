"""Feature Engineering for SafeContain AI ML Pipeline.

Extracts graph topological metrics, static asset profiles, and observable
telemetry, with strict mathematical transformation and leakage guardrails.
"""

from typing import Any, Dict, List, Optional, Tuple
import networkx as nx
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from backend.app.ml.dataset_loader import DatasetLoader
from backend.app.ml.task_definition import (
    assert_no_target_leakage,
    TOPOLOGY_FEATURE_COLUMNS,
    TELEMETRY_FEATURE_COLUMNS,
)


class FeatureEngineer:
    """Extracts, transforms, and validates graph and tabular cybersecurity features."""

    def __init__(self, loader: Optional[DatasetLoader] = None):
        self.loader = loader or DatasetLoader()
        self._cached_feature_df: Optional[pd.DataFrame] = None

    def extract_raw_features(self, force_refresh: bool = False) -> pd.DataFrame:
        """Extracts complete feature set across all nodes with graph metrics and telemetry."""
        if not force_refresh and self._cached_feature_df is not None:
            return self._cached_feature_df.copy()

        # Load datasets
        nodes_df = self.loader.load_table("nodes.csv")
        rels_df = self.loader.load_table("relationships.csv")
        assets_df = self.loader.load_table("assets.csv")
        vulns_df = self.loader.load_table("vulnerabilities.csv")
        alerts_df = self.loader.load_table("security_alerts.csv")
        evid_df = self.loader.load_table("evidence.csv")

        # 1. Build directed graph for topology analysis
        G = nx.DiGraph()
        for _, r in nodes_df.iterrows():
            G.add_node(r["node_id"])
        for _, r in rels_df.iterrows():
            G.add_edge(r["source_id"], r["target_id"])

        in_degrees = dict(G.in_degree())
        out_degrees = dict(G.out_degree())
        pagerank = nx.pagerank(G, alpha=0.85)

        # 2. Analyze high-privilege relationships
        high_priv_rels = rels_df[rels_df["privilege_level"].isin(["ADMIN", "ROOT", "DOMAIN_ADMIN"])]
        high_priv_nodes = set(high_priv_rels["source_id"]).union(set(high_priv_rels["target_id"]))
        admin_edge_counts: Dict[str, int] = {}
        for nid in nodes_df["node_id"]:
            cnt = int(((high_priv_rels["source_id"] == nid) | (high_priv_rels["target_id"] == nid)).sum())
            admin_edge_counts[nid] = cnt

        # 3. Asset and Vulnerability mappings
        asset_nodes = set(assets_df["node_id"])
        asset_to_node = dict(zip(assets_df["asset_id"], assets_df["node_id"]))
        vulns_copy = vulns_df.copy()
        vulns_copy["node_id"] = vulns_copy["asset_id"].map(asset_to_node)

        vuln_cnt = vulns_copy.groupby("node_id").size().to_dict()
        vuln_max_cvss = vulns_copy.groupby("node_id")["cvss_score"].max().to_dict()
        vuln_sum_cvss = vulns_copy.groupby("node_id")["cvss_score"].sum().to_dict()

        # 4. Security Alert aggregations
        alert_src = alerts_df.groupby("source_node_id").size().to_dict()
        alert_dst = alerts_df.groupby("target_node_id").size().to_dict()

        sev_map = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}
        alerts_copy = alerts_df.copy()
        alerts_copy["sev_weight"] = alerts_copy["severity"].map(sev_map).fillna(0)
        alert_max_sev = alerts_copy.groupby("target_node_id")["sev_weight"].max().to_dict()

        # 5. Evidence aggregations
        evid_cnt = evid_df.groupby("related_node_id").size().to_dict()
        evid_max_conf = evid_df.groupby("related_node_id")["confidence"].max().to_dict()

        # 6. Assemble tabular features per node
        records: List[Dict[str, Any]] = []
        for _, n in nodes_df.iterrows():
            nid = n["node_id"]
            in_d = in_degrees.get(nid, 0)
            out_d = out_degrees.get(nid, 0)
            tot_d = in_d + out_d
            ratio = float(in_d) / float(out_d + 1.0)
            max_cvss = float(vuln_max_cvss.get(nid, 0.0))

            row = {
                "node_id": nid,
                # Static & Categorical
                "node_type": str(n.get("node_type", "UNKNOWN")),
                "environment": str(n.get("environment", "CORP")),
                "exposure": str(n.get("exposure", "INTERNAL")),
                "criticality": float(n.get("criticality", 0.5)),
                "business_value": float(n.get("business_value", 0.0)),
                # Graph Structural Topology (Leakage-Free)
                "in_degree": int(in_d),
                "out_degree": int(out_d),
                "total_degree": int(tot_d),
                "in_out_degree_ratio": round(ratio, 4),
                "pagerank": round(float(pagerank.get(nid, 0.0)), 6),
                "is_high_privilege_connected": 1 if nid in high_priv_nodes else 0,
                "admin_edge_count": admin_edge_counts.get(nid, 0),
                "has_asset_profile": 1 if nid in asset_nodes else 0,
                # Telemetry & Threats
                "vuln_count": int(vuln_cnt.get(nid, 0)),
                "max_cvss_score": round(max_cvss, 2),
                "sum_cvss_score": round(float(vuln_sum_cvss.get(nid, 0.0)), 2),
                "has_critical_vuln": 1 if max_cvss >= 9.0 else 0,
                "alert_src_count": int(alert_src.get(nid, 0)),
                "alert_dst_count": int(alert_dst.get(nid, 0)),
                "total_alert_count": int(alert_src.get(nid, 0) + alert_dst.get(nid, 0)),
                "max_alert_severity_weight": int(alert_max_sev.get(nid, 0)),
                "evidence_count": int(evid_cnt.get(nid, 0)),
                "max_evidence_confidence": round(float(evid_max_conf.get(nid, 0.0)), 4),
                # Ground Truth Target (Separated)
                "security_status": str(n.get("security_status", "HEALTHY")),
                "target_is_at_risk": 1 if str(n.get("security_status", "HEALTHY")) != "HEALTHY" else 0,
            }
            records.append(row)

        df = pd.DataFrame(records)
        self._cached_feature_df = df
        return df.copy()

    def get_feature_subsets(self) -> Dict[str, List[str]]:
        """Returns the supported feature subsets."""
        return {
            "topology_only": list(TOPOLOGY_FEATURE_COLUMNS),
            "full": list(TOPOLOGY_FEATURE_COLUMNS + TELEMETRY_FEATURE_COLUMNS),
        }

    def get_features_and_target(
        self, feature_subset: str = "topology_only"
    ) -> Tuple[pd.DataFrame, pd.Series, List[str], List[str]]:
        """Extracts X and y, verifying zero data leakage.
        
        Args:
            feature_subset: 'topology_only' or 'full'.
            
        Returns:
            Tuple of (X_df, y_series, numeric_cols, categorical_cols).
        """
        subsets = self.get_feature_subsets()
        if feature_subset not in subsets:
            raise ValueError(
                f"Unknown feature_subset '{feature_subset}'. Must be one of {list(subsets.keys())}"
            )

        raw_df = self.extract_raw_features()
        feature_cols = subsets[feature_subset]

        # Enforce zero target leakage
        assert_no_target_leakage(feature_cols)

        X = raw_df[feature_cols].copy()
        y = raw_df["target_is_at_risk"].copy()

        categorical_cols = [c for c in feature_cols if c in ["node_type", "environment", "exposure"]]
        numeric_cols = [c for c in feature_cols if c not in categorical_cols]

        return X, y, numeric_cols, categorical_cols

    @staticmethod
    def build_preprocessor(numeric_cols: List[str], categorical_cols: List[str]) -> ColumnTransformer:
        """Constructs an sklearn ColumnTransformer ensuring clean scaling and encoding."""
        numeric_pipeline = Pipeline(
            steps=[
                ("imputer", SimpleImputer(strategy="median")),
                ("scaler", StandardScaler()),
            ]
        )

        categorical_pipeline = Pipeline(
            steps=[
                ("imputer", SimpleImputer(strategy="constant", fill_value="UNKNOWN")),
                ("onehot", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
            ]
        )

        transformers = []
        if numeric_cols:
            transformers.append(("num", numeric_pipeline, numeric_cols))
        if categorical_cols:
            transformers.append(("cat", categorical_pipeline, categorical_cols))

        return ColumnTransformer(transformers=transformers, remainder="drop")
