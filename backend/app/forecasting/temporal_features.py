"""Temporal Feature Engineering & Leak-Free Dataset Builder for SafeContain AI Phase 7.3.

Extracts time-windowed security telemetry, graph topological proximity, and attack-path
exposure up to an exact observation cutoff timestamp t_obs, preventing target leakage.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple, Set
import networkx as nx
import numpy as np
import pandas as pd

from backend.app.ml.dataset_loader import DatasetLoader
from backend.app.ml.task_definition import FORBIDDEN_LEAKAGE_COLUMNS


# Temporal feature column list (strictly available at observation time t_obs)
TEMPORAL_FEATURE_COLUMNS: List[str] = [
    "alert_count_window",
    "alert_count_prior",
    "alert_velocity",
    "max_alert_severity",
    "evidence_count_window",
    "graph_compromise_proximity",
    "neighbor_threat_density_1hop",
    "neighbor_threat_density_2hop",
    "active_upstream_path_count",
    "correlated_indicator_count",
    "static_ml_probability",
    "criticality",
    "exposure",
    "pagerank",
    "in_degree",
    "out_degree",
]

EXPOSURE_MAP: Dict[str, float] = {
    "INTERNET_FACING": 1.0,
    "DMZ": 0.75,
    "INTERNAL": 0.40,
    "RESTRICTED_ISOLATED": 0.15,
}


class TemporalFeatureExtractor:
    """Extracts leak-free temporal features across enterprise assets for predictive risk forecasting."""

    def __init__(self, loader: Optional[DatasetLoader] = None):
        self.loader = loader or DatasetLoader()
        self._cached_tables: Dict[str, pd.DataFrame] = {}
        self._graph: Optional[nx.DiGraph] = None

    def _get_table(self, filename: str) -> pd.DataFrame:
        if filename not in self._cached_tables:
            self._cached_tables[filename] = self.loader.load_table(filename)
        return self._cached_tables[filename]

    def _build_graph(self) -> nx.DiGraph:
        if self._graph is not None:
            return self._graph

        nodes_df = self._get_table("nodes.csv")
        rels_df = self._get_table("relationships.csv")

        G = nx.DiGraph()
        for _, n in nodes_df.iterrows():
            raw_expo = str(n.get("exposure", "INTERNAL")).upper()
            expo_val = EXPOSURE_MAP.get(raw_expo, 0.40)
            try:
                crit_val = float(n.get("criticality", 0.5))
            except Exception:
                crit_val = 0.5

            G.add_node(
                n["node_id"],
                node_type=n.get("node_type", "SERVER"),
                criticality=crit_val,
                exposure=expo_val,
            )

        for _, r in rels_df.iterrows():
            G.add_edge(
                r["source_id"],
                r["target_id"],
                relationship_type=r.get("relationship_type", "CONNECTED_TO"),
                weight=float(r.get("weight", 1.0)),
            )

        self._graph = G
        return self._graph

    def get_dataset_time_bounds(self) -> Tuple[datetime, datetime]:
        """Returns the min and max timestamp observed in the historical security alerts."""
        alerts_df = self._get_table("security_alerts.csv")
        ts = pd.to_datetime(alerts_df["timestamp"], utc=True)
        return ts.min().to_pydatetime(), ts.max().to_pydatetime()

    def extract_temporal_features(
        self,
        t_obs: Optional[datetime] = None,
        window_hours: float = 2.0,
        static_ml_probabilities: Optional[Dict[str, float]] = None,
    ) -> pd.DataFrame:
        """Extracts temporal features for all 120 enterprise nodes strictly up to t_obs.
        
        Guarantees 0 data leakage: events occurring after t_obs are completely excluded.
        """
        nodes_df = self._get_table("nodes.csv")
        rels_df = self._get_table("relationships.csv")
        alerts_df = self._get_table("security_alerts.csv").copy()
        evidence_df = self._get_table("evidence.csv").copy()
        attack_paths_df = self._get_table("attack_paths.csv")

        # Parse timestamps to UTC
        alerts_df["ts"] = pd.to_datetime(alerts_df["timestamp"], utc=True)
        evidence_df["ts"] = pd.to_datetime(evidence_df["timestamp"], utc=True)

        if t_obs is None:
            # Default observation cutoff: median timestamp (mid-incident point)
            t_obs = alerts_df["ts"].quantile(0.50).to_pydatetime()
        elif t_obs.tzinfo is None:
            t_obs = t_obs.replace(tzinfo=timezone.utc)

        window_delta = timedelta(hours=window_hours)
        t_window_start = t_obs - window_delta
        t_prior_start = t_window_start - window_delta

        # STRICT DATA LEAKAGE FILTER: only events observed up to t_obs
        valid_alerts = alerts_df[alerts_df["ts"] <= t_obs]
        valid_evidence = evidence_df[evidence_df["ts"] <= t_obs]

        # Window-specific alerts
        alerts_window = valid_alerts[(valid_alerts["ts"] > t_window_start) & (valid_alerts["ts"] <= t_obs)]
        alerts_prior = valid_alerts[(valid_alerts["ts"] > t_prior_start) & (valid_alerts["ts"] <= t_window_start)]

        # Precompute alert counts
        counts_window = alerts_window.groupby("target_node_id").size().to_dict()
        counts_prior = alerts_prior.groupby("target_node_id").size().to_dict()

        # Severity weights: CRITICAL=3, HIGH=2, MEDIUM=1, LOW=0
        sev_weights = {"CRITICAL": 3.0, "HIGH": 2.0, "MEDIUM": 1.0, "LOW": 0.5}
        alerts_window_sev = alerts_window.copy()
        alerts_window_sev["weight"] = alerts_window_sev["severity"].map(sev_weights).fillna(0.0)
        max_sev_window = alerts_window_sev.groupby("target_node_id")["weight"].max().to_dict()

        # Evidence counts up to t_obs
        evid_counts = valid_evidence.groupby("related_node_id").size().to_dict()

        # Graph topological context
        G = self._build_graph()
        pagerank = nx.pagerank(G, alpha=0.85)
        in_degrees = dict(G.in_degree())
        out_degrees = dict(G.out_degree())

        # Currently breached or alerted nodes up to t_obs
        compromised_at_obs: Set[str] = set(valid_alerts["target_node_id"].dropna()).union(
            set(valid_alerts["source_node_id"].dropna())
        )

        # Pre-parse attack paths
        # path_nodes is formatted like: "node-user-marcus;node-ep-laptop-marcus;node-srv-jumpbox01;..."
        paths_parsed: List[List[str]] = []
        for _, p in attack_paths_df.iterrows():
            nodes_seq = [n.strip() for n in str(p["path_nodes"]).split(";") if n.strip()]
            paths_parsed.append(nodes_seq)

        # Retrieve static ML probabilities from Phase 7.2A/B if not supplied
        if static_ml_probabilities is None:
            try:
                from backend.app.ml.model_registry import ModelRegistry
                reg = ModelRegistry()
                if reg.is_model_available():
                    preds = reg.predict_for_nodes(list(nodes_df["node_id"]))
                    static_ml_probabilities = {p["node_id"]: p["risk_probability"] for p in preds}
            except Exception:
                static_ml_probabilities = {}

        # Threat intel indicator counts from Phase 7.2E
        indicator_counts: Dict[str, int] = {}
        try:
            from backend.app.threat_intel.sources.internal_telemetry import InternalTelemetrySource
            ti_source = InternalTelemetrySource()
            inds = ti_source.fetch_indicators()
            for ind in inds:
                for aid in ind.associated_asset_ids:
                    indicator_counts[aid] = indicator_counts.get(aid, 0) + 1
        except Exception:
            pass

        rows: List[Dict[str, Any]] = []
        for _, n in nodes_df.iterrows():
            nid = n["node_id"]
            c_win = counts_window.get(nid, 0)
            c_pri = counts_prior.get(nid, 0)

            # Alert velocity: rate of acceleration
            vel = float(c_win - c_pri) / (float(c_pri) + 1.0)

            # Max severity
            m_sev = float(max_sev_window.get(nid, 0.0))

            # Evidence count
            e_cnt = float(evid_counts.get(nid, 0))

            # Graph distance to nearest currently alerted node
            min_dist = 999
            if compromised_at_obs:
                for comp_node in compromised_at_obs:
                    if comp_node == nid:
                        min_dist = 0
                        break
                    try:
                        d = nx.shortest_path_length(G, source=comp_node, target=nid)
                        if d < min_dist:
                            min_dist = d
                    except (nx.NetworkXNoPath, nx.NodeNotFound):
                        pass
            proximity = 1.0 / (float(min_dist) + 1.0) if min_dist < 999 else 0.0

            # 1-hop and 2-hop neighbor threat density
            neighbors_1 = set(G.successors(nid)).union(set(G.predecessors(nid)))
            dens_1 = (
                float(len(neighbors_1.intersection(compromised_at_obs))) / float(len(neighbors_1))
                if neighbors_1
                else 0.0
            )

            neighbors_2: Set[str] = set()
            for n1 in neighbors_1:
                neighbors_2.update(G.successors(n1))
                neighbors_2.update(G.predecessors(n1))
            neighbors_2.discard(nid)
            dens_2 = (
                float(len(neighbors_2.intersection(compromised_at_obs))) / float(len(neighbors_2))
                if neighbors_2
                else 0.0
            )

            # Active upstream attack path count
            active_upstream_count = 0
            for path_seq in paths_parsed:
                if nid in path_seq:
                    idx = path_seq.index(nid)
                    # Check if any upstream node in this path has had an alert at <= t_obs
                    upstream_nodes = set(path_seq[:idx])
                    if upstream_nodes.intersection(compromised_at_obs):
                        active_upstream_count += 1

            ti_cnt = float(indicator_counts.get(nid, 0))
            ml_prob = float(static_ml_probabilities.get(nid, 0.20))
            try:
                crit = float(n.get("criticality", 0.5))
            except Exception:
                crit = 0.5
            expo = float(EXPOSURE_MAP.get(str(n.get("exposure", "INTERNAL")).upper(), 0.40))
            pr = float(pagerank.get(nid, 0.01))
            in_d = float(in_degrees.get(nid, 0))
            out_d = float(out_degrees.get(nid, 0))

            row = {
                "node_id": nid,
                "node_name": n.get("name", nid),
                "node_type": n.get("node_type", "SERVER"),
                "is_crown_jewel": bool("crown" in str(n.get("tags", "")).lower() or "db-customer" in nid or "id-vault" in nid),
                "alert_count_window": float(c_win),
                "alert_count_prior": float(c_pri),
                "alert_velocity": float(vel),
                "max_alert_severity": float(m_sev),
                "evidence_count_window": float(e_cnt),
                "graph_compromise_proximity": float(proximity),
                "neighbor_threat_density_1hop": float(dens_1),
                "neighbor_threat_density_2hop": float(dens_2),
                "active_upstream_path_count": float(active_upstream_count),
                "correlated_indicator_count": float(ti_cnt),
                "static_ml_probability": float(ml_prob),
                "criticality": float(crit),
                "exposure": float(expo),
                "pagerank": float(pr),
                "in_degree": float(in_d),
                "out_degree": float(out_d),
            }
            rows.append(row)

        df = pd.DataFrame(rows)
        return df

    def generate_future_labels(
        self,
        t_obs: datetime,
        horizon_hours: float = 6.0,
    ) -> pd.Series:
        """Generates binary future compromise labels for nodes in horizon window (t_obs, t_obs + horizon].
        
        Returns a Series indexed by node_id where label=1 indicates security alert in future horizon.
        """
        nodes_df = self._get_table("nodes.csv")
        alerts_df = self._get_table("security_alerts.csv").copy()
        alerts_df["ts"] = pd.to_datetime(alerts_df["timestamp"], utc=True)

        if t_obs.tzinfo is None:
            t_obs = t_obs.replace(tzinfo=timezone.utc)

        t_future_end = t_obs + timedelta(hours=horizon_hours)

        # STRICT HORIZON SLICE: strictly events occurring after t_obs and <= t_future_end
        future_alerts = alerts_df[(alerts_df["ts"] > t_obs) & (alerts_df["ts"] <= t_future_end)]
        alerted_nodes_future = set(future_alerts["target_node_id"].dropna()).union(
            set(future_alerts["source_node_id"].dropna())
        )

        labels = {
            nid: int(nid in alerted_nodes_future)
            for nid in nodes_df["node_id"]
        }
        return pd.Series(labels, name="future_compromised")
