"""Graph Risk Propagation Engine for SafeContain AI Phase 7.3.

Analyzes topological diffusion and multi-hop attack-path transmission across the
enterprise graph, identifying exposed nodes, upstream breach vectors, and crown jewel threats.
"""

from typing import Any, Dict, List, Optional, Set, Tuple
import networkx as nx
import pandas as pd

from backend.app.forecasting.models import PropagationHop
from backend.app.ml.dataset_loader import DatasetLoader


class GraphRiskPropagationEngine:
    """Computes directed risk propagation over the enterprise infrastructure graph."""

    def __init__(self, loader: Optional[DatasetLoader] = None):
        self.loader = loader or DatasetLoader()
        self._graph: Optional[nx.DiGraph] = None
        self._crown_jewel_ids: Optional[Set[str]] = None

    def _get_graph(self) -> nx.DiGraph:
        if self._graph is not None:
            return self._graph

        nodes_df = self.loader.load_table("nodes.csv")
        rels_df = self.loader.load_table("relationships.csv")

        G = nx.DiGraph()
        crown_jewels = set()
        for _, n in nodes_df.iterrows():
            nid = n["node_id"]
            is_cj = bool("crown" in str(n.get("tags", "")).lower() or "db-customer" in nid or "id-vault" in nid)
            if is_cj:
                crown_jewels.add(nid)
            G.add_node(
                nid,
                name=n.get("name", nid),
                node_type=n.get("node_type", "SERVER"),
                criticality=float(n.get("criticality", 0.5)),
                is_crown_jewel=is_cj,
            )

        # Transmission attenuation weights per relationship type
        rel_weights = {
            "ADMINISTERS": 0.95,
            "AUTHENTICATES_TO": 0.85,
            "CONNECTED_TO": 0.70,
            "DEPENDS_ON": 0.65,
            "ROUTES_TO": 0.60,
            "ACCESSES": 0.75,
        }

        for _, r in rels_df.iterrows():
            rel_type = str(r.get("relationship_type", "CONNECTED_TO")).upper()
            w = rel_weights.get(rel_type, 0.60)
            G.add_edge(
                r["source_id"],
                r["target_id"],
                relationship_type=rel_type,
                weight=w,
            )

        self._graph = G
        self._crown_jewel_ids = crown_jewels
        return self._graph

    def get_crown_jewel_ids(self) -> Set[str]:
        if self._crown_jewel_ids is None:
            self._get_graph()
        return self._crown_jewel_ids or set()

    def trace_upstream_breaches(
        self,
        target_node_id: str,
        breached_nodes: Set[str],
        max_hops: int = 3,
    ) -> List[PropagationHop]:
        """Traces incoming propagation hops from any currently breached node to the target."""
        G = self._get_graph()
        if target_node_id not in G or not breached_nodes:
            return []

        hops: List[PropagationHop] = []
        for src in breached_nodes:
            if src == target_node_id:
                continue
            if src not in G:
                continue

            try:
                if nx.has_path(G, src, target_node_id):
                    path = nx.shortest_path(G, src, target_node_id)
                    d = len(path) - 1
                    if 1 <= d <= max_hops:
                        # Compute cumulative transmission attenuation
                        cum_w = 1.0
                        for i in range(len(path) - 1):
                            u, v = path[i], path[i + 1]
                            edge_w = G[u][v].get("weight", 0.7)
                            cum_w *= edge_w

                        # Direct predecessor hop
                        pred = path[-2]
                        rel_type = G[pred][target_node_id].get("relationship_type", "CONNECTED_TO")

                        hop = PropagationHop(
                            source_node_id=src,
                            target_node_id=target_node_id,
                            relationship_type=rel_type,
                            propagation_factor=round(float(cum_w), 4),
                            hop_distance=d,
                            evidence_context=(
                                f"Traverses {d}-hop lateral route: {' -> '.join(path)} "
                                f"with cumulative transmission factor {cum_w:.2f}."
                            ),
                        )
                        hops.append(hop)
            except Exception:
                continue

        # Sort by highest transmission factor
        hops.sort(key=lambda h: h.propagation_factor, reverse=True)
        return hops[:5]

    def find_exposed_downstream_assets(
        self,
        high_risk_node_ids: Set[str],
        cutoff_threshold: float = 0.35,
    ) -> List[Dict[str, Any]]:
        """Identifies downstream enterprise assets exposed to lateral contagion from high-risk nodes."""
        G = self._get_graph()
        exposed: Dict[str, Dict[str, Any]] = {}

        for hr_node in high_risk_node_ids:
            if hr_node not in G:
                continue

            # Forward BFS up to 2 hops
            for target_id in nx.single_source_shortest_path_length(G, hr_node, cutoff=2):
                if target_id == hr_node or target_id in high_risk_node_ids:
                    continue

                path = nx.shortest_path(G, hr_node, target_id)
                d = len(path) - 1
                factor = 1.0
                for i in range(len(path) - 1):
                    factor *= G[path[i]][path[i + 1]].get("weight", 0.7)

                # Attenuate by distance
                factor = factor * (0.8 ** (d - 1))

                if factor >= cutoff_threshold:
                    if target_id not in exposed or factor > exposed[target_id]["exposure_factor"]:
                        node_attrs = G.nodes[target_id]
                        is_cj = node_attrs.get("is_crown_jewel", False)
                        exposed[target_id] = {
                            "asset_id": target_id,
                            "asset_name": node_attrs.get("name", target_id),
                            "asset_type": node_attrs.get("node_type", "SERVER"),
                            "criticality": node_attrs.get("criticality", 0.5),
                            "is_crown_jewel": is_cj,
                            "exposure_factor": round(float(factor), 4),
                            "origin_breach_node": hr_node,
                            "propagation_path": path,
                            "hop_distance": d,
                        }

        sorted_exposed = sorted(
            list(exposed.values()),
            key=lambda x: (x["is_crown_jewel"], x["exposure_factor"]),
            reverse=True,
        )
        return sorted_exposed
