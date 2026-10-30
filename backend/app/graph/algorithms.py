"""Graph Traversal, Attack Path Intelligence, and Bottleneck Algorithms."""

from typing import Dict, List, Set, Tuple
import networkx as nx

from backend.app.core.config import settings
from backend.app.models.domain import (
    AttackPath,
    EvidenceStatus,
    GraphNode,
    NodeType,
)


def discover_attack_paths(
    engine,
    max_depth: int = 7,
    max_paths_per_pair: int = 10
) -> List[AttackPath]:
    """Finds all viable directed attack paths from compromised nodes to crown jewels.
    
    Adheres strictly to Principle #12: Blocking one attack path must NEVER
    automatically be treated as complete containment.
    """
    g = engine._nx_graph
    nodes: Dict[str, GraphNode] = engine._node_store

    # 1. Identify Entry Points / Attacker Footprints
    sources: List[str] = [
        nid for nid, node in nodes.items()
        if node.is_compromised or node.type in (NodeType.THREAT, NodeType.INCIDENT)
    ]

    # 2. Identify High-Value Targets / Crown Jewels
    targets: List[str] = [
        nid for nid, node in nodes.items()
        if (node.is_crown_jewel or node.criticality >= 0.85)
        and nid not in sources
    ]

    discovered_paths: List[AttackPath] = []
    path_counter = 0

    for src in sources:
        for dst in targets:
            if not nx.has_path(g, src, dst):
                continue

            try:
                # Find all simple paths up to max_depth
                simple_paths = list(nx.all_simple_paths(g, src, dst, cutoff=max_depth))
            except Exception:
                continue

            for p_nodes in simple_paths[:max_paths_per_pair]:
                path_counter += 1
                edge_sequence: List[str] = []
                confidences: List[float] = []
                uncertain_edge_count = 0

                # Resolve edge sequence and collect evidence metrics
                for i in range(len(p_nodes) - 1):
                    u, v = p_nodes[i], p_nodes[i + 1]
                    edge_data = g.get_edge_data(u, v)
                    if edge_data:
                        edge_id = edge_data.get("id", f"edge-{u}-{v}")
                        edge_sequence.append(edge_id)
                        conf = float(edge_data.get("confidence", 1.0))
                        confidences.append(conf)
                        ev_status = edge_data.get("evidence_status", EvidenceStatus.CONFIRMED.value)
                        if ev_status in (EvidenceStatus.SUSPECTED.value, EvidenceStatus.UNKNOWN.value, EvidenceStatus.STALE.value):
                            uncertain_edge_count += 1

                min_confidence = min(confidences) if confidences else 1.0
                hop_count = len(p_nodes) - 1

                # Mathematical Risk Formulations
                src_node = nodes[src]
                dst_node = nodes[dst]
                
                # Inherent Risk: scaled by target criticality and hop length attenuation
                length_factor = 1.0 / (1.0 + 0.1 * (hop_count - 1))
                inherent_risk = round(dst_node.criticality * 100.0 * length_factor, 2)
                
                # Uncertainty Penalty: adds bounded risk weight when path relies on suspected links
                uncertainty_penalty = round(
                    uncertain_edge_count * settings.UNCERTAINTY_PENALTY_WEIGHT * 10.0, 2
                )
                
                adjusted_risk = min(100.0, round(inherent_risk + uncertainty_penalty, 2))

                # Plain-Language Explanation Generation
                node_names = [nodes[n].name for n in p_nodes]
                explanation = (
                    f"Attack path traversing from '{node_names[0]}' via "
                    f"{hop_count} hops to critical asset '{node_names[-1]}'. "
                    f"Minimum evidence confidence: {min_confidence:.0%}. "
                    f"Uncertain hops: {uncertain_edge_count}."
                )

                discovered_paths.append(AttackPath(
                    id=f"path-{path_counter:03d}",
                    source_id=src,
                    target_id=dst,
                    node_sequence=p_nodes,
                    edge_sequence=edge_sequence,
                    hop_count=hop_count,
                    inherent_path_risk=inherent_risk,
                    confidence_score=min_confidence,
                    uncertainty_penalty=uncertainty_penalty,
                    adjusted_path_risk=adjusted_risk,
                    is_residual=False,
                    choke_point_nodes=[], # Populated in secondary pass
                    explanation=explanation
                ))

    # Secondary Pass: Identify Choke Points across discovered paths
    choke_map = calculate_choke_points(discovered_paths)
    for p in discovered_paths:
        p.choke_point_nodes = [nid for nid in p.node_sequence[1:-1] if choke_map.get(nid, 0) > 1]

    # Rank paths by adjusted risk descending
    discovered_paths.sort(key=lambda x: x.adjusted_path_risk, reverse=True)
    return discovered_paths


def calculate_choke_points(paths: List[AttackPath]) -> Dict[str, int]:
    """Calculates node participation frequencies across multiple attack routes."""
    frequency: Dict[str, int] = {}
    for path in paths:
        # Exclude source and target endpoints
        intermediates = path.node_sequence[1:-1]
        for nid in set(intermediates):
            frequency[nid] = frequency.get(nid, 0) + 1
    return frequency
