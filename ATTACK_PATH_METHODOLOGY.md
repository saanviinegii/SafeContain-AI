# ATTACK PATH DISCOVERY METHODOLOGY
## SafeContain AI — Graph Traversal & Choke-Point Analysis
**Document Version:** 1.0.0  

---

## 1. Attack Graph Traversal Logic

SafeContain AI discovers potential attack paths using directed acyclic and cyclic traversal across the infrastructure graph:

1. **Source Identification:** All nodes with active compromise flags (`is_compromised = true`) or typed as `NodeType.THREAT` / `NodeType.INCIDENT` serve as source root nodes.
2. **Target Crown Jewels:** Assets marked with `is_crown_jewel = true` or having `criticality >= 0.85` (such as core citizen identity databases or Kerberos Domain Controllers) serve as terminal targets.
3. **Simple Path Traversal:** Uses NetworkX directed graph depth-limited search (`nx.all_simple_paths`) up to `max_depth` (default: 7 hops).
4. **Edge Evidence Weighting:** Traversal tracks edge sequence, minimum evidence confidence ($C_{\min}$), and count of uncertain hops.

---

## 2. Bottleneck & Choke-Point Identification

A **choke-point** is defined as an intermediate graph node that participates in multiple independent attack paths:

$$\text{Frequency}(n) = \sum_{p \in P} \mathbb{I}(n \in p \setminus \{\text{source}_p, \text{target}_p\})$$

Nodes with $\text{Frequency}(n) > 1$ are prioritized for surgical containment, as severing edges at a choke-point cuts multiple lateral paths simultaneously with lower total intervention cost.

---

## 3. Residual Path Verification (Principle #12)

**Critical Safety Requirement:**  
Blocking one attack path must **never** automatically be treated as complete containment.

SafeContain AI re-runs the entire traversal algorithm on the post-containment simulation snapshot. Any path that remains viable is tagged with `is_residual = True`. If any residual path reaches a crown jewel, the plan is explicitly labeled `is_fully_contained = False`.
