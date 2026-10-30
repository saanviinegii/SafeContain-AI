# OPTIMIZATION METHODOLOGY SPECIFICATION
## SafeContain AI — Tri-Level Response Planning & CP-SAT Engine
**Document Version:** 1.0.0  

---

## 1. Strategy Tier Definitions

SafeContain AI evaluates and compares three distinct optimization tiers on identical scenarios:

### Strategy 1: Baseline Severity-First Planner
- **Algorithm:** Greedy descending sort by $\Delta R_i$.
- **Behavior:** Selects interventions targeting the highest risk nodes until budget or maximum action count is reached.
- **Weakness:** Disregards workflow disruption entirely, often severing critical shared services or causing citizen portal outages.

### Strategy 2: Greedy Risk-Per-Cost & Disruption Optimizer
- **Algorithm:** Ranks candidate interventions by composite efficiency:
  $$\text{Efficiency}(a) = \frac{\Delta R(a)}{\text{Cost}(a) + \lambda \cdot \text{Disruption}(a)}$$
- **Behavior:** Balances risk reduction with operational friction, providing a fast polynomial-time heuristic.

### Strategy 3: Constraint-Based Optimization (Google OR-Tools CP-SAT)
- **Algorithm:** Exact 0-1 Integer Programming solver with boolean decision variables $x_i \in \{0, 1\}$.
- **Objective:**
  $$\text{Maximize} \quad \sum_{i=1}^N \left( 100 \cdot \Delta R_i - 0.1 \cdot C_i - 20 \cdot D_i \right) \cdot x_i$$
- **Hard Constraints:**
  1. Financial Budget Ceiling: $\sum C_i \cdot x_i \le B_{\text{max}}$
  2. Critical Citizen SLA Guarantee: If an action disrupts a Tier-1 zero-downtime service ($D_i > \text{SLA}$), enforce $x_i = 0$.

---

## 2. Solver Performance & Fallbacks

- **Primary Solver:** Google OR-Tools CP-SAT v9.15 (solving in $< 50$ ms on 50-node topologies).
- **Time Limits:** Bounded to 5.0 seconds maximum runtime (`settings.MAX_SOLVER_TIME_SECONDS`).
- **Resilient Fallback:** If CP-SAT encounters an infeasible constraint or exceeds timeout, the engine automatically falls back to the Greedy strategy with an explicit constraint violation warning in the response.
