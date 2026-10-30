# RESEARCH CONTRIBUTION SPECIFICATION
## SafeContain AI — Novelty, Formal Evaluation & Scientific Impact
**Document Version:** 1.0.0  

---

## 1. Research Gap & Core Problem Statement

Existing academic literature and commercial security products treat cybersecurity incident response and network attack graphs through narrow, isolated silos:
1. **Network Attack Graphs (e.g. MulVAL, NetSPA):** Focus heavily on generating exploit graphs, but lack operational models of business workflow dependencies or downtime costs.
2. **Automated Containment (SOAR):** Frequently applies blunt, local isolation heuristics (e.g., quarantining an endpoint or dropping a firewall zone) without simulating secondary residual attack routes or evaluating citizen SLA impacts.
3. **Uncertainty Fallacy:** Existing risk algorithms either assume 100% telemetry omniscience or invent arbitrary Bayesian probabilities without calibration.

---

## 2. SafeContain AI Research Contributions

### Contribution 1: The Business Continuity Digital Twin
Jointly represents IT infrastructure assets and business operational workflows in a unified directed multigraph. For every proposed containment action, the system calculates exact service downtime, citizen portal SLA breaches, and financial loss, enforcing zero-outage constraints during cyber containment.

### Contribution 2: Uncertainty-Sensitive Response Optimization
Introduces an epistemic 5-state evidence model (`CONFIRMED`, `SUSPECTED`, `UNKNOWN`, `DISPUTED`, `STALE`) with exponential temporal confidence decay. Rather than treating unverified routes as either fully open or closed, the engine attaches an explicit uncertainty penalty ($\Omega_{\text{uncertainty}}$) that directly penalizes paths relying on suspected links and guides sensitivity drift analysis.

### Contribution 3: Grounded Counterfactual Decision Explanations
Rather than relying on ungrounded generative LLM wrappers that hallucinate risk numbers, SafeContain AI implements exact mathematical counterfactual reasoning: quantifying the precise security risk reduction and operational cost deltas when an action is added or omitted ($\Delta R, \Delta C, \Delta D$).

### Contribution 4: Mandatory Post-Containment Residual Path Verification
Disproves the false assumption of complete containment by unconditionally re-traversing the graph on an isolated simulation snapshot, exposing whether alternative or tertiary attack routes remain exploitable.
