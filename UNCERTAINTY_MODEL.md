# UNCERTAINTY & EVIDENCE METHODOLOGY
## SafeContain AI — Epistemic Confidence and Sensitivity Modeling
**Document Version:** 1.0.0  

---

## 1. Five-State Evidence Model

SafeContain AI does not treat evidence as binary. Every relationship and telemetry record is assigned one of five explicit epistemic states:

| State | Definition | Confidence Range | Action Implication |
| :--- | :--- | :--- | :--- |
| **`CONFIRMED`** | Corroborated by active, multi-source, unexpired telemetry | $0.80 - 1.00$ | Directly actionable in containment planning |
| **`SUSPECTED`** | Single unverified indicator or heuristic link | $0.40 - 0.79$ | Adds bounded uncertainty penalty to path risk |
| **`UNKNOWN`** | Plausible architectural route with missing telemetry | $0.10 - 0.39$ | Prompts increased monitoring action |
| **`DISPUTED`** | Contradicting telemetry from distinct security sensors | Variable | Requires manual analyst review |
| **`STALE`** | Previously confirmed evidence exceeding freshness SLA | Exponential Decay | Deprioritized until probe refresh |

---

## 2. Temporal Confidence Decay Formulation

Telemetry loses evidential value as time elapses without re-verification:

$$C(t) = C_0 \cdot \exp(-\lambda \cdot t_{\text{days}})$$

- **Decay Rate $\lambda$:** $0.05$ per day.
- **Staleness Threshold:** 72 hours. When $t > 72\text{h}$, status automatically flips from `CONFIRMED` $\to$ `STALE`.

---

## 3. Sensitivity Drift Analysis

The platform answers critical counterfactual questions:
- *What happens if a suspected route is confirmed?*
  The uncertainty penalty drops, but path confidence increases to $1.0$, potentially elevating a secondary route into high priority.
- *What happens if an unverified link is refuted (`DISPUTED`)?*
  The corresponding attack path collapses entirely ($\Delta R = -R_{\text{path}}$), proving whether expensive containment interventions can be safely avoided.
