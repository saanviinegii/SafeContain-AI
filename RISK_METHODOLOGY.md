# RISK CALCULATION METHODOLOGY
## SafeContain AI — Multi-Tier Decomposed Risk Engine
**Document Version:** 1.0.0  

---

## 1. Principles of Transparent Risk Scoring

SafeContain AI strictly adheres to Non-Negotiable Principle #5 and #11:
- Never use arbitrary uncalibrated scores disguised as probabilities.
- Separate inherent exposure from observed active compromise.
- Quantify the epistemic uncertainty penalty explicitly.

---

## 2. Risk Decomposition Tiers

1. **Inherent Risk ($R_{\text{inherent}}$):**
   The maximum theoretical loss if all discovered routes are fully exploited to crown jewels without resistance:
   $$R_{\text{inherent}} = \max_{p \in P} \left( \text{Criticality}(\text{Target}_p) \times 100.0 \times \frac{1}{1 + 0.1 \cdot (\text{Hops}_p - 1)} \right)$$

2. **Observed Risk ($R_{\text{observed}}$):**
   The risk posed strictly by verified, active paths corroborated by confirmed telemetry:
   $$R_{\text{observed}} = \max_{p \in P_{\text{confirmed}}} R_{\text{path}}(p)$$

3. **Potential Risk ($R_{\text{potential}}$):**
   The risk posed when including suspected lateral hops.

4. **Uncertainty-Adjusted Risk ($R_{\text{adjusted}}$):**
   $$R_{\text{adjusted}} = \min\left(100.0, \, R_{\text{observed}} + 0.5 \cdot (R_{\text{potential}} - R_{\text{observed}}) + \Omega_{\text{uncertainty}}\right)$$

5. **Residual Risk ($R_{\text{residual}}$):**
   The risk remaining after simulated candidate containment interventions are applied to the isolated graph copy.
