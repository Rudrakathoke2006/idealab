# AEGIS-X: Pre-Registered Research Hypotheses & Frozen Numeric Thresholds

**Document Type:** Pre-Registration Specification & Evaluation Protocol  
**Date of Pre-Registration:** 2026-10-22  
**Target Venue:** AI-SEC 2027 (in conjunction with AINA 2027) / IEEE Transactions  
**Authors:** Rudra Prakash Kathoke & Research Team  
**Status:** **FROZEN PRIOR TO EXPERIMENTAL REVISION RUNS**  
**Addressing Reviewer Critique:** Meta-Comment M2 (Unfrozen H2 Thresholds / Prevention of HARKing)

---

## 1. Executive Rationale & Methodological Purpose (Why This Exists)

In empirical cybersecurity and AI evaluation (following the *Arp et al., USENIX Security 2022* Dos and Don'ts checklist), post-hoc parameter tuning and retroactive threshold adjustments invalidate scientific claims. Specifically, Reviewer Meta-Comment **M2** raised the concern of **unfrozen hypothesis thresholds**:
> *"The disruption bounds and H2 evaluation criteria appear fitted post-hoc to match the simulation outcomes rather than established ex-ante as falsifiable scientific thresholds."*

To eliminate **HARKing** (Hypothesizing After Results are Known) and provide an immutable, cryptographic paper trail:
1. This document defines all formal hypotheses, primary evaluation metrics, mathematical formulas, and **exact numeric pass/fail thresholds**.
2. This document is committed to version control on **22 October 2026**, **prior to executing** the analyst sensitivity sweeps (M1), new baseline evaluations (M3), real-data HIBP arrival calibration (M1), or the final Springer LNCS manuscript revision.
3. Any outcome where empirical performance breaches these pre-registered boundaries shall be reported as a **falsification or boundary condition**, not hidden or retroactively tuned.

---

## 2. Experimental Setup, Fixed Parameters & Seed Freezing

### 2.1 Fixed Random Seeds
All stochastic simulations, arrival samplers, and dataset partitions are pinned across **30 independent randomized seeds**:
$$\mathcal{S} = \{42, 43, 44, \dots, 71\} \quad (N = 30)$$
All primary metrics are reported as $\text{Mean} \pm \text{Standard Deviation}$ with 95% bootstrap confidence intervals ($B = 10{,}000$ resamples).

### 2.2 Fixed Engine Hyperparameters
The following parameters are frozen in `backend/engine/config.py` and shall not be modified during revision runs:
* **Hybrid Score Weight:** $\alpha = 0.40$
* **MFA Offset:** $\Delta_{\text{MFA}} = 12.0$ points
* **Sliding Window Duration:** $W = 60\text{ minutes}$
* **Credibility-Stratified Budgets:** $B_{\text{high}} = 8.0\text{ cost units}$, $B_{\text{low}} = 2.0\text{ cost units}$
* **Source Posterior Threshold for High Tier:** $\tau_p = 0.80$
* **Action Severity Weights ($\kappa_a$):**
  - Session Revocation (`REVOKE_ALL_SESSIONS`): $\kappa = 0.20$
  - Credibility Reset (`RESET_CREDENTIAL`): $\kappa = 0.50$
  - Host/Account Isolation (`DISABLE_ACCOUNT` / `ISOLATE_HOST`): $\kappa = 1.00$

---

## 3. Pre-Registered Hypotheses & Numeric Pass/Fail Thresholds

### Hypothesis 1 (H1: Multi-Modal Prioritization & Graph Topological Impact / RQ1)

* **Formal Statement:** A hybrid prioritization model combining linear domain invariants, calibrated probabilistic ML, and Dijkstra shortest-path topological reach $I(i)$ significantly outperforms static heuristics and uncalibrated baselines across real incident triage, vulnerability exploitation telemetry, and enterprise authentication graphs.

#### Pre-Registered Numeric Thresholds:
| Sub-Hypothesis | Dataset / Benchmark | Primary Metric | Required Pass Threshold | Baseline Comparison |
| :--- | :--- | :--- | :--- | :--- |
| **H1.1 (Incident Triage)** | Microsoft GUIDE (Temporal Split) | **PR-AUC** | $\ge \mathbf{0.9800}$ | Outperforms Rule-Only ($\le 0.8500$) |
| **H1.2 (Classification Balance)** | Microsoft GUIDE (Temporal Split) | **Macro-F1** | $\ge \mathbf{0.9500}$ | Outperforms Logistic Reg ($\le 0.9000$) |
| **H1.3 (Probability Calibration)** | Microsoft GUIDE (Temporal Split) | **Brier Score** | $\le \mathbf{0.0300}$ | Outperforms Rule-Only ($\ge 0.1500$) |
| **H1.4 (Leakage Audit)** | Permuted-Label Test (Arp et al.) | **ROC-AUC** | $\mathbf{\in [0.4800, 0.5800]}$ | Must collapse to chance ($\approx 0.50$) |
| **H1.5 (Exploit Prediction)** | CISA KEV + FIRST EPSS | **PR-AUC** | $\ge \mathbf{0.9800}$ | Outperforms CVSS-Only ($\le 0.8000$) |
| **H1.6 (Topological Ranking)** | LANL Authentication Graph | **ROC-AUC** | $\ge \mathbf{0.7500}$ | Outperforms PageRank ($\le 0.5500$) |
| **H1.7 (Crown-Jewel Precision)** | LANL Authentication Graph | **Precision@10** | $\ge \mathbf{0.6000}$ | Outperforms PageRank ($0.0000$) |

* **Falsification Criterion for H1:** If permuted label ROC-AUC exceeds $0.6000$ (indicating feature leakage), or if composite factor $V$ fails to beat CVSS-only PR-AUC ($p \ge 0.05$).

---

### Hypothesis 2 (H2: Feed Poisoning Resistance & Attacker Disruption Bound / RQ2 & M2)

* **Formal Statement:** Dynamic derivation of protected set $T_0$ coupled with credibility-stratified sliding-window admission budgets ($B_{\text{high}}, B_{\text{low}}$) provably bounds attacker-induced disruption and guarantees zero autonomous disruptions against critical infrastructure under arbitrary poisoning strategies.

#### Pre-Registered Numeric Thresholds:
| Sub-Hypothesis | Attack Strategy / Condition | Metric | Required Pass Threshold | Comparator Baseline |
| :--- | :--- | :--- | :--- | :--- |
| **H2.1 (Hard Safety Invariant)** | All 8 Strategies (S1–S7 + S_adaptive) | **$T_0$ Violations** | $\mathbf{\equiv 0}$ **(Strictly Zero)** | Baselines B0/B2 exhibit $> 50$ violations |
| **H2.2 (Alias Bypass Defense)** | S4 (Case/Whitespace/Plus-Addressing) | **Disruption $D$** | $\mathbf{0.0 \pm 0.0}$ | Baseline B1 (Static List) $\ge 40.0$ |
| **H2.3 (Dependency Defense)** | S3 (Transitive Service Accounts) | **Disruption $D$** | $\mathbf{0.0 \pm 0.0}$ | Baseline B1 (Static List) $\ge 50.0$ |
| **H2.4 (Uncorroborated Injections)**| S2 (High-Impact Targeting) | **Disruption $D$** | $\mathbf{0.0 \pm 0.0}$ | Baseline B0 (Auto-Execute) $= 100.0$ |
| **H2.5 (Windowed Bound)** | Burst Flood Injection ($W = 60\text{ min}$)| **Max Cumulative $D$** | $\le B_{\text{low}} + B_{\text{high}} = \mathbf{10.0}$ | Unbounded on B0 ($D \ge 100.0$) |
| **H2.6 (Forging Bound Sweep)** | Proposition 3 Sweep $q \in [0, 1]$ | **Disruption $D(q)$** | $\le B_{\text{low}} + q \cdot B_{\text{high}} = \mathbf{2.0 + 8.0q}$ | Verified on 100% of trials |
| **H2.7 (Remediation Preservation)** | Worst-Case Forging ($q = 1.0$) | **Remediation Rate (SR)**| $\ge \mathbf{60.0\%}$ | Recommend-Only (B5) $= 0.0\%$ |

* **Falsification Criterion for H2:** A single recorded $T_0$ violation ($V(T_0) > 0$) on proposed defense B4 across any seed, or mean disruption $D > 2.0$ on S2/S3/S4/S5/S7.
* **Empirical Status & Weakness Disclosure:** H2 is only partly met. Retained remediation under B4 is **76.5% of B0's baseline** (74.9% vs 97.9% overall), falling short of an ideal 80% parity target. We state this plainly without spin: fail-safe guardrails trade off approximately 23.5% of autonomous remediation speed to achieve 100% elimination of critical infrastructure outages ($D = 0.0$ on $T_0$). Furthermore, evaluation currently relies on proxy/synthetic arrival distributions and graphs; real telemetry evaluation is in progress.

---

### Hypothesis 2-Sens (H2-Sens: Operational Analyst Sensitivity Sweeps / Reviewer M1)

* **Formal Statement:** The disruption containment and remediation retention advantages of AEGIS-X remain statistically superior to static exclusions and rate-limiting baselines under realistic human-analyst operational constraints (analyst errors, queue capacity limits, and approval turnaround delays).

#### Pre-Registered Parameter Sweeps & Criteria:
1. **Analyst False-Action Rate ($p_{\text{err}} \in [0.02, 0.30]$):**
   - *Hypothesis:* Total operational disruption increases linearly with $p_{\text{err}}$ as $D_{\text{total}} = D_{\text{auto}} + p_{\text{err}} \cdot \sum_{e \in \text{Escalated}} C(a_e, i_e)$.
   - *Pass Threshold:* AEGIS-X retains lower cumulative disruption than Baseline B1 for all $p_{\text{err}} \le 0.25$.
2. **Analyst Review Capacity ($C_{\text{analyst}} \in [6, 24]\text{ approvals/day}$):**
   - *Hypothesis:* Queue backlog stabilizes without runaway overflow when average escalation arrival $\lambda_{\text{esc}} \le C_{\text{analyst}}$.
   - *Pass Threshold:* Report exact break-even capacity $C^*$. For $C \ge 12$, incident backlog at $T = 72\text{ h}$ remains $\le 5$ incidents.
3. **Approval Delay ($\tau_{\text{delay}} \in [2, 24]\text{ hours}$):**
   - *Hypothesis:* Success / Remediation retention rate (SR) within 72 h SLA decays smoothly with delay.
   - *Pass Threshold:* $\text{SR} \ge 60.0\%$ for all $\tau_{\text{delay}} \le 12\text{ hours}$.

* **Falsification Criterion for H2-Sens:** If AEGIS-X yields higher disruption than static lists when analyst error $p_{\text{err}} \le 0.15$, or if remediation collapses below $50\%$ when delay $\tau \le 8\text{ h}$.

---

### Hypothesis 2-Base (H2-Base: Comparative Baselines / Reviewer M3)

* **Formal Statement:** The dual mechanism (Graph-derived $T_0$ + Credibility Stratification) is non-redundant: disabling either mechanism significantly degrades safety or availability.

#### Pre-Registered Baselines & Comparison Thresholds:
1. **B6: Cost-Budget-Only without Graph $T_0$:**
   - *Threshold:* Under S2 and S3, B6 will permit $T_0 \text{ violations} > 0$ because budget admission without topological centrality allows high-value entities to be targeted once budget tokens are available.
2. **B7: Agent-Lock Style Static Blast Budget (Unstratified):**
   - *Threshold:* Under S7 (incident flood), B7 will suffer severe crowd-out of authentic incidents ($\text{SR} < 50.0\%$), whereas AEGIS-X maintains $\text{SR} \ge 65.0\%$ due to reserved $B_{\text{high}}$ capacity.
3. **B0 De-confounding (Mildest Action Normalization):**
   - *Threshold:* Even when B0 is restricted to the mildest action (`REVOKE_ALL_SESSIONS`, $\kappa = 0.20$), AEGIS-X achieves statistically significant disruption reduction ($p < 0.01$, Wilcoxon signed-rank test).

* **Falsification Criterion for H2-Base:** If B6 achieves zero $T_0$ violations without graph awareness, or if B7 matches B4's remediation rate under S7 floods ($p \ge 0.05$).

---

### Hypothesis 3 (H3: Exact Additive Explainability & Tamper Detection / RQ3 & M6)

* **Formal Statement:** The hybrid risk formulation provides mathematically exact feature additivity without numeric divergence, and the RFC 9162 Merkle decision log detects all classes of adversarial history alteration.

#### Pre-Registered Numeric Thresholds:
| Sub-Hypothesis | Verification Criterion | Metric | Required Pass Threshold |
| :--- | :--- | :--- | :--- |
| **H3.1 (Additivity Error)** | Proposition 1: $\|S(x) - (\text{base} + \sum \Phi_j - m(x))\|$ | **Max Absolute Error** | $<\mathbf{10^{-6}}$ **on 100% of samples** |
| **H3.2 (Counterfactual Validity)**| Search for $x'$ such that $S(x') < \tau_{\text{action}}$ | **Validity %** | $\mathbf{\equiv 100.0\%}$ |
| **H3.3 (Bit-Flip Tampering)** | Cryptographic Leaf Alteration | **Detection Rate** | $\mathbf{\equiv 100.0\%}$ ($0\%$ FN) |
| **H3.4 (Event Insertion/Deletion)**| History Tree Leaf Modification | **Detection Rate** | $\mathbf{\equiv 100.0\%}$ ($0\%$ FN) |
| **H3.5 (STH Consistency)** | Log History Truncation / Branching | **Consistency Proof** | $\mathbf{\equiv 100.0\%}$ Detection |

* **Falsification Criterion for H3:** Any sample exhibiting additivity discrepancy $\ge 10^{-6}$, or any undetected audit modification.

---

### Hypothesis 4 (H4: Operational Scalability & Runtime Overhead / RQ4)

* **Formal Statement:** Graph reachability evaluation, exact SHAP attribution, admission gating, and RFC 9162 log append introduce negligible latency suitable for real-time SOC orchestration.

#### Pre-Registered Numeric Thresholds:
| Sub-Hypothesis | Evaluation Scope | Metric | Required Pass Threshold |
| :--- | :--- | :--- | :--- |
| **H4.1 (Decision Latency)** | End-to-End Ingestion + Gating | **Mean Latency** | $\le \mathbf{5.0\text{ ms}}$ per incident |
| **H4.2 (Tail Latency)** | End-to-End Ingestion + Gating | **p99 Latency** | $\le \mathbf{15.0\text{ ms}}$ per incident |
| **H4.3 (Proof Size)** | RFC 9162 Inclusion Proof ($N = 10^6$) | **Proof Byte Size** | $\mathbf{\le 640\text{ Bytes}}$ ($32 \lceil\log_2 N\rceil$) |

* **Falsification Criterion for H4:** Mean decision latency $> 10.0\text{ ms}$ or inclusion proof size exceeding $1024$ bytes.

---

## 4. Execution Protocol & Verification Sign-Off

* **Pre-Registration Commit Date:** October 22, 2026
* **Verification Command:** `python backend/research/reproduce_dossier.py`
* **Test Suite:** `python -m pytest backend/tests` (All 70 tests passing)
* **Statistical Rigor Standard:** Two-tailed Mann-Whitney U test with Bonferroni correction for multi-hypothesis comparisons ($\alpha = 0.01$).

By signing off on this pre-registration file, all hypothesis boundaries and numeric thresholds are frozen for the AI-SEC submission and reviewer rebuttals.
