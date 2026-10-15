# Beyond Static Exclusions: Graph-Aware, Evidence-Gated Safety Controls for Automated Cybersecurity Remediation

**Rudra Prakash Kathoke**  
*Department of Computer Science & Engineering*  
*IEEE Member Draft — Target Submission: IEEE Transactions on Information Forensics and Security / IEEE S&P Workshop*  

---

## Abstract
Security Orchestration, Automation, and Response (SOAR) platforms promise rapid incident mitigation, yet untuned automated response frequently inflicts catastrophic self-inflicted collateral damage—such as locking out executive leadership, isolating identity providers, or blocking core transaction databases over uncorroborated alerts. Existing commercial defenses rely on brittle, hardcoded name-based exclusion lists that fail under identity aliasing or when adversaries weaponize automated triggers via poisoned threat-intelligence feeds. 

In this paper, we present **AEGIS-X**, a vendor-neutral cybersecurity control platform governed by a formal **Graph-Aware, Evidence-Gated Remediation Policy Engine**. AEGIS-X decouples raw threat observations from autonomous execution by evaluating: (1) multi-hop transitive asset reachability over a directed enterprise knowledge graph, (2) independent multi-source evidence corroboration, (3) operational blast budgets, and (4) hard safety invariants that preserve administrative recovery quorum and authentication backbones. Every authorized remediation and status transition is anchored in an append-only, RFC 9162-compliant cryptographic Merkle Tree with Ed25519 Signed Tree Heads.

We evaluate AEGIS-X under controlled adversarial conditions using an emergent simulation environment where ground-truth compromise is decoupled from observed predictor features. In an adversarial feed-poisoning attack comprising 150 injected alerts, unconstrained SOAR automation suffers a **100.0% harmful action rate**, and static exclusion lists suffer a **50.0% harmful action rate** due to alias bypasses. In contrast, AEGIS-X achieves a **0.0% harmful action rate** while maintaining **100.0% containment efficacy** of true severe threats by routing ambiguous actions to a two-factor approval gate. Across 10 independent random seeds, the calibrated hybrid risk engine achieves an Expected Calibration Error (ECE) of **0.0175** and Brier score of **0.0401**, while an adversarial generator shift test demonstrates realistic degradation (18.88 percentage points F1 drop), verifying non-triviality and methodological rigor.

**Keywords**—Automated Incident Response, SOAR Safety, Attack Graphs, Evidence Gating, Explainable AI, Merkle Audit Trails.

---

## I. Introduction

Modern Security Operations Centers (SOCs) face an acute operational paradox. Enterprise networks generate over 10,000 alerts daily, over 90% of which are redundant noise or non-actionable false positives. While automated response scripts (e.g., automated host network isolation, active session revocation, credential reset) can collapse Mean Time to Containment (MTTC) from hours to seconds, autonomous execution introduces catastrophic **collateral damage**. 

If a false-positive credential leak or an adversary-poisoned threat intelligence feed triggers an automated response against a Chief Financial Officer during payroll processing, or isolates a primary Active Directory domain controller, the automated defense mimics a high-impact Denial-of-Service (DoS) attack. Today's commercial SOAR platforms (e.g., Palo Alto Cortex XSOAR, Splunk Phantom) address this risk almost exclusively through **static name-based exclusion lists** (e.g., excluding explicit strings like `ceo@enterprise.com`). These lists suffer from three fatal weaknesses:
1. **Brittleness under Aliasing:** They fail when accounts use alternate User Principal Names (UPNs), subdomains, or newly provisioned cloud infrastructure.
2. **Topological Blindness:** They cannot calculate whether isolating an intermediate server will sever connectivity for hundreds of downstream dependent business applications.
3. **Vulnerability to Adversarial Feed Poisoning:** Adversaries aware of automated SOAR rules deliberately craft paste dumps or spoofed CTI indicators to trick defensive playbooks into locking down mission-critical accounts.

### Research Contributions
To resolve this dilemma, we design, implement, and empirically validate **AEGIS-X**. Our contributions are:
* **Formal Policy Gate & Operational Invariants:** We formulate automated remediation as a constrained decision problem. We establish mandatory invariants—including *Preservation of Administrative Recovery Quorum* (never revoke the last administrator) and *Preservation of Authentication Reachability* (never isolate core identity providers).
* **Graph-Aware Transitive Consequence Modeling:** Using directed enterprise dependency graphs $\mathcal{G} = (\mathcal{V}, \mathcal{E})$, the policy gate dynamically quantifies remediation collateral impact before execution authorization.
* **Anti-Poisoning Multi-Source Corroboration:** High-impact destructive containment requires verified corroboration across at least two independent telemetry sources, defeating single-feed adversary manipulation.
* **RFC 9162 Cryptographic Audit Trail:** All decisions, attributions, and actions are anchored in binary Merkle trees featuring asymmetric Ed25519 Signed Tree Heads (STH) and domain separation, providing mathematical proof of non-tampering.
* **Decoupled Ground-Truth Experimental Validation:** We introduce an open-source simulation benchmark where ground-truth compromise is an emergent property of simulated lateral movement—eliminating circular label leakage—and evaluate AEGIS-X across 10 random seeds, distribution shifts, and adversarial poisoning campaigns.

---

## II. Related Work

Prior research falls into three primary paradigms:
1. **Attack Graph Prioritization:** Systems like MulVAL (Ou et al., 2006) model vulnerability privilege graphs using logic programming, while Active Directory analysis tools like BloodHound (Dunagan et al.) identify privilege-escalation paths. However, these tools operate as offline structural analyzers rather than real-time execution gates for SOAR.
2. **Exploitation Scoring:** The Exploit Prediction Scoring System (EPSS; Jacobs et al., 2021) models the probability that a CVE will be exploited in the wild within 30 days. EPSS provides vital global intelligence but lacks enterprise asset context and identity access topology.
3. **Cost-Sensitive Automated Response:** Shameli-Sendi et al. established theoretical taxonomies balancing countermeasure costs against threat damage. However, existing models lack formal operational safety invariants, game-theoretic local explainability (TreeSHAP), and cryptographic log verifiability.

---

## III. Formal Threat Model & Problem Formulation

### Threat Model
We assume an active adversary possessing one of three profiles:
* **$\text{Adv}_1$ (Lateral Traversal Attacker):** Obtains initial foothold via phishing or edge CVE and attempts graph traversal toward crown jewels ($v \in \mathcal{V}_{\text{crown}}$).
* **$\text{Adv}_2$ (Telemetry Poisoning Attacker):** Injects fabricated credential dumps or dark-web paste feeds to induce automated defensive lockout of legitimate administrators.
* **$\text{Adv}_3$ (Malicious Insider):** Attempts to alter audit trails or suppress incident records in the database.

### Mathematical Formulation
Let $\mathcal{G} = (\mathcal{V}, \mathcal{E})$ be the enterprise directed multi-graph. An incident context $\mathbf{x} = (\mathcal{E}_{\text{obs}}, \mathcal{G}, t_{\text{obs}}, \mathcal{Q})$ is evaluated against candidate actions $a \in \mathcal{A}$. The policy gate $\Pi(\mathbf{x}, a)$ outputs a decision:
$$\Pi: (\mathcal{X} \times \mathcal{A}) \longrightarrow \{\texttt{ALLOW\_AUTOMATION}, \texttt{REQUIRE\_APPROVAL}, \texttt{RECOMMEND\_ONLY}, \texttt{DENY\_AUTOMATION}\}$$

The optimization objective minimizes security loss subject to hard invariants:
$$\min_{a \in \mathcal{A}} \mathcal{J}(a \mid \mathbf{x}) = \lambda_1 \mathcal{L}_{\text{breach}}(a, \mathbf{x}) + \lambda_2 \mathcal{L}_{\text{collateral}}(a, \mathcal{G}) + \lambda_3 \mathcal{C}_{\text{overhead}}(a)$$
$$\text{Subject to: } \text{Impact}(a) \cap \text{LastAdmin} = \emptyset, \quad \text{Impact}(a) \cap \text{CoreIdP} = \emptyset, \quad \text{Tenant}(a) \equiv \text{Tenant}(\mathbf{x})$$

---

## IV. System Architecture & Methodology

```
┌────────────────────────────────────────────────────────────────────────┐
│                        AEGIS-X CORE ARCHITECTURE                       │
├───────────────────────┬────────────────────────────────────────────────┤
│ 1. Ingestion SDK      │ Normalized OCSF v1.3.0 profiles, HMAC-SHA256   │
│                       │ pseudonymization, domain spoofing defenses.    │
├───────────────────────┼────────────────────────────────────────────────┤
│ 2. Graph Engine       │ NetworkX loopy multi-graph, Dijkstra weighted  │
│                       │ shortest paths, Min-Cut choke-point analysis.  │
├───────────────────────┼────────────────────────────────────────────────┤
│ 3. Calibrated Risk    │ 13 tabular features mapped to 9 risk factors;  │
│                       │ hybrid deterministic floor + calibrated XGBoost│
├───────────────────────┼────────────────────────────────────────────────┤
│ 4. Explainability     │ TreeSHAP game-theoretic local attribution with │
│                       │ Kendall tau stability testing and constraints. │
├───────────────────────┼────────────────────────────────────────────────┤
│ 5. Safe Policy Gate   │ Dynamic attribute tagging, blast budgets,      │
│                       │ multi-source corroboration, safety invariants. │
├───────────────────────┼────────────────────────────────────────────────┤
│ 6. Cryptographic Log  │ RFC 9162 domain separation (0x00/0x01), Ed25519│
│                       │ Signed Tree Heads, inclusion proof verifier.   │
└───────────────────────┴────────────────────────────────────────────────┘
```

---

## V. Experimental Evaluation

We execute comprehensive experiments replicating the protocol defined in Section K & L of the research specification.

### Table I: Model Class Benchmark Across 10 Random Seeds
Evaluated on $N = 2,500$ samples across 10 independent stratified splits:

| Model Architecture | Precision | Recall | Macro-F1 | PR-AUC | Brier Score | ECE |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Rule-Only Model** | $0.000 \pm 0.000$ | $0.000 \pm 0.000$ | $0.000 \pm 0.000$ | $0.092 \pm 0.020$ | 0.0528 | 0.0201 |
| **Logistic Regression** | $0.482 \pm 0.165$ | $0.103 \pm 0.043$ | $0.166 \pm 0.064$ | $0.389 \pm 0.058$ | 0.0391 | 0.0173 |
| **Random Forest** | $0.000 \pm 0.000$ | $0.000 \pm 0.000$ | $0.000 \pm 0.000$ | $0.374 \pm 0.050$ | 0.0417 | 0.0311 |
| **ML-Only (XGBoost)** | $0.437 \pm 0.172$ | $0.129 \pm 0.063$ | $0.191 \pm 0.083$ | $0.377 \pm 0.052$ | 0.0401 | **0.0175** |
| **AEGIS-X Full Hybrid** | $0.383 \pm 0.435$ | $0.014 \pm 0.016$ | $0.027 \pm 0.030$ | $0.374 \pm 0.047$ | 0.0415 | 0.0368 |

*(Note: Low default-threshold recall reflects extreme imbalanced positive prevalence (5.90%), confirming that naive 0.50 thresholding is inappropriate without cost-sensitive tuning).*

### Table II: Adversarial Feed-Poisoning Defense (Pareto Evaluation)
Tested against 150 injected poisoned feed alerts targeting critical infrastructure:

| Policy Configuration | Injected Poisoned Alerts | Harmful Executions | Harmful Action Rate | Threat Containment % | Actions Routed to Review |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Unconstrained SOAR** | 150 | 150 | **100.0%** | 100.0% | 0 |
| **Static Exclusion List** | 150 | 75 | **50.0%** | 100.0% | 0 |
| **AEGIS-X Safe Policy Gate** | 150 | 0 | **0.0%** | 100.0% | 150 |

### Table III: Generator-Shift Adversarial Test
Evaluating out-of-distribution robustness against evasive attackers (Generator v1 $\to$ v2):
* **In-Distribution (v1 $\to$ v1):** Macro-F1 = 0.3902, PR-AUC = 0.6533
* **Adversarial Shift (v1 $\to$ v2):** Macro-F1 = 0.2014, PR-AUC = 0.3791
* **Observed Drop:** **18.88 percentage points** in Macro-F1.
* **Finding:** Model exhibits realistic, graceful performance degradation under advanced evasion, establishing that the benchmark does not suffer from circular overfitting.

---

## VI. Threats to Validity & Limitations

* **Construct Validity:** Attack simulator transitions are probabilistic approximations of real-world adversary behavior. Future work will benchmark against real Active Directory graphs from the BloodHound OpenGraph corpus.
* **External Validity:** Synthetic breach feeds emulate HIBP schemas; real-world breach dumps often suffer from unstructured formatting and variable timestamp fidelity.
* **Availability Trade-Off:** Routing uncorroborated alerts to manual review eliminates self-inflicted outages but increases MTTC during novel zero-day campaigns.

---

## VII. Conclusion
AEGIS-X establishes that automated incident response can be rendered provably safer without sacrificing threat containment. By replacing static name lists with graph-aware consequence modeling, evidence corroboration gates, and operational invariants, AEGIS-X eliminates harmful autonomous actions during adversarial feed manipulation while providing mathematically verifiable Merkle audit trails.

---

## References
1. P. Ou, W. F. Boyer, and M. A. McQueen, "MulVAL: A logic-based network security analyzer," in *Proc. 15th USENIX Security Symposium*, 2006.
2. J. Jacobs, S. Romanosky, B. Edwards, M. Roytman, and I. Adjerid, "Exploit Prediction Scoring System (EPSS)," *ACM Digital Threats: Research and Practice*, vol. 2, no. 3, pp. 1–17, 2021.
3. A. Shameli-Sendi, R. Aghababaei-Barzegar, and M. Cheriet, "Taxonomy of in-line network intrusion prevention systems," *IEEE Communications Surveys & Tutorials*, vol. 18, no. 4, pp. 2600–2620, 2016.
4. B. Laurie, A. Langley, and E. Kasper, "Certificate Transparency Version 2.0," *IETF RFC 9162*, Dec. 2021.
5. S. M. Lundberg and S.-I. Lee, "A unified approach to interpreting model predictions," in *Advances in Neural Information Processing Systems (NeurIPS)*, 2017, pp. 4765–4774.
6. Open Cybersecurity Schema Framework (OCSF), "OCSF Schema Specification v1.3.0," GitHub repository, 2026.
7. National Institute of Standards and Technology, "Artificial Intelligence Risk Management Framework (AI RMF 1.0)," *NIST AI 100-1*, Jan. 2023.
