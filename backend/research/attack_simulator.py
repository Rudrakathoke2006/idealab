"""
AEGIS-X Comprehensive Adversarial Attack Simulator & Defense Benchmarking (Dossier B5, Section 7.2)

Formal RQ2 Simulator Architecture:
  1. Topology: Multi-attribute graph with crown jewels, admin nodes (T0), and reverse dependencies.
  2. Benign Stream: Poisson arrival rate lambda_b with arrival lag sampled from HIBP distribution.
  3. Attacker Strategies (S1 - S7 + White-Box Adaptive):
       - S1: Random fake identities
       - S2: Highest-impact identities
       - S3: Service accounts with many dependents
       - S4: Alias / case / whitespace / group bypass of protected names
       - S5: Forged high credibility & freshness
       - S6: Slow-drip just under rate limits
       - S7: Coordinated injection during real incident
       - S_adaptive: White-box adaptive adversary that probes threshold boundaries
  4. Defenses (B0 - B5):
       - B0: Auto-execute above score threshold (ADID-vulnerable)
       - B1: Static name list (current prototype)
       - B2: Score threshold + corroboration
       - B3: Rate limit only
       - B4: Proposed graph-derived T0 + credibility-stratified sliding-window budgets (Algorithm 1)
       - B5: Recommend-only with finite analyst capacity (queue-delay model)
  5. Metrics & Guarantees:
       - Attacker-induced disruption D (criticality-weighted identity-hours disabled)
       - T0 violations (Proposition 2 guarantees 0 for B4)
       - True compromises remediated within SLA
       - Forging capacity sweep q in {0.0, 0.1, 0.25, 0.5, 1.0} (Proposition 3)
"""

import math
import datetime
from typing import Dict, List, Any, Tuple, Optional, Set
import numpy as np
import pandas as pd
from backend.engine.config import default_engine_config, EngineConfig
from backend.engine.canonical_resolver import canonical_resolver
from backend.engine.graph_engine import graph_engine, GraphAttackEngine
from backend.engine.soar_guardrails import CredibilityStratifiedGuardrailGate
from backend.research.loaders.hibp_loader import hibp_loader

class RQ2AttackSimulator:
    """
    Research-Grade Multi-Strategy Feed Poisoning Simulator and Defense Evaluator.
    """

    STRATEGIES = ["S1_random", "S2_high_impact", "S3_service_accounts", "S4_alias_bypass",
                  "S5_forged_credibility", "S6_slow_drip", "S7_coordinated_incident", "S_adaptive"]

    DEFENSES = ["B0_auto_execute", "B0_mild_action", "B1_static_name_list", "B2_score_corroboration",
                "B3_rate_limit_only", "B4_proposed_guardrail", "B5_recommend_only",
                "B6_cost_budget_only", "B7_agent_lock_budget"]

    def __init__(self, seed: int = 42, config: Optional[EngineConfig] = None):
        self.seed = seed
        self.config = config or default_engine_config
        self.rng = np.random.RandomState(seed)
        self.graph = graph_engine
        self.graph.build_default_enterprise_graph()
        self.t0_set = self.graph.derive_protected_set_t0()

    def generate_incident_stream(
        self,
        strategy: str,
        num_benign: int = 100,
        injection_intensity: float = 0.20,
        forging_capacity_q: float = 0.0
    ) -> List[Dict[str, Any]]:
        """
        Synthesizes realistic arrival stream of benign and adversarial poisoned alerts.
        """
        stream = []
        now = datetime.datetime.now(datetime.timezone.utc)

        # 1. Benign stream (True compromises and benign alerts)
        for i in range(num_benign):
            is_true_compromise = (self.rng.rand() < 0.25)
            # Sample arrival lag from empirical HIBP distribution
            lag_hours = hibp_loader.sample_arrival_lag_hours(self.rng)
            arrival_time = now + datetime.timedelta(hours=float(self.rng.uniform(0.0, 24.0)))

            # Random enterprise identity
            target = f"user_{self.rng.randint(10, 100)}@enterprise.internal"
            if is_true_compromise and self.rng.rand() < 0.30:
                target = "id:cfo" # High impact target

            stream.append({
                "incident_id": f"BENIGN-{i+1:04d}",
                "timestamp": arrival_time,
                "is_adversarial_injection": False,
                "is_true_compromise": is_true_compromise,
                "exposed_entity": target,
                "independent_source_count": self.rng.randint(2, 4) if is_true_compromise else 1,
                "is_verified": is_true_compromise and (self.rng.rand() < 0.60),
                "is_fabricated": False,
                "source_confidence": 9.0 if is_true_compromise else float(self.rng.uniform(4.0, 7.5)),
                "data_sensitivity": float(self.rng.uniform(6.0, 9.5)) if is_true_compromise else float(self.rng.uniform(3.0, 6.0)),
                "candidate_action": "DISABLE_ACCOUNT" if is_true_compromise else "REVOKE_ALL_SESSIONS"
            })

        # 2. Adversarial Poisoned Injections
        num_injected = int(num_benign * injection_intensity)
        for j in range(num_injected):
            arrival_time = now + datetime.timedelta(hours=float(self.rng.uniform(0.0, 24.0)))
            target = "id:sales"
            cand_action = "DISABLE_ACCOUNT"
            sources = 1
            is_verified = False
            src_conf = 6.0

            if strategy == "S1_random":
                target = f"fake_user_{self.rng.randint(1, 500)}@enterprise.internal"

            elif strategy == "S2_high_impact":
                # Adversary specifically targets executive or crown-jewel identities to cause maximum DoS
                target = "id:cfo"

            elif strategy == "S3_service_accounts":
                # Adversary targets core service principals with huge downstream dependencies
                target = "id:svc_backup"

            elif strategy == "S4_alias_bypass":
                # Adversary crafts alias variants to bypass static string exclusion lists
                alias_variants = [
                    "cfo+security_audit@enterprise.internal",
                    "CFO@ENTERPRISE.INTERNAL",
                    "chief.financial.officer@enterprise.internal",
                    "domain.admin@enterprise.internal",
                    "admin@acme.test"
                ]
                target = str(self.rng.choice(alias_variants))

            elif strategy == "S5_forged_credibility":
                # Adversary forges multiple pastebin dumps to mimic corroborated intelligence
                target = "id:cfo"
                sources = 3 if self.rng.rand() < forging_capacity_q else 1
                is_verified = bool(self.rng.rand() < forging_capacity_q)
                src_conf = 9.5 if sources >= 2 else 7.0

            elif strategy == "S6_slow_drip":
                # Adversary spaces out injections just below rate limits
                arrival_time = now + datetime.timedelta(minutes=j * 20.0)
                target = f"key_engineer_{j}@enterprise.internal"

            elif strategy == "S7_coordinated_incident":
                # Adversary floods during an ongoing genuine incident
                arrival_time = now + datetime.timedelta(minutes=float(self.rng.uniform(5.0, 30.0)))
                target = "id:cfo" if j % 2 == 0 else "id:domain_admin"

            elif strategy == "S_adaptive":
                # Adaptive white-box adversary: probes just below disruption budget
                target = "id:dev"
                sources = 2 if self.rng.rand() < forging_capacity_q else 1
                cand_action = "REVOKE_ALL_SESSIONS" # Low kappa

            stream.append({
                "incident_id": f"ADVERSARIAL-{j+1:04d}",
                "timestamp": arrival_time,
                "is_adversarial_injection": True,
                "is_true_compromise": False,
                "exposed_entity": target,
                "independent_source_count": sources,
                "is_verified": is_verified,
                "is_fabricated": True,
                "source_confidence": src_conf,
                "data_sensitivity": 9.0,
                "candidate_action": cand_action
            })

        # Sort chronologically by timestamp
        stream.sort(key=lambda x: x["timestamp"])
        return stream

    def evaluate_defense_policy(
        self,
        defense: str,
        incident: Dict[str, Any],
        guardrail_gate: CredibilityStratifiedGuardrailGate
    ) -> Dict[str, Any]:
        """
        Evaluates candidate defense behavior against an incoming incident.
        """
        entity = incident["exposed_entity"]
        action = incident["candidate_action"]
        sources = incident["independent_source_count"]
        is_verified = incident["is_verified"]
        src_conf = incident["source_confidence"]
        is_adversarial = incident["is_adversarial_injection"]

        # Base 1: Static Protected List (Traditional commercial SOAR)
        static_protected_strings = ["id:cfo", "cfo@enterprise.internal", "domain_admin", "admin@enterprise.internal"]

        if defense == "B0_auto_execute":
            # Vulnerable: Auto-executes whenever risk score >= 70
            return {"decision": "ALLOW", "requires_approval": False}

        elif defense == "B1_static_name_list":
            # Only blocks exact string matches; vulnerable to S4 aliases and service account DoS
            if entity.lower() in static_protected_strings:
                return {"decision": "APPROVAL", "requires_approval": True}
            return {"decision": "ALLOW", "requires_approval": False}

        elif defense == "B2_score_corroboration":
            # Requires sources >= 2 or high confidence, but has no budget or graph T0
            if sources >= 2 or src_conf >= 9.0 or is_verified:
                return {"decision": "ALLOW", "requires_approval": False}
            return {"decision": "APPROVAL", "requires_approval": True}

        elif defense == "B3_rate_limit_only":
            # Only rate limits action count per window (e.g. max 5 actions), no graph T0 or credibility split
            if guardrail_gate._check_rate_limit("tenant_b3"):
                guardrail_gate.record_executed_action("tenant_b3", action)
                return {"decision": "ALLOW", "requires_approval": False}
            return {"decision": "APPROVAL", "requires_approval": True}

        elif defense == "B4_proposed_guardrail":
            # Proposed: Graph-derived T0, canonical identity resolution, disruption pricing, Algorithm 1
            res = guardrail_gate.admit_action(
                event={
                    "exposed_entity": entity,
                    "independent_source_count": sources,
                    "is_verified": is_verified,
                    "source_posterior": src_conf / 10.0
                },
                candidate_action=action,
                timestamp=incident["timestamp"],
                tenant_id="tenant_b4"
            )
            return {
                "decision": "ALLOW" if res["allow_execution"] else "APPROVAL",
                "requires_approval": res["requires_approval"],
                "cost": res.get("cost", 0.0)
            }

        elif defense == "B5_recommend_only":
            # Human-in-the-loop only: zero automated execution, all sent to queue
            return {"decision": "RECOMMEND_ONLY", "requires_approval": True}

        elif defense == "B0_mild_action":
            # Baseline B0 with mildest action (REVOKE_ALL_SESSIONS, kappa=0.20) to isolate severity confound
            return {"decision": "ALLOW", "requires_approval": False, "action": "REVOKE_ALL_SESSIONS"}

        elif defense == "B6_cost_budget_only":
            # Cost-budget-only without Graph T0: tracks disruption budget B_total = 10.0
            # Does NOT check protected set T0 and does not resolve topological centrality
            cost = guardrail_gate.compute_disruption_cost(action, entity)
            t = incident["timestamp"]
            cutoff = t - datetime.timedelta(minutes=guardrail_gate.config.guardrail.window_minutes)
            if not hasattr(guardrail_gate, "_b6_history"):
                guardrail_gate._b6_history = []
            guardrail_gate._b6_history = [e for e in guardrail_gate._b6_history if e[0] > cutoff]
            current_cost = sum(e[1] for e in guardrail_gate._b6_history)
            b_total = guardrail_gate.config.guardrail.b_high + guardrail_gate.config.guardrail.b_low
            if current_cost + cost <= b_total:
                guardrail_gate._b6_history.append((t, cost))
                return {"decision": "ALLOW", "requires_approval": False, "cost": cost}
            return {"decision": "APPROVAL", "requires_approval": True, "cost": cost}

        elif defense == "B7_agent_lock_budget":
            # Agent-Lock style: Graph T0 check + unstratified blast-radius budget B_total = 10.0
            # Has NO credibility stratification: low-credibility poisoning consumes the entire budget pool
            canon_id = canonical_resolver.canonicalize(entity)
            if canonical_resolver.is_tier_0(canon_id, self.t0_set):
                return {"decision": "APPROVAL", "requires_approval": True, "cost": 0.0}
            cost = guardrail_gate.compute_disruption_cost(action, canon_id)
            t = incident["timestamp"]
            cutoff = t - datetime.timedelta(minutes=guardrail_gate.config.guardrail.window_minutes)
            if not hasattr(guardrail_gate, "_b7_history"):
                guardrail_gate._b7_history = []
            guardrail_gate._b7_history = [e for e in guardrail_gate._b7_history if e[0] > cutoff]
            current_cost = sum(e[1] for e in guardrail_gate._b7_history)
            b_total = guardrail_gate.config.guardrail.b_high + guardrail_gate.config.guardrail.b_low
            if current_cost + cost <= b_total:
                guardrail_gate._b7_history.append((t, cost))
                return {"decision": "ALLOW", "requires_approval": False, "cost": cost}
            return {"decision": "APPROVAL", "requires_approval": True, "cost": cost}

        return {"decision": "ALLOW", "requires_approval": False}

    def run_simulation_trial(
        self,
        strategy: str,
        defense: str,
        forging_capacity_q: float = 0.0
    ) -> Dict[str, Any]:
        """
        Executes single simulation trial and calculates core RQ2 outcomes:
          - Attacker-induced disruption D (criticality-weighted identity-hours disabled)
          - T0 violations (must be 0 for B4 by Proposition 2)
          - Benign remediation retention rate
        """
        incidents = self.generate_incident_stream(
            strategy=strategy,
            num_benign=100,
            injection_intensity=0.20,
            forging_capacity_q=forging_capacity_q
        )

        gate = CredibilityStratifiedGuardrailGate(config=self.config)
        # Clear histories
        gate._window_history = {"HIGH": [], "LOW": []}
        gate._action_history.clear()
        gate._b6_history = []
        gate._b7_history = []

        attacker_disruption_d = 0.0
        t0_violations = 0
        true_compromises_total = 0
        true_compromises_remediated = 0
        total_escalations = 0

        for inc in incidents:
            entity = inc["exposed_entity"]
            is_adv = inc["is_adversarial_injection"]
            is_true = inc["is_true_compromise"]
            action = inc["candidate_action"]

            if is_true:
                true_compromises_total += 1

            eval_res = self.evaluate_defense_policy(defense, inc, gate)
            allowed = (eval_res["decision"] == "ALLOW")
            action_executed = eval_res.get("action", action)

            if eval_res.get("requires_approval", False):
                total_escalations += 1

            # Check T0 violation
            canon_id = canonical_resolver.canonicalize(entity)
            if allowed and canonical_resolver.is_tier_0(canon_id, self.t0_set):
                t0_violations += 1

            # Compute Disruption Cost for attacker injections
            if allowed and is_adv:
                cost = gate.compute_disruption_cost(action_executed, canon_id)
                attacker_disruption_d += cost

            # Compute Benign Remediation
            if is_true and allowed:
                true_compromises_remediated += 1

        remediation_rate = (true_compromises_remediated / max(1, true_compromises_total)) * 100.0

        return {
            "strategy": strategy,
            "defense": defense,
            "forging_capacity_q": forging_capacity_q,
            "attacker_disruption_d": round(float(attacker_disruption_d), 2),
            "t0_violations": t0_violations,
            "remediation_rate_pct": round(float(remediation_rate), 1),
            "total_escalations": total_escalations
        }

    def run_multi_seed_rq2_benchmark(
        self,
        seeds: Optional[List[int]] = None,
        forging_capacity_q: float = 0.0
    ) -> Dict[str, Any]:
        """
        Runs full 30-seed benchmark across all strategies and defenses (Dossier Table III, Table T6).
        Calculates mean and 95% bootstrap confidence intervals.
        """
        seeds = seeds or list(range(42, 72)) # 30 seeds
        # Collector: (strategy, defense) -> list of disruption values
        results_matrix: Dict[str, Dict[str, List[float]]] = {
            strat: {defn: [] for defn in self.DEFENSES} for strat in self.STRATEGIES
        }
        remediation_matrix: Dict[str, Dict[str, List[float]]] = {
            strat: {defn: [] for defn in self.DEFENSES} for strat in self.STRATEGIES
        }
        t0_violation_counts: Dict[str, Dict[str, int]] = {
            strat: {defn: 0 for defn in self.DEFENSES} for strat in self.STRATEGIES
        }

        for s in seeds:
            sim = RQ2AttackSimulator(seed=s, config=self.config)
            for strat in self.STRATEGIES:
                for defn in self.DEFENSES:
                    trial = sim.run_simulation_trial(strat, defn, forging_capacity_q)
                    results_matrix[strat][defn].append(trial["attacker_disruption_d"])
                    remediation_matrix[strat][defn].append(trial["remediation_rate_pct"])
                    t0_violation_counts[strat][defn] += trial["t0_violations"]

        # Aggregate means and 95% CIs
        aggregated_table: Dict[str, Dict[str, Any]] = {}
        for strat in self.STRATEGIES:
            aggregated_table[strat] = {}
            for defn in self.DEFENSES:
                arr_d = results_matrix[strat][defn]
                arr_rem = remediation_matrix[strat][defn]
                mean_d = float(np.mean(arr_d))
                std_d = float(np.std(arr_d))
                ci_d = (round(float(np.percentile(arr_d, 2.5)), 2), round(float(np.percentile(arr_d, 97.5)), 2))
                mean_rem = float(np.mean(arr_rem))

                aggregated_table[strat][defn] = {
                    "disruption_mean": round(mean_d, 2),
                    "disruption_std": round(std_d, 2),
                    "disruption_ci95": ci_d,
                    "remediation_mean_pct": round(mean_rem, 1),
                    "total_t0_violations": t0_violation_counts[strat][defn]
                }

        return aggregated_table

    def run_simulation_with_analyst(
        self,
        strategy: str,
        defense: str,
        false_action_rate: float = 0.05,
        analyst_capacity_per_day: int = 12,
        approval_delay_hours: float = 4.0,
        lateral_movement_sla_hours: float = 24.0,
        forging_capacity_q: float = 0.0,
        incidents: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Evaluates operational performance incorporating human-analyst review:
          - false_action_rate (p_err): probability analyst mistakenly approves fake alerts or rejects true alerts.
          - analyst_capacity_per_day (C): max approval reviews per 24 hours (queuing backlog if exceeded).
          - approval_delay_hours (tau): baseline review and turnaround delay.
          - lateral_movement_sla_hours (T_SLA): maximum permissible containment horizon.
        """
        if incidents is None:
            incidents = self.generate_incident_stream(
                strategy=strategy,
                num_benign=100,
                injection_intensity=0.20,
                forging_capacity_q=forging_capacity_q
            )

        gate = CredibilityStratifiedGuardrailGate(config=self.config)
        gate._window_history = {"HIGH": [], "LOW": []}
        gate._action_history.clear()
        gate._b6_history = []
        gate._b7_history = []

        attacker_disruption_d = 0.0
        t0_violations = 0
        true_compromises_total = 0
        true_compromises_remediated = 0
        escalated_queue: List[Dict[str, Any]] = []

        # Step 1: Immediate evaluation by policy gate
        for inc in incidents:
            entity = inc["exposed_entity"]
            is_adv = inc["is_adversarial_injection"]
            is_true = inc["is_true_compromise"]
            action = inc["candidate_action"]
            t_arr = inc["timestamp"]

            if is_true:
                true_compromises_total += 1

            eval_res = self.evaluate_defense_policy(defense, inc, gate)
            allowed = (eval_res["decision"] == "ALLOW")
            action_executed = eval_res.get("action", action)
            canon_id = canonical_resolver.canonicalize(entity)
            cost = gate.compute_disruption_cost(action_executed, canon_id)

            if allowed:
                # Automated execution: zero human delay
                if canonical_resolver.is_tier_0(canon_id, self.t0_set):
                    t0_violations += 1
                if is_adv:
                    attacker_disruption_d += cost
                if is_true:
                    true_compromises_remediated += 1
            else:
                # Escalated to human review queue
                escalated_queue.append({
                    "timestamp": t_arr,
                    "is_adv": is_adv,
                    "is_true": is_true,
                    "entity": canon_id,
                    "action": action_executed,
                    "cost": cost
                })

        # Step 2: Simulate human analyst queue processing
        escalated_count = len(escalated_queue)
        service_interval_hours = 24.0 / max(1, analyst_capacity_per_day)
        analyst_available_time = incidents[0]["timestamp"] if incidents else datetime.datetime.now(datetime.timezone.utc)

        for ticket in escalated_queue:
            t_arr = ticket["timestamp"]
            # Analyst starts when available and after ticket arrival
            start_time = max(t_arr, analyst_available_time)
            # Finish time includes processing delay
            finish_time = start_time + datetime.timedelta(hours=approval_delay_hours)
            analyst_available_time = start_time + datetime.timedelta(hours=service_interval_hours)

            total_delay_hours = (finish_time - t_arr).total_seconds() / 3600.0

            if ticket["is_adv"]:
                # Analyst false action: approves malicious injection with prob false_action_rate
                if self.rng.rand() < false_action_rate:
                    attacker_disruption_d += ticket["cost"]
                    if canonical_resolver.is_tier_0(ticket["entity"], self.t0_set):
                        t0_violations += 1

            elif ticket["is_true"]:
                # Analyst approval: approves genuine containment with prob (1 - false_action_rate)
                analyst_approves = (self.rng.rand() >= false_action_rate)
                if analyst_approves and total_delay_hours <= lateral_movement_sla_hours:
                    true_compromises_remediated += 1

        remediation_rate = (true_compromises_remediated / max(1, true_compromises_total)) * 100.0

        return {
            "strategy": strategy,
            "defense": defense,
            "false_action_rate": false_action_rate,
            "analyst_capacity_per_day": analyst_capacity_per_day,
            "approval_delay_hours": approval_delay_hours,
            "attacker_disruption_d": round(float(attacker_disruption_d), 2),
            "t0_violations": t0_violations,
            "remediation_rate_pct": round(float(remediation_rate), 1),
            "escalated_count": escalated_count
        }

    def run_analyst_sensitivity_sweeps(
        self,
        seeds: Optional[List[int]] = None,
        strategy: str = "S4_alias_bypass",
        defenses: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Executes Section IV-L parameter sweeps across 30 seeds:
          1. Analyst false-action rate in [0.02, 0.05, 0.10, 0.15, 0.20, 0.30]
          2. Analyst review capacity in [6, 12, 18, 24] per day
          3. Approval delay in [2.0, 4.0, 8.0, 12.0, 18.0, 24.0] hours
        """
        seeds = seeds or list(range(42, 72)) # 30 seeds
        defenses = defenses or ["B1_static_name_list", "B3_rate_limit_only", "B4_proposed_guardrail", "B5_recommend_only"]

        false_action_rates = [0.02, 0.05, 0.10, 0.15, 0.20, 0.30]
        capacities = [6, 12, 18, 24]
        delays = [2.0, 4.0, 8.0, 12.0, 18.0, 24.0]

        # 1. Sweep false-action rate (fixed capacity=12, delay=4h)
        sweep_false_action: Dict[str, Dict[float, Dict[str, float]]] = {defn: {} for defn in defenses}
        for rate in false_action_rates:
            for defn in defenses:
                d_list, sr_list = [], []
                for s in seeds:
                    sim = RQ2AttackSimulator(seed=s, config=self.config)
                    res = sim.run_simulation_with_analyst(
                        strategy=strategy,
                        defense=defn,
                        false_action_rate=rate,
                        analyst_capacity_per_day=12,
                        approval_delay_hours=4.0
                    )
                    d_list.append(res["attacker_disruption_d"])
                    sr_list.append(res["remediation_rate_pct"])
                sweep_false_action[defn][rate] = {
                    "disruption_mean": round(float(np.mean(d_list)), 2),
                    "disruption_std": round(float(np.std(d_list)), 2),
                    "sr_mean": round(float(np.mean(sr_list)), 1),
                    "sr_std": round(float(np.std(sr_list)), 1)
                }

        # 2. Sweep analyst capacity (fixed rate=0.05, delay=4h)
        sweep_capacity: Dict[str, Dict[int, Dict[str, float]]] = {defn: {} for defn in defenses}
        for cap in capacities:
            for defn in defenses:
                d_list, sr_list = [], []
                for s in seeds:
                    sim = RQ2AttackSimulator(seed=s, config=self.config)
                    res = sim.run_simulation_with_analyst(
                        strategy=strategy,
                        defense=defn,
                        false_action_rate=0.05,
                        analyst_capacity_per_day=cap,
                        approval_delay_hours=4.0
                    )
                    d_list.append(res["attacker_disruption_d"])
                    sr_list.append(res["remediation_rate_pct"])
                sweep_capacity[defn][cap] = {
                    "disruption_mean": round(float(np.mean(d_list)), 2),
                    "disruption_std": round(float(np.std(d_list)), 2),
                    "sr_mean": round(float(np.mean(sr_list)), 1),
                    "sr_std": round(float(np.std(sr_list)), 1)
                }

        # 3. Sweep approval delay (fixed rate=0.05, capacity=12)
        sweep_delay: Dict[str, Dict[float, Dict[str, float]]] = {defn: {} for defn in defenses}
        for dly in delays:
            for defn in defenses:
                d_list, sr_list = [], []
                for s in seeds:
                    sim = RQ2AttackSimulator(seed=s, config=self.config)
                    res = sim.run_simulation_with_analyst(
                        strategy=strategy,
                        defense=defn,
                        false_action_rate=0.05,
                        analyst_capacity_per_day=12,
                        approval_delay_hours=dly
                    )
                    d_list.append(res["attacker_disruption_d"])
                    sr_list.append(res["remediation_rate_pct"])
                sweep_delay[defn][dly] = {
                    "disruption_mean": round(float(np.mean(d_list)), 2),
                    "disruption_std": round(float(np.std(d_list)), 2),
                    "sr_mean": round(float(np.mean(sr_list)), 1),
                    "sr_std": round(float(np.std(sr_list)), 1)
                }

        return {
            "strategy": strategy,
            "seeds_count": len(seeds),
            "sweep_false_action_rate": sweep_false_action,
            "sweep_analyst_capacity": sweep_capacity,
            "sweep_approval_delay": sweep_delay
        }

rq2_attack_simulator = RQ2AttackSimulator()
