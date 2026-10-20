"""
AEGIS-X Credibility-Stratified Budgeted Guardrails & Policy Gate (Dossier B4, U8, Algorithm 1)

Formal Specifications:
  1. Graph-derived Protected Set T0 (members of IdP admin groups, nodes with paths to/from DC/IdP, crown-jewel nodes).
  2. Canonical Identity Resolution Canon(i) with alias/case/whitespace/plus-addressing closure.
  3. Action Disruption Pricing:
       C(a, i) = kappa_a * (u_i + sum_{n in Dep(i)} w_n)
     where kappa_a in {0.2 (session revoke), 0.5 (credential reset), 1.0 (account disable)}.
  4. Credibility-Stratified Sliding-Window Admission Control (Algorithm 1):
       Two independent budgets B_high and B_low over window W.
       Guarantees attacker disruption <= B_low + q * B_high while reserving >= (1 - q) * B_high
       for genuine high-credibility incidents (Proposition 2 & 3).
"""

import threading
import datetime
from typing import Dict, Any, List, Optional, Set, Tuple
from backend.engine.config import default_engine_config, EngineConfig
from backend.engine.canonical_resolver import canonical_resolver
from backend.engine.graph_engine import graph_engine

class CredibilityStratifiedGuardrailGate:
    """
    Research-Grade Safe Automated Response & Policy Gate.
    """

    DECISION_ALLOW = "ALLOW_AUTOMATION"
    DECISION_APPROVAL = "REQUIRE_APPROVAL"
    DECISION_RECOMMEND = "RECOMMEND_ONLY"
    DECISION_DENY = "DENY_AUTOMATION"

    def __init__(self, config: Optional[EngineConfig] = None):
        self.config = config or default_engine_config
        self._lock = threading.Lock()
        # Sliding window history: tier -> list of (timestamp_utc, cost, action_type, identity_id, tenant_id)
        self._window_history: Dict[str, List[Tuple[datetime.datetime, float, str, str, str]]] = {
            "HIGH": [],
            "LOW": []
        }
        # Backward-compatible simple action history: tenant_id -> list of (timestamp_utc, action_type)
        self._action_history: Dict[str, List[Tuple[datetime.datetime, str]]] = {}
        self.MAX_ACTIONS_PER_WINDOW = self.config.guardrail.max_actions_per_window
        self.RATE_WINDOW_MINUTES = self.config.guardrail.window_minutes

    def normalize_identifier(self, identifier: str) -> str:
        """Normalizes email, UPN, or account identifier via canonical resolver."""
        return canonical_resolver.canonicalize(identifier)

    def is_action_effective(self, action_type: str, min_effectiveness: float = 0.70) -> bool:
        """Checks if action meets minimum effectiveness threshold rho(a) >= rho_min."""
        effectiveness_map = {
            "REVOKE_ALL_SESSIONS": 0.85,
            "REVOKE_ACTIVE_SESSIONS": 0.85,
            "RESET_CREDENTIAL": 0.95,
            "ROTATE_KEY": 0.95,
            "ISOLATE_HOST": 0.99,
            "DISABLE_ACCOUNT": 1.00
        }
        return effectiveness_map.get(action_type, 0.50) >= min_effectiveness

    def get_action_severity_kappa(self, action_type: str) -> float:
        """Returns action severity factor kappa_a (reversible-first policy)."""
        if "SESSION" in action_type:
            return self.config.disruption.kappa_session_revoke    # 0.2 (least disruptive)
        elif "RESET" in action_type or "ROTATE" in action_type:
            return self.config.disruption.kappa_credential_reset # 0.5
        elif "DISABLE" in action_type or "ISOLATE" in action_type or "CONTAIN" in action_type:
            return self.config.disruption.kappa_account_disable  # 1.0 (most disruptive)
        return 0.5

    def compute_disruption_cost(
        self,
        action_type: str,
        identity_id: str,
        target_attributes: Optional[Dict[str, Any]] = None
    ) -> float:
        """
        Computes formal disruption cost (Equation 6):
          C(a, i) = kappa_a * (u_i + sum_{n in Dep(i)} w_n)
        """
        target_attributes = target_attributes or {}
        kappa = self.get_action_severity_kappa(action_type)

        # 1. Identity's own business weight u_i
        is_exec = (
            target_attributes.get("is_executive", False) or
            "cfo" in identity_id.lower() or
            "ceo" in identity_id.lower() or
            target_attributes.get("privilege_level", 0) >= 9
        )
        is_service_acc = (
            target_attributes.get("is_service_account", False) or
            "svc_" in identity_id.lower() or
            "service" in str(target_attributes.get("identity_type", "")).lower()
        )

        if is_exec:
            u_i = self.config.disruption.executive_identity_weight
        elif is_service_acc:
            u_i = self.config.disruption.service_account_weight
        else:
            u_i = self.config.disruption.default_identity_weight

        # 2. Reverse dependency asset criticality sum_{n in Dep(i)} w_n
        canonical_id = canonical_resolver.canonicalize(identity_id)
        dep_assets = graph_engine.compute_reverse_dependencies(canonical_id)

        dep_weight_sum = 0.0
        for asset_id in dep_assets:
            ast_data = graph_engine.G.nodes.get(asset_id, {})
            crit = float(ast_data.get("criticality", 5.0))
            dep_weight_sum += crit

        total_cost = kappa * (u_i + dep_weight_sum)
        return float(round(total_cost, 3))

    def is_high_credibility(
        self,
        independent_sources: int = 1,
        is_verified: bool = False,
        source_posterior: float = 0.50
    ) -> bool:
        """
        Determines event credibility tier (Dossier Section 5.6):
          HIGH credibility if k >= k_min, OR is_verified == True, OR posterior >= tau_p.
        """
        if independent_sources >= self.config.guardrail.k_min:
            return True
        if is_verified:
            return True
        if source_posterior >= self.config.guardrail.tau_p:
            return True
        return False

    def admit_action(
        self,
        event: Dict[str, Any],
        candidate_action: str,
        timestamp: Optional[datetime.datetime] = None,
        tenant_id: str = "default",
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Algorithm 1: Admit(e, a, t)
          1. i* <- Canon(i); if i* in T0 then return ESCALATE
          2. a <- least-disruptive action with rho(a) >= rho_min
          3. c <- C(a, i*); tier <- HIGH if credible(e) else LOW
          4. H <- sum cost of actions admitted in tier within (t - W, t]
          5. if H + c <= B_tier then record (atomically) and return ADMIT
          6. else return ESCALATE
        """
        now = timestamp or datetime.datetime.now(datetime.timezone.utc)
        identity_raw = event.get("exposed_entity") or event.get("identity_id") or ""
        canonical_id = canonical_resolver.canonicalize(identity_raw)

        # Step 1: Check Protected Set T0 (Derived from graph and role closures)
        t0_set = graph_engine.derive_protected_set_t0()
        if canonical_resolver.is_tier_0(canonical_id, t0_set):
            return {
                "decision": self.DECISION_APPROVAL,
                "reason_code": "PROTECTED_SET_T0_ESCALATION",
                "explanation": f"Identity '{canonical_id}' belongs to Protected Set T0. Autonomous actions strictly prohibited.",
                "allow_execution": False,
                "requires_approval": True,
                "tier": "PROTECTED_T0",
                "cost": 0.0
            }

        # Step 2: Ensure action meets minimum effectiveness
        if not self.is_action_effective(candidate_action):
            candidate_action = "REVOKE_ALL_SESSIONS"

        # Step 3: Compute action disruption cost and credibility tier
        cost = self.compute_disruption_cost(candidate_action, canonical_id, event.get("target_attributes"))
        is_credible = self.is_high_credibility(
            independent_sources=event.get("independent_source_count", 1),
            is_verified=event.get("is_verified", False),
            source_posterior=event.get("source_posterior", event.get("source_confidence", 0.50))
        )
        tier = "HIGH" if is_credible else "LOW"
        budget = self.config.guardrail.b_high if tier == "HIGH" else self.config.guardrail.b_low

        # Step 4 & 5: Sliding-window budget admission under thread lock
        with self._lock:
            cutoff = now - datetime.timedelta(minutes=self.config.guardrail.window_minutes)
            # Prune expired window entries
            active_entries = [e for e in self._window_history[tier] if e[0] > cutoff]
            self._window_history[tier] = active_entries

            current_window_cost = sum(e[1] for e in active_entries)

            if current_window_cost + cost <= budget:
                if not dry_run:
                    self._window_history[tier].append((now, cost, candidate_action, canonical_id, tenant_id))
                    # Also record in tenant history
                    if tenant_id not in self._action_history:
                        self._action_history[tenant_id] = []
                    self._action_history[tenant_id].append((now, candidate_action))

                return {
                    "decision": self.DECISION_ALLOW,
                    "reason_code": "BUDGET_PERMITTED_ADMITTED",
                    "explanation": f"Action admitted in {tier} tier budget ({current_window_cost + cost:.2f}/{budget:.2f} cost used).",
                    "allow_execution": True,
                    "requires_approval": False,
                    "tier": tier,
                    "cost": cost,
                    "window_utilization": round((current_window_cost + cost) / budget, 3)
                }
            else:
                return {
                    "decision": self.DECISION_APPROVAL,
                    "reason_code": f"{tier}_BUDGET_EXCEEDED",
                    "explanation": f"Sliding-window disruption budget exceeded for {tier} credibility tier ({current_window_cost + cost:.2f} > {budget:.2f}). Escalate to analyst.",
                    "allow_execution": False,
                    "requires_approval": True,
                    "tier": tier,
                    "cost": cost,
                    "window_utilization": round(current_window_cost / budget, 3)
                }

    def _check_rate_limit(self, tenant_id: str) -> bool:
        """Verify action rate limit within rolling time window."""
        now = datetime.datetime.now(datetime.timezone.utc)
        cutoff = now - datetime.timedelta(minutes=self.RATE_WINDOW_MINUTES)
        history = self._action_history.get(tenant_id, [])
        active_history = [entry for entry in history if entry[0] > cutoff]
        self._action_history[tenant_id] = active_history
        return len(active_history) < self.MAX_ACTIONS_PER_WINDOW

    def record_executed_action(self, tenant_id: str, action_type: str):
        """Record executed action into rate-limiting window."""
        now = datetime.datetime.now(datetime.timezone.utc)
        if tenant_id not in self._action_history:
            self._action_history[tenant_id] = []
        self._action_history[tenant_id].append((now, action_type))

    def evaluate_response_policy(
        self,
        action_type: str,
        target_attributes: Dict[str, Any],
        context: Dict[str, Any],
        tenant_id: str = "default"
    ) -> Dict[str, Any]:
        """
        Master policy gate unifying the formal budget admission with enterprise safety invariants.
        """
        # 1. Tenant boundary validation
        if not tenant_id or context.get("tenant_mismatch", False):
            return {
                "decision": self.DECISION_DENY,
                "reason_code": "TENANT_SECURITY_VIOLATION",
                "explanation": "Cross-tenant action boundary violation detected. Automated remediation denied.",
                "requires_approval": False,
                "allow_execution": False
            }

        # 2. Hard Safety Invariant 1: Administrative Recovery Quorum (Never Revoke Last Admin)
        is_admin_role = target_attributes.get("is_admin", False) or target_attributes.get("privilege_level", 0) >= 9
        total_active_admins = context.get("active_admin_count", 2)
        if "REVOKE" in action_type or "RESET" in action_type or "DISABLE" in action_type:
            if is_admin_role and total_active_admins <= 1:
                return {
                    "decision": self.DECISION_DENY,
                    "reason_code": "INVARIANT_VIOLATION_LAST_ADMIN",
                    "explanation": "Safety Invariant Violated: Target is the last recovery-capable administrator.",
                    "requires_approval": True,
                    "allow_execution": False
                }

        # 3. Hard Safety Invariant 2: Preserve Core IdP & Domain Controller Reachability
        target_type = str(target_attributes.get("asset_type", "")).upper()
        is_idp_or_dc = (
            target_attributes.get("is_identity_provider", False) or
            target_attributes.get("is_domain_controller", False) or
            target_type in ["IDP", "DOMAIN_CONTROLLER", "KEY_MANAGEMENT"]
        )
        if "ISOLATE" in action_type or "CONTAIN" in action_type or "BLOCK" in action_type:
            if is_idp_or_dc:
                return {
                    "decision": self.DECISION_DENY,
                    "reason_code": "INVARIANT_VIOLATION_CORE_INFRASTRUCTURE",
                    "explanation": "Safety Invariant Violated: Target is core authentication infrastructure.",
                    "requires_approval": True,
                    "allow_execution": False
                }

        # 4. Check Protected Set T0 (Dynamic Graph & Attribute Derivation)
        target_entity = context.get("exposed_entity") or target_attributes.get("name") or target_attributes.get("email") or ""
        canonical_id = canonical_resolver.canonicalize(target_entity)
        t0_set = graph_engine.derive_protected_set_t0()

        if canonical_resolver.is_tier_0(canonical_id, t0_set) or target_attributes.get("is_crown_jewel", False) or target_attributes.get("business_criticality", 0) >= 10:
            if action_type in ["ISOLATE_HOST", "DISABLE_ACCOUNT", "REVOKE_ALL_SESSIONS", "RESET_CREDENTIAL"]:
                return {
                    "decision": self.DECISION_APPROVAL,
                    "reason_code": "PROTECTED_CROWN_JEWEL_APPROVAL_REQUIRED",
                    "explanation": f"Target entity '{canonical_id}' is part of Protected Set T0. Analyst approval required.",
                    "requires_approval": True,
                    "allow_execution": False
                }

        # 5. Anti-Poisoning Corroboration Gate
        independent_sources = context.get("independent_source_count", 1)
        source_confidence = context.get("source_confidence", 0.80)
        is_verified = context.get("is_verified", False)
        is_destructive = action_type in ["ISOLATE_HOST", "RESET_CREDENTIAL", "DISABLE_ACCOUNT"]

        if is_destructive and not self.is_high_credibility(independent_sources, is_verified, source_confidence):
            return {
                "decision": self.DECISION_APPROVAL,
                "reason_code": "UNCONFIRMED_EVIDENCE_CORROBORATION_REQUIRED",
                "explanation": "Adversarial Anti-Poisoning Gate: Single uncorroborated feed report cannot trigger automated disruptive remediation. Requires manual confirmation.",
                "requires_approval": True,
                "allow_execution": False
            }

        # 6. Rate Limit & Disruption Budget
        if not self._check_rate_limit(tenant_id):
            return {
                "decision": self.DECISION_APPROVAL,
                "reason_code": "RATE_LIMIT_BLAST_BUDGET_EXCEEDED",
                "explanation": f"Action rate limit exceeded ({self.MAX_ACTIONS_PER_WINDOW} actions within {self.RATE_WINDOW_MINUTES} mins). Human gate required.",
                "requires_approval": True,
                "allow_execution": False
            }

        # 7. Disruption Pricing Admission Check
        event_dict = {
            "exposed_entity": target_entity,
            "independent_source_count": independent_sources,
            "is_verified": is_verified,
            "source_posterior": source_confidence,
            "target_attributes": target_attributes
        }
        admission_result = self.admit_action(event_dict, action_type, tenant_id=tenant_id, dry_run=False)
        if not admission_result["allow_execution"]:
            return admission_result

        # 8. Permitted
        return {
            "decision": self.DECISION_ALLOW,
            "reason_code": "AUTOMATION_POLICY_PERMITTED",
            "explanation": "All operational safety invariants, corroboration criteria, and budgets satisfied. Automated execution authorized.",
            "requires_approval": False,
            "allow_execution": True,
            "rollback_supported": context.get("rollback_supported", True),
            "collateral_impact_score": admission_result.get("cost", 0.0),
            "disruption_cost": admission_result.get("cost", 0.0)
        }

soar_policy_gate = CredibilityStratifiedGuardrailGate()
soar_guardrails = soar_policy_gate
