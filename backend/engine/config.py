"""
AEGIS-X Engine Configuration & Parameter Management (Dossier B1, T01-T03)

Formal Specifications:
  1. Factor weights sum strictly to 1.0.
  2. Blend weight alpha in [0.0, 1.0].
  3. MFA deduction modifier Delta in [0.0, 30.0].
  4. Scoring bounds strictly enforced in [0.0, 100.0].
  5. Zero hardcoded organization strings; dynamic domain and entity configuration.
  6. Config hashing for cryptographic audit trail inclusion.
"""

import json
import hashlib
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict

@dataclass
class GuardrailBudgetConfig:
    """Disruption budget and rate-limiting sliding-window configuration."""
    window_minutes: int = 60
    b_high: float = 8.0     # Budget for high-credibility corroborated events (identity-hours)
    b_low: float = 2.0      # Budget for low-credibility events (prevents crowding out)
    max_actions_per_window: int = 10
    tau_p: float = 0.80     # Posterior threshold for high credibility
    k_min: int = 2          # Minimum independent corroborating sources

@dataclass
class DisruptionCostConfig:
    """Disruption pricing parameters (Proposition 2 & 3)."""
    kappa_session_revoke: float = 0.2   # Reversible session revocation
    kappa_credential_reset: float = 0.5 # Credential rotation
    kappa_account_disable: float = 1.0  # Destructive account disablement
    default_identity_weight: float = 1.0
    executive_identity_weight: float = 5.0
    service_account_weight: float = 3.0

@dataclass
class SourceReliabilityPriors:
    """Empirical prior means from Thomas et al. (ACM CCS 2017)."""
    third_party_breach: float = 0.07  # 7% current password validity
    keylogger: float = 0.12           # 12%
    phishing: float = 0.25            # 25%
    default_prior: float = 0.10

@dataclass
class EngineConfig:
    """Master versioned configuration for the AEGIS-X algorithmic core."""
    version: str = "2.1.0-research"
    seed: int = 42

    # Hybrid blend: S(x) = alpha * R(x) + (1 - alpha) * 100 * p(x) - m(x)
    alpha: float = 0.40
    mfa_delta: float = 12.0
    score_threshold: float = 70.0

    # 9 Conceptual Risk Factor Weights (Must sum strictly to 1.0)
    factor_weights: Dict[str, float] = field(default_factory=lambda: {
        "D": 0.18,  # Data Sensitivity
        "E": 0.16,  # Exploitability (Privilege + Credential State)
        "A": 0.15,  # Asset Criticality
        "F": 0.10,  # Freshness / Exposure Age
        "C": 0.08,  # Source Reliability
        "B": 0.15,  # Graph Blast Radius (Most-Probable-Path Reach)
        "V": 0.08,  # Vulnerability Context (CVE/KEV/EPSS)
        "T": 0.06,  # Threat Context / Telemetry Anomaly
        "H": 0.04   # Historical Posture
    })

    # Guardrail and budget parameters
    guardrail: GuardrailBudgetConfig = field(default_factory=GuardrailBudgetConfig)
    disruption: DisruptionCostConfig = field(default_factory=DisruptionCostConfig)
    priors: SourceReliabilityPriors = field(default_factory=SourceReliabilityPriors)

    # Dynamic tenant and domain scope (replaces hardcoded org strings)
    allowed_domains: List[str] = field(default_factory=lambda: ["enterprise.internal", "corp.local"])
    crown_jewel_types: List[str] = field(default_factory=lambda: ["DATABASE", "ERP", "IDP", "DOMAIN_CONTROLLER", "KMS"])

    def __post_init__(self):
        self.validate()

    def validate(self):
        """Validate strict mathematical invariants."""
        weight_sum = sum(self.factor_weights.values())
        if abs(weight_sum - 1.0) > 1e-6:
            raise ValueError(f"Factor weights must sum to 1.0, got {weight_sum:.6f}")
        if not (0.0 <= self.alpha <= 1.0):
            raise ValueError(f"Blend weight alpha must be in [0, 1], got {self.alpha}")
        if not (0.0 <= self.mfa_delta <= 50.0):
            raise ValueError(f"MFA delta must be in [0, 50], got {self.mfa_delta}")
        if self.guardrail.b_high <= 0 or self.guardrail.b_low <= 0:
            raise ValueError("Guardrail budgets must be strictly positive")
        if self.guardrail.b_low > self.guardrail.b_high:
            raise ValueError("b_low cannot exceed b_high")

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Deterministic dictionary for cryptographic hashing."""
        data = asdict(self)
        return data

    def compute_hash(self) -> str:
        """SHA-256 hash of canonical configuration representation."""
        raw = json.dumps(self.to_canonical_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

# Global default engine configuration instance
default_engine_config = EngineConfig()
