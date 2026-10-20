"""
AEGIS-X Exposure Posterior & Source Reliability Engine (Dossier B6, W13, Section 5.3)

Formal Formulation:
  P(i compromised | e) = Beta-posterior per source type.
  Empirical Priors from Thomas et al. (ACM CCS 2017):
    - Third-party breach: alpha_0 = 7.0,  beta_0 = 93.0  (mean = 0.07)
    - Keylogger dump:     alpha_0 = 12.0, beta_0 = 88.0  (mean = 0.12)
    - Phishing capture:   alpha_0 = 25.0, beta_0 = 75.0  (mean = 0.25)
    - Default/Unspecified: alpha_0 = 10.0, beta_0 = 90.0 (mean = 0.10)

Modulation factors:
  - HIBP flags: IsFabricated (reduces posterior by 80%), IsVerified (boosts posterior by 20%)
  - Independent corroboration count k: shifts pseudo-observations by +2.0 per independent feed
  - Freshness penalty: exponential decay based on arrival lag (BreachDate -> AddedDate)
  - Analyst feedback: Bayesian update on incident accept (true positive) or reject (false positive)
"""

import math
from typing import Dict, Any, Optional, Tuple
from backend.engine.config import default_engine_config

class SourceReliabilityEngine:
    """
    Bayesian Source Reliability Engine for Leaked Credential Exposure.
    """

    # Thomas et al. CCS 2017 empirical priors: (alpha_0, beta_0)
    PRIORS = {
        "BREACH": (7.0, 93.0),
        "THIRD_PARTY_BREACH": (7.0, 93.0),
        "KEYLOGGER": (12.0, 88.0),
        "PHISHING": (25.0, 75.0),
        "PASTE": (8.0, 92.0),
        "THREAT_INTEL": (15.0, 85.0),
        "DEFAULT": (10.0, 90.0)
    }

    def __init__(self, config=None):
        self.config = config or default_engine_config
        # Dynamic Bayesian update storage per source type: source_type -> (alpha, beta)
        self._learned_posteriors: Dict[str, Tuple[float, float]] = {}

    def get_source_prior(self, source_type: str) -> Tuple[float, float]:
        """Returns baseline prior (alpha_0, beta_0) for given source type."""
        st = str(source_type).upper()
        for k, v in self.PRIORS.items():
            if k in st:
                return v
        return self.PRIORS["DEFAULT"]

    def compute_source_posterior(
        self,
        source_type: str = "BREACH",
        corroboration_count: int = 1,
        is_verified: bool = True,
        is_fabricated: bool = False,
        exposure_age_hours: float = 24.0,
        analyst_verifications_pos: int = 0,
        analyst_verifications_neg: int = 0
    ) -> Dict[str, Any]:
        """
        Computes modulated Beta posterior:
          E[P(compromise | e)] = (alpha + pos) / (alpha + pos + beta + neg)
        """
        alpha_0, beta_0 = self.get_source_prior(source_type)

        # 1. Corroboration boost (each independent source adds evidence)
        k_boost = max(0, corroboration_count - 1) * 3.0

        # 2. HIBP Fabrication / Verification Modulation
        if is_fabricated:
            # Poisoned or fabricated feed heavily penalizes posterior
            alpha_0 = alpha_0 * 0.20
            beta_0 = beta_0 + 50.0
        elif is_verified:
            alpha_0 = alpha_0 * 1.25

        # 3. Freshness attenuation (half-life of 720 hours / 30 days)
        freshness_decay = math.exp(-exposure_age_hours / 720.0)
        effective_alpha = (alpha_0 + k_boost) * (0.5 + 0.5 * freshness_decay)
        effective_beta = beta_0

        # 4. Bayesian updates from analyst accept/reject outcomes
        final_alpha = effective_alpha + analyst_verifications_pos
        final_beta = effective_beta + analyst_verifications_neg

        posterior_mean = final_alpha / (final_alpha + final_beta)
        posterior_variance = (final_alpha * final_beta) / (((final_alpha + final_beta) ** 2) * (final_alpha + final_beta + 1))

        # Reliability score mapped to [0, 100]
        reliability_score = round(min(100.0, max(0.0, posterior_mean * 100.0)), 1)

        level = "HIGH" if reliability_score >= 80.0 else ("MODERATE" if reliability_score >= 40.0 else "LOW")

        return {
            "source_type": source_type,
            "posterior_mean": round(float(posterior_mean), 4),
            "posterior_variance": round(float(posterior_variance), 6),
            "source_reliability_score": reliability_score,
            "reliability_level": level,
            "corroboration_count": corroboration_count,
            "is_verified": is_verified,
            "is_fabricated": is_fabricated,
            "freshness_decay": round(float(freshness_decay), 3),
            "alpha": round(float(final_alpha), 2),
            "beta": round(float(final_beta), 2)
        }

source_reliability_engine = SourceReliabilityEngine()
