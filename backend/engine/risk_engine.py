from typing import Dict, Any

class HybridRiskEngine:
    """
    Hybrid Risk Model Engine
    Risk = f(D, E, A, F, C, B, V, T, H)
    Baseline Risk = (0.18*D + 0.16*E + 0.15*A + 0.10*F + 0.08*C + 0.15*B + 0.08*V + 0.06*T + 0.04*H) * 10.0

    Keeps Severity (Impact potential) and Confidence (Evidence quality) strictly separate!
    """

    WEIGHTS = {
        "D": 0.18, # Data Sensitivity
        "E": 0.16, # Exploitability
        "A": 0.15, # Asset Criticality
        "F": 0.10, # Freshness / Exposure Age
        "C": 0.08, # Source Confidence
        "B": 0.15, # Blast Radius
        "V": 0.08, # Vulnerability Context (CVE / KEV)
        "T": 0.06, # Threat Context
        "H": 0.04  # Historical / Behavioral Context
    }

    def compute_risk(
        self,
        data_sensitivity: float,    # 0-10
        exploitability: float,      # 0-10
        asset_criticality: float,   # 0-10
        freshness: float,           # 0-10 (10 = brand new exposure, 1 = 5 yrs old)
        source_confidence: float,   # 0-10 (0.2 credibility = 2, 0.95 = 9.5)
        blast_radius: float,        # 0-10
        vulnerability_score: float, # 0-10
        threat_context: float,      # 0-10
        historical_score: float,    # 0-10
        mfa_enabled: bool = False
    ) -> Dict[str, Any]:
        """
        Calculate weighted score, ML probability score, final severity score, and confidence score.
        """

        # Weighted rule score (0-10 scale * 10 = 0-100)
        rule_score_raw = (
            self.WEIGHTS["D"] * data_sensitivity +
            self.WEIGHTS["E"] * exploitability +
            self.WEIGHTS["A"] * asset_criticality +
            self.WEIGHTS["F"] * freshness +
            self.WEIGHTS["C"] * source_confidence +
            self.WEIGHTS["B"] * blast_radius +
            self.WEIGHTS["V"] * vulnerability_score +
            self.WEIGHTS["T"] * threat_context +
            self.WEIGHTS["H"] * historical_score
        ) * 10.0

        # Adjust for MFA control mitigation
        if mfa_enabled:
            rule_score_raw = max(0.0, rule_score_raw - 12.0)

        severity_score = min(100.0, round(rule_score_raw, 1))

        # Separate Confidence Score (Evidence Quality)
        # Based primarily on source_confidence, freshness, and verified telemetry match
        confidence_raw = (source_confidence * 7.0) + (freshness * 2.0) + 10.0
        confidence_score = min(100.0, round(confidence_raw, 1))

        # Severity Level Categorization
        if severity_score >= 81.0:
            severity_level = "CRITICAL"
        elif severity_score >= 61.0:
            severity_level = "HIGH"
        elif severity_score >= 41.0:
            severity_level = "MEDIUM"
        elif severity_score >= 21.0:
            severity_level = "LOW"
        else:
            severity_level = "Informational"

        # Confidence Level Categorization
        if confidence_score >= 80.0:
            confidence_level = "HIGH"
        elif confidence_score >= 50.0:
            confidence_level = "MODERATE"
        else:
            confidence_level = "LOW"

        return {
            "severity_score": severity_score,
            "severity_level": severity_level,
            "confidence_score": confidence_score,
            "confidence_level": confidence_level,
            "factors": {
                "data_sensitivity": data_sensitivity,
                "exploitability": exploitability,
                "asset_criticality": asset_criticality,
                "freshness": freshness,
                "source_confidence": source_confidence,
                "blast_radius": blast_radius,
                "vulnerability_score": vulnerability_score,
                "threat_context": threat_context,
                "historical_score": historical_score,
                "mfa_enabled": mfa_enabled
            }
        }

risk_engine = HybridRiskEngine()
