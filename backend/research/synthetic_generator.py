import os
import random
import pandas as pd
import numpy as np

def generate_synthetic_dataset(num_samples: int = 1200, seed: int = 42) -> pd.DataFrame:
    """
    Generate synthetic breach & telemetry dataset for AEGIS-X machine learning benchmarking.
    """
    np.random.seed(seed)
    random.seed(seed)

    records = []

    # Include explicit Test Cases 1 - 8
    test_cases = [
        # Test Case 1: Ordinary email leak (Sales, MFA=1, Age=43800h, Records=1)
        {"source_confidence": 0.90, "data_sensitivity": 3, "credential_exposed": 0, "api_token_exposed": 0, "privilege_level": 3, "asset_criticality": 4, "records_exposed": 1, "mfa_enabled": 1, "exposure_age_hours": 43800, "known_vulnerability": 0, "cisa_kev_status": 0, "internet_exposed": 0, "blast_radius": 2, "failed_login_spike": 0, "true_severity": 1},
        # Test Case 2: CFO Finance Credential (CFO, MFA=0, Age=2h, Records=50)
        {"source_confidence": 0.95, "data_sensitivity": 9, "credential_exposed": 1, "api_token_exposed": 0, "privilege_level": 9, "asset_criticality": 10, "records_exposed": 50, "mfa_enabled": 0, "exposure_age_hours": 2, "known_vulnerability": 1, "cisa_kev_status": 1, "internet_exposed": 1, "blast_radius": 9, "failed_login_spike": 1, "true_severity": 4},
        # Test Case 3: API Key Exposure (Payment API, Write scope, Age=3h)
        {"source_confidence": 0.98, "data_sensitivity": 10, "credential_exposed": 0, "api_token_exposed": 1, "privilege_level": 9, "asset_criticality": 10, "records_exposed": 500, "mfa_enabled": 0, "exposure_age_hours": 3, "known_vulnerability": 0, "cisa_kev_status": 0, "internet_exposed": 1, "blast_radius": 9, "failed_login_spike": 0, "true_severity": 4},
        # Test Case 4: Old password (Rotated 6 yrs ago, MFA=1)
        {"source_confidence": 0.85, "data_sensitivity": 5, "credential_exposed": 1, "api_token_exposed": 0, "privilege_level": 4, "asset_criticality": 5, "records_exposed": 1, "mfa_enabled": 1, "exposure_age_hours": 52560, "known_vulnerability": 0, "cisa_kev_status": 0, "internet_exposed": 0, "blast_radius": 2, "failed_login_spike": 0, "true_severity": 1},
        # Test Case 5: Network Anomaly (Foreign IP, 6GB download, Unusual Time)
        {"source_confidence": 0.88, "data_sensitivity": 7, "credential_exposed": 0, "api_token_exposed": 0, "privilege_level": 7, "asset_criticality": 8, "records_exposed": 1000, "mfa_enabled": 1, "exposure_age_hours": 1, "known_vulnerability": 0, "cisa_kev_status": 0, "internet_exposed": 1, "blast_radius": 7, "failed_login_spike": 1, "true_severity": 3},
        # Test Case 6: Vulnerable VPN Gateway (CVSS 9.8, CISA KEV)
        {"source_confidence": 0.99, "data_sensitivity": 8, "credential_exposed": 0, "api_token_exposed": 0, "privilege_level": 8, "asset_criticality": 9, "records_exposed": 10000, "mfa_enabled": 0, "exposure_age_hours": 12, "known_vulnerability": 1, "cisa_kev_status": 1, "internet_exposed": 1, "blast_radius": 10, "failed_login_spike": 0, "true_severity": 4},
        # Test Case 7: Supply-Chain Compromise (PayrollCo Vendor, 12,000 records)
        {"source_confidence": 0.92, "data_sensitivity": 8, "credential_exposed": 1, "api_token_exposed": 0, "privilege_level": 8, "asset_criticality": 8, "records_exposed": 12000, "mfa_enabled": 0, "exposure_age_hours": 24, "known_vulnerability": 0, "cisa_kev_status": 0, "internet_exposed": 0, "blast_radius": 8, "failed_login_spike": 0, "true_severity": 3},
        # Test Case 8: False-Positive Low-Credibility Source (Credibility 20%)
        {"source_confidence": 0.20, "data_sensitivity": 9, "credential_exposed": 1, "api_token_exposed": 0, "privilege_level": 7, "asset_criticality": 8, "records_exposed": 50, "mfa_enabled": 1, "exposure_age_hours": 100, "known_vulnerability": 0, "cisa_kev_status": 0, "internet_exposed": 0, "blast_radius": 3, "failed_login_spike": 0, "true_severity": 1}
    ]

    records.extend(test_cases)

    # Generate remaining random background distribution
    for i in range(num_samples - len(test_cases)):
        source_conf = round(random.uniform(0.3, 0.99), 2)
        sens = random.randint(1, 10)
        cred_exp = 1 if random.random() < 0.35 else 0
        token_exp = 1 if random.random() < 0.15 else 0
        priv = random.randint(1, 10)
        crit = random.randint(1, 10)
        recs = int(np.random.exponential(scale=500)) + 1
        mfa = 1 if random.random() < 0.60 else 0
        age_h = int(np.random.exponential(scale=5000))
        vuln = 1 if random.random() < 0.25 else 0
        kev = 1 if (vuln and random.random() < 0.40) else 0
        net_exp = 1 if random.random() < 0.30 else 0
        blast = min(10, max(1, int((crit * 0.4) + (priv * 0.4) + random.randint(-1, 2))))
        failed_login = 1 if random.random() < 0.20 else 0

        # Heuristic ground truth target determination
        raw_score = (sens * 1.8) + (priv * 1.6) + (crit * 1.5) + (blast * 1.5) + (kev * 15.0) + (cred_exp * 10.0) + (token_exp * 12.0) - (mfa * 8.0)
        if age_h > 17520: # > 2 years
            raw_score -= 15.0
        if source_conf < 0.4:
            raw_score -= 20.0

        if raw_score >= 65:
            severity = 4 # Critical
        elif raw_score >= 48:
            severity = 3 # High
        elif raw_score >= 32:
            severity = 2 # Medium
        elif raw_score >= 18:
            severity = 1 # Low
        else:
            severity = 0 # Informational

        records.append({
            "source_confidence": source_conf,
            "data_sensitivity": sens,
            "credential_exposed": cred_exp,
            "api_token_exposed": token_exp,
            "privilege_level": priv,
            "asset_criticality": crit,
            "records_exposed": recs,
            "mfa_enabled": mfa,
            "exposure_age_hours": age_h,
            "known_vulnerability": vuln,
            "cisa_kev_status": kev,
            "internet_exposed": net_exp,
            "blast_radius": blast,
            "failed_login_spike": failed_login,
            "true_severity": severity
        })

    df = pd.DataFrame(records)
    return df

if __name__ == "__main__":
    df = generate_synthetic_dataset()
    os.makedirs("backend/data", exist_ok=True)
    df.to_csv("backend/data/synthetic_breach_dataset.csv", index=False)
    print(f"Generated synthetic dataset with {len(df)} records at backend/data/synthetic_breach_dataset.csv")
