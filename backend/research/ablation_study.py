import os
import json
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score, precision_recall_curve, auc
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from backend.research.synthetic_generator import generate_synthetic_dataset

def expected_calibration_error(y_true, y_prob, n_bins=10):
    """Calculate Expected Calibration Error (ECE) for probabilistic predictions."""
    bin_boundaries = np.linspace(0, 1, n_bins + 1)
    ece = 0.0
    for i in range(n_bins):
        bin_lower, bin_upper = bin_boundaries[i], bin_boundaries[i+1]
        in_bin = (y_prob > bin_lower) & (y_prob <= bin_upper)
        prop_in_bin = np.mean(in_bin)
        if prop_in_bin > 0:
            accuracy_in_bin = np.mean(y_true[in_bin])
            avg_confidence_in_bin = np.mean(y_prob[in_bin])
            ece += np.abs(accuracy_in_bin - avg_confidence_in_bin) * prop_in_bin
    return float(ece)

def run_ablation_study() -> dict:
    """Run full 8-stage ablation benchmark comparing Model A through Model H."""
    df = generate_synthetic_dataset(num_samples=1500, seed=42)

    X_all = df.drop(columns=["true_severity"])
    # Binary critical severity target for PR-AUC/ECE calculation
    y_binary = (df["true_severity"] >= 3).astype(int)
    y_multi = df["true_severity"]

    X_train, X_test, y_train_b, y_test_b = train_test_split(X_all, y_binary, test_size=0.3, random_state=42, stratify=y_binary)
    _, _, y_train_m, y_test_m = train_test_split(X_all, y_multi, test_size=0.3, random_state=42, stratify=y_multi)

    feature_stages = {
        "Model A (Sensitivity Only)": ["data_sensitivity"],
        "Model B (+ Exploitability)": ["data_sensitivity", "credential_exposed", "privilege_level"],
        "Model C (+ Asset Criticality)": ["data_sensitivity", "credential_exposed", "privilege_level", "asset_criticality"],
        "Model D (+ Vuln Intel KEV)": ["data_sensitivity", "credential_exposed", "privilege_level", "asset_criticality", "known_vulnerability", "cisa_kev_status"],
        "Model E (+ Behavioral Context)": ["data_sensitivity", "credential_exposed", "privilege_level", "asset_criticality", "known_vulnerability", "cisa_kev_status", "failed_login_spike"],
        "Model F (+ Blast Radius)": ["data_sensitivity", "credential_exposed", "privilege_level", "asset_criticality", "known_vulnerability", "cisa_kev_status", "failed_login_spike", "blast_radius"],
        "Model G (+ Temporal Features)": ["data_sensitivity", "credential_exposed", "privilege_level", "asset_criticality", "known_vulnerability", "cisa_kev_status", "failed_login_spike", "blast_radius", "exposure_age_hours"],
        "Model H (FULL HYBRID MODEL)": list(X_all.columns)
    }

    results = {}

    for model_name, features in feature_stages.items():
        X_tr = X_train[features]
        X_te = X_test[features]

        clf = XGBClassifier(n_estimators=100, max_depth=4, learning_rate=0.1, random_state=42, eval_metric="logloss")
        clf.fit(X_tr, y_train_b)

        y_pred = clf.predict(X_te)
        y_prob = clf.predict_proba(X_te)[:, 1]

        p = precision_score(y_test_b, y_pred, zero_division=0)
        r = recall_score(y_test_b, y_pred, zero_division=0)
        f1 = f1_score(y_test_b, y_pred, zero_division=0)

        prec_curve, rec_curve, _ = precision_recall_curve(y_test_b, y_prob)
        pr_auc = auc(rec_curve, prec_curve)
        ece = expected_calibration_error(y_test_b, y_prob)

        results[model_name] = {
            "features_used": len(features),
            "precision": round(float(p), 4),
            "recall": round(float(r), 4),
            "macro_f1": round(float(f1), 4),
            "pr_auc": round(float(pr_auc), 4),
            "ece": round(float(ece), 4)
        }

    os.makedirs("backend/data", exist_ok=True)
    with open("backend/data/ablation_results.json", "w") as f:
        json.dump(results, f, indent=2)

    return results

if __name__ == "__main__":
    res = run_ablation_study()
    print("Ablation Study Results:")
    print(json.dumps(res, indent=2))
