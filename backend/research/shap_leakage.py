"""
AEGIS-X: Verifiable Explanations & SHAP Leakage Under Adversarial Probing
Research Evaluation for RQ4:
"How much do SHAP explanations leak about the model or training data 
(membership inference or extraction attacks), and does rounding, top-k 
filtering, or noise addition reduce leakage without destroying fidelity?"

Methodology:
1. Ground-Truth Data: EnterpriseAttackSimulator (non-circular, latent lateral-movement outcomes).
2. Target Model: XGBoost Classifier trained on D_train with disjoint D_holdout.
3. Attacks Evaluated:
   a. Membership Inference Attack (MIA): Uses ||phi||_1 norm and prediction confidence
      to separate D_train from D_holdout (measured via ROC-AUC).
   b. Explanation-Aware Model Extraction Attack: Queries Q points, fitting an additive
      surrogate against (x_j -> phi_j) vs. a labels-only baseline surrogate (measured via agreement R^2).
4. Defenses Evaluated:
   - Rounding (d in {1, 2, 3, 4} decimal places)
   - Top-k filtering (k in {3, 5, 7} dominant features)
   - Gaussian Noise Injection (sigma in {0.02, 0.05, 0.10, 0.20})
5. Fidelity Loss Metrics:
   - Kendall's Tau rank correlation against raw SHAP rankings
   - L1 Distance / Explanation Reconstruction Error
6. Statistical Rigor:
   - Evaluated over >= 10 independent random seeds.
   - 95% Bootstrap Confidence Intervals reported for all metrics.
"""

import os
import json
import random
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Any, Optional
from scipy.stats import kendalltau
from sklearn.metrics import roc_auc_score
from sklearn.linear_model import Ridge, LinearRegression
import xgboost as xgb
import shap

from backend.research.synthetic_generator import EnterpriseAttackSimulator

# 13 Standard Predictor Columns
FEATURE_COLS = [
    "data_sensitivity",
    "privilege_level",
    "asset_criticality",
    "exposure_age_hours",
    "source_confidence",
    "blast_radius",
    "credential_exposed",
    "api_token_exposed",
    "mfa_enabled",
    "known_vulnerability",
    "cisa_kev_status",
    "epss_score",
    "failed_login_spike",
]

def apply_shap_defense(
    phi: np.ndarray,
    defense_type: str = "none",
    **kwargs
) -> np.ndarray:
    """
    Apply privacy-preserving defenses to raw SHAP explanation vectors.
    
    Parameters:
      phi: Raw SHAP values array of shape (N, P).
      defense_type: "none", "rounding", "top_k", or "noise".
      kwargs:
        - decimals: int (for "rounding")
        - k: int (for "top_k")
        - sigma: float (for "noise")
    """
    phi_defended = phi.copy()
    if defense_type == "none":
        return phi_defended

    elif defense_type == "rounding":
        d = kwargs.get("decimals", 2)
        return np.round(phi_defended, decimals=d)

    elif defense_type == "top_k":
        k = kwargs.get("k", 5)
        n_samples, n_features = phi_defended.shape
        out = np.zeros_like(phi_defended)
        for i in range(n_samples):
            # Rank indices by absolute contribution
            top_indices = np.argsort(np.abs(phi_defended[i]))[-k:]
            out[i, top_indices] = phi_defended[i, top_indices]
        return out

    elif defense_type == "noise":
        sigma = kwargs.get("sigma", 0.05)
        noise = np.random.normal(loc=0.0, scale=sigma, size=phi_defended.shape)
        return phi_defended + noise

    else:
        raise ValueError(f"Unknown defense type: {defense_type}")

def compute_fidelity_metrics(
    raw_phi: np.ndarray,
    defended_phi: np.ndarray
) -> Dict[str, float]:
    """
    Compute explanation fidelity metrics between undefended and defended SHAP vectors.
    - mean_kendall_tau: Stability of feature importance ranking.
    - mean_l1_error: Average absolute perturbation per explanation.
    """
    n_samples = raw_phi.shape[0]
    taus = []
    l1_errors = []

    for i in range(n_samples):
        # Rank features by absolute magnitude
        r_raw = np.abs(raw_phi[i])
        r_def = np.abs(defended_phi[i])
        
        # Kendall's tau on rankings
        tau, _ = kendalltau(r_raw, r_def)
        if np.isnan(tau):
            tau = 0.0
        taus.append(tau)
        l1_errors.append(np.mean(np.abs(raw_phi[i] - defended_phi[i])))

    return {
        "mean_kendall_tau": float(np.mean(taus)),
        "mean_l1_error": float(np.mean(l1_errors))
    }

def run_membership_inference_attack(
    y_train_scores: np.ndarray,
    train_phi: np.ndarray,
    y_holdout_scores: np.ndarray,
    holdout_phi: np.ndarray
) -> float:
    """
    Membership Inference Attack (MIA) against explanation release.
    Adversary scores records using explanation magnitude: ||phi||_1 + prediction confidence.
    Returns ROC-AUC for distinguishing training records from holdout records.
    Baseline random guessing = 0.50.
    """
    train_l1 = np.sum(np.abs(train_phi), axis=1)
    holdout_l1 = np.sum(np.abs(holdout_phi), axis=1)

    # Combined adversary signal: L1 norm of explanation weighted by prediction deviation
    train_signals = train_l1 * (y_train_scores + 0.1)
    holdout_signals = holdout_l1 * (y_holdout_scores + 0.1)

    y_true = np.concatenate([np.ones(len(train_signals)), np.zeros(len(holdout_signals))])
    y_scores = np.concatenate([train_signals, holdout_signals])

    # In case scores are completely flat
    if len(np.unique(y_scores)) <= 1:
        return 0.50

    auc = roc_auc_score(y_true, y_scores)
    # If the score correlates inversely, the adversary inverts the decision boundary
    return float(max(auc, 1.0 - auc))

def run_model_extraction_attack(
    X_query: np.ndarray,
    y_query_preds: np.ndarray,
    query_phi: np.ndarray,
    X_eval: np.ndarray,
    y_eval_target_preds: np.ndarray
) -> Dict[str, float]:
    """
    Compare a labels-only surrogate against an explanation-aware additive surrogate.
    - Labels-only: Ridge regression mapping X -> y_pred.
    - Explanation-aware: Reconstructs decision boundary using additive decomposition
      f_hat(x) = base_val + sum_j f_j(x_j), where f_j is fit directly to phi_j(x_j).
    Returns R^2 fidelity agreement on unseen eval set.
    """
    # 1. Labels-only baseline surrogate
    labels_surrogate = Ridge(alpha=1.0)
    labels_surrogate.fit(X_query, y_query_preds)
    y_pred_labels = labels_surrogate.predict(X_eval)

    # Agreement R^2 with target predictions
    ss_tot = np.sum((y_eval_target_preds - np.mean(y_eval_target_preds)) ** 2) + 1e-9
    ss_res_labels = np.sum((y_eval_target_preds - y_pred_labels) ** 2)
    r2_labels = max(0.0, float(1.0 - (ss_res_labels / ss_tot)))

    # 2. Explanation-aware additive surrogate
    # Fit univariate linear/spline fits f_j(x_j) -> phi_j
    p = X_query.shape[1]
    feature_models = []
    for j in range(p):
        model_j = LinearRegression()
        model_j.fit(X_query[:, j:j+1], query_phi[:, j])
        feature_models.append(model_j)

    # Reconstruct prediction on evaluation set
    # target ~= base_val + sum(phi_j)
    base_val = np.mean(y_query_preds) - np.mean(np.sum(query_phi, axis=1))
    phi_eval_pred = np.zeros((X_eval.shape[0], p))
    for j in range(p):
        phi_eval_pred[:, j] = feature_models[j].predict(X_eval[:, j:j+1])

    y_pred_expl = base_val + np.sum(phi_eval_pred, axis=1)
    ss_res_expl = np.sum((y_eval_target_preds - y_pred_expl) ** 2)
    r2_expl = max(0.0, float(1.0 - (ss_res_expl / ss_tot)))

    return {
        "r2_labels_only": r2_labels,
        "r2_explanation_aware": r2_expl
    }

def bootstrap_ci(values: List[float], n_bootstraps: int = 1000) -> Tuple[float, float, float]:
    """Return (mean, ci_lower, ci_upper) for a given metric across seeds."""
    arr = np.array(values)
    mean_val = float(np.mean(arr))
    if len(arr) <= 1:
        return mean_val, mean_val, mean_val

    boot_means = []
    for _ in range(n_bootstraps):
        sample = np.random.choice(arr, size=len(arr), replace=True)
        boot_means.append(np.mean(sample))

    ci_lower = float(np.percentile(boot_means, 2.5))
    ci_upper = float(np.percentile(boot_means, 97.5))
    return mean_val, ci_lower, ci_upper

def run_shap_leakage_experiment(
    num_seeds: int = 10,
    n_samples_per_split: int = 800,
    query_budget: int = 150
) -> Dict[str, Any]:
    """
    Executes the full SHAP privacy vs. explanation fidelity benchmark.
    """
    defenses = [
        {"name": "Undefended (Raw)", "type": "none", "params": {}},
        {"name": "Rounding d=4", "type": "rounding", "params": {"decimals": 4}},
        {"name": "Rounding d=3", "type": "rounding", "params": {"decimals": 3}},
        {"name": "Rounding d=2", "type": "rounding", "params": {"decimals": 2}},
        {"name": "Rounding d=1", "type": "rounding", "params": {"decimals": 1}},
        {"name": "Top-k (k=7)", "type": "top_k", "params": {"k": 7}},
        {"name": "Top-k (k=5)", "type": "top_k", "params": {"k": 5}},
        {"name": "Top-k (k=3)", "type": "top_k", "params": {"k": 3}},
        {"name": "Noise (sigma=0.02)", "type": "noise", "params": {"sigma": 0.02}},
        {"name": "Noise (sigma=0.05)", "type": "noise", "params": {"sigma": 0.05}},
        {"name": "Noise (sigma=0.10)", "type": "noise", "params": {"sigma": 0.10}},
        {"name": "Noise (sigma=0.20)", "type": "noise", "params": {"sigma": 0.20}},
    ]

    results_by_defense = {d["name"]: {
        "mia_auc": [],
        "extraction_r2_expl": [],
        "extraction_r2_labels": [],
        "kendall_tau": [],
        "l1_error": []
    } for d in defenses}

    print(f"=== Starting SHAP Leakage Benchmark ({num_seeds} Seeds) ===")

    for seed_idx, seed in enumerate(range(100, 100 + num_seeds)):
        # 1. Generate Latent Enterprise Ground-Truth Data
        sim = EnterpriseAttackSimulator(seed=seed)
        df_train = sim.generate_dataset(num_samples=n_samples_per_split)
        df_holdout = sim.generate_dataset(num_samples=n_samples_per_split)
        df_eval = sim.generate_dataset(num_samples=400)

        X_train = df_train[FEATURE_COLS].values
        y_train = (df_train["true_severity"] >= 3).astype(int).values

        X_holdout = df_holdout[FEATURE_COLS].values
        y_holdout = (df_holdout["true_severity"] >= 3).astype(int).values

        X_eval = df_eval[FEATURE_COLS].values

        # 2. Train Target XGBoost Model
        target_model = xgb.XGBClassifier(
            n_estimators=60,
            max_depth=4,
            learning_rate=0.08,
            random_state=seed,
            eval_metric="logloss"
        )
        target_model.fit(X_train, y_train)

        # 3. Model Predictions and Raw TreeSHAP
        train_prob = target_model.predict_proba(X_train)[:, 1]
        holdout_prob = target_model.predict_proba(X_holdout)[:, 1]
        eval_preds = target_model.predict_proba(X_eval)[:, 1]

        explainer = shap.TreeExplainer(target_model)
        raw_train_phi = explainer.shap_values(X_train)
        raw_holdout_phi = explainer.shap_values(X_holdout)

        # Extraction query pool (simulated adversary query points from holdout)
        X_query = X_holdout[:query_budget]
        y_query_prob = holdout_prob[:query_budget]
        raw_query_phi = raw_holdout_phi[:query_budget]

        # 4. Evaluate each defense
        for d in defenses:
            name = d["name"]
            d_type = d["type"]
            params = d["params"]

            # Apply defense
            def_train_phi = apply_shap_defense(raw_train_phi, d_type, **params)
            def_holdout_phi = apply_shap_defense(raw_holdout_phi, d_type, **params)
            def_query_phi = apply_shap_defense(raw_query_phi, d_type, **params)

            # Attack A: Membership Inference
            mia_auc = run_membership_inference_attack(
                train_prob, def_train_phi,
                holdout_prob, def_holdout_phi
            )

            # Attack B: Model Extraction
            ext_metrics = run_model_extraction_attack(
                X_query, y_query_prob, def_query_phi,
                X_eval, eval_preds
            )

            # Fidelity Metrics
            fid = compute_fidelity_metrics(raw_holdout_phi, def_holdout_phi)

            results_by_defense[name]["mia_auc"].append(mia_auc)
            results_by_defense[name]["extraction_r2_expl"].append(ext_metrics["r2_explanation_aware"])
            results_by_defense[name]["extraction_r2_labels"].append(ext_metrics["r2_labels_only"])
            results_by_defense[name]["kendall_tau"].append(fid["mean_kendall_tau"])
            results_by_defense[name]["l1_error"].append(fid["mean_l1_error"])

        if (seed_idx + 1) % max(1, num_seeds // 2) == 0 or (seed_idx + 1) == num_seeds:
            print(f" Completed {seed_idx + 1}/{num_seeds} seeds...")

    # Aggregate results with Bootstrap 95% CIs
    aggregated = []
    for d in defenses:
        name = d["name"]
        res = results_by_defense[name]

        mia_mean, mia_low, mia_up = bootstrap_ci(res["mia_auc"])
        r2_expl_mean, r2_expl_low, r2_expl_up = bootstrap_ci(res["extraction_r2_expl"])
        r2_lab_mean, _, _ = bootstrap_ci(res["extraction_r2_labels"])
        tau_mean, tau_low, tau_up = bootstrap_ci(res["kendall_tau"])
        l1_mean, l1_low, l1_up = bootstrap_ci(res["l1_error"])

        record = {
            "defense": name,
            "type": d["type"],
            "mia_auc_mean": round(mia_mean, 4),
            "mia_auc_ci": [round(mia_low, 4), round(mia_up, 4)],
            "extraction_r2_expl_mean": round(r2_expl_mean, 4),
            "extraction_r2_expl_ci": [round(r2_expl_low, 4), round(r2_expl_up, 4)],
            "extraction_r2_labels_mean": round(r2_lab_mean, 4),
            "kendall_tau_mean": round(tau_mean, 4),
            "kendall_tau_ci": [round(tau_low, 4), round(tau_up, 4)],
            "l1_fidelity_error": round(l1_mean, 4),
            "l1_fidelity_error_ci": [round(l1_low, 4), round(l1_up, 4)]
        }
        aggregated.append(record)

    output = {
        "experiment": "SHAP Explanation Leakage vs. Privacy Defenses",
        "research_question": "RQ4: Privacy-vs-Fidelity Trade-off Curve",
        "num_seeds": num_seeds,
        "query_budget": query_budget,
        "data_samples_per_split": n_samples_per_split,
        "results": aggregated
    }
    return output

def save_and_print_summary(output: Dict[str, Any], filepath: str = "backend/research/shap_leakage_results.json"):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print("\n" + "=" * 90)
    print(f"SUMMARY: SHAP LEAKAGE & FIDELITY TRADE-OFF CURVE (RQ4)")
    print("=" * 90)
    headers = f"{'Defense Configuration':<24} | {'MIA AUC':<11} | {'Extr. R^2':<11} | {'Kendall Tau':<14} | {'L1 Error':<10}"
    print(headers)
    print("-" * 90)
    for r in output["results"]:
        mia_str = f"{r['mia_auc_mean']:.3f} [{r['mia_auc_ci'][0]:.2f},{r['mia_auc_ci'][1]:.2f}]"
        ext_str = f"{r['extraction_r2_expl_mean']:.3f}"
        tau_str = f"{r['kendall_tau_mean']:.3f} [{r['kendall_tau_ci'][0]:.2f},{r['kendall_tau_ci'][1]:.2f}]"
        l1_str = f"{r['l1_fidelity_error']:.4f}"
        print(f"{r['defense']:<24} | {mia_str:<11} | {ext_str:<11} | {tau_str:<14} | {l1_str:<10}")
    print("=" * 90)
    print(f"[+] Saved structured experiment results to: {filepath}\n")

if __name__ == "__main__":
    out = run_shap_leakage_experiment(num_seeds=10, n_samples_per_split=500, query_budget=100)
    save_and_print_summary(out)
