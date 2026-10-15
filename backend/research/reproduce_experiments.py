"""
AEGIS-X One-Command Research Experiment Replication Runner
Ref: K1 / L1-L7 Checklist Specification

Executes and reproduces all experimental benchmarks reported in the manuscript:
  - Table I: Multi-Seed Model Class Comparison (10 seeds, 5 baselines)
  - Table II: Generator-Shift Adversarial Generalization (v1 -> v2)
  - Table III: Label-Noise Degradation Robustness
  - Table IV: Guardrail Pareto Defense under Poisoned Telemetry Attacks
"""

import sys
import json
from backend.research.ablation_study import run_ablation_study

def main():
    print("=" * 80)
    print("       AEGIS-X: RESEARCH EXPERIMENT REPLICATION SUITE (FIXED SEEDS)     ")
    print("=" * 80)
    
    results = run_ablation_study()

    # Print Table I: Model Class Benchmark
    print("\n" + "=" * 80)
    print("TABLE I: Multi-Seed Model Comparison (10 Seeds, Mean +- Std)")
    print("=" * 80)
    header = f"{'Model Architecture':<25} | {'Precision':<15} | {'Recall':<15} | {'Macro-F1':<15} | {'PR-AUC':<15} | {'Brier':<8} | {'ECE':<8}"
    print(header)
    print("-" * 115)
    
    models = results["model_class_comparison_10_seeds"]
    for m_name, m in models.items():
        p_str = f"{m['precision_mean']:.3f} +- {m['precision_std']:.3f}"
        r_str = f"{m['recall_mean']:.3f} +- {m['recall_std']:.3f}"
        f1_str = f"{m['f1_mean']:.3f} +- {m['f1_std']:.3f}"
        pr_str = f"{m['prauc_mean']:.3f} +- {m['prauc_std']:.3f}"
        row = f"{m_name:<25} | {p_str:<15} | {r_str:<15} | {f1_str:<15} | {pr_str:<15} | {m['brier_score']:<8.4f} | {m['ece_score']:<8.4f}"
        print(row)

    # Print Table II: Generator Shift Test
    print("\n" + "=" * 80)
    print("TABLE II: Generator-Shift Adversarial Robustness Test (v1 -> v2 Evasive)")
    print("=" * 80)
    shift = results["generator_shift_adversary_test"]
    print(f"  • In-Distribution (v1 -> v1): Macro-F1 = {shift['in_distribution_v1']['macro_f1']:.4f}, PR-AUC = {shift['in_distribution_v1']['pr_auc']:.4f}")
    print(f"  • Adversarial Shift (v1 -> v2): Macro-F1 = {shift['generator_shift_v2']['macro_f1']:.4f}, PR-AUC = {shift['generator_shift_v2']['pr_auc']:.4f}")
    print(f"  • Degradation Delta: {shift['f1_drop_percentage_points']} percentage points")
    print(f"  • Assessment: {shift['shift_conclusion']}")

    # Print Table III: Label Noise Degradation Curve
    print("\n" + "=" * 80)
    print("TABLE III: Label Noise Robustness Curve (Macro-F1 vs Noise Rate)")
    print("=" * 80)
    noise = results["label_noise_robustness_curve"]
    for k, v in noise.items():
        print(f"  • {k.replace('_', ' ').upper()}: Macro-F1 = {v:.4f}")

    # Print Table IV: Guardrail Pareto Analysis
    print("\n" + "=" * 80)
    print("TABLE IV: Guardrail Defense Evaluation under Poisoned Feed Injection")
    print("=" * 80)
    hdr_g = f"{'Policy Configuration':<28} | {'Harmful Actions':<18} | {'Harmful Action %':<18} | {'Containment %':<16} | {'Manual Reviews':<15}"
    print(hdr_g)
    print("-" * 105)
    pareto = results["guardrail_pareto_defense_evaluation"]
    for pol_name, p in pareto.items():
        row_g = f"{pol_name:<28} | {p['harmful_automatic_actions']:<18} | {p['harmful_action_rate_pct']:<18.1f} | {p['containment_success_pct']:<16.1f} | {p['manual_review_count']:<15}"
        print(row_g)

    print("\n[+] Full experimental replication complete. Artifacts saved to backend/data/research_benchmark_results.json")

if __name__ == "__main__":
    main()
