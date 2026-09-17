import pytest
import os
import json
from backend.seed import init_db, hash_identifier
from backend.engine.entity_extractor import entity_extractor
from backend.engine.exposure_surface import exposure_surface_engine
from backend.engine.graph_engine import graph_engine
from backend.engine.risk_engine import risk_engine
from backend.engine.xai_engine import xai_engine
from backend.engine.response_engine import response_engine
from backend.research.ablation_study import run_ablation_study

def test_entity_extractor():
    raw = "Exposure alert for john.cfo@acme.test in finance department with secret sec_key_123456789012345678901234 and password indicator."
    res = entity_extractor.extract(raw)
    assert res["entity_count"] >= 3
    tokens = [e.get("token") for e in res["entities"] if "token" in e]
    assert all("sec_key" not in t for t in tokens)
    assert all("john.cfo" not in t for t in tokens)

def test_exposure_surface():
    eval_res = exposure_surface_engine.evaluate_asset_weakness(
        asset_name="VPN Gateway",
        asset_criticality=9,
        internet_exposed=True,
        mfa_enabled=False,
        has_cve=True,
        cvss_score=9.8,
        cisa_kev=True
    )
    assert eval_res["weakness_score"] >= 80.0
    assert eval_res["weakness_count"] >= 4

def test_graph_blast_radius():
    graph_engine.build_default_acme_graph()
    blast = graph_engine.calculate_blast_radius("id:cfo")
    assert blast["blast_radius_score"] >= 75.0
    assert "ERP-01 Core System" in blast["reachable_critical_services"]
    assert "FinanceDB Production Cluster" in blast["reachable_databases"]

def test_hybrid_risk_model():
    # Test Case 2: CFO Finance Credential
    res = risk_engine.compute_risk(
        data_sensitivity=9,
        exploitability=9,
        asset_criticality=10,
        freshness=9.5,
        source_confidence=9.5,
        blast_radius=8.5,
        vulnerability_score=9.2,
        threat_context=8.0,
        historical_score=7.0,
        mfa_enabled=False
    )
    assert res["severity_score"] >= 90.0
    assert res["severity_level"] == "CRITICAL"
    assert res["confidence_score"] >= 80.0
    assert res["confidence_level"] == "HIGH"

def test_xai_narrative():
    risk_out = risk_engine.compute_risk(9, 9, 10, 9.5, 9.5, 8.5, 9.2, 8.0, 7.0, False)
    xai_res = xai_engine.explain_risk(risk_out)
    assert "CRITICAL" in xai_res["narrative_explanation"]
    assert len(xai_res["shap_attributions"]) >= 4

def test_response_playbook():
    playbook = response_engine.generate_playbook("CREDENTIAL_EXPOSURE")
    p0_actions = [p["action_type"] for p in playbook if p["priority"] == "P0"]
    assert "RESET_CREDENTIAL" in p0_actions
    assert "REVOKE_SESSIONS" in p0_actions

def test_ablation_study():
    results = run_ablation_study()
    assert "Model A (Sensitivity Only)" in results
    assert "Model H (FULL HYBRID MODEL)" in results
    # Model H full hybrid should achieve highest Macro-F1 / PR-AUC
    assert results["Model H (FULL HYBRID MODEL)"]["macro_f1"] >= results["Model A (Sensitivity Only)"]["macro_f1"]
