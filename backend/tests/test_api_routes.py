import pytest
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_login():
    res = client.post("/api/v1/auth/login", json={"email": "soc.analyst@acme.test", "password": "SocPass2026!"})
    assert res.status_code == 200
    assert "access_token" in res.json()

def test_dashboard_summary():
    res = client.get("/api/v1/dashboard/summary")
    assert res.status_code == 200
    data = res.json()
    assert "overall_risk_score" in data
    assert "total_protected_assets" in data

def test_get_exposures():
    res = client.get("/api/v1/exposures")
    assert res.status_code == 200
    assert isinstance(res.json(), list)

def test_ingest_exposure():
    res = client.post("/api/v1/exposures/ingest", json={
        "raw_text": "Exposed credential for cfo@acme.test on darkweb paste site",
        "source": "HIBP / CTI Feed",
        "exposure_type": "CREDENTIAL_LEAK"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] in ["INGESTION_AND_DETECTION_COMPLETE", "INGESTED_BUT_UNMATCHED"]

def test_run_detection():
    res = client.post("/api/v1/detect", json={
        "type": "CREDENTIAL_LEAK",
        "identity": "cfo@acme.test",
        "asset": "FinanceDB Production Cluster",
        "cvss_score": 9.8,
        "cisa_kev": True
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "DETECTION_COMPLETE"
    assert "xai_explanations" in data["detection_event"]

def test_graph_endpoint():
    res = client.get("/api/v1/graph")
    assert res.status_code == 200
    data = res.json()
    assert "nodes" in data
    assert "edges" in data

def test_merkle_anchor_endpoint():
    res = client.post("/api/v1/audit/merkle-anchor")
    assert res.status_code == 200
    data = res.json()
    assert "merkle_root" in data
    assert "hsm_signature" in data

def test_run_demo_scenario_endpoint():
    res = client.post("/api/v1/demo/run-scenario")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "SCENARIO_EXECUTION_SUCCESSFUL"
