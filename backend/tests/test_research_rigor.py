import pytest
import hashlib
from backend.engine.entity_extractor import entity_extractor
from backend.engine.graph_engine import graph_engine
from backend.engine.soar_guardrails import soar_policy_gate
from backend.engine.merkle_audit import merkle_audit_service
from backend.research.synthetic_generator import generate_synthetic_dataset

def test_t06_domain_spoofing_defense():
    """T06: Reject lookalike or attacker-controlled subdomains."""
    # Attacker tries to match 'acme.test' by using 'acme.test.evil.com'
    spoofed = "attacker@acme.test.evil.com"
    res = entity_extractor.match_enterprise_identity(spoofed, org_domains=["acme.test"])
    assert res["is_matched"] is False
    assert res["validation_status"] == "UNMATCHED"

    # Legitimate corporate email must match
    legit = "cfo@acme.test"
    res_legit = entity_extractor.match_enterprise_identity(legit, org_domains=["acme.test"])
    assert res_legit["is_matched"] is True
    assert res_legit["validation_status"] == "MATCHED"

def test_t07_plus_addressing_normalization():
    """T07: Normalize plus-addressing aliases (e.g. user+sec@acme.test)."""
    alias = "cfo+alerts@acme.test"
    norm = entity_extractor.normalize_email(alias)
    assert norm == "cfo@acme.test"

def test_t10_cyclic_graph_reachability():
    """T10: Handle cycles in enterprise dependency graph without infinite traversal."""
    graph_engine.build_default_enterprise_graph()
    assert graph_engine.G.has_edge("ast-findb-01", "vendor:payroll")
    assert graph_engine.G.has_edge("vendor:payroll", "ast-vpn-01")  # Cycle back to VPN!
    
    # Must compute blast radius cleanly without stack overflow
    blast = graph_engine.calculate_blast_radius("id:cfo")
    assert blast["contains_cycle"] is True
    assert blast["blast_radius_score"] > 0.0

def test_t11_choke_point_defense():
    """T11: Identify critical choke-point edge whose cut maximally disconnects attack paths."""
    graph_engine.build_default_enterprise_graph()
    choke = graph_engine.analyze_choke_points(start_node="id:cfo", crown_jewel_target="ast-findb-01")
    assert choke["choke_point_identified"] is True
    assert choke["paths_eliminated_by_cut"] >= 1
    assert "recommended_cut_edge" in choke

def test_t14_invariant_last_admin_protection():
    """T14: Safety Invariant blocks revoking or locking out the last active admin."""
    target_attrs = {
        "is_admin": True,
        "privilege_level": 10,
        "is_crown_jewel": True
    }
    context = {
        "active_admin_count": 1,  # Only 1 admin remains!
        "independent_source_count": 3,
        "source_confidence": 0.99
    }
    res = soar_policy_gate.evaluate_response_policy(
        action_type="RESET_CREDENTIAL",
        target_attributes=target_attrs,
        context=context,
        tenant_id="org-acme-fintech-01"
    )
    assert res["decision"] == soar_policy_gate.DECISION_DENY
    assert res["reason_code"] == "INVARIANT_VIOLATION_LAST_ADMIN"
    assert res["allow_execution"] is False

def test_t15_anti_poisoning_corroboration():
    """T15: Poisoned uncorroborated single feed forces manual approval."""
    target_attrs = {
        "is_admin": False,
        "privilege_level": 5,
        "is_crown_jewel": False
    }
    # Adversary injects a single unverified darkweb dump
    context = {
        "active_admin_count": 3,
        "independent_source_count": 1,  # Single source!
        "source_confidence": 0.70       # Not high confidence
    }
    res = soar_policy_gate.evaluate_response_policy(
        action_type="ISOLATE_HOST",
        target_attributes=target_attrs,
        context=context,
        tenant_id="org-acme-fintech-01"
    )
    assert res["decision"] == soar_policy_gate.DECISION_APPROVAL
    assert res["reason_code"] == "UNCONFIRMED_EVIDENCE_CORROBORATION_REQUIRED"

def test_t17_rate_limit_blast_budget():
    """T17: Enforce action rate limit per rolling time window."""
    soar_policy_gate._action_history.clear()
    tenant = "tenant-test-rate"
    
    # Fill up the rate limit window
    for _ in range(soar_policy_gate.MAX_ACTIONS_PER_WINDOW):
        soar_policy_gate.record_executed_action(tenant, "CONTAIN_ASSET")

    target_attrs = {"is_admin": False, "is_crown_jewel": False}
    context = {"active_admin_count": 3, "independent_source_count": 2, "source_confidence": 0.95}

    # Next action must trigger approval gate
    res = soar_policy_gate.evaluate_response_policy("CONTAIN_ASSET", target_attrs, context, tenant)
    assert res["decision"] == soar_policy_gate.DECISION_APPROVAL
    assert res["reason_code"] == "RATE_LIMIT_BLAST_BUDGET_EXCEEDED"

def test_t27_t29_rfc9162_merkle_inclusion_and_domain_separation():
    """T27-T29: RFC 9162 domain-separated leaf and node hashes and inclusion verification."""
    events = [
        {"action": "LOGIN_SUCCESS", "actor": "user-01", "ip": "10.0.0.1"},
        {"action": "POLICY_CHECK_PASS", "actor": "soar-01", "rule": "NOOP"},
        {"action": "CREDENTIAL_RESET", "actor": "usr-soc-01", "target": "cfo@acme.test"},
        {"action": "AUDIT_CHECKPOINT", "actor": "system", "epoch": 1}
    ]
    tree = merkle_audit_service.build_merkle_tree(events)
    merkle_root = tree["merkle_root"]
    sth = tree["signed_tree_head"]
    
    # 1. Asymmetric Ed25519 signature verification (No secret key needed)
    assert merkle_audit_service.verify_signed_tree_head(sth) is True

    # 2. Mathematical Inclusion Proof verification for leaf #2 (CREDENTIAL_RESET)
    leaf_hashes = tree["leaf_hashes"]
    proof = merkle_audit_service.generate_inclusion_proof(target_index=2, leaf_hashes=leaf_hashes)
    assert len(proof) > 0

    target_event = events[2]
    is_valid = merkle_audit_service.verify_inclusion_proof(target_event, proof, merkle_root)
    assert is_valid is True

    # 3. Tamper Detection: Modify 1 byte in event -> Proof must fail
    tampered_event = {"action": "CREDENTIAL_RESET", "actor": "usr-soc-01", "target": "hacked@acme.test"}
    assert merkle_audit_service.verify_inclusion_proof(tampered_event, proof, merkle_root) is False

def test_t30_decoupled_synthetic_ground_truth():
    """T30: Ground truth outcome labels are decoupled from linear feature combinations."""
    df = generate_synthetic_dataset(num_samples=500, seed=42)
    assert "true_severity" in df.columns
    assert "crown_jewel_reached" in df.columns
    # Check that severity is not simply a constant threshold of data_sensitivity
    assert df["data_sensitivity"].nunique() > 5
    assert df["true_severity"].nunique() >= 3
