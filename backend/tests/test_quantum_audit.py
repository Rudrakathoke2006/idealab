"""
AEGIS-X: Quantum-Resilient Verifiable Audit & Explanation Integrity Test Suite
Comprehensive validation of:
1. RFC 9162 Domain-Separated Merkle Log (Inclusion & Consistency Proofs)
2. Tamper Detection Matrix (Modify, Delete, Reorder, Truncate, Replay)
3. Second-Preimage / Leaf-vs-Node Confusion Resistance
4. Hybrid STH Dual Signatures (Classical Ed25519 + Post-Quantum ML-DSA-65)
5. Simulated Quantum Forgery Resistance (Classical-only & PQ-only forgery rejection)
6. Verifiable Decision Explanations & Exact Local Additivity (Error < 1e-6)
7. Hybrid KEM (X25519 + ML-KEM-768 + AES-256-GCM) with Tenant-Bound AAD
8. Standalone Zero-Trust Offline Verifier (verify_bundle.py)
"""

import os
import json
import pytest
import hashlib
from fastapi.testclient import TestClient
from backend.main import app
from backend.engine.merkle_audit import (
    canonical, leaf_hash, node_hash, mth,
    inclusion_proof, verify_inclusion,
    consistency_proof, verify_consistency
)
from backend.engine.audit_signing import (
    HybridSigner, verify_sth, sth_bytes, STH_DOMAIN
)
from backend.engine.export_crypto import (
    seal, open_, TenantExportKeyManager, RAW_FORMAT
)
from backend.engine.xai_engine import xai_engine
from backend.tools.verify_bundle import verify_audit_bundle

client = TestClient(app)

# =====================================================================
# 1. RFC 9162 Domain Separation & Preimage Resistance
# =====================================================================

def test_rfc9162_domain_separation():
    """Verify 0x00 leaf prefix and 0x01 internal node prefix."""
    raw_data = b"audit_event_payload"
    l_hash = leaf_hash(raw_data)
    
    # Must equal SHA256(0x00 || raw_data)
    expected_leaf = hashlib.sha256(b"\x00" + raw_data).digest()
    assert l_hash == expected_leaf

    left = hashlib.sha256(b"left").digest()
    right = hashlib.sha256(b"right").digest()
    n_hash = node_hash(left, right)
    
    # Must equal SHA256(0x01 || left || right)
    expected_node = hashlib.sha256(b"\x01" + left + right).digest()
    assert n_hash == expected_node
    assert l_hash != n_hash


def test_leaf_vs_node_collision_resistance():
    """Leaf data cannot collide with an internal node hash (second preimage resistance)."""
    left = os.urandom(32)
    right = os.urandom(32)
    n_hash = node_hash(left, right)

    # An adversary crafts a leaf whose raw data is (left || right)
    colliding_leaf = leaf_hash(left + right)
    assert colliding_leaf != n_hash


# =====================================================================
# 2. RFC 9162 Inclusion Proofs across various tree sizes (up to 4096)
# =====================================================================

def test_inclusion_proofs_exhaustive_small_trees():
    """Verify 100% of inclusion proofs for all tree sizes N = 1 to 32."""
    for n in range(1, 33):
        leaves = [leaf_hash(f"leaf_{i}".encode()) for i in range(n)]
        root = mth(leaves)
        for m in range(n):
            proof = inclusion_proof(m, leaves)
            valid = verify_inclusion(leaves[m], m, n, proof, root)
            assert valid is True, f"Failed inclusion proof for m={m}, n={n}"


def test_inclusion_proofs_powers_of_two_up_to_4096():
    """Test inclusion proofs for large trees: powers of 2 up to 4096."""
    for n in [64, 128, 256, 512, 1024, 2048, 4096]:
        leaves = [leaf_hash(f"event_{i}".encode()) for i in range(n)]
        root = mth(leaves)
        
        # Test boundary and middle indices
        test_indices = [0, 1, n // 4, n // 2 - 1, n // 2, n - 2, n - 1]
        for m in test_indices:
            proof = inclusion_proof(m, leaves)
            valid = verify_inclusion(leaves[m], m, n, proof, root)
            assert valid is True, f"Failed inclusion proof for m={m}, n={n}"


# =====================================================================
# 3. RFC 9162 Consistency Proofs (all m <= n <= 32)
# =====================================================================

def test_consistency_proofs_exhaustive():
    """Verify consistency proofs for all pairs 1 <= m <= n <= 32."""
    leaves = [leaf_hash(f"log_event_{i}".encode()) for i in range(32)]
    for n in range(1, 33):
        new_root = mth(leaves[:n])
        for m in range(1, n + 1):
            old_root = mth(leaves[:m])
            proof = consistency_proof(m, leaves[:n])
            valid = verify_consistency(m, n, old_root, new_root, proof)
            assert valid is True, f"Failed consistency proof for m={m}, n={n}"


# =====================================================================
# 4. Tamper Detection Matrix (Modify, Delete, Reorder, Truncate, Replay)
# =====================================================================

def test_tamper_detection_modify():
    """Modifying a single bit in a leaf must fail inclusion proof."""
    leaves = [leaf_hash(f"event_{i}".encode()) for i in range(8)]
    root = mth(leaves)
    proof = inclusion_proof(3, leaves)

    # Corrupt target leaf
    corrupted_leaf = bytearray(leaves[3])
    corrupted_leaf[0] ^= 0xFF
    assert verify_inclusion(bytes(corrupted_leaf), 3, 8, proof, root) is False


def test_tamper_detection_delete_and_reorder():
    """Deleting or reordering leaves modifies the root hash."""
    leaves = [leaf_hash(f"event_{i}".encode()) for i in range(8)]
    original_root = mth(leaves)

    # Delete leaf
    deleted_leaves = leaves[:3] + leaves[4:]
    assert mth(deleted_leaves) != original_root

    # Reorder leaves
    reordered_leaves = list(leaves)
    reordered_leaves[2], reordered_leaves[3] = reordered_leaves[3], reordered_leaves[2]
    assert mth(reordered_leaves) != original_root


def test_tamper_detection_truncation_via_consistency():
    """Truncating history is caught by consistency proof against retained STH."""
    leaves = [leaf_hash(f"event_{i}".encode()) for i in range(10)]
    legit_n_root = mth(leaves)

    # Adversary presents a truncated tree of size 6
    truncated_leaves = leaves[:6]
    truncated_root = mth(truncated_leaves)

    # Auditor retained old checkpoint at size 7
    old_root_7 = mth(leaves[:7])

    # Truncated tree cannot prove consistency against older larger retained tree (m=7 > n=6)
    with pytest.raises(ValueError):
        consistency_proof(7, truncated_leaves)


# =====================================================================
# 5. Hybrid Classical + Post-Quantum STH Signatures & Forgery Defense
# =====================================================================

def test_hybrid_sth_signing_and_verification():
    """Verify that dual signature (Ed25519 + ML-DSA-65) passes."""
    signer = HybridSigner()
    root = hashlib.sha256(b"merkle_root_test").digest()
    sth = signer.sign_sth("tenant-alpha", 15, root)

    assert sth["classical_alg"] == "Ed25519"
    assert sth["classical_sig_size_bytes"] == 64
    assert sth["pq_alg"] == "ML-DSA-65"
    assert sth["pq_sig_size_bytes"] == 3309
    assert sth["pq_public_key_size_bytes"] == 1952

    assert verify_sth(sth) is True


def test_hybrid_forgery_rejection_classical_only():
    """Simulated quantum adversary forges Ed25519 alone -> Hybrid verifier REJECTS."""
    signer = HybridSigner()
    root = hashlib.sha256(b"merkle_root_test").digest()
    sth = signer.sign_sth("tenant-alpha", 15, root)

    # Adversary corrupts post-quantum signature
    bad_pq = bytearray(bytes.fromhex(sth["pq_sig"]))
    bad_pq[10] ^= 0xAA
    sth["pq_sig"] = bytes(bad_pq).hex()

    # Must fail because BOTH signatures are mandatory
    assert verify_sth(sth) is False


def test_hybrid_forgery_rejection_pq_only():
    """Classical Ed25519 signature corrupted -> Hybrid verifier REJECTS."""
    signer = HybridSigner()
    root = hashlib.sha256(b"merkle_root_test").digest()
    sth = signer.sign_sth("tenant-alpha", 15, root)

    # Adversary corrupts Ed25519 signature
    bad_ed = bytearray(bytes.fromhex(sth["classical_sig"]))
    bad_ed[5] ^= 0xFF
    sth["classical_sig"] = bytes(bad_ed).hex()

    assert verify_sth(sth) is False


# =====================================================================
# 6. Verifiable Decision Explanations & SHAP Additivity (RQ3)
# =====================================================================

def test_verifiable_explanation_commitment_and_additivity():
    """Test decision commitment creation, hash verification, and exact additivity."""
    features = [9.0, 9.0, 10.0, 24.0, 0.95, 8.5, 1.0, 0.0, 0.0, 1.0, 1.0, 0.90, 1.0]
    shap_vals = [18.4, 16.8, 14.2, 12.0, 8.5, 7.2, 5.0, 0.0, 0.0, 4.0, 3.5, 2.0, 1.4]
    
    commitment = xai_engine.create_decision_commitment(
        tenant_id="tenant-alpha",
        model_bytes=b"xgboost_v1_model_bytes",
        config={"threshold": 80.0},
        features=features,
        shap_vals=shap_vals,
        score=93.0,
        guardrail="REQUIRE_HUMAN_CONFIRMATION"
    )

    assert "shap_sha256" in commitment
    assert "commitment_hash" in commitment

    # Recomputing exact hash
    recomputed_sha = hashlib.sha256(canonical([round(float(v), 6) for v in shap_vals])).hexdigest()
    assert recomputed_sha == commitment["shap_sha256"]

    # Tamper test: perturb 1 SHAP value by 0.01 -> Mismatch
    tampered_shap = list(shap_vals)
    tampered_shap[0] += 0.01
    tampered_sha = hashlib.sha256(canonical([round(float(v), 6) for v in tampered_shap])).hexdigest()
    assert tampered_sha != commitment["shap_sha256"]

    # Test local additivity check
    additivity = xai_engine.verify_shap_additivity(features)
    assert additivity["additivity_holds"] is True
    assert additivity["error"] < 1e-6


# =====================================================================
# 7. Hybrid KEM (X25519 + ML-KEM-768 + AES-256-GCM) Confidentiality
# =====================================================================

def test_hybrid_kem_roundtrip_and_aad():
    """Test seal/open roundtrip and tenant AAD authentication."""
    key_mgr = TenantExportKeyManager()
    keys = key_mgr.get_or_create_tenant_keys("tenant-beta")

    plaintext = b"Sensitive forensic audit trail & incident database backup."
    aad = b"tenant-beta"

    # Seal bundle
    bundle = seal(
        recipient_x25519_pub=keys["x25519_pub"],
        recipient_ml_kem_pub=keys["kem_pub"],
        plaintext=plaintext,
        aad=aad
    )
    assert bundle["classical_kem"] == "X25519"
    assert bundle["pq_kem"] == "ML-KEM-768"
    assert bundle["aead"] == "AES-256-GCM"

    # Open bundle
    decrypted = open_(
        recipient_x25519_priv=keys["x25519_priv"],
        recipient_ml_kem_provider=keys["kem_provider"],
        recipient_x25519_pub=keys["x25519_pub"],
        recipient_ml_kem_pub=keys["kem_pub"],
        sealed_bundle=bundle,
        aad=aad
    )
    assert decrypted == plaintext

    # Wrong AAD (cross-tenant tampering) -> Must raise Decryption Error
    with pytest.raises(Exception):
        open_(
            recipient_x25519_priv=keys["x25519_priv"],
            recipient_ml_kem_provider=keys["kem_provider"],
            recipient_x25519_pub=keys["x25519_pub"],
            recipient_ml_kem_pub=keys["kem_pub"],
            sealed_bundle=bundle,
            aad=b"wrong-tenant-gamma"
        )


# =====================================================================
# 8. API Endpoints & Standalone Offline Bundle Verifier
# =====================================================================

def test_api_quantum_audit_endpoints_and_offline_verifier():
    """Verify /audit/{tenant}/sth/latest, consistency, and verify_bundle.py integration."""
    tenant = "org-acme-fintech-01"

    # 1. Latest STH
    res_sth = client.get(f"/api/v1/audit/{tenant}/sth/latest")
    assert res_sth.status_code == 200
    sth_data = res_sth.json()
    assert sth_data["hybrid_verified"] is True
    assert sth_data["classical_alg"] == "Ed25519"
    assert sth_data["pq_alg"] == "ML-DSA-65"

    # 2. Inclusion Proof
    res_inc = client.get(f"/api/v1/audit/{tenant}/inclusion/0")
    assert res_inc.status_code == 200
    assert res_inc.json()["is_valid"] is True

    # 3. Consistency Proof
    res_cons = client.get(f"/api/v1/audit/{tenant}/consistency?first=1&second=2")
    assert res_cons.status_code == 200
    assert res_cons.json()["is_consistent"] is True

    # 4. Hybrid Export
    res_exp = client.post(f"/api/v1/export/{tenant}")
    assert res_exp.status_code == 200
    assert res_exp.json()["status"] == "SEALED"

    # 5. Offline Bundle Export & Standalone Verifier
    res_bundle = client.get(f"/api/v1/audit/{tenant}/bundle")
    assert res_bundle.status_code == 200
    bundle_data = res_bundle.json()

    # Pass directly to offline verifier (zero network, zero secrets)
    report = verify_audit_bundle(bundle_data)
    assert report["overall_status"] == "PASS"
    assert report["sths_verified"] >= 1
    assert len(report["failures"]) == 0
