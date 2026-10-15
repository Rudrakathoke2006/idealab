"""
AEGIS-X Standalone Offline Merkle Audit Verifier CLI
RFC 9162 Compliant Independent Verification Tool
Requires NO server access, database credentials, or secret keys.
"""

import sys
import json
import hashlib
from typing import Dict, Any, List, Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

def canonical_serialize(data: Dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')

def hash_leaf(event_data: Dict[str, Any]) -> str:
    ser = canonical_serialize(event_data)
    hasher = hashlib.sha256()
    hasher.update(LEAF_PREFIX)
    hasher.update(ser)
    return hasher.hexdigest()

def hash_children(left_hex: str, right_hex: str) -> str:
    hasher = hashlib.sha256()
    hasher.update(NODE_PREFIX)
    hasher.update(bytes.fromhex(left_hex))
    hasher.update(bytes.fromhex(right_hex))
    return hasher.hexdigest()

def verify_sth(signed_tree_head: Dict[str, str]) -> bool:
    try:
        pub_bytes = bytes.fromhex(signed_tree_head["public_key_hex"])
        sig_bytes = bytes.fromhex(signed_tree_head["signature_hex"])
        payload = signed_tree_head["signed_payload"].encode('utf-8')
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub_key.verify(sig_bytes, payload)
        return True
    except (InvalidSignature, Exception):
        return False

def verify_proof(event: Dict[str, Any], proof: List[Tuple[str, str]], expected_root: str) -> bool:
    curr = hash_leaf(event)
    for sibling_hash, direction in proof:
        if direction == "left":
            curr = hash_children(sibling_hash, curr)
        else:
            curr = hash_children(curr, sibling_hash)
    return curr == expected_root

def main():
    print("===============================================================")
    print("  AEGIS-X Independent RFC 9162 Cryptographic Audit Verifier   ")
    print("===============================================================")
    
    # Test verification on sample event
    sample_event = {
        "action": "PLAYBOOK_EXECUTED_RESET_CREDENTIAL",
        "actor": "usr-soc-01",
        "timestamp": "2026-10-15T10:00:00Z"
    }
    sample_leaf = hash_leaf(sample_event)
    print(f"[*] Canonical Event Hash (RFC 9162 0x00 leaf): {sample_leaf}")
    print("[+] Offline verifier initialized and ready for verification bundles.")

if __name__ == "__main__":
    main()
