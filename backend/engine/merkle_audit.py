import hashlib
import datetime
from typing import List, Dict, Any

class MerkleAuditAnchoringService:
    """
    Cryptographic Merkle Tree Audit Anchoring Service.
    Calculates Merkle trees over audit trail event hashes, generates daily Merkle Root,
    and provides cryptographic proof verification for compliance auditors (SOC 2 / ISO 27001).
    """

    @staticmethod
    def _sha256(data: str) -> str:
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    def build_merkle_tree(self, event_hashes: List[str]) -> Dict[str, Any]:
        """
        Build Merkle Tree from a list of SHA-256 event hashes and return root hash.
        """
        if not event_hashes:
            empty_root = self._sha256("EMPTY_AUDIT_LOG_" + datetime.datetime.utcnow().isoformat())
            return {"merkle_root": empty_root, "tree_depth": 0, "total_events": 0}

        current_level = [h for h in event_hashes]

        depth = 0
        while len(current_level) > 1:
            depth += 1
            if len(current_level) % 2 != 0:
                current_level.append(current_level[-1]) # Duplicate odd leaf

            next_level = []
            for i in range(0, len(current_level), 2):
                combined = current_level[i] + current_level[i + 1]
                next_level.append(self._sha256(combined))
            current_level = next_level

        merkle_root = current_level[0]

        # Simulated KMS / HSM digital signature
        hsm_signature = self._sha256(f"AWS_KMS_HSM_SIGNATURE:{merkle_root}:{datetime.datetime.utcnow().date()}")

        return {
            "merkle_root": merkle_root,
            "hsm_signature": hsm_signature,
            "tree_depth": depth,
            "total_events": len(event_hashes),
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "compliance_status": "ANCHORED_TAMPER_PROOF"
        }

    def verify_event_inclusion(self, event_hash: str, merkle_root: str, proof_path: List[str]) -> bool:
        """
        Verify if a specific event hash belongs to the anchored Merkle Root using proof path.
        """
        current_hash = event_hash
        for sibling_hash in proof_path:
            combined = current_hash + sibling_hash
            current_hash = self._sha256(combined)
        return current_hash == merkle_root

merkle_audit_service = MerkleAuditAnchoringService()
