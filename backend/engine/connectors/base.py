from abc import ABC, abstractmethod
from typing import Dict, Any, List
import datetime

class BaseConnectorAdapter(ABC):
    """
    Abstract Connector Adapter interface for Enterprise Telemetry Feeds
    (IAM, SIEM, EDR, Vuln Scanners, CTI Feeds).
    """

    def __init__(self, connector_id: str, tenant_id: str, config: Dict[str, Any] = None):
        self.connector_id = connector_id
        self.tenant_id = tenant_id
        self.config = config or {}

    @abstractmethod
    def fetch_telemetry(() -> List[Dict[str, Any]]:
        """Fetch raw telemetry events from vendor API endpoint."""
        pass

    @abstractmethod
    def normalize_to_ocsf(self, raw_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize vendor-specific payload into OCSF v1.1.0 event schema."""
        pass
