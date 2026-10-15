"""
AEGIS-X Secure Incident Messaging Subsystem
Zero-Plaintext, Matrix-Backed End-to-End Encrypted Architecture
"""

from .security_event_service import record_security_event, security_event_service
from .policy_service import policy_service
from .identity_service import identity_service
from .authorization_service import authorization_service
from .room_link_service import room_link_service

__all__ = [
    "security_event_service",
    "record_security_event",
    "policy_service",
    "identity_service",
    "authorization_service",
    "room_link_service"
]
