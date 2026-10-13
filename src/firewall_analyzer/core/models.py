import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any

# ============================================================================
# Enumerations
# ============================================================================


class VendorType(Enum):
    """Supported firewall vendors"""
    PALO_ALTO = "palo_alto"
    CISCO_ASA = "cisco_asa"
    FORTINET = "fortinet"
    CHECKPOINT = "checkpoint"
    JUNIPER_SRX = "juniper_srx"
    GENERIC = "generic"


class RiskLevel(Enum):
    """Risk level enumeration for security assessment"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RuleIssueType(Enum):
    """Types of issues that can be found in firewall rules"""
    OVERLY_PERMISSIVE = "overly_permissive"
    INSECURE_PROTOCOL = "insecure_protocol"
    APPLICATION_RISK = "application_risk"
    REDUNDANT = "redundant"
    SHADOWED = "shadowed"
    UNUSED = "unused"
    DISABLED = "disabled"
    MISSING_LOGGING = "missing_logging"
    WEAK_AUTHENTICATION = "weak_authentication"
    EXPIRED = "expired"
    MISCONFIGURED = "misconfigured"
    MANAGEMENT_ACCESS = "management_access"
    LATERAL_MOVEMENT = "lateral_movement"
    UNENCRYPTED_TRAFFIC = "unencrypted_traffic"
    BROAD_APPLICATION_ALLOW = "broad_application_allow"
    WEAK_CRYPTO = "weak_crypto"
    MISSING_TIME_RESTRICTIONS = "missing_time_restrictions"


# ============================================================================
# Data Models
# ============================================================================


@dataclass
class SecurityFinding:
    """Represents a security finding for a rule"""
    rule_id: str
    rule_name: str
    issue_type: RuleIssueType
    risk_level: RiskLevel
    description: str
    recommendation: str
    details: Dict[str, Any] = field(default_factory=dict)
    score: int = 0
    score_breakdown: Dict[str, Any] = field(default_factory=dict)
    calculation_formula: str = ""


@dataclass
class FirewallRule:
    """Structured representation of a firewall rule"""
    id: str
    name: str
    source_zones: List[str]
    dest_zones: List[str]
    source_addresses: List[str]
    dest_addresses: List[str]
    source_users: List[str]
    services: List[str]
    applications: List[str]
    action: str
    disabled: bool
    rule_usage: str
    modified: str
    raw_data: Dict[str, str]
    logging: str = ''
    findings: List[SecurityFinding] = field(default_factory=list)
    risk_score: int = 0
    score_breakdown: Dict[str, Any] = field(default_factory=dict)
    vendor_type: VendorType = VendorType.GENERIC
