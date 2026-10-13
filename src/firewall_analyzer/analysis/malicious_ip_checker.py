"""Malicious IP check - flags rules that ALLOW known malicious IP lists / threat feeds.

Vendors are clearly separated so you know which reference belongs to which:
  - PALO ALTO : built-in External Dynamic Lists (EDLs), fixed 'panw-*' names.
  - FORTINET  : ISDB (Internet Service Database) IP-Reputation objects
                (FortiGuard-managed, fixed names) + optional external feed URLs.
"""
from .base import BaseAnalyzer
from ..core.models import SecurityFinding, RuleIssueType, RiskLevel


# ============================================================================
# PALO ALTO - built-in malicious IP EDLs (fixed names)
# ============================================================================
PALO_ALTO_MALICIOUS_LISTS = [
    "panw-bulletproof-ip-list",
    "panw-highrisk-ip-list",
    "panw-known-ip-list",
    "panw-torexit-ip-list",
]

# ============================================================================
# FORTINET - ISDB IP-Reputation objects (FortiGuard built-in, fixed names).
# These are the true equivalent of Palo Alto's built-in EDLs.
# ============================================================================
FORTINET_MALICIOUS_LISTS = [
    "Botnet-C&C.Server",
    "Malicious-Malicious.Server",
    "Phishing-Phishing.Server",
    "Spam-Spamming.Server",
    "Proxy-Proxy.Server",
    "Tor-Exit.Node",
    "Tor-Relay.Node",
    "Tor-Tor.Node",
    "VPN-Anonymous.VPN",
    "Blockchain-Crypto.Mining.Pool",
]

# FORTINET - optional external threat-feed URLs / keywords (customer-defined).
FORTINET_THREAT_FEEDS = [
    "lists.blocklist.de",
    "feodotracker.abuse.ch",
    "rules.emergingthreats.net",
    "cinsscore.com",
    "blocklist.greensnow.co",
    "danger.rulez.sk",
    "opendbl.net",
    "fortiguard",
    "botnet",
    "threat-feed",
    "malicious-ip-feed",
]

# Combined list used for detection (both vendors).
ALL_MALICIOUS_REFERENCES = (
    PALO_ALTO_MALICIOUS_LISTS
    + FORTINET_MALICIOUS_LISTS
    + FORTINET_THREAT_FEEDS
)

# ============================================================================
# Severity tiers - how bad it is to ALLOW each type of malicious reference.
# (name-substring -> extra score). Higher = more dangerous.
# ============================================================================
CRITICAL_REFS = [
    "bulletproof", "botnet-c&c", "malicious-malicious", "phishing", "highrisk", "known-ip",
]
HIGH_REFS = [
    "spam", "proxy-proxy", "vpn-anonymous", "feodotracker", "blocklist.de",
    "emergingthreats", "cinsscore", "greensnow", "malicious-ip-feed", "botnet",
]
# everything else (tor, crypto mining, generic feeds) -> MEDIUM


def _refs(rule):
    """Return the malicious lists/feeds referenced by a rule (source or destination)."""
    found = []
    for v in list(rule.source_addresses) + list(rule.dest_addresses):
        vl = str(v).lower()
        for mal in ALL_MALICIOUS_REFERENCES:
            if mal.lower() in vl:
                found.append(mal)
    return sorted(set(found))


def _severity_for(refs):
    """Pick the worst severity among the matched references."""
    joined = " ".join(refs).lower()
    if any(k in joined for k in CRITICAL_REFS):
        return RiskLevel.CRITICAL, 30
    if any(k in joined for k in HIGH_REFS):
        return RiskLevel.HIGH, 20
    return RiskLevel.MEDIUM, 10


class MaliciousIPAnalyzer(BaseAnalyzer):
    """A rule that ALLOWS malicious IP lists/feeds -> finding (severity by type)."""

    def analyze(self, rule):
        findings = []
        refs = _refs(rule)
        if not refs:
            return findings

        if rule.action.lower() == "allow":
            lists = ", ".join(refs)
            level, factor = _severity_for(refs)
            base = 60
            per_list = factor
            factor_total = per_list * len(refs)
            total = base + factor_total

            print(f"REJECTED : '{rule.name}' ALLOWS malicious IPs ({lists})")

            findings.append(SecurityFinding(
                rule_id=rule.id,
                rule_name=rule.name,
                issue_type=RuleIssueType.MISCONFIGURED,
                risk_level=level,
                description=f"Rule ALLOWS traffic to/from known malicious IP lists/feeds ({lists}).",
                recommendation=f"Change the Action of '{rule.name}' to DENY to block these malicious IPs.",
                details={"malicious_lists": refs},
                score=total,
                calculation_formula=f"Score = {base} + {per_list} x {len(refs)} = {total}",
            ))
        else:
            print(f"APPROVED : '{rule.name}' DENIES malicious IPs")

        return findings