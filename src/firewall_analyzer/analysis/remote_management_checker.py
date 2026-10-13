"""
Remote Management check - flags ALLOW rules that expose remote-management access.

Logic follows the decision flowchart:
  1. Only ALLOW rules are considered.
  2. If Application is in the remote-access APP list      -> match type APPLICATION (high confidence)
  3. Else if a remote-access PORT appears in the Service   -> match type PORT      (medium confidence)
  4. If App = any AND Service = any                        -> BROAD RULE RISK      (low confidence)

Risk mapping:
  - BROAD RULE (any/any)                 -> CRITICAL
  - Remote access allowed from ANY source-> CRITICAL
  - Remote access from a specific source -> MEDIUM

Note: UDP 514 = Syslog, NOT RSH -> excluded from port matching.
"""
from .base import BaseAnalyzer
from ..core.models import SecurityFinding, RuleIssueType, RiskLevel


# A. Remote access APPLICATION list (Palo Alto App-IDs). '-' prefix handles gotomypc-*, etc.
REMOTE_ACCESS_APPS = [
    "ssh", "ms-rdp", "rdp", "logmein", "vnc-base", "vnc", "rsh", "telnet",
    "teamviewer", "anydesk", "gotomypc", "splashtop", "beyondtrust",
    "winrm", "rlogin", "rexec", "pcanywhere", "radmin", "xdmcp", "x11",
]

# B. Remote access PORT list -> protocol name.
REMOTE_ACCESS_PORTS = {
    "22": "SSH", "23": "Telnet", "3389": "RDP", "5900": "VNC",
    "514": "RSH", "513": "rlogin", "512": "rexec",
    "5985": "WinRM (HTTP)", "5986": "WinRM (HTTPS)",
    "177": "XDMCP", "3283": "Apple Remote Desktop",
}
# C. Remote access SERVICE NAMES -> protocol name.
# For files that store the Service as a NAME (SSH, RDP, TELNET) instead of a port number.
REMOTE_ACCESS_SERVICE_NAMES = {
    "ssh": "SSH",
    "telnet": "Telnet",
    "rdp": "RDP", "ms.rdp": "RDP", "ms-rdp": "RDP", "mstsc": "RDP",
    "vnc": "VNC",
    "rsh": "RSH",
    "rlogin": "rlogin",
    "rexec": "rexec",
    "winrm": "WinRM (HTTP)",
    "xdmcp": "XDMCP",
    "x11": "X11",
}

X11_RANGE = range(6000, 6064)  # X11 uses 6000-6063


def _is_any(values):
    return any(str(v).lower() == "any" for v in values)


def _app_matches(applications):
    matched = []
    for app in applications:
        al = str(app).lower()
        for known in REMOTE_ACCESS_APPS:
            if al == known or al.startswith(known + "-") or known in al:
                matched.append(known)
                break
    return sorted(set(matched))


def _port_matches(services):
    """Match remote-access ports in the service field. Skips UDP 514 (Syslog).

    Also matches service NAMES: many exports store the service as "SSH" or
    "RDP" rather than a port number, and a name-only file would otherwise
    register no remote-management exposure at all.
    """
    matched = []
    for svc in services:
        s = str(svc).lower()
        for name, proto in REMOTE_ACCESS_SERVICE_NAMES.items():
            if name in s:
                matched.append(proto)
                break
        is_udp_514 = ("udp" in s and "514" in s)
        token = s.replace("tcp", " ").replace("udp", " ").replace("/", " ").replace(":", " ")
        for part in token.split():
            if not part.isdigit():
                continue
            if part == "514" and is_udp_514:
                continue  # syslog, not rsh
            if part in REMOTE_ACCESS_PORTS:
                matched.append(REMOTE_ACCESS_PORTS[part])
            else:
                try:
                    if int(part) in X11_RANGE:
                        matched.append("X11")
                except ValueError:
                    pass
    return sorted(set(matched))


class RemoteManagementAnalyzer(BaseAnalyzer):
    """Flags ALLOW rules that expose remote-management access (app / port / broad)."""

    def analyze(self, rule):
        findings = []

        if rule.action.lower() != "allow":
            return findings

        app_any = _is_any(rule.applications)
        svc_any = _is_any(rule.services)
        src_any = _is_any(rule.source_addresses)

        match_type, matched = None, []

        # 1) APPLICATION match (highest confidence)
        app_hits = _app_matches(rule.applications)
        if app_hits:
            match_type, matched = "APPLICATION", app_hits

        # 2) PORT match (medium confidence) - only if no app match
        if not matched:
            port_hits = _port_matches(rule.services)
            if port_hits:
                match_type, matched = "PORT", port_hits

        if not matched:
            return findings

        protos = ", ".join(matched)

        # Risk + score
        if match_type == "BROAD RULE":
            level, base, extra = RiskLevel.CRITICAL, 60, 40
        elif src_any:
            level, base, extra = RiskLevel.CRITICAL, 50, 40
        else:
            level, base, extra = RiskLevel.MEDIUM, 40, 0
        total = base + extra

        suffix = " from ANY source!" if (src_any and match_type != "BROAD RULE") else ""
        print(f"REMOTE-MGMT [{match_type}] : '{rule.name}' allows {protos}{suffix}")

        findings.append(SecurityFinding(
            rule_id=rule.id,
            rule_name=rule.name,
            issue_type=RuleIssueType.MANAGEMENT_ACCESS,
            risk_level=level,
            description=f"Rule allows remote management ({match_type} match: {protos}).",
            recommendation=(
                f"Restrict '{rule.name}' to specific administrator source IPs, "
                f"use secure protocols over VPN, and avoid 'any' source. "
                f"Review broad rules manually."
            ),
            details={"match_type": match_type, "protocols": matched, "any_source": src_any},
            score=total,
            calculation_formula=f"Score = {base} + {extra} = {total}",
        ))
        return findings