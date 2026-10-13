import re
from typing import List, Dict, Any

from .base import BaseAnalyzer
from ..core.models import FirewallRule, SecurityFinding, RuleIssueType, RiskLevel


class InsecureProtocolAnalyzer(BaseAnalyzer):
    """Analyzes rules for insecure protocols and services"""

    INSECURE_PROTOCOLS = {
        'telnet': {
            'port': 23,
            'risk': RiskLevel.CRITICAL,
            'base_score': 20,
            'alternate_ports': [],
            'common_names': ['telnet', 'telnet-service', 'tcp-23'],
            'score_factors': {
                'cleartext_auth': 30,
                'no_encryption': 30,
                'legacy_protocol': 20,
                # 'known_vulnerabilities': 15
            },
            'recommendation': 'Replace Telnet with SSH for secure remote access'
        },
        'ftp': {
            'port': 21,
            'risk': RiskLevel.HIGH,
            'base_score': 20,
            'alternate_ports': [2121, 8021],
            'common_names': ['ftp', 'ftp-data', 'ftp-control', 'tcp-21', 'tcp-20'],
            'score_factors': {
                'cleartext_auth': 25,
                'no_encryption': 25,
                'data_exposure': 20,
                # 'bounce_attacks': 15
            },
            'recommendation': 'Replace FTP with SFTP or FTPS for secure file transfer'
        },
        'http': {
            'port': 80,
            'risk': RiskLevel.MEDIUM,
            'base_score': 40,
            'alternate_ports': [8080, 8000, 8008, 8088, 3000, 5000],
            'common_names': ['http', 'www', 'web', 'tcp-80', 'http-service', 'web-browsing'],
            'score_factors': {
                'no_encryption': 20,
                'session_hijacking': 15,
                'data_exposure': 15,
                'mitm_vulnerable': 10
            },
            'recommendation': 'Use HTTPS instead of HTTP for encrypted communication'
        },
        'rdp': {
            'port': 3389,
            'risk': RiskLevel.MEDIUM,
            'base_score': 55,
            'alternate_ports': [3388, 3390],
            'common_names': ['rdp', 'mstsc', 'remote-desktop', 'tcp-3389', 'ms-wbt-server'],
            'score_factors': {
                'brute_force_target': 20,
                'known_vulnerabilities': 15,
                'lateral_movement': 10,
                'credential_theft': 10
            },
            'recommendation': 'Implement RDP with Network Level Authentication and restrict access'
        },
        'snmp': {
            'port': 161,
            'risk': RiskLevel.MEDIUM,
            'base_score': 65,
            'alternate_ports': [],
            'common_names': ['snmp', 'simple-network-management-protocol', 'udp-161', 'snmp-agent'],
            'score_factors': {
                'weak_auth': 20,
                'information_disclosure': 15,
                'default_communities': 15,
                'version_specific': 15
            },
            'recommendation': 'Use SNMPv3 with authentication and encryption'
        },
        'smbv1': {
            'port': 445,
            'risk': RiskLevel.CRITICAL,
            'base_score': 95,
            'alternate_ports': [139],
            'common_names': ['smbv1', 'smb-version-1', 'smb-1', 'cifs', 'microsoft-ds'],
            'score_factors': {
                'wannacry_vulnerable': 35,
                'known_exploits': 30,
                'legacy_protocol': 20,
                'no_signing': 10
            },
            'recommendation': 'Disable SMBv1 immediately and upgrade to SMBv3'
        },
        'ldap': {
            'port': 389,
            'risk': RiskLevel.MEDIUM,
            'base_score': 40,
            'alternate_ports': [3268, 3269],
            'common_names': ['ldap', 'lightweight-directory-access-protocol', 'tcp-389'],
            'score_factors': {
                'no_encryption': 20,
                'auth_bypass': 15,
                'information_disclosure': 15,
                'injection_vulnerable': 10
            },
            'recommendation': 'Use LDAPS (port 636) for encrypted directory access'
        },
        'tftp': {
            'port': 69,
            'risk': RiskLevel.HIGH,
            'base_score': 30,
            'alternate_ports': [],
            'common_names': ['tftp', 'udp-69'],
            'score_factors': {
                'no_auth': 30,
                'no_encryption': 20,
                'data_exposure': 10,
                'unauthenticated_access': 10,
            },
            'recommendation': 'Avoid TFTP; use secure file transfer protocols like SFTP or FTPS'

            },
        'netbios': {
            'port': 137,
            'risk': RiskLevel.HIGH,
            'base_score': 80,
            'alternate_ports': [138, 139],
            'common_names': ['netbios', 'netbios-ns', 'netbios-dgm', 'netbios-ssn', 'udp-137', 'udp-138', 'tcp-139'],
            'score_factors': {
                'information_disclosure': 25,
                'known_exploits': 25,
                'legacy_protocol': 20,
                'lateral_movement': 10,
            },
            'recommendation': 'Disable NetBIOS unless absolutely required'

            },
        'pop3': {
            'port': 110,
            'risk': RiskLevel.MEDIUM,
            'base_score': 60,
            'alternate_ports': [995],  # 995 is POP3S (secure)
            'common_names': ['pop3', 'tcp-110', 'pop'],
            'score_factors': {
                'cleartext_auth': 20,
                'no_encryption': 20,
                'data_exposure': 15,
                'legacy_protocol': 10,
            },
            'recommendation': 'Use POP3S (port 995) for encrypted email retrieval'

            },
        'imap': {
            'port': 143,
            'risk': RiskLevel.MEDIUM,
            'base_score': 60,
            'alternate_ports': [993],  # 993 is IMAPS (secure)
            'common_names': ['imap', 'tcp-143'],
            'score_factors': {
                'cleartext_auth': 20,
                'no_encryption': 20,
                'data_exposure': 15,
                'legacy_protocol': 10,
            },
            'recommendation': 'Use IMAPS (port 993) for encrypted email access'

            },
        'smtp': {
            'port': 25,
            'risk': RiskLevel.HIGH,
            'base_score': 75,
            'alternate_ports': [587, 465],  # 465/587 are for secure SMTP
            'common_names': ['smtp', 'tcp-25'],
            'score_factors': {
                'cleartext_auth': 25,
                'no_encryption': 25,
                'spam_abuse': 15,
                'open_relay': 10,
            },
            'recommendation': 'Use SMTPS (port 465/587) or enforce STARTTLS for secure mail transfer'

            },
        'nfs': {
            'port': 2049,
            'risk': RiskLevel.HIGH,
            'base_score': 75,
            'alternate_ports': [],
            'common_names': ['nfs', 'tcp-2049', 'udp-2049'],
            'score_factors': {
                'no_encryption': 25,
                'data_exposure': 25,
                'weak_auth': 15,
                'unauthorized_access': 10,
            },
            'recommendation': 'Use NFSv4 with Kerberos authentication and encryption'

            },
        'rpc': {
            'port': 135,
            'risk': RiskLevel.HIGH,
            'base_score': 75,
            'alternate_ports': [],
            'common_names': ['rpc', 'tcp-135', 'epmap'],
            'score_factors': {
                'known_exploits': 25,
                'lateral_movement': 20,
                'legacy_protocol': 15,
                'excessive_exposure': 10,
            },
            'recommendation': 'Restrict RPC exposure and use secure alternatives where possible'

            },    

        'rlogin': {
            'port': 513,
            'risk': RiskLevel.CRITICAL,
            'base_score': 90,
            'alternate_ports': [],
            'common_names': ['rlogin', 'tcp-513'],
            'score_factors': {
                'cleartext_auth': 30,
                'no_encryption': 30,
                'legacy_protocol': 20,
            },
            'recommendation': 'Replace rlogin with SSH for secure remote access'
        },
        'mysql': {
            'port': 3306,
            'risk': RiskLevel.MEDIUM,
            'base_score': 65,
            'alternate_ports': [],
            'common_names': ['mysql', 'tcp-3306'],
            'score_factors': {
                'no_encryption': 25,
                'weak_auth': 20,
                'information_disclosure': 15,
            },
            'recommendation': 'Restrict MySQL access to trusted hosts and enable SSL/TLS encryption for connections'
        },

        'postgresql': {
            'port': 5432,
            'risk': RiskLevel.MEDIUM,
            'base_score': 65,
            'alternate_ports': [],
            'common_names': ['postgresql', 'postgres', 'tcp-5432'],
            'score_factors': {
                'no_encryption': 25,
                'weak_auth': 20,
                'information_disclosure': 15,
            },
            'recommendation': 'Restrict PostgreSQL access to trusted hosts and enable SSL/TLS encryption for connections'
        }

    }

    def analyze(self, rule: FirewallRule) -> List[SecurityFinding]:
        """Analyze a rule for insecure protocols with detailed scoring"""
        findings = []

        # Skip disabled rules
        if rule.disabled:
            return findings

        for service in rule.services:
            service_lower = service.lower().strip()

            for protocol, info in self.INSECURE_PROTOCOLS.items():
                if self._detect_protocol(service_lower, protocol, info):
                    score_breakdown = self._calculate_protocol_score(protocol, info, rule)

                    formula = self._generate_formula(score_breakdown)

                    finding = SecurityFinding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        issue_type=RuleIssueType.INSECURE_PROTOCOL,
                        risk_level=info['risk'],
                        description=f"Rule allows insecure protocol: {protocol.upper()} (service: {service})",
                        recommendation=info['recommendation'],
                        details={
                            'protocol': protocol,
                            'port': info['port'],
                            'service': service,
                            'detection_method': self._get_detection_method(service_lower, protocol, info)
                        },
                        score=score_breakdown['total_score'],
                        score_breakdown=score_breakdown,
                        calculation_formula=formula
                    )
                    findings.append(finding)
                    break

        return findings

    def _detect_protocol(self, service_str: str, protocol: str, info: Dict) -> bool:
        """Enhanced protocol detection"""
        if 'common_names' in info:
            for name in info['common_names']:
                if name in service_str:
                    return True

        if protocol in service_str:
            return True

        port = info['port']
        port_patterns = [
            f"tcp-{port}", f"tcp_{port}", f"tcp/{port}",
            f"udp-{port}", f"udp_{port}", f"udp/{port}",
            f"port-{port}", f"port_{port}", f"port {port}",
            f":{port}", f"/{port}", f"-{port}-", f"_{port}_", f" {port} "
        ]

        for pattern in port_patterns:
            if pattern in service_str:
                return True

        port_regex = rf'\b{port}\b'
        if re.search(port_regex, service_str):
            if self._is_likely_port_reference(service_str, str(port)):
                return True

        if 'alternate_ports' in info:
            for alt_port in info['alternate_ports']:
                if (f"tcp-{alt_port}" in service_str or
                    f"udp-{alt_port}" in service_str or
                    f"port-{alt_port}" in service_str or
                    f":{alt_port}" in service_str or
                    re.search(rf'\b{alt_port}\b', service_str)):
                    return True

        port_range_pattern = r'(\d+)\s*[-–]\s*(\d+)'
        matches = re.findall(port_range_pattern, service_str)
        for start, end in matches:
            if int(start) <= port <= int(end):
                return True

        return False

    def _is_likely_port_reference(self, service_str: str, port: str) -> bool:
        """Determine if a number is likely referring to a port"""
        port_indicators = [
            'tcp', 'udp', 'port', 'service', 'allow', 'deny',
            'permit', 'block', 'listen', 'connect', 'dst', 'src'
        ]

        service_lower = service_str.lower()
        for indicator in port_indicators:
            if indicator in service_lower:
                return True

        if service_str.strip() == port:
            return True

        if re.search(rf'(^|[^0-9]){port}($|[^0-9])', service_str):
            port_num = int(port)
            if 1 <= port_num <= 65535:
                return True

        return False

    def _get_detection_method(self, service_str: str, protocol: str, info: Dict) -> str:
        """Return how the protocol was detected"""
        if protocol in service_str:
            return f"Protocol name '{protocol}' found"

        port = info['port']
        if f"tcp-{port}" in service_str or f"udp-{port}" in service_str:
            return f"Standard port notation (tcp/udp-{port})"

        if f":{port}" in service_str:
            return f"Port notation (:{port})"

        if re.search(rf'\b{port}\b', service_str):
            return f"Standalone port number {port}"

        if 'common_names' in info:
            for name in info['common_names']:
                if name in service_str:
                    return f"Common service name '{name}'"

        if 'alternate_ports' in info:
            for alt_port in info['alternate_ports']:
                if str(alt_port) in service_str:
                    return f"Alternate port {alt_port}"

        port_range_pattern = r'(\d+)\s*[-–]\s*(\d+)'
        matches = re.findall(port_range_pattern, service_str)
        for start, end in matches:
            if int(start) <= port <= int(end):
                return f"Port range {start}-{end}"

        return "Unknown detection method"

    def _calculate_protocol_score(self, protocol: str, info: Dict, rule: FirewallRule) -> Dict[str, Any]:
        """Calculate detailed score breakdown for insecure protocol"""
        score_breakdown = {
            'base_score': info['base_score'],
            'factors': {},
            'modifiers': {},
            'calculation_steps': [f"Base score for {protocol.upper()}: {info['base_score']} points"],
            'total_score': info['base_score']
        }

        for factor, points in info['score_factors'].items():
            score_breakdown['factors'][factor] = points
            score_breakdown['calculation_steps'].append(f"{factor.replace('_', ' ').title()}: +{points} points")
            score_breakdown['total_score'] += points

        if 'untrusted' in [zone.lower() for zone in rule.source_zones]:
            score_breakdown['modifiers']['untrusted_source_zone'] = 10
            score_breakdown['calculation_steps'].append("Untrusted source zone: +10 points")
            score_breakdown['total_score'] += 10

        if score_breakdown['total_score'] > 100:
            score_breakdown['calculation_steps'].append(f"Score capped at 100 (was {score_breakdown['total_score']})")
            score_breakdown['total_score'] = 100

        return score_breakdown

    def _generate_formula(self, score_breakdown: Dict[str, Any]) -> str:
        """Generate calculation formula from score breakdown"""
        components = [f"Base ({score_breakdown['base_score']})"]
        for factor, points in score_breakdown['factors'].items():
            components.append(f"{factor.replace('_', ' ').title()} ({points})")
        for modifier, points in score_breakdown.get('modifiers', {}).items():
            components.append(f"{modifier.replace('_', ' ').title()} ({points})")
        return f"Score = {' + '.join(components)} = {score_breakdown['total_score']}"