import json
from datetime import datetime
from functools import lru_cache
from importlib import resources
from typing import Dict, Any, List

from ..core.models import SecurityFinding, FirewallRule, RiskLevel

MALICIOUS_IP_LISTS = [
    "panw-bulletproof-ip-list",
    "panw-highrisk-ip-list",
    "panw-known-ip-list",
    "panw-torexit-ip-list",
]

@lru_cache(maxsize=None)
def _read_asset(filename: str) -> str:
    """Read a bundled report asset (CSS/JS) from firewall_analyzer.reporting.assets."""
    return resources.files(__package__).joinpath("assets", filename).read_text(encoding="utf-8")


class EnhancedHTMLReportGenerator:
    """Extended report generator with zone-based filtering and full rule visibility"""

    def __init__(self, detailed_mode=False, group_by_name=False):
        self.detailed_mode = detailed_mode
        self.group_by_name = group_by_name
        self.colors = {
            'signature_orange': '#EB8C00',
            'black': '#000000',
            'dark_grey': '#2C2C2C',
            'medium_grey': '#5A5A5A',
            'light_grey': '#E8E8E8',
            'very_light_grey': '#F5F5F5',
            'risk_critical': '#B71C1C',
            'risk_high': '#E65100',
            'risk_medium': '#F9A825',
            'risk_low': '#2E7D32',
            'risk_info': '#0277BD',
            'white': '#FFFFFF',
            'success': '#4CAF50',
            'warning': '#FF9800',
            'danger': '#F44336',
            'info': '#2196F3'
        }

    def generate_report(self, analysis_results: Dict[str, Any], output_file: str):
        """Generate enhanced HTML report with all new features"""
        html_content = self._generate_enhanced_html(analysis_results)

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

        print(f"\n✓ Enhanced HTML report generated: {output_file}")

    def _generate_enhanced_html(self, results: Dict[str, Any]) -> str:
        """Generate the complete enhanced HTML report"""
        self._malicious_verdict, self._malicious_critical, self._malicious_deny = self._evaluate_malicious_ip(results)
        summary = results['summary']
        stats = results['statistics']
        zone_summary = results.get('zone_summary', {})
        disabled_rules = results.get('disabled_rules', [])
        deny_rules = results.get('deny_rules', [])
        grouped_findings = results.get('grouped_findings', {})
        findings_summary = results.get('findings_summary', {})

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enhanced Firewall Rules Security Analysis Report</title>
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.4/css/jquery.dataTables.min.css">
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.4/js/jquery.dataTables.min.js"></script>
    <style>
        {self._get_css_styles()}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 Multi-Vendor Firewall Rules Security Analysis Report</h1>
            <div class="report-meta">
                <span>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
                <span>Total Rules Analyzed: {stats['total_rules']} (of {stats['all_rules_total']} total)</span>
                <span>Total Findings: {stats['total_findings']}</span>
            </div>
        </header>

        {self._generate_executive_summary(summary, stats)}
        {self._generate_filtered_rules_notice(stats)}
        {self._generate_remote_management_section(results)}
        {self._generate_logging_audit_section(results)}
        {self._generate_zone_based_analysis(zone_summary, results)}
        {self._generate_external_communications_section(results)}
        {self._generate_risk_distribution_charts(stats)}
        {self._generate_deny_any_any_section(results)}
        {self._generate_critical_findings(results)}
        {self._generate_recommendations(summary['recommendations'])}
        {self._generate_detailed_statistics(stats)}
        {self._generate_scoring_methodology()}
        {self._generate_zone_traffic_matrix(zone_summary)}
        {self._generate_high_risk_rules_table(results['high_risk_rules'])}
        {self._generate_complete_findings_table(results['findings'])}
        {self._generate_security_profile_table(results['findings'])}
        {self._generate_expired_rules_table(results['findings'])}
        {self._generate_disabled_rules_table(disabled_rules)}
        {self._generate_deny_rules_table(deny_rules)}
        {self._generate_full_rule_details_section(results.get('rules', []))}
        {self._generate_footer()}
    </div>

    <script>
        {self._get_enhanced_javascript(stats)}
    </script>
</body>
</html>"""
        return html

    def _get_css_styles(self) -> str:
        """Return the report stylesheet, prefixed with the palette as CSS variables."""
        variables = "\n".join(
            f"    --{name.replace('_', '-')}: {value};"
            for name, value in self.colors.items()
        )
        return f":root {{\n{variables}\n}}\n\n{_read_asset('report.css')}"

    def _generate_executive_summary(self, summary: Dict, stats: Dict) -> str:
        """Generate executive summary section"""
        health_class = f"health-{summary['overall_health'].lower().replace(' ', '-')}"
        rating = summary.get('posture') or {}
        score_line = (f"<div style=\"margin-top:10px;color:var(--text-muted, #6F6F6F)\">"
                      f"Posture score {rating['score']}/100 · rated on the share of assessed rules "
                      f"at each severity</div>") if rating.get('score') is not None else ""

        return f"""
        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div style="text-align: center; margin: 35px 0;">
                <div class="health-badge {health_class}">
                    Overall Risk Rating: {summary['overall_health']}
                </div>
                {score_line}
            </div>

            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{stats['total_rules']}</div>
                    <div class="stat-label">Rules Analyzed</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{summary['total_issues']}</div>
                    <div class="stat-label">Total Issues</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{summary['critical_issues']}</div>
                    <div class="stat-label">Critical Issues</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{summary['high_risk_issues']}</div>
                    <div class="stat-label">High Risk Issues</div>
                </div>
            </div>

                    {self._generate_critical_alert(summary) if summary['critical_issues'] > 0 else ''}
            {self._generate_malicious_recommendation_box() if self._malicious_verdict == 'missing' else ''}
        </div>
        """

    def _generate_deny_any_any_section(self, results):
        """Dedicated section showing Deny Any Any status per firewall."""
        deny_findings = [
            f for f in results['findings']
            if 'Deny Any Any' in f.description or 'Any Any' in f.description
        ]

        if not deny_findings:
            return ""

        rows = ""
        for f in deny_findings:
            if 'Compliant' in f.description:
                color = self.colors['risk_low']
                status = '✅ COMPLIANT'
            else:
                color = self.colors['risk_high']
                status = '⚠️ ACTION REQUIRED'

            rows += f"""
            <tr>
                <td><strong>{f.rule_name}</strong></td>
                <td style="color: {color}; font-weight: 700;">{status}</td>
                <td>{f.description}</td>
                <td>{f.recommendation}</td>
            </tr>
            """

        return f"""
        <div class="section" style="border-left: 6px solid {self.colors['signature_orange']};">
            <h2>🛡️ Deny Any Any Cleanup Rule Check (Per Firewall)</h2>
            <p style="margin-bottom: 15px; color: {self.colors['medium_grey']};">
                Verifies that each firewall ends with a Deny Any Any cleanup rule.
            </p>
            <table>
                <thead>
                    <tr>
                        <th>Firewall / Rule</th>
                        <th>Status</th>
                        <th>Details</th>
                        <th>Recommendation</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>
        """



    def _generate_critical_alert(self, summary: Dict) -> str:
        """Generate critical issues alert"""
        return f"""
        <div class="critical-alert">
            <h3>⚠️ Critical Security Issues Detected</h3>
            <p style="font-size: 1.1em;"><strong>{summary['critical_issues']}</strong> critical security issues require immediate attention.</p>
            <p>These issues pose significant security risks and should be addressed as a priority.</p>
        </div>
        """

    def _generate_filtered_rules_notice(self, stats: Dict) -> str:
        """Generate notice about rules excluded from analysis"""
        excluded_count = stats.get('disabled_rules_excluded', 0) + stats.get('deny_any_rules_excluded', 0)

        if excluded_count == 0:
            return ""

        return f"""
        <div class="section" style="background: linear-gradient(135deg, #E3F2FD 0%, {self.colors['white']} 100%); border-left: 5px solid {self.colors['info']};">
            <h2>ℹ️ Analysis Scope Information</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{stats['disabled_rules_excluded']}</div>
                    <div class="stat-label">Disabled Rules Excluded</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{stats['deny_any_rules_excluded']}</div>
                    <div class="stat-label">Deny Any/All Rules Excluded</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{stats['all_rules_total']}</div>
                    <div class="stat-label">Total Rules in File</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{stats['total_rules']}</div>
                    <div class="stat-label">Rules Analyzed</div>
                </div>
            </div>
            <p style="margin-top: 20px; color: {self.colors['medium_grey']};">
                <strong>Note:</strong> Analysis focuses on active ALLOW rules and non-trivial DENY rules.
                Disabled rules and catch-all DENY rules are excluded from security analysis but listed separately.
            </p>
        </div>
        """

    def _generate_remote_management_section(self, results):
        """List ALL remote-management protocols and how many rules allow each."""
        from ..core.models import RuleIssueType

        # Canonical protocols we display (no duplicates)
        ALL_PROTOCOLS = [
            "SSH", "Telnet", "RDP", "VNC", "WinRM (HTTP)", "WinRM (HTTPS)",
            "RSH", "rlogin", "rexec", "XDMCP", "X11", "Apple Remote Desktop",
            "TeamViewer", "AnyDesk", "LogMeIn", "GoToMyPC", "Splashtop",
            "BeyondTrust", "pcAnywhere", "Radmin",
        ]

        # Map any alias/case the checker might emit -> canonical display name
        ALIAS_TO_CANONICAL = {
            "ssh": "SSH", "telnet": "Telnet",
            "rdp": "RDP", "ms-rdp": "RDP", "ms.rdp": "RDP",
            "vnc": "VNC", "vnc-base": "VNC",
            "winrm": "WinRM (HTTP)", "winrm (http)": "WinRM (HTTP)",
            "winrm (https)": "WinRM (HTTPS)",
            "rsh": "RSH", "rlogin": "rlogin", "rexec": "rexec",
            "xdmcp": "XDMCP", "x11": "X11",
            "apple remote desktop": "Apple Remote Desktop",
            "teamviewer": "TeamViewer", "anydesk": "AnyDesk", "logmein": "LogMeIn",
            "gotomypc": "GoToMyPC", "splashtop": "Splashtop",
            "beyondtrust": "BeyondTrust", "pcanywhere": "pcAnywhere", "radmin": "Radmin",
        }

        rm = [f for f in results['findings']
              if f.issue_type == RuleIssueType.MANAGEMENT_ACCESS]

        # Count rules per protocol -- normalize every value to its canonical name
        counts = {}
        for f in rm:
            for p in (f.details or {}).get("protocols", []):
                canonical = ALIAS_TO_CANONICAL.get(str(p).strip().lower(), str(p))
                counts[canonical] = counts.get(canonical, 0) + 1

        found_rows = ""
        notfound_rows = ""
        found_total = 0
        for proto in ALL_PROTOCOLS:
            n = counts.get(proto, 0)
            if n > 0:
                found_total += 1
                found_rows += f"""
                <tr>
                    <td style="font-weight:600;">{proto}</td>
                    <td><span class="risk-badge risk-critical">FOUND</span></td>
                    <td><strong style="color:{self.colors['signature_orange']};">{n}</strong></td>
                </tr>"""
            else:
                notfound_rows += f"""
                <tr style="opacity:0.6;">
                    <td>{proto}</td>
                    <td><span class="risk-badge risk-low">NONE</span></td>
                    <td>0</td>
                </tr>"""

        return f"""
        <div class="section">
            <h2>🖥️ Remote Management Exposure</h2>
            <p style="margin-bottom:20px; color:{self.colors['medium_grey']};">
                List of remote-management protocols and how many rules allow each.
                <strong>{found_total}</strong> protocol(s) found across <strong>{len(rm)}</strong> rule(s).
            </p>
            <table>
                <thead>
                    <tr>
                        <th>Remote Management Protocol</th>
                        <th>Status</th>
                        <th>Rules Allowing It</th>
                    </tr>
                </thead>
                <tbody>
                    {found_rows}
                    {notfound_rows}
                </tbody>
            </table>
        </div>
        """

    def _generate_zone_based_analysis(self, zone_summary: Dict, results: Dict) -> str:
        """Generate zone-based traffic analysis section"""
        if not zone_summary:
            return ""

        zone_pairs_html = ""
        for pair, data in sorted(zone_summary.items(), key=lambda x: x[1]['total_rules'], reverse=True):
            zone_pairs_html += f"""
            <div class="zone-pair-card">
                <div style="font-weight: 600; font-size: 1.1em; margin-bottom: 10px;">{pair}</div>
                <div class="zone-stats">
                    <span class="zone-stat-badge allow">ALLOW: {data['allow_rules']}</span>
                    <span class="zone-stat-badge deny">DENY: {data['deny_rules']}</span>
                    <span class="zone-stat-badge total">TOTAL: {data['total_rules']}</span>
                </div>
            </div>
            """

        return f"""
        <div class="section">
            <h2>🌐 Zone-Based Traffic Analysis</h2>
            <p style="margin-bottom: 20px;">Analysis of traffic flows between configured network zones:</p>
            <div class="zone-pairs-grid">
                {zone_pairs_html}
            </div>
        </div>
        """

    def _generate_external_communications_section(self, results):
        rules = results.get("all_rules") or results.get("rules", [])

        rules_data = []

        for rule in rules:
            rules_data.append({
                "id": str(rule.id),
                "name": str(rule.name),
                "source_zones": list(rule.source_zones),
                "destination_zones": list(rule.dest_zones),
                "source_addresses": list(rule.source_addresses),
                "destination_addresses": list(rule.dest_addresses),
                "applications": list(rule.applications),
                "services": list(rule.services),
                "action": str(rule.action),
                "disabled": bool(rule.disabled)
            })


        rules_json = json.dumps(rules_data)

        return f"""
        <div class="section">
            <h2>🌍 External Communications Discovery</h2>

            <p>
                Enter external zones to identify enabled Allow rules where the
                source zone or destination zone is external.
                Rules using Any are shown as potential external communication.
            </p>

            <div style="margin:20px 0;">
                <input
                    type="text"
                    id="externalZoneInput"
                    placeholder="Enter external zone"
                    style="
                        padding:12px;
                        width:320px;
                        border:2px solid #E8E8E8;
                        border-radius:6px;
                    "
                >

                <button
                    type="button"
                    onclick="addExternalZone()"
                    style="
                        padding:12px 18px;
                        background:#EB8C00;
                        color:white;
                        border:none;
                        border-radius:6px;
                        cursor:pointer;
                        font-weight:bold;
                    "
                >
                    + Add
                </button>

                <button
                    type="button"
                    onclick="runExternalDiscovery()"
                    style="
                        padding:12px 18px;
                        background:#2C2C2C;
                        color:white;
                        border:none;
                        border-radius:6px;
                        cursor:pointer;
                        font-weight:bold;
                    "
                >
                    Analyze
                </button>

                <button
                    type="button"
                    onclick="analyzeExternalPorts()"
                >
                    Find All Ports
                </button>

                <button
                    type="button"
                    onclick="findInsecurePorts()"
                >
                    Show Insecure Ports
                </button>

                
            </div>

            <div id="externalZonesList" style="margin:15px 0;"></div>
            <div id="externalPortsTable"></div>

            <div id="insecurePortsTable"></div>

            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number" id="totalAllowRulesCount">
                        0
                    </div>
                    <div class="stat-label">
                        Active Allow Rules
                    </div>
                </div>

                <div class="stat-card">
                    <div class="stat-number" id="confirmedExternalCount">
                        0
                    </div>
                    <div class="stat-label">
                        Confirmed External
                    </div>
                </div>

                <div class="stat-card">
                    <div class="stat-number" id="potentialExternalCount">
                        0
                    </div>
                    <div class="stat-label">
                        Potential External (Any)
                    </div>
                </div>

                <div class="stat-card">
                    <div class="stat-number" id="internalRulesCount">
                        0
                    </div>
                    <div class="stat-label">
                        Internal Rules
                    </div>
                </div>
            </div>

            <div
                id="externalDiscoveryMessage"
                style="margin-top:20px;"
            ></div>

            <button
                type="button"
                id="downloadExternalCsvButton"
                onclick="downloadExternalCommunicationsCSV()"
                style="
                    display:none;
                    margin-top:20px;
                    padding:12px 18px;
                    background:#2E7D32;
                    color:white;
                    border:none;
                    border-radius:6px;
                    cursor:pointer;
                    font-weight:bold;
                "
            >
                Download External Communications CSV
            </button>

            <div
                id="externalResultsTable"
                style="margin-top:20px; overflow-x:auto;"
            ></div>
        </div>

        <script>
            window.externalDiscoveryRules = {rules_json};
        </script>
        """

    def _generate_logging_audit_section(self, results):
        """Logging audit: enabled vs not, and lists of not-logged Allow/Deny rules."""
        from ..core.models import RuleIssueType
        from ..analysis.logging_audit_checker import _logging_enabled

        all_rules = results.get('all_rules') or results.get('rules', [])

        checked = [r for r in all_rules if _logging_enabled(r) is not None]
        if not checked:
            return ""

        enabled_count = sum(1 for r in checked if _logging_enabled(r))
        not_enabled = [r for r in checked if not _logging_enabled(r)]
        no_log_allow = [r for r in not_enabled if r.action.lower() == "allow"]
        no_log_deny = [r for r in not_enabled if r.action.lower() == "deny"]

        def rows(rule_list, badge):
            html = ""
            for r in rule_list:
                html += f"""
                <tr>
                    <td>{r.id}</td>
                    <td style="font-weight:600;">{r.name}</td>
                    <td><span class="action-badge {r.action.lower()}">{r.action.upper()}</span></td>
                    <td><span class="risk-badge {badge}">NO LOGGING</span></td>
                </tr>"""
            return html or '<tr><td colspan="4" style="color:#888;">None</td></tr>'

        return f"""
        <div class="section">
            <h2>📝 Logging Configuration Audit</h2>
            <p style="margin-bottom:20px; color:{self.colors['medium_grey']};">
                Checks whether rules have logging enabled for auditability.
            </p>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{enabled_count}</div>
                    <div class="stat-label">Logging Enabled</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(not_enabled)}</div>
                    <div class="stat-label">No Logging</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(no_log_allow)}</div>
                    <div class="stat-label">No Log + Allow (Critical)</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(no_log_deny)}</div>
                    <div class="stat-label">No Log + Deny (High)</div>
                </div>
            </div>
            <h3 style="margin-top:30px;">🔴 Allow Rules Without Logging (Critical)</h3>
            <table>
                <thead><tr><th>ID</th><th>Rule Name</th><th>Action</th><th>Status</th></tr></thead>
                <tbody>{rows(no_log_allow, "risk-critical")}</tbody>
            </table>
            <h3 style="margin-top:30px;">🟠 Deny Rules Without Logging (High)</h3>
            <table>
                <thead><tr><th>ID</th><th>Rule Name</th><th>Action</th><th>Status</th></tr></thead>
                <tbody>{rows(no_log_deny, "risk-high")}</tbody>
            </table>
        </div>
        """

    def _generate_zone_traffic_matrix(self, zone_summary: Dict) -> str:
        """Generate zone traffic matrix visualization"""
        if not zone_summary or len(zone_summary) < 2:
            return ""

        zones = set()
        for pair in zone_summary.keys():
            src, dst = pair.split(' → ')
            zones.add(src)
            zones.add(dst)

        zones = sorted(zones)

        matrix_data = {}
        for zone in zones:
            matrix_data[zone] = {}
            for zone2 in zones:
                pair = f"{zone} → {zone2}"
                if pair in zone_summary:
                    matrix_data[zone][zone2] = zone_summary[pair]['total_rules']
                else:
                    matrix_data[zone][zone2] = 0

        matrix_html = "<table class='zone-matrix'><thead><tr><th>From \\ To</th>"
        for zone in zones:
            matrix_html += f"<th>{zone}</th>"
        matrix_html += "</tr></thead><tbody>"

        for src_zone in zones:
            matrix_html += f"<tr><th>{src_zone}</th>"
            for dst_zone in zones:
                count = matrix_data[src_zone][dst_zone]
                color_class = "high" if count > 10 else "medium" if count > 0 else "low"
                matrix_html += f"<td class='matrix-cell {color_class}'>{count}</td>"
            matrix_html += "</tr>"

        matrix_html += "</tbody></table>"

        return f"""
        <div class="section">
            <h2>📊 Zone Traffic Matrix</h2>
            <p style="margin-bottom: 20px;">Number of rules for each source → destination zone pair:</p>
            {matrix_html}
        </div>
        """

    def _generate_risk_distribution_charts(self, stats: Dict) -> str:
        """Generate risk distribution charts section"""
        return f"""
        <div class="section">
            <h2>📈 Risk Distribution Analysis</h2>
            <div class="chart-container">
                <div class="chart-box">
                    <h3>Findings by Risk Level</h3>
                    <canvas id="riskChart"></canvas>
                </div>
                <div class="chart-box">
                    <h3>Findings by Issue Type</h3>
                    <canvas id="typeChart"></canvas>
                </div>
            </div>
        </div>
        """

    def _evaluate_malicious_ip(self, results):
        rules = results.get('all_rules') or results.get('rules', [])
        critical_rules, deny_rules = [], []
        for rule in rules:
            refs = []
            for v in list(rule.source_addresses) + list(rule.dest_addresses):
                vl = str(v).lower()
                for mal in MALICIOUS_IP_LISTS:
                    if mal.lower() in vl:
                        refs.append(mal)
            refs = sorted(set(refs))
            if not refs:
                continue
            if rule.action.lower() == 'allow':
                critical_rules.append((rule, refs))
            elif rule.action.lower() == 'deny':
                deny_rules.append((rule, refs))
        if critical_rules:
            verdict = 'critical'
        elif deny_rules:
            verdict = 'approved'
        else:
            verdict = 'missing'
        return verdict, critical_rules, deny_rules

    def _generate_malicious_recommendation_box(self, results=None):
        # Detect vendor from the rules
        rules = (results or {}).get('all_rules') or (results or {}).get('rules', [])
        vendor = rules[0].vendor_type.value if rules else "generic"

        # Vendor-specific malicious IP references
        PALO_ALTO_LISTS = [
            "panw-bulletproof-ip-list", "panw-highrisk-ip-list",
            "panw-known-ip-list", "panw-torexit-ip-list",
        ]
        FORTINET_LISTS = [
            "Botnet-C&C.Server", "Malicious-Malicious.Server", "Phishing-Phishing.Server",
            "Spam-Spamming.Server", "Proxy-Proxy.Server", "Tor-Exit.Node",
            "Tor-Relay.Node", "Tor-Tor.Node", "VPN-Anonymous.VPN",
            "Blockchain-Crypto.Mining.Pool",
        ]

        if vendor == "fortinet":
            lists = FORTINET_LISTS
            label = "FortiGate FortiGuard IP Reputation (ISDB) objects"
        elif vendor == "palo_alto":
            lists = PALO_ALTO_LISTS
            label = "Palo Alto built-in malicious IP lists"
        else:
            lists = PALO_ALTO_LISTS + FORTINET_LISTS
            label = "known malicious IP lists / threat feeds"

        items = "".join(f"<li>{m}</li>" for m in lists)
        return f"""
        <div class="critical-alert" style="border-color: {self.colors['warning']};
             background: linear-gradient(135deg, #FFF8E1 0%, {self.colors['white']} 100%);">
            <h3 style="color: {self.colors['warning']};">⚠️ Recommended: Add Malicious IP Blocking</h3>
            <p style="font-size: 1.1em;">No rule was found that blocks the {label}.</p>
            <p>It is <strong>recommended</strong> to add a <strong>DENY</strong> rule
               (source + destination) referencing:</p>
            <ul style="margin-left: 25px; margin-top: 10px; line-height: 1.8;">{items}</ul>
        </div>
        """

    def _generate_critical_findings(self, results: Dict) -> str:
        """Generate critical findings section"""
        critical_findings = [f for f in results['findings'] if f.risk_level == RiskLevel.CRITICAL]

        if not critical_findings:
            return ""

        findings_html = ""
        for finding in critical_findings[:10]:
            findings_html += f"""
            <div class="recommendation-item">
                <span class="risk-badge risk-critical">CRITICAL</span>
                <div style="flex-grow: 1;">
                    <strong style="font-size: 1.1em;">Rule: {finding.rule_name}</strong><br>
                    <span style="color: {self.colors['medium_grey']}; font-size: 1em;">{finding.description}</span><br>
                    <em style="color: {self.colors['signature_orange']}; font-size: 0.95em;">Recommendation: {finding.recommendation}</em>
                    <div class="formula" style="margin-top: 10px;">
                        <strong>Score Calculation:</strong> {finding.calculation_formula}
                    </div>
                </div>
            </div>
            """

        return f"""
        <div class="section">
            <h2>🚨 Critical Security Findings</h2>
            {findings_html}
        </div>
        """

    def _generate_recommendations(self, recommendations: List[Dict]) -> str:
        """Generate recommendations section"""
        if not recommendations:
            return ""

        rec_html = ""
        for rec in recommendations:
            risk_class = f"risk-{rec['risk_level']}"
            rec_html += f"""
            <div class="recommendation-item">
                <span class="priority-badge">{rec['priority']}</span>
                <div style="flex-grow: 1;">
                    <span class="risk-badge {risk_class}">{rec['risk_level']}</span>
                    <span style="margin-left: 10px; font-weight: 600;">Impact Score: {rec['score']}</span><br>
                    <span style="margin-top: 10px; display: block; font-size: 1.05em;">{rec['recommendation']}</span>
                </div>
            </div>
            """

        return f"""
        <div class="section">
            <h2>💡 Top Security Recommendations</h2>
            <div class="recommendations">
                {rec_html}
            </div>
        </div>
        """

    def _generate_detailed_statistics(self, stats: Dict) -> str:
        """Generate detailed statistics section"""
        protocols_html = ""
        if stats['insecure_protocols_found']:
            protocols = ", ".join([p.upper() for p in stats['insecure_protocols_found']])
            protocols_html = f"""
            <h3 style="margin-top: 35px;">Insecure Protocols Detected</h3>
            <div style="background: linear-gradient(135deg, #FFEBEE 0%, {self.colors['white']} 100%); padding: 25px; border-radius: 10px; margin-top: 15px; border-left: 5px solid {self.colors['risk_critical']};">
                <strong style="color: {self.colors['dark_grey']}; font-size: 1.1em;">Protocols:</strong>
                <span style="color: {self.colors['risk_critical']}; font-size: 1.1em; font-weight: 600;">{protocols}</span>
            </div>
            """

        return f"""
        <div class="section">
            <h2>📊 Detailed Statistics</h2>

            <h3>Overly Permissive Rules</h3>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{stats['rules_with_any']['source']}</div>
                    <div class="stat-label">Any Source</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{stats['rules_with_any']['destination']}</div>
                    <div class="stat-label">Any Destination</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{stats['rules_with_any']['service']}</div>
                    <div class="stat-label">Any Service</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{stats['rules_with_any']['multiple_any']}</div>
                    <div class="stat-label">Multiple Any Fields</div>
                </div>
            </div>

            <h3 style="margin-top: 35px;">Other Metrics</h3>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{stats.get('subnet_overlaps_found', 0)}</div>
                    <div class="stat-label">Subnet Overlaps Found</div>
                </div>
            </div>

            {protocols_html}
        </div>
        """

    def _generate_scoring_methodology(self) -> str:
        """Generate scoring methodology section"""
        return f"""
        <div class="section">
            <h2>📐 Scoring Methodology</h2>

            <div class="methodology-box">
                <h3>Risk Score Calculation</h3>
                <p style="font-size: 1.05em; margin-bottom: 20px;">Each security finding is assigned a risk score based on multiple factors.</p>

                <div class="formula">
                    Total Risk Score = Base Score + Σ(Factor Scores) + Σ(Modifiers)
                </div>

                <h4 style="margin-top: 25px;">Score Components:</h4>
                <ul style="margin-left: 25px; line-height: 2;">
                    <li><strong>Base Score:</strong> Initial score based on the security issue type</li>
                    <li><strong>Factor Scores:</strong> Additional points for specific risk factors</li>
                    <li><strong>Modifiers:</strong> Contextual adjustments to the score</li>
                </ul>

                <h4 style="margin-top: 25px;">Risk Level Thresholds:</h4>
                <div style="margin-top: 15px;">
                    <div class="score-component">
                        <span><span class="risk-badge risk-critical">CRITICAL</span></span>
                        <span class="score-value">≥ 90 points</span>
                    </div>
                    <div class="score-component">
                        <span><span class="risk-badge risk-high">HIGH</span></span>
                        <span class="score-value">70-89 points</span>
                    </div>
                    <div class="score-component">
                        <span><span class="risk-badge risk-medium">MEDIUM</span></span>
                        <span class="score-value">40-69 points</span>
                    </div>
                    <div class="score-component">
                        <span><span class="risk-badge risk-low">LOW</span></span>
                        <span class="score-value">20-39 points</span>
                    </div>
                    <div class="score-component">
                        <span><span class="risk-badge risk-info">INFO</span></span>
                        <span class="score-value">&lt; 20 points</span>
                    </div>
                </div>
            </div>
        </div>
        """

    

    def _generate_high_risk_rules_table(self, high_risk_rules: List[FirewallRule]) -> str:
        """Generate high risk rules table"""
        if not high_risk_rules:
            return ""

        rows = ""
        for rule in sorted(high_risk_rules, key=lambda r: r.risk_score, reverse=True):
            rows += f"""
            <tr>
                <td>{rule.id}</td>
                <td>{rule.name}</td>
                <td>{rule.vendor_type.value.replace('_', ' ').title()}</td>
                <td><strong style="color: {self.colors['signature_orange']}; font-size: 1.1em;">{rule.risk_score}</strong></td>
                <td>{len(rule.findings)}</td>
                <td>{rule.action}</td>
                <td>{'Yes' if rule.disabled else 'No'}</td>
            </tr>
            """

        return f"""
        <div class="section">
            <h2>⚠️ High Risk Rules ({len(high_risk_rules)} Total)</h2>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Name</th>
                        <th>Vendor</th>
                        <th>Risk Score</th>
                        <th>Issues</th>
                        <th>Action</th>
                        <th>Disabled</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>
        """

    def _generate_complete_findings_table(self, findings: List[SecurityFinding]) -> str:
        """Generate complete findings table with all findings"""
        if not findings:
            return ""

        findings_by_risk = {}
        for finding in findings:
            if finding.risk_level not in findings_by_risk:
                findings_by_risk[finding.risk_level] = []
            findings_by_risk[finding.risk_level].append(finding)

        risk_order = [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFO]

        html = f"""
        <div class="section">
            <h2>🔍 Complete Security Findings ({len(findings)} Total)</h2>
        """

        for risk_level in risk_order:
            if risk_level not in findings_by_risk:
                continue

            risk_findings = sorted(findings_by_risk[risk_level], key=lambda f: f.score, reverse=True)
            risk_class = f"risk-{risk_level.value}"

            table_id = f"findingsTable_{risk_level.value}"
            rows = ""

            for finding in risk_findings:
                rows += f"""
                <tr>
                    <td>{finding.rule_id}</td>
                    <td>{finding.rule_name}</td>
                    <td>{finding.issue_type.value.replace('_', ' ').title()}</td>
                    <td>{finding.description}</td>
                    <td><strong style="color: {self.colors['signature_orange']};">{finding.score}</strong></td>
                    <td>{finding.calculation_formula[:80]}...</td>
                </tr>
                """

            html += f"""
            <h3 style="margin-top: 30px;">
                <span class="risk-badge {risk_class}">{risk_level.value.upper()}</span>
                Risk Findings ({len(risk_findings)} items)
            </h3>
            <table id="{table_id}" class="findings-datatable">
                <thead>
                    <tr>
                        <th>Rule ID</th>
                        <th>Rule Name</th>
                        <th>Issue Type</th>
                        <th>Description</th>
                        <th>Score</th>
                        <th>Formula</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
            """

        html += "</div>"
        return html

    def _get_enhanced_javascript(self, stats: Dict) -> str:
        """Return the report script, prefixed with the data it reads at render time."""
        risk_data = stats.get("findings_by_risk", {})
        type_data = stats.get("findings_by_type", {})

        config = {
            "colors": self.colors,
            "riskCounts": {
                level: risk_data.get(level, 0)
                for level in ("critical", "high", "medium", "low", "info")
            },
            "typeLabels": [key.replace("_", " ").title() for key in type_data],
            "typeValues": list(type_data.values()),
        }

        return f"var REPORT_CONFIG = {json.dumps(config)};\n\n{_read_asset('report.js')}"

    def _generate_expired_rules_table(self, findings):
        """Generate table of expired rules (only from ExpiredRuleAnalyzer)."""
        expired = [f for f in findings if f.issue_type.value == 'expired']

        if not expired:
            return ""

        seen = set()
        unique_expired = []
        for f in expired:
            # Only include OUR analyzer's findings (they have 'days_passed')
            if 'days_passed' not in f.details:
                continue

            date = f.details.get('expiry_date')

            # Skip if no valid date
            if not date or str(date).strip() in ('', '-', 'N/A', 'None'):
                continue

            # Skip duplicates
            if f.rule_id in seen:
                continue

            seen.add(f.rule_id)
            unique_expired.append(f)

        if not unique_expired:
            return ""

        rows = ""
        for f in sorted(unique_expired, key=lambda x: x.details.get('days_passed', 0), reverse=True):
            days = f.details.get('days_passed', 'N/A')
            date = f.details.get('expiry_date', 'N/A')
            rows += f"""
            <tr>
                <td>{f.rule_id}</td>
                <td>{f.rule_name}</td>
                <td>{date}</td>
                <td>{days}</td>
                <td>{f.recommendation}</td>
            </tr>
            """

        return f"""
        <div class="section" style="border-left: 6px solid {self.colors['risk_medium']};">
            <h2>⏰ Expired / Temporary Rules ({len(unique_expired)} Total)</h2>
            <p style="margin-bottom: 20px; color: {self.colors['medium_grey']};">
                Time-bound rules whose date has already passed. These should be reviewed, renewed, or removed.
            </p>
            <table>
                <thead>
                    <tr>
                        <th>Rule ID</th>
                        <th>Rule Name</th>
                        <th>Expired Date</th>
                        <th>Days Passed</th>
                        <th>Recommendation</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>
        """

    def _generate_security_profile_table(self, findings):
        """Generate table of rules WITH security profiles (deduplicated)."""
        profile_findings = [
            f for f in findings
            if 'HASPROFILE' in f.description
        ]

        if not profile_findings:
            return ""

        # Deduplicate by rule_id
        seen = set()
        unique = []
        for f in profile_findings:
            if f.rule_id not in seen:
                seen.add(f.rule_id)
                unique.append(f)

        rows = ""
        for f in unique:
            profile = f.details.get('security_profile', '')
            rows += f"""
            <tr>
                <td>{f.rule_id}</td>
                <td>{f.rule_name}</td>
                <td style="color: {self.colors['risk_low']}; font-weight: 600;">{profile}</td>
                <td>{f.recommendation}</td>
            </tr>
            """

        return f"""
        <div class="section" style="background: linear-gradient(135deg, #E8F5E9 0%, {self.colors['white']} 100%); border-left: 6px solid {self.colors['risk_low']};">
            <h2>🛡️ Rules With Security Profiles ({len(unique)} Total)</h2>
            <p style="margin-bottom: 20px; color: {self.colors['medium_grey']};">
                ALLOW rules that have security profiles applied (threat inspection enabled). These are correctly protected.
            </p>
            <table>
                <thead>
                    <tr>
                        <th>Rule ID</th>
                        <th>Rule Name</th>
                        <th>Security Profiles</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>
        """

    
    def _generate_disabled_rules_table(self, disabled_rules: List[FirewallRule]) -> str:
        """Generate table of disabled rules"""
        if not disabled_rules:
            return ""

        rows = ""
        for rule in sorted(disabled_rules, key=lambda r: r.name)[:100]:
            rows += f"""
            <tr>
                <td>{rule.id}</td>
                <td>{rule.name}</td>
                <td>{rule.vendor_type.value.replace('_', ' ').title()}</td>
                <td>{rule.action}</td>
                <td>{len(rule.source_addresses)} sources</td>
                <td>{len(rule.dest_addresses)} destinations</td>
            </tr>
            """

        return f"""
        <div class="section">
            <h2>⊘ Disabled Rules ({len(disabled_rules)} Total)</h2>
            <p style="margin-bottom: 20px; color: {self.colors['medium_grey']};">
                These rules are disabled and not included in active security analysis.
            </p>
            <table>
                <thead>
                    <tr>
                        <th>Rule ID</th>
                        <th>Name</th>
                        <th>Vendor</th>
                        <th>Action</th>
                        <th>Sources</th>
                        <th>Destinations</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>
        """

    def _generate_deny_rules_table(self, deny_rules: List[FirewallRule]) -> str:
        """Generate table of DENY rules"""
        if not deny_rules:
            return ""

        deny_rules_filtered = [r for r in deny_rules if not all(
            addr.lower() == 'any' for addr in r.source_addresses + r.dest_addresses
        )]

        if not deny_rules_filtered:
            return ""

        rows = ""
        for rule in sorted(deny_rules_filtered, key=lambda r: r.name)[:50]:
            src_display = ', '.join(rule.source_addresses[:2]) + ('...' if len(rule.source_addresses) > 2 else '')
            dst_display = ', '.join(rule.dest_addresses[:2]) + ('...' if len(rule.dest_addresses) > 2 else '')

            rows += f"""
            <tr>
                <td>{rule.id}</td>
                <td>{rule.name}</td>
                <td>{src_display}</td>
                <td>{dst_display}</td>
                <td>{', '.join(rule.services[:2]) + ('...' if len(rule.services) > 2 else '')}</td>
            </tr>
            """

        return f"""
        <div class="section">
            <h2>🚫 DENY Rules ({len(deny_rules_filtered)} Total)</h2>
            <p style="margin-bottom: 20px; color: {self.colors['medium_grey']};">
                Non-trivial DENY rules shown for reference. Catch-all deny any rules are excluded.
            </p>
            <table>
                <thead>
                    <tr>
                        <th>Rule ID</th>
                        <th>Name</th>
                        <th>Source</th>
                        <th>Destination</th>
                        <th>Service</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>
        """
    

    def _generate_full_rule_details_section(self, rules: List[FirewallRule]) -> str:
        """Generate comprehensive section with expandable rule details"""
        if not rules:
            return ""

        # Sort rules by risk score (descending - highest risk first)
        sorted_rules = sorted(rules, key=lambda r: r.risk_score, reverse=True)

        rules_html = ""
        for rule_idx, rule in enumerate(sorted_rules):
            src_tags = self._format_address_list(rule.source_addresses)
            dst_tags = self._format_address_list(rule.dest_addresses)
            svc_tags = self._format_service_list(rule.services)

            action_class = 'allow' if rule.action.lower() == 'allow' else 'deny'

            # Generate findings for this rule
            findings_html = self._format_rule_findings(rule.findings)

            # Risk score color coding
            if rule.risk_score >= 90:
                risk_color = self.colors['risk_critical']
                risk_indicator = '🔴'
            elif rule.risk_score >= 70:
                risk_color = self.colors['risk_high']
                risk_indicator = '🟠'
            elif rule.risk_score >= 40:
                risk_color = self.colors['risk_medium']
                risk_indicator = '🟡'
            elif rule.risk_score >= 20:
                risk_color = self.colors['risk_low']
                risk_indicator = '🟢'
            else:
                risk_color = self.colors['risk_info']
                risk_indicator = '🔵'

            rules_html += f"""
            <div class="rule-detail-section" id="rule-{rule_idx}">
                <div class="rule-detail-header" onclick="toggleRuleDetails({rule_idx})">
                    <div>
                        <h4 style="margin: 0;">
                            <span style="font-size: 1.4em; margin-right: 8px;">{risk_indicator}</span>
                            Rule ID: {rule.id} - {rule.name}
                        </h4>
                        <span style="color: {self.colors['medium_grey']}; font-size: 0.9em;">Click to expand/collapse details</span>
                    </div>
                    <div style="text-align: right;">
                        <span class="action-badge {action_class}">{rule.action.upper()}</span>
                        <span style="margin-left: 10px; font-weight: 600; color: {risk_color}; font-size: 1.1em;">Risk Score: {rule.risk_score}</span>
                    </div>
                </div>

                <div id="rule-details-{rule_idx}" class="collapsed" style="margin-top: 20px;">
                    <div class="rule-detail-body">
                        <div class="detail-group">
                            <h5>Basic Information</h5>
                            <div class="detail-item">
                                <span class="detail-label">Rule ID:</span>
                                <span class="detail-value">{rule.id}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Rule Name:</span>
                                <span class="detail-value">{rule.name}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Vendor:</span>
                                <span class="detail-value">{rule.vendor_type.value.replace('_', ' ').title()}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Action:</span>
                                <span class="detail-value"><span class="action-badge {action_class}">{rule.action.upper()}</span></span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Disabled:</span>
                                <span class="detail-value">{'Yes' if rule.disabled else 'No'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Risk Score:</span>
                                <span class="detail-value" style="font-weight: 700; color: {risk_color}; font-size: 1.05em;">{rule.risk_score}</span>
                            </div>
                        </div>

                        <div class="detail-group">
                            <h5>Zone Configuration</h5>
                            <div class="detail-item">
                                <span class="detail-label">Source Zones:</span>
                                <span class="detail-value">{', '.join(rule.source_zones) if rule.source_zones else 'N/A'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Destination Zones:</span>
                                <span class="detail-value">{', '.join(rule.dest_zones) if rule.dest_zones else 'N/A'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Rule Usage:</span>
                                <span class="detail-value">{rule.rule_usage or 'N/A'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Modified:</span>
                                <span class="detail-value">{rule.modified or 'N/A'}</span>
                            </div>
                        </div>

                        <div class="detail-group" style="grid-column: 1 / -1;">
                            <h5>Source Addresses ({len(rule.source_addresses)})</h5>
                            <div class="detail-value" style="margin-top: 8px;">
                                {src_tags}
                            </div>
                        </div>

                        <div class="detail-group" style="grid-column: 1 / -1;">
                            <h5>Destination Addresses ({len(rule.dest_addresses)})</h5>
                            <div class="detail-value" style="margin-top: 8px;">
                                {dst_tags}
                            </div>
                        </div>

                        <div class="detail-group" style="grid-column: 1 / -1;">
                            <h5>Services ({len(rule.services)})</h5>
                            <div class="detail-value" style="margin-top: 8px;">
                                {svc_tags}
                            </div>
                        </div>

                        <div class="detail-group" style="grid-column: 1 / -1;">
                            <h5>Applications</h5>
                            <div class="detail-value">
                                {', '.join(rule.applications) if rule.applications else 'N/A'}
                            </div>
                        </div>

                        <div class="detail-group" style="grid-column: 1 / -1;">
                            <h5>Source Users</h5>
                            <div class="detail-value">
                                {', '.join(rule.source_users) if rule.source_users else 'N/A'}
                            </div>
                        </div>

                        {findings_html}
                    </div>
                </div>
            </div>
            """

        return f"""
        <div class="section">
            <h2>📋 Complete Rule Details (All {len(rules)} Active Rules - Sorted by Risk Score)</h2>
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px;">
                <div style="display: flex; gap: 20px; flex-wrap: wrap;">
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span style="font-size: 1.4em;">🔴</span>
                        <span>Critical (≥90)</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span style="font-size: 1.4em;">🟠</span>
                        <span>High (70-89)</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span style="font-size: 1.4em;">🟡</span>
                        <span>Medium (40-69)</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span style="font-size: 1.4em;">🟢</span>
                        <span>Low (20-39)</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span style="font-size: 1.4em;">🔵</span>
                        <span>Info (<20)</span>
                    </div>
                </div>
                <div style="text-align: right;">
                    <button onclick="toggleAllRules()" style="padding: 10px 20px; background: {self.colors['signature_orange']}; color: {self.colors['white']}; border: none; border-radius: 6px; cursor: pointer; font-weight: 600;">
                        Expand/Collapse All
                    </button>
                </div>
            </div>
            <p style="margin-bottom: 20px; color: {self.colors['medium_grey']};">Click on any rule to expand and view all details. Rules are sorted by risk score (highest first)</p>
            {rules_html}
        </div>
        """

    def _format_address_list(self, addresses: List[str]) -> str:
        """Format address list with styling"""
        html = ""
        for addr in addresses:
            if addr.lower() == 'any':
                html += f"<span class='address-tag any'>ANY</span>"
            elif '/' in addr:
                html += f"<span class='address-tag subnet'>{addr}</span>"
            else:
                html += f"<span class='address-tag ip'>{addr}</span>"
        return html

    def _format_service_list(self, services: List[str]) -> str:
        """Format service list with styling"""
        html = ""
        for svc in services:
            if svc.lower() == 'any':
                html += f"<span class='service-tag any'>ANY</span>"
            else:
                html += f"<span class='service-tag'>{svc}</span>"
        return html

    def _format_rule_findings(self, findings: List[SecurityFinding]) -> str:
        """Format findings for rule detail view"""
        if not findings:
            return f"""
            <div class="detail-group" style="grid-column: 1 / -1; background: linear-gradient(135deg, #C8E6C9 0%, {self.colors['white']} 100%);">
                <h5>Security Findings</h5>
                <div style="color: {self.colors['risk_low']}; font-weight: 600;">✓ No security findings for this rule</div>
            </div>
            """

        html = f"""
        <div class="detail-group" style="grid-column: 1 / -1;">
            <h5>Security Findings ({len(findings)})</h5>
        """

        for finding in findings:
            html += f"""
            <div style="background: {self.colors['white']}; padding: 15px; border-radius: 8px; margin-top: 12px; border-left: 5px solid var(--risk-{finding.risk_level.value}, {self.colors['risk_' + finding.risk_level.value]});">
                <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 10px;">
                    <span class="risk-badge risk-{finding.risk_level.value}">{finding.risk_level.value.upper()}</span>
                    <span style="font-weight: 600; color: {self.colors['signature_orange']};">Score: {finding.score}</span>
                </div>
                <div style="font-weight: 600; margin-bottom: 8px;">{finding.issue_type.value.replace('_', ' ').title()}</div>
                <div style="color: {self.colors['medium_grey']}; margin-bottom: 8px;">{finding.description}</div>
                <div style="background: {self.colors['very_light_grey']}; padding: 10px; border-radius: 6px; font-size: 0.95em;">
                    <strong>Recommendation:</strong> {finding.recommendation}
                </div>
                <div style="background: {self.colors['dark_grey']}; color: {self.colors['white']}; padding: 10px; border-radius: 6px; font-size: 0.85em; margin-top: 10px; font-family: monospace; overflow-x: auto;">
                    <strong>Calculation:</strong> {finding.calculation_formula}
                </div>
            </div>
            """

        html += "</div>"
        return html

    def _generate_footer(self) -> str:
        """Generate footer"""
        return f"""
        <footer>
            <p><strong>Multi-Vendor Firewall Security Analysis Report</strong></p>
            <p>Enhanced Security Analyzer - Full Implementation with All Features</p>
            <p style="margin-top: 12px; opacity: 0.9;">Zone-Based Analysis • Subnet Overlap Detection • Complete Rule Visibility • Comprehensive Risk Scoring</p>
            <p style="margin-top: 8px; opacity: 0.8;">Report generated on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}</p>
        </footer>
        """