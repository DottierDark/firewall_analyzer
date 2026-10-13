"""
Compliance Analyzer  --  NCA Essential Cybersecurity Controls (ECC-1:2018) mapping.

Framework:
  National Cybersecurity Authority (NCA) - Essential Cybersecurity Controls
  Main Domain 2: Cybersecurity Defence
    2-5   Networks Security Management        (2-5-3-3, 2-5-3-5, 2-5-3-8)
    2-12  Event Logs and Monitoring Mgmt      (2-12-2)
    2-15  Web Application Security            (2-15-3-3)

Vendor coverage:
  Column names for EVERY vendor supported by the ConfigurationManager are
  defined here in VENDOR_FIELDS -- palo_alto, cisco_asa, fortinet, checkpoint,
  juniper_srx and generic. The vendor is detected automatically from
  rule.vendor_type, so no change is needed in the manager.
"""

from ..core.models import SecurityFinding, RuleIssueType, RiskLevel


# ---------------------------------------------------------------------------
# Detection vocabularies
# ---------------------------------------------------------------------------

INSECURE_PROTOCOLS = [
    "http", "telnet", "ftp", "ftp-data", "tftp", "rlogin", "rsh",
    "pop3", "imap", "smtp", "snmp", "ldap", "netbios", "smbv1",
    "www", "web-browsing", "tcp-80", "tcp-23", "tcp-21", "tcp-25",
    "tcp-110", "tcp-143", "tcp-389", "tcp-69",
]

MALICIOUS_REFERENCES = [
    "panw-bulletproof-ip-list", "panw-highrisk-ip-list",
    "panw-known-ip-list", "panw-torexit-ip-list",
    "botnet", "malicious", "phishing", "spam", "tor-exit", "tor-relay",
    "anonymous.vpn", "crypto.mining", "proxy-proxy", "c&c", "cnc",
]

RISKY_WEB_KEYWORDS = [
    "file-sharing", "filesharing", "file-storage", "cloud-storage",
    "dropbox", "mega", "mediafire", "wetransfer", "torrent", "bittorrent",
    "remote-access", "teamviewer", "anydesk", "vnc", "rdp", "logmein",
    "ultrasurf", "psiphon", "tor", "proxy", "anonymizer",
]

LOGGING_OFF_VALUES = ["", "no", "none", "disabled", "disable", "off", "false", "0", "-"]
EMPTY_VALUES = ("", "-", "--", "n/a", "none", "null", "no-inspection")


# ---------------------------------------------------------------------------
# VENDOR FIELD MAP -- one block per vendor supported by ConfigurationManager.
# To support a new vendor, add a block here only.
# ---------------------------------------------------------------------------

VENDOR_FIELDS = {
    "palo_alto": {
        "services":         ["Service", "Services"],
        "applications":     ["Application", "Applications"],
        "logging":          ["Log Setting", "Log at Session End", "Log Forwarding", "Log End"],
        "av_profile":       ["Antivirus Profile", "Antivirus", "Virus and Wildfire Analysis"],
        "ips_profile":      ["Vulnerability Protection", "Anti-Spyware", "Vulnerability"],
        "web_filter":       ["URL Filtering", "URL Filtering Profile", "URLFiltering"],
        "security_profile": ["Profile Group", "Security Profile Group", "Profile"],
        "zones":            ["Source Zone", "Destination Zone"],
    },
    "fortinet": {
        "services":         ["Service", "Services"],
        "applications":     ["Application", "ApplicationControlProfile"],
        "logging":          ["Log", "LogTraffic", "Log Setting"],
        "av_profile":       ["AVProfile", "AntiVirus", "Antivirus", "AV"],
        "ips_profile":      ["IPSProfile", "IPS", "IntrusionPrevention"],
        "web_filter":       ["WebFilterProfile", "WebFilter", "Web Filter"],
        "security_profile": ["Security Profile", "SecurityProfile", "SSLSSHProfile"],
        "zones":            ["From", "To", "SrcZone", "DstZone", "SrcInterface", "DstInterface"],
    },
    "checkpoint": {
        "services":         ["service", "Service", "services"],
        "applications":     ["application", "Application", "app"],
        "logging":          ["track", "Track", "Track Settings", "log"],
        "av_profile":       ["anti-virus", "AntiVirus", "av", "anti_virus"],
        "ips_profile":      ["ips", "IPS", "ips-profile"],
        "web_filter":       ["url-filtering", "URLFiltering", "content-awareness"],
        "security_profile": ["threat-prevention", "action-settings", "profile"],
        "zones":            ["source-zone", "destination-zone", "install-on"],
    },
    "cisco_asa": {
        "services":         ["protocol", "service", "port"],
        "applications":     ["application"],
        "logging":          ["log", "logging"],
        "av_profile":       ["inspect-av", "av"],
        "ips_profile":      ["inspect", "ips"],
        "web_filter":       ["filter", "url-filter"],
        "security_profile": ["policy-map", "service-policy"],
        "zones":            ["interface", "nameif"],
    },
    "juniper_srx": {
        "services":         ["application", "service"],
        "applications":     ["application", "dynamic-application"],
        "logging":          ["log", "session-close", "session-init"],
        "av_profile":       ["av-policy", "anti-virus"],
        "ips_profile":      ["idp-policy", "idp"],
        "web_filter":       ["web-filtering", "utm-web"],
        "security_profile": ["utm-policy", "security-profile"],
        "zones":            ["from-zone", "to-zone"],
    },
    "generic": {
        "services":         ["services", "Service", "Services", "protocol", "port", "ports"],
        "applications":     ["applications", "Application", "Applications", "App"],
        "logging":          ["logging", "Log", "LogTraffic", "Log Setting", "track"],
        "av_profile":       ["av_profile", "AVProfile", "Antivirus", "anti-virus", "AV"],
        "ips_profile":      ["ips_profile", "IPSProfile", "IPS", "ips"],
        "web_filter":       ["web_filter", "WebFilterProfile", "URL Filtering", "url-filtering"],
        "security_profile": ["security_profile", "Security Profile", "Profile Group", "Profile"],
        "zones":            ["source_zones", "dest_zones", "Source Zone", "Destination Zone"],
    },
}


# ---------------------------------------------------------------------------
# ECC control catalog
# ---------------------------------------------------------------------------

ECC_FRAMEWORK = "NCA Essential Cybersecurity Controls (ECC-1:2018)"
ECC_DOMAIN = "2 - Cybersecurity Defence"

CONTROLS = {
    "2-5-3-3": {
        "subdomain": "2-5", "subdomain_name": "Networks Security Management",
        "title": "Secure browsing and internet connectivity (strict restrictions "
                 "on suspicious, file storage/sharing, and remote-access websites)",
        "recommendation": "Block malicious/suspicious IP lists and file-sharing / "
                          "remote-access categories, and apply a Web-Filter (URL) "
                          "profile on all internet-bound ALLOW rules.",
        "na_recommendation": "This control targets internet-bound ALLOW rules. A rule "
                            "is N/A when it is not an ALLOW rule (e.g. DENY). No action "
                            "needed unless the action changes.",
    },
    "2-5-3-5": {
        "subdomain": "2-5", "subdomain_name": "Networks Security Management",
        "title": "Restricting and managing network services, protocols and ports",
        "recommendation": "Replace 'any' service/port with the specific ports and "
                          "protocols the business actually requires (least privilege).",
        "na_recommendation": "N/A means no service/port field was found for this rule "
                            "in the CSV. Add the vendor's service column so port "
                            "restriction can be verified.",
    },
    "2-5-3-8": {
        "subdomain": "2-5", "subdomain_name": "Networks Security Management",
        "title": "Protection of the Internet browsing channel against Advanced "
                 "Persistent Threats (APT) / zero-day malware",
        "recommendation": "Apply Anti-Virus AND IPS (threat-prevention) security "
                          "profiles to ALLOW rules so zero-day malware is inspected.",
        "na_recommendation": "APT/threat inspection applies to ALLOW rules. A DENY rule "
                            "is N/A because it blocks traffic and needs no malware "
                            "inspection. No action needed unless the action changes.",
    },
    "2-12-2": {
        "subdomain": "2-12", "subdomain_name": "Cybersecurity Event Logs and Monitoring Management",
        "title": "Cybersecurity requirements for event logs and monitoring "
                 "management must be implemented",
        "recommendation": "Enable logging on every rule so all permitted/denied "
                          "traffic is auditable and can be monitored.",
        "na_recommendation": "N/A means no logging column exists in this CSV, so "
                            "logging cannot be verified. Add the vendor's logging "
                            "column to assess this control.",
    },
    "2-15-3-3": {
        "subdomain": "2-15", "subdomain_name": "Web Application Security",
        "title": "Use of secure protocols (e.g. HTTPS)",
        "recommendation": "Disallow cleartext protocols (HTTP, Telnet, FTP, etc.) and "
                          "enforce their encrypted equivalents (HTTPS, SSH, SFTP).",
        "na_recommendation": "N/A means the rule defines no service/application to "
                            "inspect for protocol security. Populate the service / "
                            "application column so protocol usage can be verified.",
    },
}

CONTROL_ORDER = ["2-5-3-3", "2-5-3-5", "2-5-3-8", "2-12-2", "2-15-3-3"]
SUBDOMAIN_ORDER = ["2-5", "2-12", "2-15"]
SUBDOMAIN_NAMES = {
    "2-5": "Networks Security Management",
    "2-12": "Cybersecurity Event Logs and Monitoring Management",
    "2-15": "Web Application Security",
}


class ComplianceAnalyzer:
    """Evaluates the ruleset against the NCA ECC controls for any vendor."""

    def __init__(self):
        self._vendor = "generic"
        self._fields = VENDOR_FIELDS["generic"]

    # ---- vendor detection ------------------------------------------------

    def _load_vendor(self, rules):
        """Detect the vendor from the first rule and load its column names."""
        self._vendor = "generic"
        if rules:
            try:
                vt = rules[0].vendor_type
                name = getattr(vt, "value", str(vt)).lower()
                if name in VENDOR_FIELDS:
                    self._vendor = name
            except Exception:
                pass
        self._fields = VENDOR_FIELDS.get(self._vendor, VENDOR_FIELDS["generic"])

    def _cols(self, key):
        """Vendor-specific column names first, then generic fallbacks."""
        cols = list(self._fields.get(key, []))
        for c in VENDOR_FIELDS["generic"].get(key, []):
            if c not in cols:
                cols.append(c)
        return cols

    # ---- value resolution ------------------------------------------------

    def _get_value(self, rule, target_names):
        """First non-empty value among the target column names, resolved
        against raw_data with exact, normalized and partial matching."""
        raw = rule.raw_data or {}
        for name in target_names:
            v = raw.get(name)
            if v is not None:
                return str(v).strip()
        normalized = {}
        for k, val in raw.items():
            nk = str(k).lower().replace(" ", "").replace("_", "").replace("-", "")
            normalized[nk] = val
        for name in target_names:
            key = name.lower().replace(" ", "").replace("_", "").replace("-", "")
            v = normalized.get(key)
            if v is not None:
                return str(v).strip()
        for name in target_names:
            key = name.lower().replace(" ", "").replace("_", "").replace("-", "")
            for nk, val in normalized.items():
                if key and key in nk:
                    return str(val).strip()
        return ""

    def _is_empty(self, value):
        return value is None or str(value).strip().lower() in EMPTY_VALUES

    def _list_field(self, rule, attr, columns):
        val = getattr(rule, attr, None)
        if val:
            return [str(x).strip() for x in val if str(x).strip()]
        raw_val = self._get_value(rule, columns)
        if not raw_val:
            return []
        for sep in [";", ",", "|"]:
            raw_val = raw_val.replace(sep, " ")
        return [tok for tok in raw_val.split() if tok]

    def _is_internet_bound(self, rule):
        zones = [z.lower() for z in (rule.source_zones or []) + (rule.dest_zones or [])]
        raw_zones = self._get_value(rule, self._cols("zones"))
        blob = " ".join(zones) + " " + raw_zones.lower()
        keywords = ("wan", "internet", "external", "untrust", "outside", "any", "public")
        return any(k in blob for k in keywords)

    # ---- per-control checks -> (result, reason) --------------------------
    # result: True=pass, False=fail, None=not applicable

    def _check_services(self, rule):
        services = [s.lower() for s in self._list_field(rule, "services", self._cols("services"))]
        if not services:
            return None, "No service/port field found for this rule in the CSV"
        if "any" in services or "all" in services:
            return False, "Service/port is 'any' (no restriction) - violates least privilege"
        return True, f"Specific service(s) defined: {', '.join(services[:4])}"

    def _check_secure_proto(self, rule):
        services = [s.lower() for s in self._list_field(rule, "services", self._cols("services"))]
        apps = [a.lower() for a in self._list_field(rule, "applications", self._cols("applications"))]
        haystack = services + apps
        if not haystack:
            return None, "No service/application defined to inspect for protocol security"
        for token in haystack:
            for bad in INSECURE_PROTOCOLS:
                if bad == token or bad in token:
                    return False, f"Uses insecure/cleartext protocol '{token}' (use HTTPS/SSH/SFTP)"
        return True, "Only secure protocols in use"

    def _check_browsing(self, rule):
        if rule.action.lower() not in ("allow", "accept", "permit"):
            return None, "Not an ALLOW rule - browsing restriction does not apply"
        addrs = [str(a).lower() for a in (rule.source_addresses or []) + (rule.dest_addresses or [])]
        apps = [str(a).lower() for a in self._list_field(rule, "applications", self._cols("applications"))]
        for token in addrs + apps:
            for m in MALICIOUS_REFERENCES:
                if m in token:
                    return False, f"References malicious/suspicious object '{m}'"
            for w in RISKY_WEB_KEYWORDS:
                if w in token:
                    return False, f"Allows risky web/remote-access category '{w}'"
        if self._is_internet_bound(rule):
            wf = self._get_value(rule, self._cols("web_filter"))
            if self._is_empty(wf):
                return False, "Internet-bound ALLOW rule has no Web-Filter (URL) profile"
            return True, f"Web-Filter profile applied ('{wf}')"
        return True, "No risky references; rule is not internet-bound"

    def _check_apt(self, rule):
        if rule.action.lower() not in ("allow", "accept", "permit"):
            return None, "Not an ALLOW rule - malware inspection not required for blocked traffic"
        av = self._get_value(rule, self._cols("av_profile"))
        ips = self._get_value(rule, self._cols("ips_profile"))
        generic = self._get_value(rule, self._cols("security_profile"))
        has_av = not self._is_empty(av)
        has_ips = not self._is_empty(ips)
        has_generic = not self._is_empty(generic)
        if has_av and has_ips:
            return True, f"AV ('{av}') + IPS ('{ips}') profiles applied"
        if has_generic:
            return True, f"Security profile applied ('{generic}')"
        missing = []
        if not has_av:
            missing.append("AV")
        if not has_ips:
            missing.append("IPS")
        return False, f"Missing threat profile(s): {', '.join(missing) or 'AV/IPS'}"

    def _check_logging(self, rule):
        value = getattr(rule, "logging", None)
        if value is None or str(value).strip() == "":
            value = self._get_value(rule, self._cols("logging"))
        if self._is_empty(value):
            return None, "No logging column found in this CSV - cannot verify logging"
        if str(value).strip().lower() in LOGGING_OFF_VALUES:
            return False, f"Logging disabled ('{value}')"
        return True, f"Logging enabled ('{value}')"

    def _checkers(self):
        return {
            "2-5-3-3": self._check_browsing,
            "2-5-3-5": self._check_services,
            "2-5-3-8": self._check_apt,
            "2-12-2": self._check_logging,
            "2-15-3-3": self._check_secure_proto,
        }

    # ---- main ------------------------------------------------------------

    def analyze_ruleset(self, rules):
        self._load_vendor(rules)
        checkers = self._checkers()

        controls = {}
        for cid in CONTROL_ORDER:
            meta = CONTROLS[cid]
            controls[cid] = {
                "id": cid, "subdomain": meta["subdomain"],
                "subdomain_name": meta["subdomain_name"], "title": meta["title"],
                "recommendation": meta["recommendation"],
                "na_recommendation": meta["na_recommendation"],
                "applicable": 0, "compliant": 0, "non_compliant": 0,
                "na": 0, "violating_rules": [],
            }

        evaluated_rules = 0
        rules_fully = 0
        rules_partial = 0
        rules_non = 0
        total_checks = 0
        passed_checks = 0
        total_na = 0
        rule_reports = []

        print(f"=== NCA ECC Compliance check | vendor: {self._vendor} ===")

        seen = set()
        for rule in rules:
            if rule.disabled:
                continue
            if rule.id in seen:
                continue
            seen.add(rule.id)

            rule_applicable = 0
            rule_passed = 0
            rule_failed = 0
            rule_na = 0
            per_control = {}
            failed_controls = []
            na_controls = []

            for cid in CONTROL_ORDER:
                checker = checkers.get(cid)
                result, reason = checker(rule)
                if result is None:
                    per_control[cid] = {
                        "result": "NA", "reason": reason,
                        "recommendation": controls[cid]["na_recommendation"],
                    }
                    controls[cid]["na"] += 1
                    rule_na += 1
                    total_na += 1
                    na_controls.append(cid)
                    continue
                controls[cid]["applicable"] += 1
                rule_applicable += 1
                total_checks += 1
                if result:
                    controls[cid]["compliant"] += 1
                    passed_checks += 1
                    rule_passed += 1
                    per_control[cid] = {"result": "PASS", "reason": reason,
                                        "recommendation": ""}
                else:
                    controls[cid]["non_compliant"] += 1
                    rule_failed += 1
                    failed_controls.append(cid)
                    per_control[cid] = {"result": "FAIL", "reason": reason,
                                        "recommendation": controls[cid]["recommendation"]}
                    controls[cid]["violating_rules"].append(
                        {"id": rule.id, "name": rule.name})

            if rule_applicable == 0:
                rule_reports.append({
                    "id": rule.id, "name": rule.name, "action": rule.action,
                    "status": "NOT_APPLICABLE", "applicable": 0,
                    "passed": 0, "failed": 0, "na": rule_na,
                    "failed_controls": [], "na_controls": na_controls,
                    "per_control": per_control,
                })
                continue

            evaluated_rules += 1
            if rule_failed == 0:
                rule_status = "FULLY_COMPLIANT"
                rules_fully += 1
            elif rule_passed == 0:
                rule_status = "NON_COMPLIANT"
                rules_non += 1
            else:
                rule_status = "PARTIALLY_COMPLIANT"
                rules_partial += 1

            rule_reports.append({
                "id": rule.id, "name": rule.name, "action": rule.action,
                "status": rule_status, "applicable": rule_applicable,
                "passed": rule_passed, "failed": rule_failed, "na": rule_na,
                "failed_controls": failed_controls, "na_controls": na_controls,
                "per_control": per_control,
            })

        for cid in controls:
            c = controls[cid]
            if c["applicable"] == 0:
                c["status"] = "NOT_APPLICABLE"
            elif c["non_compliant"] == 0:
                c["status"] = "COMPLIANT"
            elif c["compliant"] == 0:
                c["status"] = "NON_COMPLIANT"
            else:
                c["status"] = "PARTIAL"

        subdomains = {}
        for sd in SUBDOMAIN_ORDER:
            member_ids = [cid for cid in CONTROL_ORDER if CONTROLS[cid]["subdomain"] == sd]
            applicable = sum(controls[c]["applicable"] for c in member_ids)
            compliant = sum(controls[c]["compliant"] for c in member_ids)
            non_compliant = sum(controls[c]["non_compliant"] for c in member_ids)
            if applicable == 0:
                sd_status = "NOT_APPLICABLE"
            elif non_compliant == 0:
                sd_status = "COMPLIANT"
            elif compliant == 0:
                sd_status = "NON_COMPLIANT"
            else:
                sd_status = "PARTIAL"
            subdomains[sd] = {
                "id": sd, "name": SUBDOMAIN_NAMES[sd], "controls": member_ids,
                "applicable": applicable, "compliant": compliant,
                "non_compliant": non_compliant, "status": sd_status,
            }

        if total_checks == 0:
            overall = "NOT_APPLICABLE"
        elif passed_checks == total_checks:
            overall = "FULLY_COMPLIANT"
        elif passed_checks == 0:
            overall = "NON_COMPLIANT"
        else:
            overall = "PARTIALLY_COMPLIANT"

        compliance_pct = (
            round(100 * passed_checks / total_checks, 1) if total_checks else 0.0
        )

        print(f"Evaluated rules: {evaluated_rules}")
        print(f"  Fully compliant : {rules_fully}")
        print(f"  Partially       : {rules_partial}")
        print(f"  Non-compliant   : {rules_non}")
        print(f"Checks passed: {passed_checks}/{total_checks}  |  N/A checks: {total_na}")
        print(f"Overall: {overall} ({compliance_pct}%)")

        result = {
            "framework": ECC_FRAMEWORK, "domain": ECC_DOMAIN,
            "vendor": self._vendor,
            "overall_status": overall, "evaluated_rules": evaluated_rules,
            "rules_fully_compliant": rules_fully,
            "rules_partially_compliant": rules_partial,
            "rules_non_compliant": rules_non,
            "rules_with_issues": rules_partial + rules_non,
            "total_checks": total_checks, "passed_checks": passed_checks,
            "failed_checks": total_checks - passed_checks, "na_checks": total_na,
            "compliance_pct": compliance_pct, "controls": controls,
            "subdomains": subdomains, "rule_reports": rule_reports,
            "compliant_rules": rules_fully,
            "non_compliant_rules": rules_partial + rules_non,
        }
        result["findings"] = self._build_findings(controls)
        return result

    def _build_findings(self, controls):
        findings = []
        for cid in controls:
            c = controls[cid]
            if c["status"] in ("COMPLIANT", "NOT_APPLICABLE"):
                continue
            level = RiskLevel.HIGH if c["status"] == "NON_COMPLIANT" else RiskLevel.MEDIUM
            n = c["non_compliant"]
            findings.append(
                SecurityFinding(
                    rule_id=f"ECC-{cid}", rule_name=f"ECC {cid}",
                    issue_type=RuleIssueType.MISCONFIGURED, risk_level=level,
                    description=(f"ECC {cid} ({c['title']}): {c['status']} - "
                                 f"{n} of {c['applicable']} applicable rule(s) non-compliant."),
                    recommendation=c["recommendation"],
                    details={"control": cid, "subdomain": c["subdomain"],
                             "non_compliant": n, "applicable": c["applicable"]},
                    score=90 if level == RiskLevel.HIGH else 50,
                )
            )
        return findings

# ===========================================================================
# HTML SECTION BUILDER  (report style).
# Under each ECC control: flag ONLY the rules that are NON-COMPLIANT to THAT
# control, labeled Non-Compliant (for this control) with the reason + rule ID.
# ===========================================================================

def generate_compliance_section(result, colors=None):
    colors = colors or {}
    green = colors.get("risk_low", "#2E7D32")
    red = colors.get("risk_critical", "#B71C1C")
    amber = colors.get("risk_medium", "#F9A825")
    grey = colors.get("medium_grey", "#5A5A5A")
    dark = colors.get("dark_grey", "#1A1A1A")
    light = colors.get("very_light_grey", "#F5F5F5")

    status = result["overall_status"]

    status_meta = {
        "FULLY_COMPLIANT": ("FULLY COMPLIANT", green, "health-good"),
        "PARTIALLY_COMPLIANT": ("PARTIALLY COMPLIANT", amber, "health-fair"),
        "NON_COMPLIANT": ("NON COMPLIANT", red, "health-critical"),
        "NOT_APPLICABLE": ("NOT APPLICABLE", grey, "health-fair"),
    }
    label, colr, health_class = status_meta.get(status, status_meta["NOT_APPLICABLE"])

    framework = result.get("framework", "NCA ECC")
    domain = result.get("domain", "2 - Cybersecurity Defence")
    ev = result["evaluated_rules"]
    full = result.get("rules_fully_compliant", 0)
    part = result.get("rules_partially_compliant", 0)
    non = result.get("rules_non_compliant", 0)
    passed = result.get("passed_checks", 0)
    total = result.get("total_checks", 0)
    na = result.get("na_checks", 0)
    pct = result["compliance_pct"]

    if status == "FULLY_COMPLIANT":
        summary = (f"All <b>{total}</b> control checks across <b>{ev}</b> rules passed. "
                   f"The ruleset is fully compliant with the assessed ECC controls.")
    elif status == "NON_COMPLIANT":
        summary = (f"All <b>{total}</b> control checks failed. The ruleset is "
                   f"non-compliant with every assessed ECC control and requires remediation.")
    elif status == "PARTIALLY_COMPLIANT":
        summary = (f"<b>{passed}</b> of <b>{total}</b> control checks passed "
                   f"(<b>{pct}%</b>). Rules break down as <b>{full}</b> fully compliant, "
                   f"<b>{part}</b> partially compliant, and <b>{non}</b> non-compliant. "
                   f"<b>{na}</b> check(s) were not applicable.")
    else:
        summary = "No rules could be evaluated for these ECC controls in this file."

    # control status -> colored text
    def control_status_text(st):
        m = {
            "COMPLIANT": (green, "Compliant"),
            "PARTIAL": (amber, "Partial"),
            "NON_COMPLIANT": (red, "Non-Compliant"),
            "NOT_APPLICABLE": (grey, "N/A"),
        }
        c, txt = m.get(st, (grey, "N/A"))
        return f'<strong style="color:{c};">{txt}</strong>'

    # red "Non-Compliant" flag pill (for THIS control)
    non_compliant_pill = (f'<span style="background:{red};color:#fff;padding:2px 12px;'
                          f'border-radius:12px;font-size:0.82em;font-weight:700;'
                          f'white-space:nowrap;">Non-Compliant</span>')

    # ---------- ECC Control Detail with NON-COMPLIANT-only breakdown ----------
    control_rows = ""
    for sd in SUBDOMAIN_ORDER:
        member_ids = [cid for cid in CONTROL_ORDER if CONTROLS[cid]["subdomain"] == sd]
        if not member_ids:
            continue
        control_rows += f"""
            <tr style="background:{light};">
                <td colspan="4" style="font-weight:700;color:{dark};font-size:1.05em;">
                    ECC {sd} — {SUBDOMAIN_NAMES[sd]}
                </td>
            </tr>"""
        for cid in member_ids:
            c = result["controls"][cid]

            # main control row — requirement text HEAVY BOLD BLACK
            control_rows += f"""
            <tr>
                <td style="vertical-align:top;"><strong>{cid}</strong></td>
                <td style="vertical-align:top;">
                    <span style="font-weight:800;color:{dark};font-size:1.02em;">{c['title']}</span>
                    <div style="margin-top:6px;color:{grey};font-size:0.9em;">
                        <b>Recommendation:</b> {c['recommendation']}
                    </div>
                </td>
                <td style="vertical-align:top;">{control_status_text(c['status'])}</td>
                <td style="vertical-align:top;">{c['compliant']}/{c['applicable']}</td>
            </tr>"""

            # collect ONLY the rules that FAIL this control (non-compliant to it)
            fail_rows = ""
            fail_count = 0
            for r in result.get("rule_reports", []):
                pc = r["per_control"].get(cid)
                if not pc or pc["result"] != "FAIL":
                    continue
                fail_count += 1
                fail_rows += f"""
                    <tr>
                        <td style="white-space:nowrap;">{r['id']}</td>
                        <td><strong>{r['name']}</strong></td>
                        <td style="color:{grey};">{pc['reason']}</td>
                        <td style="text-align:center;">{non_compliant_pill}</td>
                    </tr>"""

            if fail_rows:
                control_rows += f"""
            <tr>
                <td colspan="4" style="background:#FFF6F6;padding:16px 20px;border-left:4px solid {red};">
                    <div style="font-weight:800;color:{dark};font-size:1.0em;margin-bottom:10px;
                                text-transform:uppercase;letter-spacing:0.5px;">
                        {fail_count} rule(s) non-compliant to {cid}
                    </div>
                    <table style="width:100%;margin:0;">
                        <thead>
                            <tr style="background:{dark};color:#fff;">
                                <th>Rule ID</th>
                                <th>Rule Name</th>
                                <th>Reason for Violation</th>
                                <th style="text-align:center;">Status</th>
                            </tr>
                        </thead>
                        <tbody>{fail_rows}</tbody>
                    </table>
                </td>
            </tr>"""

    return f"""
        <div class="section">
            <h2>&#128220; NCA ECC Compliance Assessment</h2>
            <p style="margin:-10px 0 20px 0;color:{grey};font-size:0.95em;">
                Framework: <b>{framework}</b> &nbsp;|&nbsp; Main Domain: <b>{domain}</b>
            </p>

            <div style="text-align:center; margin: 25px 0;">
                <div class="health-badge {health_class}">
                    Compliance: {label} &nbsp;&bull;&nbsp; {pct}%
                </div>
            </div>

            <p style="margin-bottom:20px;">{summary}</p>

            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{ev}</div>
                    <div class="stat-label">Rules Evaluated</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" style="color:{green};">{full}</div>
                    <div class="stat-label">Fully Compliant</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" style="color:{amber};">{part}</div>
                    <div class="stat-label">Partially Compliant</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" style="color:{red};">{non}</div>
                    <div class="stat-label">Non-Compliant</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{na}</div>
                    <div class="stat-label">N/A Checks</div>
                </div>
            </div>

            <h3 style="margin-top:30px;">&#128203; ECC Control Detail (non-compliant rules flagged)</h3>
            <p style="color:{grey};margin-bottom:10px;">
                Under each control, only the rules that are
                <span style="color:{red};font-weight:700;">non-compliant to that control</span>
                are listed, with the rule ID and the reason. A control showing
                <b>17/20</b> means 3 rules are non-compliant and only those 3 appear below it.
            </p>
            <table>
                <thead>
                    <tr><th>Control</th><th>Requirement</th><th>Status</th><th>Compliant / Applicable</th></tr>
                </thead>
                <tbody>{control_rows}</tbody>
            </table>
        </div>
    """