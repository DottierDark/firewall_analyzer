from ..core.models import SecurityFinding, RuleIssueType, RiskLevel


class DenyAnyAnyAnalyzer:
    """Runs the Deny Any Any flow on EVERY firewall in the file."""

    def _is_deny_any_any(self, rule):
        return (not rule.disabled
                and rule.action.lower() == "deny"
                and "any" in [a.lower() for a in rule.source_addresses]
                and "any" in [a.lower() for a in rule.dest_addresses])

    def _get_firewall_name(self, rule):
        raw = rule.raw_data or {}
        for key in ["Location", "location", "Name", "Firewall", "firewall", "Device"]:
            value = raw.get(key)
            if value:
                return value
        return "UNKNOWN_FIREWALL"

    def analyze_ruleset(self, rules):
        findings = []

        # Group rules by firewall
        firewalls = {}
        for rule in rules:
            fw = self._get_firewall_name(rule)
            firewalls.setdefault(fw, []).append(rule)

        print("=== Deny Any Any check for ALL firewalls ===")
        print("Total firewalls to check:", len(firewalls))

        # Run YOUR flow on EACH firewall
        for fw_name, fw_rules in firewalls.items():

            deny_rules = [r for r in fw_rules if self._is_deny_any_any(r)]
            last_rule = fw_rules[-1]
            last_info = f"{last_rule.name} ({last_rule.action})"

            # QUESTION 1: does any-any rule exist?
            if not deny_rules:
                # NO -> display + recommendation + exit this firewall
                print(f"[{fw_name}] No Any Any found")
                print(f"[{fw_name}] Recommendation: Deny Any Any has to be deployed as the last rule")
                findings.append(
                    SecurityFinding(
                        rule_id=fw_name,
                        rule_name=fw_name,
                        issue_type=RuleIssueType.MISCONFIGURED,
                        risk_level=RiskLevel.HIGH,
                        description=f"[{fw_name}] No Deny Any Any rule found. Last rule is {last_info}",
                        recommendation="Any Any has to be deployed as the last rule",
                        score=90
                    )
                )
                continue

            # YES found -> QUESTION 2: is it the last rule?
            if self._is_deny_any_any(last_rule):
                # YES -> compliant
                print(f"[{fw_name}] Deny Any Any exists and is the last rule - No issue found (Compliant)")
                findings.append(
                    SecurityFinding(
                        rule_id=last_rule.id,
                        rule_name=f"{fw_name} / {last_rule.name}",
                        issue_type=RuleIssueType.MISCONFIGURED,
                        risk_level=RiskLevel.LOW,
                        description=f"[{fw_name}] Compliant: Deny Any Any exists and is the last rule ({last_info})",
                        recommendation="No action needed. The cleanup rule is correctly positioned.",
                        score=1
                    )
                )
            else:
                # NO -> recommendation: any any has to be last
                print(f"[{fw_name}] Recommendation: Deny Any Any has to be the last rule")
                findings.append(
                    SecurityFinding(
                        rule_id=deny_rules[0].id,
                        rule_name=f"{fw_name} / {deny_rules[0].name}",
                        issue_type=RuleIssueType.MISCONFIGURED,
                        risk_level=RiskLevel.HIGH,
                        description=f"[{fw_name}] Deny Any Any exists but is not the last rule. Last rule is {last_info}",
                        recommendation=" Deny Any Any has to be the last rule",
                        score=80
                    )
                )

        return findings