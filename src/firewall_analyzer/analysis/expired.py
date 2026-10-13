from datetime import datetime

from ..core.models import SecurityFinding, RuleIssueType, RiskLevel


class ExpiredRuleAnalyzer:
    """Flags rules whose Expiration Date has already passed."""

    def _parse_date(self, date_str):
        if not date_str:
            return None
        date_part = str(date_str).split()[0]
        for fmt in ["%Y-%m-%d", "%m/%d/%Y", "%Y/%m/%d", "%d/%m/%Y"]:
            try:
                return datetime.strptime(date_part, fmt)
            except ValueError:
                continue
        return None

    def _get_value(self, rule, target_names):
        raw = rule.raw_data or {}
        for name in target_names:
            value = raw.get(name)
            if value is not None:
                return str(value).strip()
        normalized = {}
        for k, v in raw.items():
            clean_key = str(k).lower().replace(" ", "").replace("_", "")
            normalized[clean_key] = v
        for name in target_names:
            key = name.lower().replace(" ", "").replace("_", "")
            value = normalized.get(key)
            if value is not None:
                return str(value).strip()
        return ""

    def analyze_ruleset(self, rules):
        findings = []
        today = datetime.now()

        print("=== Expired Rule check (using Expiration Date) ===")

        # DEBUG
        if rules:
            r = rules[0]
            print(">>> First rule disabled?:", r.disabled)
            print(">>> First rule action:", r.action)
            print(">>> raw_data keys:", list((r.raw_data or {}).keys()))
            print(">>> ExpiryDate value:", (r.raw_data or {}).get("ExpiryDate"))

        for rule in rules:
            # NOTE: disabled skip removed for testing

            expiry_raw = self._get_value(rule, ["Expiration Date", "ExpirationDate", "ExpiryDate", "Expiry"])

            # Skip if NO expiration date (rule runs forever)
            if not expiry_raw or expiry_raw in ("-", "--", "N/A", "None", "none"):
                continue

            expiry_date = self._parse_date(expiry_raw)
            if expiry_date is None:
                continue

            # Only flag if the date has already passed
            if expiry_date < today:
                days_passed = (today - expiry_date).days
                print(f"[EXPIRED] {rule.name} - expired on {expiry_raw}")
                findings.append(
                    SecurityFinding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        issue_type=RuleIssueType.EXPIRED,
                        risk_level=RiskLevel.MEDIUM,
                        description=f"EXPIREDRULE: '{rule.name}' passed its expiration date ({expiry_raw}), {days_passed} day(s) ago.",
                        recommendation="Review this time-bound rule. Remove it or renew its expiration date.",
                        details={"expiry_date": expiry_raw, "days_passed": days_passed},
                        score=30
                    )
                )

        print(f"Total expired rules found: {len(findings)}")
        return findings