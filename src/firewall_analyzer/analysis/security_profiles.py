from ..core.models import SecurityFinding, RuleIssueType, RiskLevel


class SecurityProfileAnalyzer:
    """Checks whether each ALLOW/ACCEPT rule has security profiles applied.
    Works for any CSV (FortiGate multi-column, Palo Alto single-column, etc.)."""

    # All possible profile column names across vendors
    PROFILE_COLUMNS = [
        "AVProfile", "IPSProfile", "WebFilterProfile",
        "ApplicationControlProfile", "SSLSSHProfile",
        "Security Profile", "SecurityProfile", "Profile",
    ]

    def _is_empty(self, value):
        if value is None:
            return True
        v = str(value).strip().lower()
        return v in ("", "-", "--", "n/a", "none")

    def _get_all_profiles(self, rule):
        """Collect unique 'ColumnName=value' pairs, avoiding duplicate columns/values."""
        raw = rule.raw_data or {}

        found = []
        seen_columns = set()   # avoid same normalized column twice
        seen_pairs = set()     # avoid identical column=value twice

        for col in self.PROFILE_COLUMNS:
            # normalize the column name to avoid "Security Profile" == "SecurityProfile"
            norm_col = col.lower().replace(" ", "").replace("_", "")
            if norm_col in seen_columns:
                continue

            # find the value for this column (exact, then flexible)
            value = raw.get(col)
            if value is None:
                for k, v in raw.items():
                    if str(k).lower().replace(" ", "").replace("_", "") == norm_col:
                        value = v
                        break

            if not self._is_empty(value):
                pair = f"{col}={str(value).strip()}"
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    seen_columns.add(norm_col)
                    found.append(pair)

        return found

    def analyze_ruleset(self, rules):
        findings = []
        seen_rule_ids = set()   # avoid duplicate rules

        print("=== Security Profile check ===")

        for rule in rules:
            # Only ALLOW/ACCEPT rules
            if rule.action.lower() not in ("allow", "accept"):
                continue

            # Avoid processing the same rule twice
            if rule.id in seen_rule_ids:
                continue
            seen_rule_ids.add(rule.id)

            profiles = self._get_all_profiles(rule)

            # Show rules that HAVE at least one profile
            if profiles:
                profile_str = ", ".join(profiles)
                print(f"[HAS PROFILE] {rule.name} -> {profile_str}")
                findings.append(
                    SecurityFinding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        issue_type=RuleIssueType.MISCONFIGURED,
                        risk_level=RiskLevel.LOW,
                        description=f"HASPROFILE: Rule '{rule.name}' has security profiles: {profile_str}",
                        recommendation="No action needed. Security profiles are applied.",
                        details={"security_profile": profile_str},
                        score=1
                    )
                )

        print(f"Total ALLOW rules WITH security profiles: {len(findings)}")
        return findings