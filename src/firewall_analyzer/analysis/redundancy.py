import hashlib
from typing import List

from ..core.models import FirewallRule, SecurityFinding, RuleIssueType, RiskLevel


class RedundancyAnalyzer:
    """Analyzes rules for redundancy and shadowing"""

    def analyze_ruleset(self, rules: List[FirewallRule]) -> List[SecurityFinding]:
        """Analyze entire ruleset for redundancy and shadowing"""
        findings = []
        findings.extend(self._find_duplicate_rules(rules))
        findings.extend(self._find_shadowed_rules(rules))
        return findings

    def _find_duplicate_rules(self, rules: List[FirewallRule]) -> List[SecurityFinding]:
        """Find exact duplicate rules with scoring"""
        findings = []
        rule_signatures = {}

        for rule in rules:
            if rule.disabled:
                continue

            signature = self._create_rule_signature(rule)

            if signature in rule_signatures:
                duplicate_of = rule_signatures[signature]

                score_breakdown = {
                    'base_score': 45,
                    'factors': {
                        'exact_duplicate': 30,
                        'maintenance_overhead': 10,
                        'confusion_risk': 5
                    },
                    'calculation_steps': [
                        'Exact duplicate: 30 points',
                        'Maintenance overhead: 10 points',
                        'Confusion risk: 5 points',
                        'Total: 45 points'
                    ],
                    'total_score': 45
                }

                formula = "Score = 30 (duplicate) + 10 (maintenance) + 5 (confusion) = 45"

                finding = SecurityFinding(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    issue_type=RuleIssueType.REDUNDANT,
                    risk_level=RiskLevel.MEDIUM,
                    description=f"Duplicate rule. Identical to rule '{duplicate_of['name']}' (ID: {duplicate_of['id']})",
                    recommendation="Remove duplicate rule to simplify ruleset and reduce maintenance overhead",
                    details={'duplicate_of': duplicate_of['id'], 'duplicate_name': duplicate_of['name']},
                    score=45,
                    score_breakdown=score_breakdown,
                    calculation_formula=formula
                )
                findings.append(finding)
            else:
                rule_signatures[signature] = {'id': rule.id, 'name': rule.name}

        return findings

    def _find_shadowed_rules(self, rules: List[FirewallRule]) -> List[SecurityFinding]:
        """Find rules that are shadowed by earlier rules with scoring"""
        findings = []

        for i, rule in enumerate(rules):
            if rule.disabled:
                continue

            for j in range(i):
                earlier_rule = rules[j]
                if earlier_rule.disabled:
                    continue

                if self._is_shadowed_by(rule, earlier_rule):
                    score_breakdown = {
                        'base_score': 65,
                        'factors': {
                            'never_matched': 25,
                            'rule_order_issue': 20,
                            'ineffective_rule': 15,
                            'troubleshooting_difficulty': 5
                        },
                        'calculation_steps': [
                            'Never matched: 25 points',
                            'Rule order issue: 20 points',
                            'Ineffective rule: 15 points',
                            'Troubleshooting difficulty: 5 points',
                            'Total: 65 points'
                        ],
                        'total_score': 65
                    }

                    formula = "Score = 25 (never matched) + 20 (order) + 15 (ineffective) + 5 = 65"

                    finding = SecurityFinding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        issue_type=RuleIssueType.SHADOWED,
                        risk_level=RiskLevel.HIGH,
                        description=f"Rule is shadowed by earlier rule '{earlier_rule.name}' (ID: {earlier_rule.id})",
                        recommendation="Review rule order or remove shadowed rule to avoid confusion",
                        details={'shadowed_by': earlier_rule.id, 'shadowing_rule': earlier_rule.name},
                        score=65,
                        score_breakdown=score_breakdown,
                        calculation_formula=formula
                    )
                    findings.append(finding)
                    break

        return findings

    def _create_rule_signature(self, rule: FirewallRule) -> str:
        """Create a unique signature for a rule"""
        components = [
            ','.join(sorted(rule.source_zones)),
            ','.join(sorted(rule.dest_zones)),
            ','.join(sorted(rule.source_addresses)),
            ','.join(sorted(rule.dest_addresses)),
            ','.join(sorted(rule.services)),
            ','.join(sorted(rule.applications)),
            rule.action
        ]
        return hashlib.md5('|'.join(components).encode()).hexdigest()

    def _is_shadowed_by(self, rule: FirewallRule, earlier_rule: FirewallRule) -> bool:
        """Check if a rule is shadowed by an earlier rule"""
        return (
            self._is_subset(rule.source_zones, earlier_rule.source_zones) and
            self._is_subset(rule.dest_zones, earlier_rule.dest_zones) and
            self._is_subset(rule.source_addresses, earlier_rule.source_addresses) and
            self._is_subset(rule.dest_addresses, earlier_rule.dest_addresses) and
            self._is_subset(rule.services, earlier_rule.services) and
            self._is_subset(rule.applications, earlier_rule.applications)
        )

    def _is_subset(self, list1: List[str], list2: List[str]) -> bool:
        """Check if list1 is a subset of list2 or if list2 contains 'any'"""
        if 'any' in [item.lower() for item in list2]:
            return True
        set1 = set(item.lower() for item in list1)
        set2 = set(item.lower() for item in list2)
        return set1.issubset(set2)