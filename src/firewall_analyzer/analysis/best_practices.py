from datetime import datetime
from typing import List, Dict, Any

from .base import BaseAnalyzer
from ..core.models import FirewallRule, SecurityFinding, RuleIssueType, RiskLevel


class BestPracticesAnalyzer(BaseAnalyzer):
    """Analyzes rules against firewall best practices with detailed scoring"""

    def analyze(self, rule: FirewallRule) -> List[SecurityFinding]:
        """Analyze a rule against best practices"""
        findings = []

        # Skip disabled rules - they should not be analyzed for issues
        if rule.disabled:
            return findings

        if rule.rule_usage.lower() == 'unused' and not rule.disabled:
            score_breakdown = {
                'base_score': 30,
                'factors': {
                    'attack_surface': 15,
                    'performance_impact': 10,
                    'maintenance_burden': 5
                },
                'calculation_steps': [
                    'Attack surface increase: 15 points',
                    'Performance impact: 10 points',
                    'Maintenance burden: 5 points',
                    'Total: 30 points'
                ],
                'total_score': 30
            }

            formula = "Score = 15 (attack surface) + 10 (performance) + 5 (maintenance) = 30"

            finding = SecurityFinding(
                rule_id=rule.id,
                rule_name=rule.name,
                issue_type=RuleIssueType.UNUSED,
                risk_level=RiskLevel.LOW,
                description="Rule is unused and should be reviewed",
                recommendation="Consider disabling or removing unused rules to reduce attack surface",
                score=30,
                score_breakdown=score_breakdown,
                calculation_formula=formula
            )
            findings.append(finding)

        # Don't flag disabled rules as disabled - they're already filtered out from analysis
        # so this check is redundant, but left for reference

        findings.extend(self._check_rule_age(rule))

        return findings

    def _check_rule_age(self, rule: FirewallRule) -> List[SecurityFinding]:
        """Check if rule hasn't been modified in a long time"""
        findings = []

        if rule.modified:
            try:
                for fmt in ['%Y-%m-%d', '%Y/%m/%d', '%m/%d/%Y']:
                    try:
                        modified_date = datetime.strptime(rule.modified.split()[0], fmt)
                        break
                    except ValueError:
                        continue
                else:
                    return findings

                days_old = (datetime.now() - modified_date).days

                if days_old > 365:
                    years_old = days_old // 365
                    age_modifier = min(10, years_old)

                    score_breakdown = {
                        'base_score': 20,
                        'factors': {
                            'stale_configuration': 10,
                            'review_needed': 5,
                            'potential_obsolescence': 5
                        },
                        'age_modifier': age_modifier,
                        'calculation_steps': [
                            'Stale configuration: 10 points',
                            'Review needed: 5 points',
                            'Potential obsolescence: 5 points',
                            f'Age modifier ({years_old} years): +{age_modifier} points',
                            f'Total: {20 + age_modifier} points'
                        ],
                        'total_score': min(30, 20 + age_modifier)
                    }

                    formula = f"Score = 20 (base) + {age_modifier} (age) = {score_breakdown['total_score']}"

                    finding = SecurityFinding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        issue_type=RuleIssueType.EXPIRED,
                        risk_level=RiskLevel.LOW,
                        description=f"Rule hasn't been modified in {days_old} days ({years_old} years)",
                        recommendation="Regular review of firewall rules is essential for security",
                        details={'days_old': days_old, 'last_modified': rule.modified},
                        score=score_breakdown['total_score'],
                        score_breakdown=score_breakdown,
                        calculation_formula=formula
                    )
                    findings.append(finding)
            except Exception:
                pass

        return findings