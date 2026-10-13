from typing import List, Dict, Any

from .base import BaseAnalyzer
from ..core.models import FirewallRule, SecurityFinding, RuleIssueType, RiskLevel


class OverlyPermissiveRuleAnalyzer(BaseAnalyzer):
    """Analyzes rules for overly permissive configurations with detailed scoring"""

    SCORING_WEIGHTS = {
        'any_source': {'base': 35, 'description': 'Unrestricted source addresses'},
        'any_destination': {'base': 35, 'description': 'Unrestricted destination addresses'},
        'any_service': {'base': 45, 'description': 'All services allowed'},
        'any_application': {'base': 25, 'description': 'All applications allowed'},
        'any_source_zone': {'base': 30, 'description': 'Unrestricted source zones'},
        'any_dest_zone': {'base': 30, 'description': 'Unrestricted destination zones'}
    }

    def analyze(self, rule: FirewallRule) -> List[SecurityFinding]:
        """Analyze a rule for overly permissive settings with detailed scoring"""
        findings = []

        # Skip disabled rules
        if rule.disabled:
            return findings

        score_breakdown = {
            'components': {},
            'modifiers': {},
            'calculation_steps': [],
            'total_score': 0
        }
        issues = []

        if 'any' in [addr.lower() for addr in rule.source_addresses]:
            issues.append("source addresses")
            score_breakdown['components']['any_source'] = self.SCORING_WEIGHTS['any_source']
            score_breakdown['calculation_steps'].append(f"Any source: +{self.SCORING_WEIGHTS['any_source']['base']}")
            score_breakdown['total_score'] += self.SCORING_WEIGHTS['any_source']['base']

        if 'any' in [addr.lower() for addr in rule.dest_addresses]:
            issues.append("destination addresses")
            score_breakdown['components']['any_destination'] = self.SCORING_WEIGHTS['any_destination']
            score_breakdown['calculation_steps'].append(f"Any destination: +{self.SCORING_WEIGHTS['any_destination']['base']}")
            score_breakdown['total_score'] += self.SCORING_WEIGHTS['any_destination']['base']

        if 'any' in [svc.lower() for svc in rule.services]:
            issues.append("services")
            score_breakdown['components']['any_service'] = self.SCORING_WEIGHTS['any_service']
            score_breakdown['calculation_steps'].append(f"Any service: +{self.SCORING_WEIGHTS['any_service']['base']}")
            score_breakdown['total_score'] += self.SCORING_WEIGHTS['any_service']['base']

        if 'any' in [app.lower() for app in rule.applications]:
            issues.append("applications")
            score_breakdown['components']['any_application'] = self.SCORING_WEIGHTS['any_application']
            score_breakdown['calculation_steps'].append(f"Any application: +{self.SCORING_WEIGHTS['any_application']['base']}")
            score_breakdown['total_score'] += self.SCORING_WEIGHTS['any_application']['base']

        if 'any' in [zone.lower() for zone in rule.source_zones]:
            issues.append("source zones")
            score_breakdown['components']['any_source_zone'] = self.SCORING_WEIGHTS['any_source_zone']
            score_breakdown['calculation_steps'].append(f"Any source zone: +{self.SCORING_WEIGHTS['any_source_zone']['base']}")
            score_breakdown['total_score'] += self.SCORING_WEIGHTS['any_source_zone']['base']

        if 'any' in [zone.lower() for zone in rule.dest_zones]:
            issues.append("destination zones")
            score_breakdown['components']['any_dest_zone'] = self.SCORING_WEIGHTS['any_dest_zone']
            score_breakdown['calculation_steps'].append(f"Any dest zone: +{self.SCORING_WEIGHTS['any_dest_zone']['base']}")
            score_breakdown['total_score'] += self.SCORING_WEIGHTS['any_dest_zone']['base']

        if len(issues) >= 3:
            score_breakdown['modifiers']['multiple_any_fields'] = 15
            score_breakdown['calculation_steps'].append(f"Multiple any fields penalty: +15")
            score_breakdown['total_score'] += 15

        if rule.action.lower() == 'allow' and len(issues) >= 2:
            score_breakdown['modifiers']['permissive_allow_rule'] = 10
            score_breakdown['calculation_steps'].append(f"Permissive allow rule: +10")
            score_breakdown['total_score'] += 10

        if issues:
            total_score = score_breakdown['total_score']
            if total_score >= 120:
                risk_level = RiskLevel.CRITICAL
            elif total_score >= 90:
                risk_level = RiskLevel.HIGH
            elif total_score >= 60:
                risk_level = RiskLevel.MEDIUM
            else:
                risk_level = RiskLevel.LOW

            description = f"Rule is overly permissive with 'any' in: {', '.join(issues)}"
            recommendation = self._generate_recommendation(issues, rule)

            formula = f"Score = {' + '.join([str(v['base']) for k, v in score_breakdown['components'].items()])} + {sum(score_breakdown.get('modifiers', {}).values())} = {total_score}"

            finding = SecurityFinding(
                rule_id=rule.id,
                rule_name=rule.name,
                issue_type=RuleIssueType.OVERLY_PERMISSIVE,
                risk_level=risk_level,
                description=description,
                recommendation=recommendation,
                details={'permissive_fields': issues},
                score=total_score,
                score_breakdown=score_breakdown,
                calculation_formula=formula
            )
            findings.append(finding)

        findings.extend(self._check_wide_subnets(rule))

        return findings

    def _generate_recommendation(self, issues: List[str], rule: FirewallRule) -> str:
        """Generate specific recommendations based on issues found"""
        recommendations = []

        if "source addresses" in issues:
            recommendations.append("Define specific source IP addresses or subnets using least privilege")
        if "destination addresses" in issues:
            recommendations.append("Specify exact destination servers or networks rather than broad ranges")
        if "services" in issues:
            recommendations.append("Limit to specific required ports and protocols instead of all services")
        if "applications" in issues:
            recommendations.append("Define specific applications instead of 'any' to control application-layer traffic")
        if "source zones" in issues or "destination zones" in issues:
            recommendations.append("Implement proper network segmentation with defined zones")

        return ". ".join(recommendations) + ". Consider implementing Zero Trust principles."

    def _check_wide_subnets(self, rule: FirewallRule) -> List[SecurityFinding]:
        """Check for overly wide subnet ranges with detailed scoring"""
        findings = []

        for addr in rule.source_addresses + rule.dest_addresses:
            if '/' in addr:
                try:
                    _, cidr = addr.rsplit('/', 1)
                    cidr_int = int(cidr)

                    score_breakdown = {
                        'subnet': addr,
                        'cidr': cidr_int,
                        'base_score': 0,
                        'factors': {},
                        'calculation_steps': []
                    }

                    if cidr_int <= 8:
                        risk_level = RiskLevel.CRITICAL
                        score_breakdown['base_score'] = 90
                        score_breakdown['factors']['class_a_network'] = 90
                        score_breakdown['calculation_steps'].append(f"Class A network (/{cidr_int}): 90 points")
                    elif cidr_int <= 12:
                        risk_level = RiskLevel.HIGH
                        score_breakdown['base_score'] = 75
                        score_breakdown['factors']['large_network'] = 75
                        score_breakdown['calculation_steps'].append(f"Large network (/{cidr_int}): 75 points")
                    elif cidr_int <= 16:
                        risk_level = RiskLevel.MEDIUM
                        score_breakdown['base_score'] = 60
                        score_breakdown['factors']['class_b_network'] = 60
                        score_breakdown['calculation_steps'].append(f"Class B network (/{cidr_int}): 60 points")
                    else:
                        continue

                    formula = f"Score = Base ({score_breakdown['base_score']}) for /{cidr_int} network"

                    finding = SecurityFinding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        issue_type=RuleIssueType.OVERLY_PERMISSIVE,
                        risk_level=risk_level,
                        description=f"Rule contains wide subnet: {addr}",
                        recommendation=f"Narrow the subnet range {addr} to specific required networks",
                        details={'subnet': addr, 'cidr': cidr_int},
                        score=score_breakdown['base_score'],
                        score_breakdown=score_breakdown,
                        calculation_formula=formula
                    )
                    findings.append(finding)
                except (ValueError, IndexError):
                    pass

        return findings