from typing import List, Dict, Any

from ..core.models import FirewallRule, SecurityFinding, RuleIssueType, RiskLevel
from ..utils.ip_utils import IPAddressUtils


class SubnetOverlapDetector:
    """Detects overlapping subnets and hidden allow patterns"""

    def analyze_rules(self, rules: List[FirewallRule]) -> List[SecurityFinding]:
        """Analyze rules for subnet overlaps and hidden patterns"""
        findings = []

        findings.extend(self._detect_subnet_overlaps(rules))
        findings.extend(self._detect_hidden_allows(rules))

        return findings

    def _detect_subnet_overlaps(self, rules: List[FirewallRule]) -> List[SecurityFinding]:
        """Detect overlapping subnets within allow rules"""
        findings = []
        allow_rules = [r for r in rules if r.action.lower() == 'allow' and not r.disabled]

        for i, rule1 in enumerate(allow_rules):
            for rule2 in allow_rules[i+1:]:
                for src1 in rule1.source_addresses:
                    if src1.lower() == 'any':
                        continue

                    for src2 in rule2.source_addresses:
                        if src2.lower() == 'any':
                            continue

                        overlap = IPAddressUtils.subnet_overlap_check(src1, src2)

                        if overlap['overlaps'] and overlap['overlap_type'] != 'identical':
                            score = self._calculate_overlap_score(overlap['overlap_type'])

                            score_breakdown = {
                                'base_score': score,
                                'factors': {
                                    'overlap_type': overlap['overlap_type'],
                                    'potential_redundancy': 15
                                },
                                'calculation_steps': [
                                    f"Overlap type ({overlap['overlap_type']}): {score} points",
                                    'Potential redundancy: +15 points',
                                    f'Total: {score + 15} points'
                                ],
                                'total_score': score + 15
                            }

                            formula = f"Score = {score} ({overlap['overlap_type']}) + 15 = {score + 15}"

                            finding = SecurityFinding(
                                rule_id=rule1.id,
                                rule_name=rule1.name,
                                issue_type=RuleIssueType.REDUNDANT,
                                risk_level=RiskLevel.MEDIUM,
                                description=f"Source subnet overlap: {src1} overlaps with rule '{rule2.name}'",
                                recommendation="Review overlapping subnets for different purposes or consolidate",
                                details={
                                    'overlap_type': overlap['overlap_type'],
                                    'subnet1': src1,
                                    'subnet2': src2,
                                    'conflicting_rule': rule2.id
                                },
                                score=score_breakdown['total_score'],
                                score_breakdown=score_breakdown,
                                calculation_formula=formula
                            )
                            findings.append(finding)

        return findings

    def _detect_hidden_allows(self, rules: List[FirewallRule]) -> List[SecurityFinding]:
        """Detect scenarios where effective access differs from intended access"""
        findings = []
        allow_rules = [r for r in rules if r.action.lower() == 'allow' and not r.disabled]
        deny_rules = [r for r in rules if r.action.lower() == 'deny' and not r.disabled]

        if not deny_rules:
            return findings

        for deny_rule in deny_rules:
            if all(addr.lower() == 'any' for addr in deny_rule.source_addresses + deny_rule.dest_addresses):
                continue

            for allow_rule in allow_rules:
                hidden_access = self._check_hidden_access(allow_rule, deny_rule)

                if hidden_access['found']:
                    score = 75

                    score_breakdown = {
                        'base_score': score,
                        'factors': {
                            'hidden_access': 40,
                            'policy_inconsistency': 25,
                            'bypass_potential': 10
                        },
                        'calculation_steps': [
                            'Hidden access pattern: 40 points',
                            'Policy inconsistency: 25 points',
                            'Bypass potential: 10 points',
                            f'Total: {score} points'
                        ],
                        'total_score': score
                    }

                    formula = "Score = 40 + 25 + 10 = 75"

                    finding = SecurityFinding(
                        rule_id=allow_rule.id,
                        rule_name=allow_rule.name,
                        issue_type=RuleIssueType.MISCONFIGURED,
                        risk_level=RiskLevel.HIGH,
                        description=f"Hidden ALLOW: Rule allows access denied by '{deny_rule.name}'",
                        recommendation="Review rule order - ensure deny rules evaluated before allow rules",
                        details={
                            'allow_rule': allow_rule.id,
                            'deny_rule': deny_rule.id,
                            'hidden_access_details': hidden_access['details']
                        },
                        score=score_breakdown['total_score'],
                        score_breakdown=score_breakdown,
                        calculation_formula=formula
                    )
                    findings.append(finding)

        return findings

    def _check_hidden_access(self, allow_rule: FirewallRule, deny_rule: FirewallRule) -> Dict:
        """Check if allow rule creates hidden access bypassing deny rule"""
        allow_src_any = any(addr.lower() == 'any' for addr in allow_rule.source_addresses)
        allow_dst_any = any(addr.lower() == 'any' for addr in allow_rule.dest_addresses)
        allow_svc_any = any(svc.lower() == 'any' for svc in allow_rule.services)

        deny_src_any = any(addr.lower() == 'any' for addr in deny_rule.source_addresses)
        deny_dst_any = any(addr.lower() == 'any' for addr in deny_rule.dest_addresses)
        deny_svc_any = any(svc.lower() == 'any' for svc in deny_rule.services)

        if (allow_src_any and not deny_src_any) or \
           (allow_dst_any and not deny_dst_any) or \
           (allow_svc_any and not deny_svc_any):
            return {
                'found': True,
                'details': {
                    'allow_broader_sources': allow_src_any and not deny_src_any,
                    'allow_broader_destinations': allow_dst_any and not deny_dst_any,
                    'allow_broader_services': allow_svc_any and not deny_svc_any
                }
            }

        return {'found': False, 'details': {}}

    def _calculate_overlap_score(self, overlap_type: str) -> int:
        """Calculate score based on overlap type"""
        scores = {
            'identical': 60,
            'contained_in': 40,
            'contains': 50,
            'partial_overlap': 45
        }
        return scores.get(overlap_type, 30)