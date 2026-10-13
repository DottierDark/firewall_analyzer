from collections import defaultdict
from typing import Dict, Any, List

from .analysis.logging_audit_checker import LoggingAuditAnalyzer          
from .analysis.remote_management_checker import RemoteManagementAnalyzer
from .analysis.malicious_ip_checker import MaliciousIPAnalyzer
from .analysis.zone_analyzer import ZoneBasedAnalyzer
from .analysis.overlap_detector import SubnetOverlapDetector
from .analysis.protocols import InsecureProtocolAnalyzer
from .analysis.permissions import OverlyPermissiveRuleAnalyzer
from .analysis.redundancy import RedundancyAnalyzer
from .analysis.best_practices import BestPracticesAnalyzer
from .analysis.deny import DenyAnyAnyAnalyzer
from .analysis.expired import ExpiredRuleAnalyzer
from .analysis.security_profiles import SecurityProfileAnalyzer
from .analysis.application_risk import ApplicationRiskAnalyzer
from .reporting.aggregator import FindingGrouper
from .core.models import FirewallRule
from .analysis.external_communications import ExternalCommunicationsAnalyzer
from .analysis import frameworks as compliance_frameworks
from .core import posture


class EnhancedFirewallRuleAnalyzer:
    """Extended analyzer with zone-based, application-aware scoring and subnet overlap detection"""

    def __init__(self, high_risk_threshold: int = 70, medium_risk_threshold: int = 40,
                 zone_config: Dict = None, config_manager=None, analysis_config: Dict = None,
                 app_id_handler=None, frameworks=None):
        self.high_risk_threshold = high_risk_threshold
        self.medium_risk_threshold = medium_risk_threshold
        self.zone_config = zone_config or config_manager.DEFAULT_ZONE_CONFIG if config_manager else {}
        self.config_manager = config_manager
        self.analysis_config = analysis_config or (
            config_manager.load_analysis_config() if config_manager else {})
        self.app_id_handler = app_id_handler

        self.logging_audit_analyzer = LoggingAuditAnalyzer()            
        self.remote_mgmt_analyzer = RemoteManagementAnalyzer()
        self.malicious_ip_analyzer = MaliciousIPAnalyzer()

        self.zone_analyzer = ZoneBasedAnalyzer(self.zone_config)
        self.subnet_overlap_detector = SubnetOverlapDetector()

        self.insecure_protocol_analyzer = InsecureProtocolAnalyzer()
        self.permissive_analyzer = OverlyPermissiveRuleAnalyzer()
        self.redundancy_analyzer = RedundancyAnalyzer()
        self.deny_any_any_analyzer = DenyAnyAnyAnalyzer()
        self.expired_analyzer = ExpiredRuleAnalyzer()
        self.security_profile_analyzer = SecurityProfileAnalyzer()
        self.best_practices_analyzer = BestPracticesAnalyzer()
        self.application_risk_analyzer = ApplicationRiskAnalyzer(
            analysis_config=self.analysis_config,
            app_id_handler=self.app_id_handler
        )
        self.external_communications_analyzer = ExternalCommunicationsAnalyzer()
        # Compliance frameworks to assess, by registry key (see
        # analysis/frameworks.py). ECC alone unless the caller asks for more.
        self.frameworks = compliance_frameworks.normalize_keys(
            frameworks or compliance_frameworks.DEFAULT_FRAMEWORKS)


    def analyze_rules(self, rules: List[FirewallRule]) -> Dict[str, Any]:
        """Perform enhanced analysis including zone-based and subnet analysis"""
        filtered_rules = self._filter_analysis_rules(rules)

        all_findings = []

        for rule in filtered_rules:
            # Skip disabled rules - do not analyze them at all
            if rule.disabled:
                continue

            rule_findings = []
            rule_findings.extend(self.insecure_protocol_analyzer.analyze(rule))
            rule_findings.extend(self.permissive_analyzer.analyze(rule))
            rule_findings.extend(self.best_practices_analyzer.analyze(rule))
            rule_findings.extend(self.application_risk_analyzer.analyze(rule))
            rule_findings.extend(self.malicious_ip_analyzer.analyze(rule))
            rule_findings.extend(self.remote_mgmt_analyzer.analyze(rule))
            rule_findings.extend(self.logging_audit_analyzer.analyze(rule))

            rule.risk_score = sum(f.score for f in rule_findings)
            rule.score_breakdown = self._aggregate_score_breakdown(rule_findings)
            rule.findings = rule_findings
            all_findings.extend(rule_findings)

        # Only analyze redundancy and subnet overlaps on non-disabled rules
        redundancy_findings = self.redundancy_analyzer.analyze_ruleset(filtered_rules)
        all_findings.extend(redundancy_findings)

        for finding in redundancy_findings:
            for rule in filtered_rules:
                if rule.id == finding.rule_id:
                    rule.findings.append(finding)
                    rule.risk_score += finding.score
                    break

        subnet_findings = self.subnet_overlap_detector.analyze_rules(filtered_rules)
        all_findings.extend(subnet_findings)
        deny_findings = self.deny_any_any_analyzer.analyze_ruleset(rules)
        all_findings.extend(deny_findings)
        expired_findings = self.expired_analyzer.analyze_ruleset(rules)
        all_findings.extend(expired_findings)
        sp_findings = self.security_profile_analyzer.analyze_ruleset(rules)
        all_findings.extend(sp_findings)

        for finding in subnet_findings:
            for rule in filtered_rules:
                if rule.id == finding.rule_id:
                    rule.findings.append(finding)
                    rule.risk_score += finding.score
                    break

        # Compliance is assessed against every rule in the file, not the
        # filtered set: "is logging enabled on every rule" is a question about
        # the configuration as written, including the cleanup rules the risk
        # analyzers deliberately skip. Each requested framework is assessed
        # independently; see analysis/frameworks.py for the result contract.
        assessments, compliance_findings = compliance_frameworks.assess_all(self.frameworks, rules)
        all_findings.extend(compliance_findings)

        zone_summary = self.zone_analyzer.get_zone_summary(filtered_rules)
        external_results = {
                "external_rules": [],
                "potential_external_rules": [],
                "total_external_rules": 0,
                "total_potential_external": 0
            }

        stats = self._generate_enhanced_statistics(filtered_rules, all_findings, rules)

        high_risk_rules = [r for r in filtered_rules if r.risk_score >= self.high_risk_threshold]
        medium_risk_rules = [r for r in filtered_rules if self.medium_risk_threshold <= r.risk_score < self.high_risk_threshold]

        # Group findings by rule name
        grouped_findings = FindingGrouper.group_findings_by_rule_name(all_findings)
        findings_summary = FindingGrouper.get_findings_summary_by_rule(all_findings)

        return {
            'rules': filtered_rules,
            'findings': all_findings,
            'statistics': stats,
            'high_risk_rules': high_risk_rules,
            'medium_risk_rules': medium_risk_rules,
            'summary': self._generate_summary(stats, all_findings, filtered_rules),
            'zone_summary': zone_summary,
            'disabled_rules': [r for r in rules if r.disabled],
            'deny_rules': [r for r in rules if r.action.lower() == 'deny'],
            'all_rules': rules,
            'grouped_findings': grouped_findings,
            'findings_summary': findings_summary,
            'external_communications': external_results,
            'compliance': {'frameworks': list(assessments), 'assessments': assessments},
        }

    def _filter_analysis_rules(self, rules: List[FirewallRule]) -> List[FirewallRule]:
        """Filter out disabled and DENY Any/All rules from analysis"""
        filtered = []

        for rule in rules:
            # Skip disabled rules completely
            if rule.disabled:
                continue

            # Skip DENY Any/All rules (catch-all deny rules)
            if rule.action.lower() == 'deny':
                if all(addr.lower() == 'any' for addr in rule.source_addresses + rule.dest_addresses):
                    continue

            filtered.append(rule)

        return filtered

    def _aggregate_score_breakdown(self, findings: List) -> Dict:
        """Aggregate score breakdown from multiple findings"""
        breakdown = {
            'total_score': sum(f.score for f in findings),
            'by_issue_type': {},
            'findings_count': len(findings),
            'calculation_details': []
        }

        for finding in findings:
            issue_type = finding.issue_type.value
            if issue_type not in breakdown['by_issue_type']:
                breakdown['by_issue_type'][issue_type] = {
                    'score': 0,
                    'count': 0,
                    'details': []
                }

            breakdown['by_issue_type'][issue_type]['score'] += finding.score
            breakdown['by_issue_type'][issue_type]['count'] += 1
            if finding.score_breakdown:
                breakdown['by_issue_type'][issue_type]['details'].append(finding.score_breakdown)

            if finding.calculation_formula:
                breakdown['calculation_details'].append({
                    'issue': issue_type,
                    'formula': finding.calculation_formula,
                    'score': finding.score
                })

        return breakdown

    def _generate_enhanced_statistics(self, filtered_rules: List[FirewallRule],
                                    findings: List, all_rules: List[FirewallRule]) -> Dict[str, Any]:
        """Generate enhanced statistics including zone and rule type breakdowns"""
        stats = {
            'total_rules': len(filtered_rules),
            'allow_rules': len([r for r in filtered_rules if r.action.lower() == 'allow']),
            'all_rules_total': len(all_rules),
            'disabled_rules_excluded': len([r for r in all_rules if r.disabled]),
            'deny_any_rules_excluded': len([r for r in all_rules if r.action.lower() == 'deny' and
                                           all(addr.lower() == 'any' for addr in r.source_addresses + r.dest_addresses)]),
            'disabled_rules': len([r for r in all_rules if r.disabled]),
            'unused_rules': len([r for r in filtered_rules if r.rule_usage.lower() == 'unused']),
            'total_findings': len(findings),
            'findings_by_type': defaultdict(int),
            'findings_by_risk': defaultdict(int),
            'rules_with_any': {
                'source': 0,
                'destination': 0,
                'service': 0,
                'multiple_any': 0
            },
            'insecure_protocols_found': set(),
            'redundant_rules': 0,
            'shadowed_rules': 0,
            'vendor_distribution': defaultdict(int),
            'zone_summary': self.zone_analyzer.get_zone_summary(filtered_rules),
            'zone_traffic_pairs': 0,
            'subnet_overlaps_found': 0
        }

        for rule in filtered_rules:
            stats['vendor_distribution'][rule.vendor_type.value] += 1

        for finding in findings:
            stats['findings_by_type'][finding.issue_type.value] += 1
            stats['findings_by_risk'][finding.risk_level.value] += 1

            if finding.issue_type.value == 'insecure_protocol':
                if 'protocol' in finding.details:
                    stats['insecure_protocols_found'].add(finding.details['protocol'])
            elif finding.issue_type.value == 'redundant':
                stats['redundant_rules'] += 1
            elif finding.issue_type.value == 'shadowed':
                stats['shadowed_rules'] += 1

        for rule in filtered_rules:
            any_count = 0
            if 'any' in [addr.lower() for addr in rule.source_addresses]:
                stats['rules_with_any']['source'] += 1
                any_count += 1
            if 'any' in [addr.lower() for addr in rule.dest_addresses]:
                stats['rules_with_any']['destination'] += 1
                any_count += 1
            if 'any' in [svc.lower() for svc in rule.services]:
                stats['rules_with_any']['service'] += 1
                any_count += 1
            if any_count >= 2:
                stats['rules_with_any']['multiple_any'] += 1

        stats['insecure_protocols_found'] = list(stats['insecure_protocols_found'])
        stats['zone_traffic_pairs'] = len(stats['zone_summary'])

        overlap_findings = [f for f in findings if f.issue_type.value == 'redundant' and
                          'overlap_type' in f.details]
        stats['subnet_overlaps_found'] = len(overlap_findings)

        return stats

    def _generate_summary(self, stats: Dict[str, Any], findings: List,
                          assessed_rules: List[FirewallRule] = ()) -> Dict[str, Any]:
        """Generate executive summary.

        The overall rating is Critical / High / Medium / Low - the same scale as
        a finding - from the posture score over assessed rules (core/posture.py).
        """
        critical_findings = [f for f in findings if f.risk_level.value == 'critical']
        high_findings = [f for f in findings if f.risk_level.value == 'high']

        worst = posture.worst_by_rule(findings, [r.id for r in assessed_rules])
        rating = posture.rate(posture.count_worst(worst), self.analysis_config)

        return {
            'overall_health': rating['rating'] or 'Not rated',
            'posture': rating,
            'critical_issues': len(critical_findings),
            'high_risk_issues': len(high_findings),
            'total_issues': len(findings),
            'recommendations': self._generate_top_recommendations(findings)
        }

    def _generate_top_recommendations(self, findings: List, top_n: int = 15) -> List[Dict]:
        """Generate top recommendations based on findings"""
        recommendations = []
        sorted_findings = sorted(findings, key=lambda f: f.score, reverse=True)

        seen_recommendations = set()
        for finding in sorted_findings:
            if finding.recommendation not in seen_recommendations:
                recommendations.append({
                    'priority': len(recommendations) + 1,
                    'recommendation': finding.recommendation,
                    'risk_level': finding.risk_level.value,
                    'score': finding.score,
                    'affected_rules': [finding.rule_name]
                })
                seen_recommendations.add(finding.recommendation)
                if len(recommendations) >= top_n:
                    break

        return recommendations