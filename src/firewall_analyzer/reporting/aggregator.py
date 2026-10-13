from collections import defaultdict
from typing import List, Dict, Any

from ..core.models import SecurityFinding


class FindingGrouper:
    """Groups and aggregates findings by rule name and other criteria"""

    @staticmethod
    def group_findings_by_rule_name(findings: List[SecurityFinding]) -> Dict[str, List[SecurityFinding]]:
        """Group findings by rule name"""
        grouped = defaultdict(list)
        for finding in findings:
            grouped[finding.rule_name].append(finding)
        return dict(grouped)

    @staticmethod
    def get_findings_summary_by_rule(findings: List[SecurityFinding]) -> Dict[str, Dict[str, Any]]:
        """Get summary statistics for findings grouped by rule"""
        summary = {}
        for finding in findings:
            if finding.rule_name not in summary:
                summary[finding.rule_name] = {
                    'rule_id': finding.rule_id,
                    'total_findings': 0,
                    'total_score': 0,
                    'risk_levels': defaultdict(int),
                    'issue_types': defaultdict(int),
                    'findings': []
                }

            summary[finding.rule_name]['total_findings'] += 1
            summary[finding.rule_name]['total_score'] += finding.score
            summary[finding.rule_name]['risk_levels'][finding.risk_level.value] += 1
            summary[finding.rule_name]['issue_types'][finding.issue_type.value] += 1
            summary[finding.rule_name]['findings'].append({
                'issue_type': finding.issue_type.value,
                'risk_level': finding.risk_level.value,
                'score': finding.score
            })

        return summary