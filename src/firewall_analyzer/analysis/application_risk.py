from typing import List, Dict, Any, Optional

from .base import BaseAnalyzer
from ..core.models import FirewallRule, SecurityFinding, RuleIssueType, RiskLevel


class ApplicationRiskAnalyzer(BaseAnalyzer):
    """Scores applications using configuration and Palo Alto App-ID metadata."""

    def __init__(self, analysis_config: Optional[Dict[str, Any]] = None, app_id_handler=None):
        self.analysis_config = analysis_config or {}
        scoring_config = self.analysis_config.get('application_risk_scoring', {})

        self.enabled = scoring_config.get('enabled', False)
        self.applipedia_enabled = scoring_config.get('applipedia_enabled', True)
        self.max_score_per_application = scoring_config.get('max_score_per_application', 35)
        self.max_score_per_rule = scoring_config.get('max_score_per_rule', 90)
        self.min_risk_rating_for_finding = scoring_config.get('min_risk_rating_for_finding', 3)
        self.default_risk_levels = scoring_config.get(
            'default_risk_levels',
            {'high': 5, 'medium': 3, 'low': 1}
        )

        risk_weights = self.analysis_config.get('risk_scoring', {}).get('risk_weights', {})
        self.application_weight = risk_weights.get('application_risk', 0.25)
        self.max_weighted_score = max(int(100 * self.application_weight), 1)

        application_levels = self.analysis_config.get('application_risk_levels', {})
        self.high_risk_apps = {app.lower(): self.default_risk_levels.get('high', 5)
                               for app in application_levels.get('high', [])}
        self.medium_risk_apps = {app.lower(): self.default_risk_levels.get('medium', 3)
                                 for app in application_levels.get('medium', [])}
        self.low_risk_apps = {app.lower(): self.default_risk_levels.get('low', 1)
                              for app in application_levels.get('low', [])}

        self.app_id_handler = app_id_handler

    def analyze(self, rule: FirewallRule) -> List[SecurityFinding]:
        if not self.enabled or rule.disabled:
            return []

        if not rule.applications or all(app.lower() == 'any' for app in rule.applications):
            return []

        findings: List[SecurityFinding] = []
        cumulative_score = 0

        for application in rule.applications:
            app_name = application.strip()
            if not app_name or app_name.lower() == 'any':
                continue

            risk_info = self._determine_risk_rating(app_name)
            risk_rating = risk_info['risk']

            if risk_rating < self.min_risk_rating_for_finding:
                continue

            score = self._calculate_score(risk_rating)
            if score <= 0:
                continue

            if cumulative_score + score > self.max_score_per_rule:
                score = max(self.max_score_per_rule - cumulative_score, 0)

            if score == 0:
                break

            risk_level = self._map_risk_level(risk_rating)
            display_label = risk_info.get('display_label', app_name)
            breakdown = self._build_score_breakdown(display_label, risk_rating, risk_info, score)

            finding = SecurityFinding(
                rule_id=rule.id,
                rule_name=rule.name,
                issue_type=RuleIssueType.APPLICATION_RISK,
                risk_level=risk_level,
                description=f"Rule allows application '{display_label}' with risk rating {risk_rating}/5",
                recommendation="Restrict or closely monitor high-risk applications and validate business justification.",
                details={
                    'application': display_label,
                    'risk_rating': risk_rating,
                    'metadata': risk_info.get('metadata', {}),
                    'risk_source': risk_info.get('source')
                },
                score=score,
                score_breakdown=breakdown,
                calculation_formula=(
                    f"Score = min({self.max_weighted_score} * {risk_rating}/5, "
                    f"{self.max_score_per_application}) = {score}"
                )
            )

            findings.append(finding)
            cumulative_score += score

            if cumulative_score >= self.max_score_per_rule:
                break

        return findings

    def _determine_risk_rating(self, application: str) -> Dict[str, Any]:
        app_lower = application.lower()
        metadata = {}
        source = 'config'
        risk_rating = 0

        if self.applipedia_enabled and self.app_id_handler:
            metadata = self.app_id_handler.get_application_metadata(application)
            if not metadata:
                metadata = self.app_id_handler.get_application_metadata(app_lower)
            risk_rating = metadata.get('risk', 0)
            if risk_rating:
                source = 'palo_alto_applipedia'

        if risk_rating == 0 and app_lower in self.high_risk_apps:
            risk_rating = self.high_risk_apps[app_lower]
            source = 'analysis_config_high'
        elif risk_rating == 0 and app_lower in self.medium_risk_apps:
            risk_rating = self.medium_risk_apps[app_lower]
            source = 'analysis_config_medium'
        elif risk_rating == 0 and app_lower in self.low_risk_apps:
            risk_rating = self.low_risk_apps[app_lower]
            source = 'analysis_config_low'

        display_label = metadata.get('display_name') if metadata else application

        return {
            'risk': min(max(risk_rating, 0), 5),
            'source': source,
            'metadata': metadata,
            'display_label': display_label
        }

    def _calculate_score(self, risk_rating: int) -> int:
        raw_score = int((risk_rating / 5) * self.max_weighted_score)
        return min(raw_score, self.max_score_per_application)

    @staticmethod
    def _map_risk_level(risk_rating: int) -> RiskLevel:
        if risk_rating >= 5:
            return RiskLevel.CRITICAL
        if risk_rating == 4:
            return RiskLevel.HIGH
        if risk_rating == 3:
            return RiskLevel.MEDIUM
        if risk_rating == 2:
            return RiskLevel.LOW
        return RiskLevel.INFO

    def _build_score_breakdown(self, application: str, risk_rating: int,
                               risk_info: Dict[str, Any], score: int) -> Dict[str, Any]:
        metadata = risk_info.get('metadata', {})
        return {
            'application': application,
            'risk_rating': risk_rating,
            'risk_source': risk_info.get('source'),
            'metadata': {
                'category': metadata.get('category'),
                'subcategory': metadata.get('subcategory'),
                'technology': metadata.get('technology'),
                'description': metadata.get('description')
            },
            'max_weighted_score': self.max_weighted_score,
            'score_cap_per_application': self.max_score_per_application,
            'final_score': score
        }
