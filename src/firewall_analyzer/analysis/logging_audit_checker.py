"""Logging Configuration Audit - flags rules that do NOT have logging enabled.

Vendor-agnostic: reads the logging value from the mapped `rule.logging` field.
The actual source column (LogTraffic, Log Setting, etc.) is defined per vendor
in the ConfigurationManager field mappings - NOT hardcoded here.
"""
from .base import BaseAnalyzer
from ..core.models import SecurityFinding, RuleIssueType, RiskLevel

# Values that mean logging is OFF (works across vendors).
# FortiGate: 'disable' = OFF, 'all'/'utm' = ON. Palo Alto: blank/'no' = OFF.
LOGGING_OFF_VALUES = ["", "no", "none", "disabled", "disable", "off", "false", "0"]


def _logging_enabled(rule):
    """Read the mapped logging value from the rule. Return True / False / None."""
    value = getattr(rule, "logging", None)
    if value is None or str(value).strip() == "":
        return None  # no logging info mapped for this vendor -> nothing to audit
    return str(value).strip().lower() not in LOGGING_OFF_VALUES


class LoggingAuditAnalyzer(BaseAnalyzer):
    """Flags rules without logging. Allow+NoLog = CRITICAL, Deny+NoLog = HIGH."""

    def analyze(self, rule):
        findings = []
        enabled = _logging_enabled(rule)

        # No logging value mapped -> skip (nothing to audit)
        if enabled is None:
            return findings

        # Logging is on -> good, no finding
        if enabled:
            return findings

        action = rule.action.lower()
        base = 60  # base score for missing logging

        if action == "allow":
            factor = 30
            level = RiskLevel.CRITICAL
            print(f"LOGGING [CRITICAL] : '{rule.name}' ALLOW rule has NO logging")
        else:  # deny
            factor = 10
            level = RiskLevel.HIGH
            print(f"LOGGING [HIGH] : '{rule.name}' DENY rule has NO logging")

        total = base + factor
        findings.append(SecurityFinding(
            rule_id=rule.id,
            rule_name=rule.name,
            issue_type=RuleIssueType.MISSING_LOGGING,
            risk_level=level,
            description=f"Rule '{rule.name}' ({rule.action.upper()}) does not have logging enabled - traffic is not auditable.",
            recommendation=f"Enable logging on '{rule.name}' so this {rule.action.upper()} traffic can be audited and monitored.",
            details={"action": rule.action, "logging": "disabled"},
            score=total,
            calculation_formula=f"Score = {base} + {factor} = {total}",
        ))
        return findings