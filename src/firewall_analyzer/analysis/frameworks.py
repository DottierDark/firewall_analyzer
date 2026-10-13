"""Compliance framework registry.

One analysis can be assessed against several frameworks at once. Each
framework is a class registered here; the orchestrator, the web API, the
upload wizard and the Compliance page all read this registry, so adding a
framework is one new class and one line in REGISTRY - nothing else changes.

Adding a framework
------------------
1. Subclass ComplianceFramework, set the metadata attributes, and implement
   `assess(rules)` returning the RESULT CONTRACT below. NCA ECC
   (analysis/compliance.py) is the reference implementation.
2. Add an instance to REGISTRY.

Until step 1 is done a framework can still be listed with `PlannedFramework`:
it appears in the wizard as "not yet available", can be selected, and the run
records that it was requested without inventing a result.

RESULT CONTRACT (what `assess` returns)
---------------------------------------
    framework         str   full name, e.g. "NCA ... (ECC-1:2018)"
    domain            str   scope statement shown under the name
    overall_status    str   FULLY_COMPLIANT | PARTIALLY_COMPLIANT | NON_COMPLIANT | NOT_APPLICABLE
    compliance_pct    float passed_checks / total_checks * 100
    total_checks, passed_checks, failed_checks, na_checks            int
    evaluated_rules, rules_fully_compliant, rules_with_issues        int
    controls          {id: {id, subdomain, subdomain_name, title, recommendation,
                            na_recommendation, applicable, compliant,
                            non_compliant, na, status, violating_rules: [{id, name}]}}
                      control status: COMPLIANT | PARTIAL | NON_COMPLIANT | NOT_APPLICABLE
    subdomains        {id: {id, name, controls: [ids], applicable, compliant,
                            non_compliant, status}}
                      "subdomain" is the framework's grouping level; its display
                      name comes from `group_label` (Subdomain, Function, Domain...).
    findings          [SecurityFinding] control-level findings, rule_id prefixed
                      with `finding_prefix` so they are never mistaken for rules.
    rule_reports      optional per-rule detail; not persisted by the web UI.

Every assessment the registry hands back also carries `status`:
"assessed", "not_implemented" or "error" (the framework raised - the run
continues and the error is shown on that framework's tab).
"""

import logging
from typing import Any, Dict, Iterable, List, Tuple

from .compliance import ComplianceAnalyzer, ECC_DOMAIN, ECC_FRAMEWORK

logger = logging.getLogger(__name__)


class ComplianceFramework:
    key = ""                 # stable id, stored with the analysis
    short = ""               # badge text, e.g. "ECC"
    name = ""                # full title
    description = ""         # one line for the wizard
    group_label = "Subdomain"
    implemented = True

    @property
    def finding_prefix(self) -> str:
        return f"{self.short or self.key.upper()}-"

    def assess(self, rules) -> Dict[str, Any]:
        raise NotImplementedError

    def meta(self) -> Dict[str, Any]:
        return {
            "key": self.key, "short": self.short, "name": self.name,
            "description": self.description, "group_label": self.group_label,
            "implemented": self.implemented, "finding_prefix": self.finding_prefix,
        }


class EccFramework(ComplianceFramework):
    key = "ecc"
    short = "ECC"
    name = "Essential Cybersecurity Controls"
    description = "NCA ECC-1:2018 — Saudi national baseline. Network segmentation and perimeter controls."
    group_label = "Subdomain"

    def assess(self, rules) -> Dict[str, Any]:
        result = ComplianceAnalyzer().analyze_ruleset(rules)
        result.setdefault("framework", ECC_FRAMEWORK)
        result.setdefault("domain", ECC_DOMAIN)
        return result


class PlannedFramework(ComplianceFramework):
    """Listed and selectable, but not assessed yet."""
    implemented = False

    def __init__(self, key: str, short: str, name: str, description: str, group_label: str):
        self.key, self.short, self.name = key, short, name
        self.description, self.group_label = description, group_label

    def assess(self, rules) -> Dict[str, Any]:
        raise NotImplementedError(f"{self.short} assessment is not implemented yet")


REGISTRY: Dict[str, ComplianceFramework] = {
    fw.key: fw for fw in [
        EccFramework(),
        PlannedFramework("ccc", "CCC", "Cloud Cybersecurity Controls",
                         "NCA CCC-1:2020 — cloud-hosted and hybrid estates.", "Domain"),
        PlannedFramework("nist", "NIST", "NIST Cybersecurity Framework",
                         "NIST CSF 2.0 — Govern / Identify / Protect / Detect / Respond / Recover.", "Function"),
    ]
}

DEFAULT_FRAMEWORKS = ["ecc"]


def catalog() -> List[Dict[str, Any]]:
    """Every registered framework's metadata, in registry order."""
    return [fw.meta() for fw in REGISTRY.values()]


def finding_prefixes() -> Tuple[str, ...]:
    return tuple(fw.finding_prefix for fw in REGISTRY.values())


def normalize_keys(keys: Iterable[str]) -> List[str]:
    """Lower-case, de-duplicate, keep order; unknown keys raise ValueError."""
    out: List[str] = []
    for raw in keys or []:
        for part in str(raw).split(","):
            key = part.strip().lower()
            if not key:
                continue
            if key not in REGISTRY:
                raise ValueError(f"Unknown compliance framework '{key}'")
            if key not in out:
                out.append(key)
    return out


def assess_all(keys: Iterable[str], rules) -> Tuple[Dict[str, Dict[str, Any]], List[Any]]:
    """Assess `rules` against each requested framework.

    Returns (assessments keyed by framework, control-level findings from every
    framework that was assessed). One framework failing never fails the run.
    """
    assessments: Dict[str, Dict[str, Any]] = {}
    findings: List[Any] = []
    for key in normalize_keys(keys) or DEFAULT_FRAMEWORKS:
        fw = REGISTRY[key]
        base = {"key": fw.key, "short": fw.short, "name": fw.name, "group_label": fw.group_label}
        if not fw.implemented:
            assessments[key] = {
                **base, "status": "not_implemented",
                "message": "Its controls are not implemented yet, so no assessment was produced on this run.",
            }
            continue
        try:
            result = fw.assess(rules)
        except Exception as exc:  # one framework must not sink the others
            logger.exception("compliance framework %s failed", key)
            assessments[key] = {**base, "status": "error", "message": f"{type(exc).__name__}: {exc}"}
            continue
        findings.extend(result.get("findings") or [])
        assessments[key] = {**result, **base, "status": "assessed"}
    return assessments, findings
