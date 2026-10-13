"""Reference data the UI needs to render its controls."""

from fastapi import APIRouter, Depends

from firewall_analyzer.analysis import frameworks as compliance_frameworks
from firewall_analyzer.config.manager import ConfigurationManager
from firewall_analyzer.core.models import RiskLevel, RuleIssueType, VendorType

from .. import store
from .auth import current_user

router = APIRouter(tags=["meta"])

#: /health stays open so a probe does not need credentials; the rest require one.
_authed = [Depends(current_user)]

#: Severity order, worst first. The UI relies on this for sorting and for the
#: order of legend entries, so it lives here rather than being hardcoded twice.
RISK_ORDER = ["critical", "high", "medium", "low", "info"]

#: One line of context per vendor for the "choose a solution" picker. Purely
#: descriptive — the actual column mapping lives in field_mapping_schema.json
#: and is read below, so this text can never drift out of sync with it.
VENDOR_BLURB = {
    "palo_alto": "PAN-OS rule export (Security Policy CSV)",
    "cisco_asa": "ASA access-list export",
    "fortinet": "FortiGate policy export (PolicyID, SrcZone, ...)",
    "checkpoint": "Check Point rulebase export",
    "juniper_srx": "SRX security policy export",
    "generic": "Any CSV with source/destination/service/action columns",
}

#: `VendorType.value.title()` mangles acronyms ("Cisco Asa", "Juniper Srx"), so
#: the picker's display name is spelled out here instead of derived.
VENDOR_LABEL = {
    "palo_alto": "Palo Alto",
    "cisco_asa": "Cisco ASA",
    "fortinet": "Fortinet",
    "checkpoint": "Check Point",
    "juniper_srx": "Juniper SRX",
    "generic": "Generic / Other",
}

_config_manager = ConfigurationManager()


def _vendor_info(vendor: VendorType) -> dict:
    schema = _config_manager.get_vendor_schema(vendor)
    return {
        "value": vendor.value,
        "label": VENDOR_LABEL.get(vendor.value, vendor.value.replace("_", " ").title()),
        "description": VENDOR_BLURB.get(vendor.value, ""),
        "required_fields": schema.get("required_fields", []),
        "optional_fields": schema.get("optional_fields", []),
    }


@router.get("/meta", dependencies=_authed)
def get_meta():
    return {
        "vendors": [_vendor_info(v) for v in VendorType],
        "risk_levels": RISK_ORDER,
        "issue_types": [
            {"value": t.value, "label": t.value.replace("_", " ").title()}
            for t in RuleIssueType
        ],
        "all_risk_levels": [r.value for r in RiskLevel],
        # Compliance frameworks, implemented or planned, from the registry.
        "frameworks": compliance_frameworks.catalog(),
    }


@router.get("/projects", dependencies=_authed)
def list_projects():
    return {"items": store.list_projects()}


@router.get("/health")
def health():
    return {"status": "ok"}
