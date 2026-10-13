"""Bridges the API to the `firewall_analyzer` package.

The analyzer is imported and driven in-process rather than shelled out to, so
results arrive as objects instead of being parsed back out of HTML. Two things
matter for responsiveness:

* The Applipedia database (~6 MB of JSON, 5k applications) is loaded once and
  shared by every run. Parsing it per analysis dominated the CLI's runtime.
* The analyzers print progress to stdout. That output is captured per run rather
  than being allowed to interleave in the server log.
"""

import contextlib
import csv
import io
import json
import logging
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from firewall_analyzer.analysis import frameworks as compliance_frameworks
from firewall_analyzer.config.manager import ConfigurationManager
from firewall_analyzer.core.models import FirewallRule, SecurityFinding, VendorType
from firewall_analyzer.data.appid_handler import PaloAltoAppIDHandler
from firewall_analyzer.data.parser import MultiVendorCSVParser
from firewall_analyzer.orchestrator import EnhancedFirewallRuleAnalyzer
from firewall_analyzer.reporting.html_generator import EnhancedHTMLReportGenerator

from . import config

logger = logging.getLogger(__name__)

_appid_lock = threading.Lock()
_appid_handler: Optional[PaloAltoAppIDHandler] = None


def get_appid_handler() -> PaloAltoAppIDHandler:
    """Load the Applipedia database once, on first use."""
    global _appid_handler
    with _appid_lock:
        if _appid_handler is None:
            logger.info("loading Applipedia database from %s", config.APPID_DB)
            with contextlib.redirect_stdout(io.StringIO()):
                _appid_handler = PaloAltoAppIDHandler(str(config.APPID_DB))
            logger.info("Applipedia ready: %d applications", len(_appid_handler.app_id_database))
    return _appid_handler


def warm_up() -> None:
    """Called at startup so the first user request is not the one that pays."""
    get_appid_handler()


# --------------------------------------------------------------- input prep

EXCEL_SUFFIXES = {".xlsx", ".xls", ".xlsm"}


def to_csv(source: Path) -> Path:
    """Return a CSV path for `source`, converting a spreadsheet if needed.

    The analyzer's parser reads CSV only; handing it a .xlsx produces an opaque
    UTF-8 decode error. Converting here means the UI can accept either.
    """
    if source.suffix.lower() not in EXCEL_SUFFIXES:
        return source

    try:
        import openpyxl
    except ImportError as exc:  # pragma: no cover - dependency is declared
        raise RuntimeError(
            "Excel upload needs the 'openpyxl' package on the API service."
        ) from exc

    book = openpyxl.load_workbook(source, read_only=True, data_only=True)
    sheet = book.active
    target = source.with_suffix(".converted.csv")
    with open(target, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        for row in sheet.iter_rows(values_only=True):
            writer.writerow(["" if cell is None else cell for cell in row])
    book.close()
    return target


def sniff_headers(source: Path) -> List[str]:
    """Column names of the uploaded file, for the wizard's preview step."""
    path = to_csv(source)
    with open(path, "r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle)
        for row in reader:
            if any(cell.strip() for cell in row):
                return [cell.strip() for cell in row]
    return []


# ------------------------------------------------------------ serialization


def _finding_dict(finding: SecurityFinding) -> Dict[str, Any]:
    return {
        "rule_id": str(finding.rule_id),
        "rule_name": finding.rule_name,
        "issue_type": finding.issue_type.value,
        "risk_level": finding.risk_level.value,
        "score": int(finding.score),
        "description": finding.description,
        "recommendation": finding.recommendation,
        "formula": finding.calculation_formula or "",
        "details": _jsonable(finding.details),
    }


def _rule_dict(rule: FirewallRule, seq: int, analyzed: bool = True) -> Dict[str, Any]:
    return {
        "seq": seq,
        "analyzed": analyzed,
        "rule_id": str(rule.id),
        "name": rule.name,
        "action": (rule.action or "").lower(),
        "disabled": bool(rule.disabled),
        "src_zones": list(rule.source_zones),
        "dst_zones": list(rule.dest_zones),
        "src_addresses": list(rule.source_addresses),
        "dst_addresses": list(rule.dest_addresses),
        "services": list(rule.services),
        "applications": list(rule.applications),
        "logging": rule.logging or "",
        "rule_usage": rule.rule_usage or "",
        "risk_score": int(rule.risk_score),
        "finding_count": len(rule.findings),
        "raw": _jsonable(rule.raw_data),
    }


#: Stored shape of the `compliance` column. Version 1 was a single ECC result;
#: store.py upgrades those on read, so both shapes reach the UI as version 2.
COMPLIANCE_VERSION = 2


def _compliance_record(compliance: Dict[str, Any]) -> Dict[str, Any]:
    """Every requested framework's assessment, minus the bulky parts.

    `rule_reports` (per-rule detail, ~200 KB for 240 rules) and `findings`
    (already persisted in the findings table) are dropped; the violating rule
    ids stay on each control, so the detail can be rebuilt from the rules table.
    """
    assessments = compliance.get("assessments") or {}
    return {
        "version": COMPLIANCE_VERSION,
        "frameworks": list(compliance.get("frameworks") or assessments),
        "assessments": {
            key: _jsonable({k: v for k, v in result.items() if k not in ("rule_reports", "findings")})
            for key, result in assessments.items()
        },
    }


def _jsonable(value: Any) -> Any:
    """Coerce analyzer payloads into something json.dumps accepts.

    Findings carry `details` dicts assembled ad hoc by each analyzer; they can
    hold sets, enums and nested rule objects.
    """
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, set):
        return sorted(_jsonable(v) for v in value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if hasattr(value, "value"):        # Enum
        return value.value
    return str(value)


# ------------------------------------------------------------------- runner


def run_analysis(
    source_path: Path,
    *,
    vendor: Optional[str],
    report_path: Path,
    progress: Callable[[str], None] = lambda _step: None,
    frameworks: Optional[List[str]] = None,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Parse, analyze and render one ruleset.

    Returns `(meta, findings, rules)` where meta carries the summary, statistics
    and zone matrix. Raises on any failure; the caller records it on the row.
    """
    progress("Reading input file")
    csv_path = to_csv(source_path)

    manager = ConfigurationManager()
    zone_config = manager.load_zone_config(None)
    analysis_config = manager.load_analysis_config(str(config.ANALYSIS_CONFIG))
    handler = get_appid_handler()

    vendor_type = VendorType(vendor) if vendor else None

    # The analyzers narrate to stdout; keep that out of the server log but hold
    # on to it so a failed run can show what it managed to do.
    captured = io.StringIO()

    progress("Parsing rules")
    with contextlib.redirect_stdout(captured):
        parser = MultiVendorCSVParser(
            vendor_type=vendor_type,
            config_manager=manager,
            use_hashed=False,
            debug=False,
            app_id_handler=handler,
        )
        rules = parser.parse_csv(str(csv_path))

    if not rules:
        raise ValueError("No rules were parsed from the file. Check that it is a rule export.")

    progress(f"Analyzing {len(rules)} rules")
    with contextlib.redirect_stdout(captured):
        analyzer = EnhancedFirewallRuleAnalyzer(
            zone_config=zone_config,
            config_manager=manager,
            analysis_config=analysis_config,
            app_id_handler=handler,
            frameworks=frameworks,
        )
        results = analyzer.analyze_rules(rules)

    progress("Generating report")
    with contextlib.redirect_stdout(captured):
        generator = EnhancedHTMLReportGenerator(detailed_mode=True, group_by_name=False)
        generator.generate_report(results, str(report_path))

    stats = results["statistics"]
    detected_vendor = rules[0].vendor_type.value if rules else "unknown"

    meta = {
        "vendor": detected_vendor,
        "summary": _jsonable(results["summary"]),
        "stats": _jsonable(
            {
                **{k: v for k, v in stats.items() if k != "zone_summary"},
                "findings_by_type": dict(stats.get("findings_by_type", {})),
                "findings_by_risk": dict(stats.get("findings_by_risk", {})),
                "vendor_distribution": dict(stats.get("vendor_distribution", {})),
            }
        ),
        "zone_summary": _jsonable(results.get("zone_summary", {})),
        "compliance": _compliance_record(results.get("compliance") or {}),
        "log": captured.getvalue()[-8000:],
    }

    findings = [_finding_dict(f) for f in results["findings"]]

    # Every rule in the file, so the Rule Explorer can show disabled and
    # filtered-out rules too - not just the ones that reached the analyzers.
    #
    # `results["rules"]` is the filtered set the orchestrator actually scored
    # (it drops disabled rules and catch-all deny any->any cleanup rules), so
    # membership in it is the authoritative answer to "was this assessed?".
    # Recording that is what stops an unscored rule being counted as clean.
    analyzed = {id(r): r for r in results.get("rules", [])}
    all_rules = results.get("all_rules", rules)
    rule_rows = [
        _rule_dict(analyzed.get(id(r), r), i + 1, analyzed=id(r) in analyzed)
        for i, r in enumerate(all_rules)
    ]

    return meta, findings, rule_rows
