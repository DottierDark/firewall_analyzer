"""Aggregates behind the Overview dashboards.

One call returns everything the Executive, Security Manager and Analyst presets
draw, so switching preset never refetches and the three views can never
disagree about a number.

Two distinctions matter here and are made once, in this module:

* **Pass records are not issues.** The security-profile and deny-any-any
  analyzers emit a score-1 finding to record that a rule is *compliant*. They
  are real rows in the findings table, so severity totals include them (and
  match the Findings page), but every "what needs fixing" figure excludes them.
  Otherwise "Misconfigured" ranks as a top problem while being almost entirely
  confirmations.

* **Rules are counted, not just findings.** Findings multiply - one rule can
  carry ten - so "how many rules need attention" is computed from distinct rule
  ids, joined to the rules table so compliance-level rows (rule id "ECC-...")
  are never counted as rules.
"""

import json
import logging
from collections import Counter, defaultdict
from statistics import median
from typing import Any, Dict, List, Optional

from firewall_analyzer.analysis.frameworks import finding_prefixes
from firewall_analyzer.core import posture

from . import config, store

logger = logging.getLogger(__name__)

SEVERITIES = posture.LEVELS
_SEV_RANK = {level: i for i, level in enumerate(SEVERITIES)}

#: A finding at or below this score records a pass, not a problem.
PASS_SCORE = posture.PASS_SCORE

#: The engine's own rule thresholds (orchestrator high/medium_risk_threshold).
HIGH_THRESHOLD = 70
MEDIUM_THRESHOLD = 40

#: Issue types grouped into the risk areas an executive reads. The wording for
#: each lives in the frontend; this only decides membership, because the
#: distinct-rule union per area has to be computed where the rows are.
THEMES = {
    "logging": ["missing_logging"],
    "protocols": ["insecure_protocol", "unencrypted_traffic", "weak_crypto"],
    "access": ["overly_permissive", "lateral_movement", "weak_authentication"],
    "management": ["management_access"],
    "applications": ["application_risk", "broad_application_allow"],
    "hygiene": ["shadowed", "redundant", "unused", "expired", "disabled",
                "missing_time_restrictions"],
    "config": ["misconfigured"],
}
_THEME_OF = {t: theme for theme, types in THEMES.items() for t in types}

#: Rules that can most likely be deleted outright: they never match, duplicate
#: another rule, have never been hit, or are past their own expiry date.
_REMOVABLE = ("shadowed", "redundant", "unused", "past_expiry")

#: Rule-score bands for the distribution chart. The first two edges are the
#: engine's own thresholds, so the high-risk line falls on a band boundary.
SCORE_BINS = [0, MEDIUM_THRESHOLD, HIGH_THRESHOLD, 100, 150, 200, 250, 300]


def _worst(levels) -> Optional[str]:
    present = [lvl for lvl in levels if lvl in _SEV_RANK]
    return min(present, key=_SEV_RANK.__getitem__) if present else None


def _sev_dict() -> Dict[str, int]:
    return {level: 0 for level in SEVERITIES}


def _loads_list(value: Optional[str]) -> List[str]:
    try:
        data = json.loads(value) if value else []
    except ValueError:
        return []
    return [str(v) for v in data] if isinstance(data, list) else []


def build(analysis_id: str, record: Dict[str, Any]) -> Dict[str, Any]:
    conn = store.connect()

    # ── Severity over every finding: identical to the Findings page chips.
    severity = _sev_dict()
    pass_records = 0
    for row in conn.execute(
        """SELECT risk_level, COUNT(*) AS n,
                  SUM(CASE WHEN score <= ? THEN 1 ELSE 0 END) AS passes
           FROM findings WHERE analysis_id = ? GROUP BY risk_level""",
        (PASS_SCORE, analysis_id),
    ):
        severity[row["risk_level"]] = severity.get(row["risk_level"], 0) + row["n"]
        pass_records += row["passes"] or 0

    # ── Rules: every rule in the file, with whether the engine scored it.
    rules: Dict[str, Dict[str, Any]] = {}
    for row in conn.execute(
        """SELECT rule_id, seq, name, action, disabled, analyzed, src_zones,
                  dst_zones, services, risk_score, finding_count
           FROM rules WHERE analysis_id = ? ORDER BY seq""",
        (analysis_id,),
    ):
        rules[row["rule_id"]] = {
            "rule_id": row["rule_id"],
            "seq": row["seq"],
            "name": row["name"],
            "action": (row["action"] or "").lower(),
            "disabled": bool(row["disabled"]),
            "analyzed": bool(row["analyzed"]),
            "src_zones": _loads_list(row["src_zones"]),
            "dst_zones": _loads_list(row["dst_zones"]),
            "services": _loads_list(row["services"]),
            "risk_score": row["risk_score"] or 0,
            "finding_count": row["finding_count"] or 0,
            "levels": Counter(),
            "theme_worst": {},          # risk area -> most severe level in it
        }

    # ── Issues only (pass records excluded), aggregated per rule/type/level.
    categories: Dict[str, Dict[str, Any]] = {}
    theme_rules: Dict[str, set] = defaultdict(set)
    theme_findings: Dict[str, Counter] = defaultdict(Counter)
    theme_types: Dict[str, set] = defaultdict(set)
    cleanup_rules: Dict[str, set] = defaultdict(set)
    issue_severity = _sev_dict()

    for row in conn.execute(
        """SELECT rule_id, issue_type, risk_level, COUNT(*) AS n,
                  SUM(CASE WHEN description LIKE 'EXPIREDRULE:%' THEN 1 ELSE 0 END) AS past_expiry
           FROM findings
           WHERE analysis_id = ? AND score > ?
           GROUP BY rule_id, issue_type, risk_level""",
        (analysis_id, PASS_SCORE),
    ):
        rule_id, itype, level, n = row["rule_id"], row["issue_type"], row["risk_level"], row["n"]
        issue_severity[level] = issue_severity.get(level, 0) + n

        cat = categories.setdefault(itype, {
            "type": itype, "findings": 0, "rules": set(), "by_severity": _sev_dict(),
        })
        cat["findings"] += n
        cat["by_severity"][level] = cat["by_severity"].get(level, 0) + n

        # Compliance control summaries (every framework's, e.g. "ECC-2-5-3-3")
        # sit under "misconfigured" with a synthetic rule id; compliance has
        # its own page, so keep them out of the configuration-gap area rather
        # than double-reporting them.
        is_rule = rule_id in rules
        theme = _THEME_OF.get(itype, "config")
        if not (theme == "config" and str(rule_id).startswith(finding_prefixes())):
            theme_findings[theme][level] += n
            theme_types[theme].add(itype)
            if is_rule:
                theme_rules[theme].add(rule_id)

        if is_rule:
            cat["rules"].add(rule_id)
            rules[rule_id]["levels"][level] += n
            tw = rules[rule_id]["theme_worst"]
            tw[theme] = _worst([level, tw.get(theme)])
            if itype in ("shadowed", "redundant", "unused"):
                cleanup_rules[itype].add(rule_id)
            elif itype == "expired":
                if row["past_expiry"]:
                    cleanup_rules["past_expiry"].add(rule_id)
                if n - (row["past_expiry"] or 0) > 0:
                    cleanup_rules["stale"].add(rule_id)

    assessed = [r for r in rules.values() if r["analyzed"]]
    disabled = [r for r in rules.values() if r["disabled"]]

    def worst_of(rule):
        return _worst(rule["levels"].keys())

    with_issue = [r for r in assessed if r["levels"]]
    with_critical = [r for r in assessed if r["levels"].get("critical")]
    with_urgent = [r for r in assessed if r["levels"].get("critical") or r["levels"].get("high")]

    # Each assessed rule counted once, under its single worst finding.
    by_worst = {**_sev_dict(), "clean": 0}
    for r in assessed:
        by_worst[worst_of(r) or "clean"] += 1

    # ── Categories, worst-first: critical count, then high, and so on.
    category_rows = sorted(
        (
            {**c, "rules": len(c["rules"]), "worst": _worst(k for k, v in c["by_severity"].items() if v)}
            for c in categories.values()
        ),
        key=lambda c: tuple(-c["by_severity"].get(level, 0) for level in SEVERITIES),
    )

    theme_rows = []
    for key in THEMES:
        counts = theme_findings.get(key)
        if not counts:
            continue
        theme_rows.append({
            "key": key,
            "rules": len(theme_rules.get(key, ())),
            "findings": sum(counts.values()),
            "by_severity": {level: counts.get(level, 0) for level in SEVERITIES},
            "worst": _worst(level for level, v in counts.items() if v),
            "types": sorted(theme_types[key]),
        })
    # Worst severity first; within it, the area with the most critical
    # findings, then the widest reach.
    theme_rows.sort(key=lambda t: (
        _SEV_RANK.get(t["worst"], 9),
        -t["by_severity"].get(t["worst"], 0),
        -t["rules"],
    ))

    # ── Overall rating, from the same module the engine rates with. The
    # parameters stored with the run are reused, so the dashboard reproduces
    # the run's own rating even if the configuration has changed since.
    method = ((record.get("summary") or {}).get("posture") or {}).get("method") or _settings()
    rating = posture.rate(by_worst, method)
    impact = _remediation_impact(assessed, theme_rows, method, rating)

    # ── Cleanup candidates: rules that can very likely be deleted outright.
    removable = set().union(*(cleanup_rules.get(k, set()) for k in _REMOVABLE))
    removable |= {r["rule_id"] for r in disabled}
    cleanup = {
        "shadowed": len(cleanup_rules.get("shadowed", ())),
        "redundant": len(cleanup_rules.get("redundant", ())),
        "unused": len(cleanup_rules.get("unused", ())),
        "past_expiry": len(cleanup_rules.get("past_expiry", ())),
        "stale": len(cleanup_rules.get("stale", ())),
        "disabled": len(disabled),
        "candidates": len(removable),
    }

    # ── Rule risk-score distribution over the assessed population.
    scores = [r["risk_score"] for r in assessed]
    bins = []
    for i, lo in enumerate(SCORE_BINS):
        hi = SCORE_BINS[i + 1] if i + 1 < len(SCORE_BINS) else None
        count = sum(1 for s in scores if s >= lo and (hi is None or s < hi))
        bins.append({"lo": lo, "hi": hi, "count": count})

    # ── Highest-risk rules, worst first (with per-rule severity counts).
    top = sorted(assessed, key=lambda r: (-r["risk_score"], r["seq"]))[:10]
    top_rules = [
        {
            **{k: r[k] for k in ("rule_id", "seq", "name", "action", "src_zones",
                                 "dst_zones", "services", "risk_score", "finding_count")},
            "critical": r["levels"].get("critical", 0),
            "high": r["levels"].get("high", 0),
            "worst": worst_of(r),
        }
        for r in top
    ]

    # ── Zone-to-zone flows, straight from each rule's own zone columns. The
    # engine's zone_summary resolves addresses against zone_config.json, which
    # is usually a generic default; the export's zones are the operator's own.
    flows: Dict[tuple, Dict[str, Any]] = {}
    for r in assessed:
        for src in r["src_zones"] or ["any"]:
            for dst in r["dst_zones"] or ["any"]:
                f = flows.setdefault((src, dst), {
                    "src": src, "dst": dst, "rules": 0, "allow": 0,
                    "critical_rules": 0, "total_risk": 0, "max_risk": 0,
                })
                f["rules"] += 1
                f["allow"] += r["action"] == "allow"
                f["critical_rules"] += bool(r["levels"].get("critical"))
                f["total_risk"] += r["risk_score"]
                f["max_risk"] = max(f["max_risk"], r["risk_score"])
    zone_flows = sorted(flows.values(), key=lambda f: (-f["critical_rules"], -f["total_risk"]))
    for f in zone_flows:
        f["mean_risk"] = round(f["total_risk"] / f["rules"]) if f["rules"] else 0

    # ── Insecure protocols observed, by distinct rules allowing each.
    protocols = [
        {"protocol": row["p"], "rules": row["n"]}
        for row in conn.execute(
            """SELECT LOWER(json_extract(details, '$.protocol')) AS p,
                      COUNT(DISTINCT rule_id) AS n
               FROM findings
               WHERE analysis_id = ? AND issue_type = 'insecure_protocol'
                 AND json_extract(details, '$.protocol') IS NOT NULL
               GROUP BY p ORDER BY n DESC, p""",
            (analysis_id,),
        )
    ]

    stats = record.get("stats") or {}
    return {
        "posture": rating,
        "impact": impact,
        "severity": severity,
        "total_findings": sum(severity.values()),
        "pass_records": pass_records,
        "issues": sum(issue_severity.values()),
        "issue_severity": issue_severity,
        "categories": category_rows,
        "themes": theme_rows,
        "rules": {
            "in_file": len(rules),
            "assessed": len(assessed),
            "disabled": len(disabled),
            "cleanup_excluded": sum(1 for r in rules.values() if not r["analyzed"] and not r["disabled"]),
            "allow": sum(1 for r in assessed if r["action"] == "allow"),
            "deny": sum(1 for r in assessed if r["action"] == "deny"),
            "with_issues": len(with_issue),
            "with_critical": len(with_critical),
            "with_critical_or_high": len(with_urgent),
            "clean": len(assessed) - len(with_issue),
            "by_worst": by_worst,
        },
        "cleanup": cleanup,
        "scores": {
            "bins": bins,
            "mean": round(sum(scores) / len(scores)) if scores else 0,
            "median": round(median(scores)) if scores else 0,
            "max": max(scores) if scores else 0,
            "high_threshold": HIGH_THRESHOLD,
            "medium_threshold": MEDIUM_THRESHOLD,
            "high": sum(1 for s in scores if s >= HIGH_THRESHOLD),
        },
        "top_rules": top_rules,
        "zone_flows": zone_flows[:12],
        "zone_flow_count": len(zone_flows),
        "exposure": {
            "any": stats.get("rules_with_any") or {},
            "protocols": protocols,
        },
    }


# ─────────────────────────────────────────────── rating helpers


def _settings() -> Dict[str, Any]:
    """Rating parameters from the packaged analysis config, else the defaults."""
    try:
        with open(config.ANALYSIS_CONFIG, encoding="utf-8") as fh:
            return posture.settings(json.load(fh))
    except (OSError, ValueError):
        return posture.settings(None)


def _remediation_impact(assessed, themes, method, current) -> Dict[str, Any]:
    """Posture points recovered by fully resolving each risk area on its own.

    A rule keeps counting at the severity of whatever issues remain, so an area
    whose rules also fail elsewhere recovers little - which is the honest
    answer, and the reason "resolve every critical issue" is shown alongside.
    """
    def score_with(keep):
        counts = {**{level: 0 for level in SEVERITIES}, "clean": 0}
        for r in assessed:
            counts[_worst(keep(r)) or "clean"] += 1
        return posture.rate(counts, method)

    base = current.get("score")
    if base is None:
        return {"areas": [], "all_critical": None}

    areas = []
    for t in themes:
        key = t["key"]
        after = score_with(lambda r, k=key: [lvl for th, lvl in r["theme_worst"].items() if th != k])
        areas.append({"key": key, "rules": t["rules"], "worst": t["worst"],
                      "gain": after["score"] - base, "score_after": after["score"],
                      "rating_after": after["rating"]})
    areas.sort(key=lambda a: (-a["gain"], _SEV_RANK.get(a["worst"], 9)))

    no_critical = score_with(lambda r: [lvl for lvl in r["levels"] if lvl != "critical" and r["levels"][lvl]])
    return {
        "areas": areas,
        "all_critical": {"gain": no_critical["score"] - base, "score_after": no_critical["score"],
                         "rating_after": no_critical["rating"]},
    }


def backfill_posture() -> int:
    """Rate analyses stored before the Critical/High/Medium/Low rating existed.

    Their summary carries the retired Critical/Poor/Fair/Good label. The rating
    is recomputed from their own findings and rules and written back, with the
    old label kept as `legacy_health`. Runs once per analysis; returns the count.
    """
    conn = store.connect()
    updated = 0
    rows = conn.execute("SELECT id, summary FROM analyses WHERE status = 'succeeded'").fetchall()
    for row in rows:
        try:
            summary = json.loads(row["summary"]) if row["summary"] else {}
        except ValueError:
            continue
        if not summary or summary.get("posture"):
            continue
        assessed = [r["rule_id"] for r in conn.execute(
            "SELECT rule_id FROM rules WHERE analysis_id = ? AND analyzed = 1", (row["id"],))]
        findings = [dict(f) for f in conn.execute(
            "SELECT rule_id, risk_level, score FROM findings WHERE analysis_id = ?", (row["id"],))]
        rating = posture.rate(posture.count_worst(posture.worst_by_rule(findings, assessed)), _settings())
        summary["legacy_health"] = summary.get("overall_health")
        summary["overall_health"] = rating["rating"] or "Not rated"
        summary["posture"] = rating
        store.update_analysis(row["id"], summary=json.dumps(summary))
        updated += 1
    if updated:
        logger.info("rated %d earlier analyses on the Critical/High/Medium/Low scale", updated)
    return updated
