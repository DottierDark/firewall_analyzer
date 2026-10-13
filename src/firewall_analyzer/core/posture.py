"""Overall risk rating for a rule base.

The rating uses the same four levels as individual findings - Critical, High,
Medium, Low - so the headline and the evidence underneath it speak one
language. It is derived in two steps, both documented in the report:

1. **Posture score (0-100, higher is better).** Every assessed rule counts
   once, by its most severe open issue, weighted relative to a critical one:

       exposure = sum(weight[worst issue of rule]) / assessed rules
       score    = round(100 * (1 - exposure))

   A rule with no open issue weighs 0. Counting rules rather than findings
   stops a rule that trips ten checks from outweighing ten rules that trip one.

2. **Rating.** The score falls into a band, then a severity floor applies: a
   single critical issue means the rule base is rated at least High, and a
   single high issue at least Medium. The score alone would let one exposed
   rule disappear inside a large, otherwise clean policy; the floor stops that
   without letting one finding dictate the whole rating either.

Pass records (score <= 1, emitted to confirm a control is in place) are never
issues. Weights, bands and floors can be overridden under "posture_rating" in
analysis_config.json.
"""

from typing import Any, Dict, Iterable, Mapping, Optional

LEVELS = ["critical", "high", "medium", "low", "info"]
RATINGS = ["Critical", "High", "Medium", "Low"]          # worst -> best

#: A finding at or below this score records a pass, not a problem.
PASS_SCORE = 1

DEFAULTS: Dict[str, Any] = {
    # Relative to a critical issue.
    "weights": {"critical": 1.0, "high": 0.5, "medium": 0.2, "low": 0.05, "info": 0.0},
    # Lowest score for each rating, best first.
    "bands": [
        {"rating": "Low", "min_score": 85},
        {"rating": "Medium", "min_score": 70},
        {"rating": "High", "min_score": 50},
        {"rating": "Critical", "min_score": 0},
    ],
    # The best rating allowed while at least one rule has an issue this severe.
    "floors": {"critical": "High", "high": "Medium"},
}


def settings(analysis_config: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Defaults, overlaid with analysis_config["posture_rating"] where present."""
    custom = (analysis_config or {}).get("posture_rating") or {}
    merged = {
        "weights": {**DEFAULTS["weights"], **(custom.get("weights") or {})},
        "bands": sorted(custom.get("bands") or DEFAULTS["bands"],
                        key=lambda b: -float(b["min_score"])),
        "floors": {**DEFAULTS["floors"], **(custom.get("floors") or {})},
    }
    return merged


def worst_by_rule(findings: Iterable[Any], rule_ids: Iterable[Any]) -> Dict[str, Optional[str]]:
    """Most severe open issue per rule, for the given (assessed) rule ids.

    `findings` may be SecurityFinding objects or dicts with rule_id, risk_level
    and score. Findings on ids outside `rule_ids` - compliance control
    summaries, a missing deny-all - are policy-level and do not rate a rule.
    """
    rank = {level: i for i, level in enumerate(LEVELS)}
    worst: Dict[str, Optional[str]] = {str(r): None for r in rule_ids}
    for f in findings:
        get = f.get if isinstance(f, dict) else lambda k, _f=f: getattr(_f, k, None)
        rid = str(get("rule_id"))
        if rid not in worst or (get("score") or 0) <= PASS_SCORE:
            continue
        level = get("risk_level")
        level = getattr(level, "value", level)
        if level not in rank:
            continue
        current = worst[rid]
        if current is None or rank[level] < rank[current]:
            worst[rid] = level
    return worst


def count_worst(worst: Mapping[str, Optional[str]]) -> Dict[str, int]:
    counts = {level: 0 for level in LEVELS}
    counts["clean"] = 0
    for level in worst.values():
        counts[level or "clean"] += 1
    return counts


def rate(by_worst: Mapping[str, int], config: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Score and rating from per-rule worst-severity counts.

    `by_worst` maps each severity (plus "clean") to the number of assessed
    rules whose most severe open issue is that level.
    """
    # Accept either resolved settings (as stored with a result) or a whole
    # analysis_config, with or without a posture_rating block.
    is_resolved = bool(config) and all(k in config for k in ("weights", "bands", "floors"))
    cfg = config if is_resolved else settings(config)
    weights, bands, floors = cfg["weights"], cfg["bands"], cfg["floors"]

    assessed = sum(int(by_worst.get(k, 0)) for k in LEVELS + ["clean"])
    if not assessed:
        return {
            "score": None, "rating": None, "band_rating": None, "floor_applied": None,
            "assessed_rules": 0, "by_worst": dict(by_worst),
            "method": _method(cfg),
        }

    top = max(weights.values()) or 1.0
    exposure = sum(float(weights.get(level, 0)) * int(by_worst.get(level, 0)) for level in LEVELS)
    exposure /= assessed * top
    score = max(0, min(100, round(100 * (1 - exposure))))

    band_rating = next((b["rating"] for b in bands if score >= float(b["min_score"])), RATINGS[0])
    rating, floor_applied = band_rating, None
    for level in LEVELS:                      # worst severity present sets the floor
        if by_worst.get(level) and level in floors:
            cap = floors[level]
            if RATINGS.index(cap) < RATINGS.index(rating):
                rating, floor_applied = cap, level
            break

    return {
        "score": score,
        "rating": rating,
        "band_rating": band_rating,
        "floor_applied": floor_applied,
        "assessed_rules": assessed,
        "by_worst": {k: int(by_worst.get(k, 0)) for k in LEVELS + ["clean"]},
        "method": _method(cfg),
    }


def _method(cfg: Mapping[str, Any]) -> Dict[str, Any]:
    """The parameters used, stored with the result so it can be explained."""
    return {"weights": dict(cfg["weights"]), "bands": list(cfg["bands"]), "floors": dict(cfg["floors"])}
