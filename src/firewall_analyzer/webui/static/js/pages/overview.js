// Overview — three dashboards over one analysis, one per audience.
//
//   Executive         posture, the risk areas behind it, compliance, next steps
//   Security Manager  the remediation workload, what fixing each area is worth,
//                     cleanup, and control status per compliance framework
//   Analyst           rule-level evidence: where findings sit and why rules score
//
// All three draw from one /dashboard response (webui/dashboard.py), so the
// presets can never disagree about a number. The overall rating is the one the
// engine computes (core/posture.py): Critical / High / Medium / Low, the same
// scale as a finding.

import { api } from "../api.js";
import { el, panel, empty, loading, fmtNumber, titleCase, sevBadge, fmtDate,
         relativeTime, toastError, svgIcon, tagList } from "../ui.js";
import { severityDonut, severityLegend, rankedBars,
         stackedBar, severitySegments, inlineLegend, meter, histogram, heatStyle,
         installTooltips, cssVar, sevColor, SEV_ORDER } from "../charts.js";
import { STATUS as ECC_STATUS, statusChip } from "./compliance.js";
import { getState, selectAnalysis } from "../state.js";
import { navigate } from "../router.js";

/** Audience presets. Each is its own layout, not a filter over one. */
export const VIEWS = {
  executive: { label: "Executive", sub: "Security posture at a glance", build: buildExecutive },
  manager: { label: "Security Manager", sub: "Remediation workload, impact and control status", build: buildManager },
  analyst: { label: "Analyst", sub: "Rule-level evidence behind every score", build: buildAnalyst },
};

const saved = localStorage.getItem("fwa-view");
let activeView = VIEWS[saved] ? saved : "analyst";

export function getView() { return activeView; }
export function setView(v) {
  if (!VIEWS[v]) return;
  activeView = v;
  localStorage.setItem("fwa-view", v);
}

// ───────────────────────────────────────────── vocabulary

const WARN_ICON = ["M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"];
/** The overall rating uses the finding scale, so headline and evidence match. */
const RATING = {
  Critical: { tone: "--sev-critical-ink", icon: WARN_ICON, note: "Immediate attention required" },
  High:     { tone: "--sev-high-ink", icon: WARN_ICON, note: "Significant exposure to remediate" },
  Medium:   { tone: "--sev-medium-ink", icon: ["M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z", "M12 8v4m0 4h.01"], note: "Moderate exposure — plan remediation" },
  Low:      { tone: "--sev-low-ink", icon: ["M22 11.08V12a10 10 0 1 1-5.93-9.14", "M22 4 12 14.01l-3-3"], note: "Limited exposure" },
};
/** Labels from before the current scale, for anything not yet re-rated. */
const LEGACY_RATING = { Poor: "High", Fair: "Medium", Good: "Low" };
const ratingOf = (label) => (RATING[label] ? label : LEGACY_RATING[label] || null);

/**
 * The risk areas an executive reads, keyed as in dashboard.THEMES. Membership
 * (which issue types) is decided server-side; the words live here.
 */
const AREAS = {
  logging: {
    title: "Traffic that is not logged",
    impact: "Permitted traffic leaves no audit trail, so an incident on these paths cannot be investigated.",
    action: (n) => `Enable logging on ${rules(n)}`,
  },
  protocols: {
    title: "Unencrypted protocols allowed",
    impact: "Telnet, FTP, HTTP and similar protocols send credentials and data in clear text.",
    action: (n) => `Replace clear-text protocols with encrypted equivalents on ${rules(n)}`,
  },
  access: {
    title: "Overly broad access",
    impact: "Rules using ‘any’ permit far more traffic than the business needs.",
    action: (n) => `Narrow sources, destinations and services on ${rules(n)}`,
  },
  management: {
    title: "Remote administration exposed",
    impact: "Management protocols such as RDP, SSH and VNC are reachable across zones.",
    action: (n) => `Restrict remote administration to a dedicated admin network on ${rules(n)}`,
  },
  applications: {
    title: "High-risk applications permitted",
    impact: "Applications with a high Applipedia risk rating are allowed through.",
    action: (n) => `Block or tightly scope high-risk applications on ${rules(n)}`,
  },
  hygiene: {
    title: "Stale and redundant rules",
    impact: "Rules that never match, duplicate others or have expired make the policy harder to audit.",
    action: (n) => `Remove or consolidate ${rules(n)} that ${agree(n, "is", "are")} shadowed, duplicated, unused or expired`,
  },
  config: {
    title: "Configuration gaps",
    impact: "Rule-base settings that depart from best practice, such as a missing catch-all deny.",
    action: (n) => `Correct ${n ? rules(n) : "the policy-wide configuration gaps"}`,
  },
};

const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };

// ───────────────────────────────────────────── small helpers

const pct = (n, d) => (d ? Math.round((n / d) * 100) : 0);
const rules = (n) => `${fmtNumber(n)} rule${n === 1 ? "" : "s"}`;
/** Verb agreement for "N of M rules …" — the verb follows N. */
const agree = (n, one, many) => (n === 1 ? one : many);

function findingsLink(types = [], risk = null, q = null) {
  const sp = new URLSearchParams();
  types.forEach((t) => sp.append("type", t));
  if (risk) sp.append("risk", risk);
  if (q) sp.append("q", q);
  const s = sp.toString();
  return `/findings${s ? `?${s}` : ""}`;
}

function kpi(label, value, foot, { tone = null } = {}) {
  return el("div", { class: "kpi" }, [
    el("span", { class: "kpi-label" }, label),
    value && value.nodeType ? value
      : el("div", { class: "kpi-value", style: tone ? `color:var(${tone})` : null }, value),
    el("span", { class: "kpi-foot" }, foot),
  ]);
}

function footnote(text) {
  return el("p", { class: "panel-foot" }, text);
}

function viewAll(label, path) {
  return el("button", { class: "btn ghost small", onclick: () => navigate(path) }, label);
}

/** A rule's zone path: source zones → destination zones, 'any' called out. */
function zonePath(src, dst) {
  return el("span", { class: "zone-path" }, [
    tagList(src.length ? src : ["any"], { max: 2 }),
    el("span", { class: "zone-arrow", "aria-hidden": "true" }, "→"),
    tagList(dst.length ? dst : ["any"], { max: 2 }),
  ]);
}

function openRule(ruleId) {
  navigate(`/rules?rule=${encodeURIComponent(ruleId)}`);
}

// ───────────────────────────────────────────── render

export async function render(host) {
  const { current } = getState();
  const sub = document.getElementById("page-sub");
  if (sub) sub.textContent = VIEWS[activeView].sub;

  if (!current) {
    host.append(empty("No analysis selected", "Run a new analysis or pick one from History."));
    return;
  }
  if (current.status !== "succeeded") {
    host.append(renderPending(current));
    return;
  }

  installTooltips();
  host.append(loading("Loading dashboard…"));

  try {
    const wantsRecent = activeView === "manager";
    const [data, runs] = await Promise.all([
      api.dashboard(current.id),
      wantsRecent ? api.analyses(8).then((r) => r.items) : Promise.resolve([]),
    ]);
    const ctx = { a: current, d: data, runs };
    host.replaceChildren(el("div", { class: "dash" }, VIEWS[activeView].build(ctx)));
  } catch (err) {
    toastError(err);
    host.replaceChildren(empty("Could not load the dashboard", err.message));
  }
}

function renderPending(a) {
  if (a.status === "failed") {
    return panel("Analysis failed", [
      el("div", { class: "notice bad" }, [
        svgIcon(WARN_ICON),
        el("div", {}, a.error || "The run did not complete."),
      ]),
      el("button", { class: "btn primary", style: "margin-top:1rem", onclick: () => navigate("/new") },
        "Start a new analysis"),
    ]);
  }
  return panel("Analysis in progress", [
    el("p", { class: "panel-sub" }, a.progress || "Queued…"),
    el("div", { class: "progress-track", style: "margin-top:.6rem" },
      el("div", { class: "progress-fill", style: "width:45%" })),
    el("p", { class: "panel-sub", style: "margin-top:.7rem" },
      "This page refreshes automatically when the run finishes."),
  ]);
}

function summaryStrip(a) {
  return el("div", { class: "panel summary-strip" }, [
    el("div", { style: "min-width:0" }, [
      el("div", { class: "eyebrow" }, "Analysis Summary"),
      el("div", { class: "summary-strip__title" },
        `${a.project_name} • ${a.label} • ${titleCase(a.vendor || "unknown")}`),
    ]),
    el("span", { style: "flex:1" }),
    el("span", { class: "pill state-succeeded" }, "Completed"),
    el("span", { class: "panel-sub" }, fmtDate(a.created_at)),
  ]);
}

// ═════════════════════════════════════════════ Executive

function buildExecutive({ a, d }) {
  const r = d.rules;
  return [
    summaryStrip(a),
    postureHero(a, d),
    el("div", { class: "kpi-grid kpi-grid--4" }, [
      kpi("Rules with critical issues", fmtNumber(r.with_critical),
        `${pct(r.with_critical, r.assessed)}% of ${fmtNumber(r.assessed)} active rules`,
        { tone: r.with_critical ? "--sev-critical-ink" : null }),
      kpi("Critical findings", fmtNumber(d.severity.critical),
        d.severity.high ? `plus ${fmtNumber(d.severity.high)} rated high` : "none rated high",
        { tone: d.severity.critical ? "--sev-critical-ink" : null }),
      complianceKpi(a),
      kpi("Rules that can be removed", fmtNumber(d.cleanup.candidates),
        "shadowed, duplicate, unused, expired or disabled"),
    ]),
    el("div", { class: "dash-row" }, [riskAreasPanel(d), severityPanel(d)]),
    el("div", { class: "dash-row dash-row--even" }, [compliancePanel(a), nextStepsPanel(d)]),
  ];
}

function postureHero(a, d) {
  const p = d.posture || {};
  const rating = ratingOf(p.rating) || ratingOf(a.summary?.overall_health) || "Medium";
  const meta = RATING[rating];
  const r = d.rules;
  const lead = d.themes[0];

  let lede;
  if (!r.with_critical_or_high) {
    lede = `No critical or high-severity issues across the ${fmtNumber(r.assessed)} active rules assessed.`;
  } else {
    const highOnly = r.with_critical_or_high - r.with_critical;
    lede = r.with_critical
      ? `${fmtNumber(r.with_critical)} of ${fmtNumber(r.assessed)} active rules ` +
        `${agree(r.with_critical, "carries", "carry")} at least one critical issue` +
        (highOnly ? `, and ${fmtNumber(highOnly)} more a high-severity one.` : ".")
      : `${fmtNumber(highOnly)} of ${fmtNumber(r.assessed)} active rules ` +
        `${agree(highOnly, "carries", "carry")} a high-severity issue.`;
    if (lead && AREAS[lead.key]) {
      lede += ` The most pressing area is ${AREAS[lead.key].title.toLowerCase()}, ` +
        (lead.rules ? `affecting ${rules(lead.rules)}.` : "across the policy as a whole.");
    }
  }

  const skipped = r.in_file - r.assessed;
  const segments = [
    ...severitySegments(r.by_worst, { suffix: " rules" }),
    { label: "No issues", value: r.by_worst.clean || 0, color: cssVar("--muted"),
      tip: `No issues: ${fmtNumber(r.by_worst.clean || 0)} rules` },
  ];

  return el("section", { class: "panel posture", style: `--tone:var(${meta.tone})` }, [
    el("div", { class: "posture__status" }, [
      el("div", { class: "eyebrow" }, "Overall risk rating"),
      el("div", { class: "posture__word" }, [svgIcon(meta.icon, { size: 34 }), rating]),
      el("div", { class: "posture__score" }, p.score == null ? "Not scored" : [
        el("strong", {}, String(p.score)), " / 100 posture score",
      ]),
      el("div", { class: "panel-sub" }, meta.note),
    ]),
    el("div", { class: "posture__body" }, [
      el("p", { class: "posture__lede" }, lede),
      el("div", { class: "posture__bar" }, [
        el("div", { class: "posture__bar-head" }, [
          el("span", {}, "Active rules by their most severe issue"),
          el("span", { class: "panel-sub" }, `${fmtNumber(r.assessed)} rules`),
        ]),
        stackedBar(segments, { height: 14, label: "Active rules by most severe issue" }),
        inlineLegend(segments),
      ]),
      skipped > 0
        ? el("p", { class: "panel-sub", style: "margin:.2rem 0 0" },
            `${fmtNumber(skipped)} of the ${fmtNumber(r.in_file)} rules in the file ${agree(skipped, "was", "were")} not assessed ` +
            `(${fmtNumber(r.disabled)} disabled, ${fmtNumber(r.cleanup_excluded)} catch-all deny).`)
        : null,
      ratingMethod(p),
    ]),
  ]);
}

/** One line on how the rating was reached, from the parameters the run used. */
function ratingMethod(p) {
  if (p.score == null || !p.method) return null;
  const bands = [...p.method.bands].sort((x, y) => y.min_score - x.min_score);
  const scale = bands.map((b, i) => {
    const upper = i ? bands[i - 1].min_score - 1 : 100;
    return b.min_score === 0 ? `below ${bands[i - 1]?.min_score ?? 1} ${b.rating}`
      : i === 0 ? `${b.min_score}+ ${b.rating}` : `${b.min_score}–${upper} ${b.rating}`;
  }).join(" · ");
  const floorNote = p.floor_applied
    ? ` The score alone would rate it ${p.band_rating}; a ${p.floor_applied} issue holds it at ${p.rating}.`
    : "";
  return el("p", { class: "posture__method" },
    `How it is rated: each assessed rule counts once, by its most severe issue. ` +
    `Score ${scale}. Any critical issue rates the rule base at least ${p.method.floors?.critical || "High"}, ` +
    `any high issue at least ${p.method.floors?.high || "Medium"}.` + floorNote);
}

function riskAreasPanel(d) {
  if (!d.themes.length) {
    return panel("Key risk areas", empty("No issues found", "Every assessed rule passed the checks."));
  }
  const total = d.rules.in_file;
  const list = el("div", { class: "area-list" }, d.themes.map((t) => {
    const copy = AREAS[t.key] || AREAS.config;
    const color = t.worst ? sevColor(t.worst) : cssVar("--muted");
    return el("button", {
      class: "area", type: "button",
      onclick: () => navigate(findingsLink(t.types)),
      "aria-label": `${copy.title}: ${rules(t.rules)}, worst severity ${t.worst}. Open findings.`,
    }, [
      sevBadge(t.worst),
      el("div", { class: "area__text" }, [
        el("div", { class: "area__title" }, copy.title),
        el("div", { class: "area__impact" }, copy.impact),
      ]),
      el("div", { class: "area__meter" }, [
        meter(t.rules, total, {
          color,
          label: `${fmtNumber(t.rules)} of ${fmtNumber(total)} rules in the policy (${pct(t.rules, total)}%)`,
        }),
        el("span", { class: "panel-sub" }, `${pct(t.rules, total)}% of rules`),
      ]),
      el("div", { class: "area__n" }, [
        el("strong", {}, t.rules ? fmtNumber(t.rules) : "—"),
        el("span", {}, t.rules ? (t.rules === 1 ? "rule" : "rules") : "policy-wide"),
      ]),
    ]);
  }));
  return panel("Key risk areas", list, { sub: "worst first · select one to see its findings" });
}

function severityPanel(d) {
  return panel("Findings by severity", [
    el("div", { class: "donut-stack" }, [
      severityDonut(d.severity, { size: 176, stroke: 24 }),
      severityLegend(d.severity),
    ]),
    d.pass_records
      ? footnote(`Includes ${fmtNumber(d.pass_records)} low-severity pass records that confirm a control is in place.`)
      : null,
  ], { actions: viewAll("Findings", "/findings") });
}

/** Framework assessments for this analysis, in the order they were requested. */
function frameworkList(a) {
  const c = a.compliance || {};
  return (c.frameworks || []).map((key) => ({ key, ...(c.assessments?.[key] || { status: "missing" }) }));
}
const fwShort = (f) => f.short || String(f.key).toUpperCase();
const fwPct = (f) => `${Math.round(f.compliance_pct ?? 0)}%`;

function complianceKpi(a, { controls = false } = {}) {
  const all = frameworkList(a);
  const done = all.filter((f) => f.status === "assessed");
  if (!done.length) {
    return kpi("Compliance", el("div", { class: "kpi-value muted" }, "—"),
      all.length ? `${all.map(fwShort).join(", ")} not assessed yet` : "no framework assessed for this run");
  }
  const f = done[0];
  const meta = ECC_STATUS[f.overall_status] || ECC_STATUS.NOT_APPLICABLE;
  const ctrls = Object.values(f.controls || {});
  const failing = ctrls.filter((x) => x.non_compliant > 0).length;
  const more = done.length > 1 ? ` · +${done.length - 1} more framework${done.length > 2 ? "s" : ""}` : "";
  return kpi(`${fwShort(f)} compliance`,
    el("div", { class: "kpi-value", style: `color:var(${meta.ink})` }, fwPct(f)),
    (controls
      ? `${failing} of ${ctrls.length} controls with failing rules`
      : `${fmtNumber(f.passed_checks)} of ${fmtNumber(f.total_checks)} checks · ${meta.label.toLowerCase()}`) + more);
}

function frameworkBadge(f) {
  return el("span", { class: "fw-badge" }, fwShort(f));
}

/** A framework that was requested but produced no assessment. */
function pendingFramework(f) {
  return el("div", { class: "fw-block fw-block--pending" }, [
    el("div", { class: "fw-block__head" }, [
      frameworkBadge(f),
      el("span", { class: "fw-block__name" }, f.name || fwShort(f)),
      el("span", { class: "pill" }, f.status === "error" ? "Assessment failed"
        : f.status === "missing" ? "No result stored" : "Not yet available"),
    ]),
    f.message ? el("p", { class: "panel-sub", style: "margin:.35rem 0 0" }, f.message) : null,
  ]);
}

function compliancePanel(a) {
  const title = "Regulatory compliance";
  const all = frameworkList(a);
  if (!all.length) {
    return panel(title, empty("No compliance assessment",
      "Choose one or more frameworks when running an analysis."));
  }
  const blocks = all.map((f) => {
    if (f.status !== "assessed") return pendingFramework(f);
    const groups = Object.values(f.subdomains || {});
    const ink = (ECC_STATUS[f.overall_status] || ECC_STATUS.NOT_APPLICABLE).ink;
    return el("div", { class: "fw-block" }, [
      el("button", {
        class: "fw-block__head is-link", type: "button",
        onclick: () => navigate(`/compliance?fw=${encodeURIComponent(f.key)}`),
      }, [
        frameworkBadge(f),
        el("span", { class: "fw-block__name" }, f.name),
        statusChip(f.overall_status),
        el("span", { class: "fw-block__pct", style: `color:var(${ink})` }, fwPct(f)),
      ]),
      el("div", { class: "panel-sub", style: "margin:-.2rem 0 .55rem" },
        `${fmtNumber(f.passed_checks)} of ${fmtNumber(f.total_checks)} applicable checks passed`),
      el("div", { class: "ecc-subs" }, groups.map((sd) => {
        const p = pct(sd.compliant, sd.applicable);
        return el("div", { class: "ecc-sub" }, [
          el("div", { class: "ecc-sub__head" }, [
            el("span", { class: "ecc-sub__name" }, [el("span", { class: "mono ecc-id" }, sd.id), " ", sd.name]),
            el("span", { class: "ecc-sub__pct" }, `${p}%`),
          ]),
          meter(sd.compliant, sd.applicable, {
            color: cssVar(ECC_STATUS[sd.status]?.fill || "--muted"),
            label: `${sd.name}: ${fmtNumber(sd.compliant)} of ${fmtNumber(sd.applicable)} checks passed (${p}%)`,
          }),
        ]);
      })),
    ]);
  });
  return panel(title, el("div", { class: "fw-list" }, blocks),
    { sub: all.map(fwShort).join(" · "), actions: viewAll("Details", "/compliance") });
}

function nextStepsPanel(d) {
  // Low-only areas are not worth an executive's action list; everything from
  // medium up is, worst first. Cleanup ranks by the severity of the hygiene
  // area it resolves, so a Poor rule base (all high findings are shadowed
  // rules) leads with it rather than burying it under medium items.
  const rank = (sev) => (sev ? SEV_ORDER.indexOf(sev) : SEV_ORDER.length);
  const actionable = (sev) => sev === "critical" || sev === "high" || sev === "medium";
  const steps = d.themes
    .filter((t) => t.key !== "hygiene" && actionable(t.worst))
    .slice(0, 3)
    .map((t) => ({
      text: (AREAS[t.key] || AREAS.config).action(t.rules),
      sev: t.worst,
      meta: t.rules ? rules(t.rules) : "policy-wide",
      to: findingsLink(t.types),
    }));
  if (d.cleanup.candidates) {
    const n = d.cleanup.candidates;
    steps.push({
      text: `Remove or consolidate ${rules(n)} that ${agree(n, "is", "are")} shadowed, duplicated, unused, expired or disabled`,
      sev: null,
      order: rank(d.themes.find((t) => t.key === "hygiene")?.worst),
      meta: "rule-base cleanup",
      to: findingsLink(["shadowed", "redundant", "unused", "expired"]),
    });
  }
  steps.sort((x, y) => (x.order ?? rank(x.sev)) - (y.order ?? rank(y.sev)));
  if (!steps.length) {
    return panel("Recommended next steps", empty("Nothing to act on", "No issues rated medium or above."));
  }
  return panel("Recommended next steps", el("ol", { class: "todo" }, steps.map((s) =>
    el("li", {}, el("button", { class: "todo__item", type: "button", onclick: () => navigate(s.to) }, [
      el("span", { class: "todo__text" }, s.text),
      el("span", { class: "todo__meta" }, [
        s.sev ? sevBadge(s.sev) : el("span", { class: "pill" }, "Hygiene"),
        el("span", { class: "panel-sub" }, s.meta),
      ]),
    ]))
  )), { sub: "in priority order" });
}

// ═════════════════════════════════════════════ Security Manager

function buildManager({ a, d, runs }) {
  const r = d.rules;
  return [
    summaryStrip(a),
    el("div", { class: "kpi-grid" }, [
      kpi("Open issues", fmtNumber(d.issues),
        `${fmtNumber(d.issue_severity.critical)} critical · ${fmtNumber(d.issue_severity.high)} high`),
      kpi("Rules requiring action", fmtNumber(r.with_critical_or_high),
        `critical or high · ${pct(r.with_critical_or_high, r.assessed)}% of ${fmtNumber(r.assessed)} active`,
        { tone: r.with_critical_or_high ? "--sev-critical-ink" : null }),
      kpi("Cleanup candidates", fmtNumber(d.cleanup.candidates), "rules that can likely be removed",
        { tone: d.cleanup.candidates ? "--brand-orange-deep" : null }),
      complianceKpi(a, { controls: true }),
      postureKpi(d),
    ]),
    el("div", { class: "dash-row" }, [workloadPanel(d), impactPanel(d)]),
    el("div", { class: "dash-row" }, [topRulesPanel(d, "manager"), cleanupPanel(d)]),
    el("div", { class: "dash-row" }, [controlsPanel(a), recentPanel(a, runs)]),
  ];
}

function postureKpi(d) {
  const p = d.posture || {};
  const rating = ratingOf(p.rating);
  const gain = d.impact?.all_critical?.gain || 0;
  return kpi("Posture score",
    el("div", { class: "kpi-value", style: rating ? `color:var(${RATING[rating].tone})` : null },
      p.score == null ? "—" : [String(p.score), el("span", { class: "kpi-unit" }, "/100")]),
    rating
      ? `rated ${rating}` + (gain > 0 ? ` · +${gain} if every critical issue is resolved` : "")
      : "not rated");
}

function workloadPanel(d) {
  const cats = d.categories;
  if (!cats.length) return panel("Remediation workload", empty("No open issues"));
  const peak = Math.max(...cats.map((c) => c.findings), 1);
  const present = SEV_ORDER.filter((level) => d.issue_severity[level]);

  const rows = cats.map((c) =>
    el("button", {
      class: "workload__row", type: "button",
      onclick: () => navigate(findingsLink([c.type])),
      "aria-label": `${titleCase(c.type)}: ${c.findings} findings on ${c.rules} rules. Open findings.`,
    }, [
      el("span", { class: "workload__label" }, titleCase(c.type)),
      el("span", { class: "workload__bar" },
        stackedBar(severitySegments(c.by_severity, { suffix: " findings" }),
          { height: 12, scale: c.findings / peak, label: titleCase(c.type) })),
      el("span", { class: "workload__num", title: c.rules ? null : "Recorded against the policy, not individual rules" },
        c.rules ? fmtNumber(c.rules) : "—"),
      el("span", { class: "workload__num" }, fmtNumber(c.findings)),
    ]));

  return panel("Remediation workload", [
    el("div", { class: "chart-legend chart-legend--inline", style: "margin-bottom:.7rem" },
      present.map((level) => el("span", { class: "item" }, [
        el("span", { class: "swatch", style: `background:${sevColor(level)}` }),
        el("span", { class: "lg-label" }, SEV_LABEL[level]),
      ]))),
    el("div", { class: "workload" }, [
      el("div", { class: "workload__row workload__row--head" }, [
        el("span", {}, "Category"), el("span", {}, "Findings by severity"),
        el("span", { class: "workload__num" }, "Rules"), el("span", { class: "workload__num" }, "Findings"),
      ]),
      ...rows,
    ]),
    d.pass_records
      ? footnote(`Excludes ${fmtNumber(d.pass_records)} pass records (score 1) that confirm a control is in place.`)
      : null,
  ], { sub: "by category, worst first", actions: viewAll("Findings", "/findings") });
}

/**
 * What fixing each risk area is worth, in posture points. Replaces a trend:
 * it answers "where does effort move the rating" from this run alone.
 */
function impactPanel(d) {
  const title = "Remediation impact";
  const p = d.posture || {};
  const imp = d.impact || {};
  if (p.score == null) return panel(title, empty("Not rated", "This run has no assessed rules."));

  const types = Object.fromEntries(d.themes.map((t) => [t.key, t.types]));
  const areas = imp.areas || [];
  const allCrit = imp.all_critical;
  const peak = Math.max(...areas.map((x) => x.gain), allCrit?.gain || 0, 1);
  const rating = ratingOf(p.rating);

  const rows = areas.map((x) => {
    const name = (AREAS[x.key] || AREAS.config).title;
    return {
      label: name,
      value: x.gain,
      display: x.gain > 0 ? `+${x.gain}` : "0",
      tip: `Resolving "${name}" on ${rules(x.rules)}: score ${p.score} → ${x.score_after}, rated ${x.rating_after}`,
      onClick: () => navigate(findingsLink(types[x.key] || [])),
    };
  });

  return panel(title, [
    el("div", { class: "impact-head" }, [
      el("div", {}, [
        el("div", { class: "section-label", style: "margin:0 0 .2rem" }, "Today"),
        el("span", { class: "impact-score", style: rating ? `color:var(${RATING[rating].tone})` : null }, String(p.score)),
        el("span", { class: "panel-sub" }, ` / 100 · ${p.rating}`),
      ]),
      allCrit && allCrit.gain > 0 ? el("div", {}, [
        el("div", { class: "section-label", style: "margin:0 0 .2rem" }, "Every critical issue resolved"),
        el("span", { class: "impact-score", style: `color:var(${RATING[allCrit.rating_after]?.tone || "--text"})` },
          String(allCrit.score_after)),
        el("span", { class: "panel-sub" }, ` / 100 · ${allCrit.rating_after}`),
      ]) : null,
    ]),
    el("div", { class: "section-label" }, "Points recovered by resolving one area"),
    rows.length
      ? rankedBars(rows, { max: rows.length, sort: false, peak })
      : el("p", { class: "panel-sub", style: "margin:0" }, "No open issues."),
    footnote("A rule failing several areas only stops counting once all of them are fixed, " +
      "so single-area gains are small where issues overlap and do not add up."),
  ], { sub: "posture points per area" });
}

function topRulesPanel(d, mode) {
  const items = d.top_rules;
  const title = "Highest risk rules";
  if (!items.length) return panel(title, empty("No assessed rules"));

  const head = mode === "manager"
    ? [["#", "num"], "Rule", "Path", ["Critical", "num"], ["High", "num"], ["Risk", "num"]]
    : [["#", "num"], "Rule", "Action", "Path", "Services", "Worst", ["Risk", "num"], ["Findings", "num"]];

  const row = (r) => mode === "manager"
    ? [
        el("td", { class: "num muted" }, r.seq),
        el("td", { class: "rule-name truncate", style: "max-width:30ch", title: r.name }, r.name),
        el("td", {}, zonePath(r.src_zones, r.dst_zones)),
        el("td", { class: "num" }, r.critical ? el("strong", { class: "sev-critical" }, r.critical) : el("span", { class: "muted" }, "0")),
        el("td", { class: "num" }, r.high ? el("strong", { class: "sev-high" }, r.high) : el("span", { class: "muted" }, "0")),
        el("td", { class: "num" }, el("strong", {}, fmtNumber(r.risk_score))),
      ]
    : [
        el("td", { class: "num muted" }, r.seq),
        el("td", { class: "rule-name truncate", style: "max-width:22ch", title: r.name }, r.name),
        el("td", {}, el("span", { class: `pill ${r.action}` }, r.action || "—")),
        el("td", {}, zonePath(r.src_zones, r.dst_zones)),
        el("td", {}, tagList(r.services, { max: 2 })),
        el("td", {}, r.worst ? sevBadge(r.worst) : el("span", { class: "muted" }, "—")),
        el("td", { class: "num" }, el("strong", {}, fmtNumber(r.risk_score))),
        el("td", { class: "num muted" }, r.finding_count),
      ];

  return panel(title, el("div", { class: "table-wrap" },
    el("table", { class: "data" }, [
      el("thead", {}, el("tr", {}, head.map((h) =>
        Array.isArray(h) ? el("th", { class: h[1] }, h[0]) : el("th", {}, h)))),
      el("tbody", {}, items.map((r) =>
        el("tr", {
          class: "clickable", tabindex: "0",
          onclick: () => openRule(r.rule_id),
          onkeydown: (e) => { if (e.key === "Enter") openRule(r.rule_id); },
        }, row(r)))),
    ])
  ), {
    sub: `top ${items.length} of ${fmtNumber(d.rules.assessed)} by risk score`,
    actions: viewAll("Rule Explorer", "/rules?sort=risk&dir=desc"),
  });
}

function cleanupPanel(d) {
  const c = d.cleanup;
  // Short labels so the bars keep their width on a laptop; the full reason
  // is in each row's tooltip.
  const rows = [
    { label: "Shadowed", why: "Shadowed by an earlier rule, so never matched", value: c.shadowed, to: findingsLink(["shadowed"]) },
    { label: "Duplicates", why: "Identical to another rule", value: c.redundant, to: findingsLink(["redundant"]) },
    { label: "Never hit", why: "No traffic has ever matched", value: c.unused, to: findingsLink(["unused"]) },
    { label: "Past expiry date", why: "Past their own expiry date", value: c.past_expiry, to: findingsLink(["expired"], null, "EXPIREDRULE") },
    { label: "Disabled", why: "Disabled but still in the rule base", value: c.disabled, to: "/rules" },
  ].map((row) => ({ ...row, onClick: () => navigate(row.to), tip: `${row.why}: ${rules(row.value)}` }));

  const peak = Math.max(...rows.map((row) => row.value), c.stale, 1);
  return panel("Cleanup candidates", [
    el("div", { class: "big-stat" }, [
      el("span", { class: "big-stat__value", style: c.candidates ? null : "color:var(--muted)" },
        fmtNumber(c.candidates)),
      el("span", { class: "panel-sub" }, "distinct rules that can likely be removed"),
    ]),
    el("div", { class: "section-label", style: "margin-top:0" }, "Remove"),
    rankedBars(rows, { max: rows.length, sort: false, peak }),
    el("div", { class: "section-label" }, "Review"),
    rankedBars([{
      label: "Unchanged 1+ year", value: c.stale,
      tip: `Not modified in over a year: ${rules(c.stale)}`,
      onClick: () => navigate(findingsLink(["expired"], null, "modified")),
    }], { max: 1, sort: false, peak }),
    footnote("A rule can meet more than one reason, so the rows add up to more than the total. " +
      "Stale rules are listed for review, not removal."),
  ], { sub: "rules the policy can likely do without" });
}

function controlsPanel(a) {
  const title = "Control status";
  const all = frameworkList(a);
  const done = all.filter((f) => f.status === "assessed");
  const pending = all.filter((f) => f.status !== "assessed");
  const pendingNote = pending.length
    ? footnote(`${pending.map(fwShort).join(", ")} ${agree(pending.length, "was", "were")} requested but ` +
        `${agree(pending.length, "is", "are")} not available yet.`)
    : null;
  if (!done.length) {
    return panel(title, [
      empty("No compliance assessment", all.length ? "No requested framework could be assessed yet."
        : "Choose one or more frameworks when running an analysis."),
      pendingNote,
    ]);
  }

  let chosen = done[0].key;
  const body = el("div");
  const tabs = done.length > 1 ? el("div", { class: "seg seg--small" }) : null;

  function paint() {
    const f = done.find((x) => x.key === chosen);
    if (tabs) {
      tabs.replaceChildren(...done.map((x) => el("button", {
        type: "button", "aria-pressed": String(x.key === chosen),
        onclick: () => { chosen = x.key; paint(); },
      }, fwShort(x))));
    }
    body.replaceChildren(
      el("div", { class: "panel-sub", style: "margin:-.35rem 0 .5rem" },
        `${f.name} · ${fwPct(f)} of checks passed`),
      el("div", { class: "controls" }, Object.values(f.controls || {}).map((ctrl) => {
        const p = pct(ctrl.compliant, ctrl.applicable);
        const fill = ECC_STATUS[ctrl.status]?.fill || "--muted";
        return el("button", {
          class: "control", type: "button",
          onclick: () => navigate(`/compliance?fw=${encodeURIComponent(f.key)}`),
        }, [
          el("span", { class: "mono ecc-id" }, ctrl.id),
          el("span", { class: "control__title", title: ctrl.title }, ctrl.title),
          el("span", { class: "control__meter" }, [
            meter(ctrl.compliant, ctrl.applicable, {
              color: cssVar(fill),
              label: `${ctrl.id}: ${fmtNumber(ctrl.compliant)} of ${fmtNumber(ctrl.applicable)} applicable rules pass (${p}%)`,
            }),
            el("span", { class: "panel-sub" }, `${p}% pass · ${fmtNumber(ctrl.non_compliant)} failing`),
          ]),
          statusChip(ctrl.status),
        ]);
      })),
    );
  }
  paint();

  return panel(title, [body, pendingNote], {
    sub: done.length > 1 ? `${done.length} frameworks` : fwShort(done[0]),
    actions: el("div", { style: "display:flex;gap:.5rem;align-items:center" }, [tabs, viewAll("Compliance", "/compliance")]),
  });
}

function recentPanel(a, runs) {
  const items = runs.slice(0, 6);
  return panel("Recent analyses", items.length
    ? el("div", { class: "recent" }, items.map((r) => {
        const health = ratingOf(r.summary?.overall_health);
        const tone = RATING[health]?.tone;
        return el("button", {
          class: `recent__item${r.id === a.id ? " is-current" : ""}`, type: "button",
          disabled: r.status !== "succeeded",
          onclick: async () => {
            if (r.id === a.id) return;
            await selectAnalysis(r.id);
            navigate("/overview");
          },
        }, [
          el("span", { style: "flex:1;min-width:0" }, [
            el("span", { class: "recent__label truncate" }, r.label),
            el("span", { class: "panel-sub" }, `${relativeTime(r.created_at)} • ${titleCase(r.vendor || "—")}`),
          ]),
          r.status === "succeeded" && health
            ? el("span", { class: "sev-badge", style: `color:var(${tone})` }, [el("span", { class: "sev-dot" }), health])
            : el("span", { class: `pill state-${r.status}` }, r.status),
        ]);
      }))
    : empty("No analyses yet"),
  { actions: viewAll("All", "/analyses") });
}

// ═════════════════════════════════════════════ Analyst

function buildAnalyst({ a, d }) {
  const r = d.rules;
  const s = d.scores;
  return [
    summaryStrip(a),
    el("div", { class: "kpi-grid" }, [
      kpi("Total findings", fmtNumber(d.total_findings),
        `${fmtNumber(d.issues)} issues · ${fmtNumber(d.pass_records)} pass records`),
      kpi("Rules assessed", fmtNumber(r.assessed),
        `of ${fmtNumber(r.in_file)} · ${fmtNumber(r.disabled)} disabled, ${fmtNumber(r.cleanup_excluded)} catch-all deny skipped`,
        { tone: "--brand-orange-deep" }),
      kpi("Rules with critical findings", fmtNumber(r.with_critical),
        `${pct(r.with_critical, r.assessed)}% of assessed rules`,
        { tone: r.with_critical ? "--sev-critical-ink" : null }),
      kpi("Median rule score", fmtNumber(s.median),
        `mean ${fmtNumber(s.mean)} · max ${fmtNumber(s.max)} · high-risk at ${s.high_threshold}`),
      kpi("Zone flows", fmtNumber(d.zone_flow_count), "distinct source → destination zone pairs"),
    ]),
    el("div", { class: "dash-row" }, [heatmapPanel(d), distributionPanel(d)]),
    el("div", { class: "dash-row" }, [topRulesPanel(d, "analyst"), exposurePanel(d)]),
    el("div", { class: "dash-row" }, [zoneFlowsPanel(d), populationPanel(d)]),
  ];
}

function heatmapPanel(d) {
  const cats = d.categories;
  if (!cats.length) return panel("Severity by category", empty("No issues"));
  const levels = SEV_ORDER.filter((level) => d.issue_severity[level]);
  const peak = Math.max(...cats.flatMap((c) => levels.map((level) => c.by_severity[level] || 0)), 1);

  const table = el("div", { class: "table-wrap" },
    el("table", { class: "data heat" }, [
      el("thead", {}, el("tr", {}, [
        el("th", {}, "Category"),
        ...levels.map((level) => el("th", { class: "num" },
          el("span", { class: "heat-head" }, [
            el("span", { class: "sev-dot", style: `background:${sevColor(level)}` }), SEV_LABEL[level],
          ]))),
        el("th", { class: "num" }, "Findings"),
        el("th", { class: "num" }, "Rules"),
      ])),
      el("tbody", {}, cats.map((c) => el("tr", {}, [
        el("td", { class: "rule-name" }, titleCase(c.type)),
        ...levels.map((level) => {
          const n = c.by_severity[level] || 0;
          return n
            ? el("td", {
                class: "num heat-cell", style: heatStyle(n, peak), tabindex: "0",
                "data-tip": `${titleCase(c.type)} · ${SEV_LABEL[level]}: ${fmtNumber(n)} findings`,
                onclick: () => navigate(findingsLink([c.type], level)),
                onkeydown: (e) => { if (e.key === "Enter") navigate(findingsLink([c.type], level)); },
              }, fmtNumber(n))
            : el("td", { class: "num heat-zero" }, "·");
        }),
        el("td", { class: "num" }, el("strong", {}, fmtNumber(c.findings))),
        el("td", { class: "num muted" }, c.rules ? fmtNumber(c.rules) : "—"),
      ]))),
    ]));

  return panel("Severity by category", [
    table,
    footnote(`Cell shade is finding count. Select a cell to open those findings.` +
      (d.pass_records ? ` ${fmtNumber(d.pass_records)} pass records (score 1) are excluded.` : "")),
  ], { sub: `${fmtNumber(d.issues)} issues across ${cats.length} categories` });
}

function distributionPanel(d) {
  const s = d.scores;
  const bins = s.bins.map((b) => ({
    label: b.hi == null ? `${b.lo}+` : `${b.lo}–${b.hi - 1}`,
    count: b.count,
    emphasis: b.lo >= s.high_threshold,
    tip: `Score ${b.hi == null ? `${b.lo} or more` : `${b.lo}–${b.hi - 1}`}: ${rules(b.count)}`,
  }));
  const markAfter = s.bins.findIndex((b) => b.hi === s.high_threshold);
  const assessed = d.rules.assessed;

  const low = s.bins.filter((b) => b.hi != null && b.hi <= s.medium_threshold).reduce((x, b) => x + b.count, 0);
  const medium = assessed - s.high - low;
  return panel("Rule score distribution", [
    histogram(bins, { markAfter, markLabel: `high risk ≥ ${s.high_threshold}`, width: 440, height: 250 }),
    el("div", { class: "hist-bands" }, [
      el("span", {}, ["Low (< ", s.medium_threshold, ") ", el("strong", {}, fmtNumber(low))]),
      el("span", {}, [`Medium (${s.medium_threshold}–${s.high_threshold - 1}) `, el("strong", {}, fmtNumber(medium))]),
      el("span", {}, [`High (≥ ${s.high_threshold}) `, el("strong", {}, fmtNumber(s.high))]),
    ]),
    footnote(`${fmtNumber(s.high)} of ${fmtNumber(assessed)} assessed rules score ${s.high_threshold} or more. ` +
      "A rule's score is the sum of its findings' scores, so one critical finding is usually enough to cross the line."),
  ], { sub: "assessed rules by risk score" });
}

function exposurePanel(d) {
  const any = d.exposure.any || {};
  const assessed = d.rules.assessed;
  const toPermissive = () => navigate(findingsLink(["overly_permissive"]));
  const anyRows = [
    { label: "Destination address", value: any.destination || 0 },
    { label: "Source address", value: any.source || 0 },
    { label: "Service", value: any.service || 0 },
    { label: "Two or more fields", value: any.multiple_any || 0 },
  ].map((row) => ({
    ...row,
    display: `${fmtNumber(row.value)} · ${pct(row.value, assessed)}%`,
    tip: `'any' in ${row.label.toLowerCase()}: ${rules(row.value)} of ${fmtNumber(assessed)} assessed`,
    onClick: toPermissive,
  }));

  const protos = d.exposure.protocols || [];
  return panel("Exposure", [
    el("div", { class: "section-label", style: "margin-top:0" }, "‘any’ used in the rule"),
    rankedBars(anyRows, { max: 4, sort: false, peak: assessed }),
    el("div", { class: "section-label" }, "Clear-text protocols allowed"),
    protos.length
      ? el("div", { class: "proto-chips" }, protos.map((p) =>
          el("button", {
            class: "chip", type: "button",
            "data-tip": `${p.protocol.toUpperCase()} allowed by ${rules(p.rules)}`,
            onclick: () => navigate(findingsLink(["insecure_protocol"], null, p.protocol)),
          }, [p.protocol.toUpperCase(), el("span", { class: "n" }, p.rules)])))
      : el("p", { class: "panel-sub", style: "margin:0" }, "None detected."),
  ], { sub: `share of ${fmtNumber(assessed)} assessed rules` });
}

function zoneFlowsPanel(d) {
  const flows = d.zone_flows;
  if (!flows.length) return panel("Zone flows", empty("No zones on these rules"));
  const peak = Math.max(...flows.map((f) => f.critical_rules), 1);
  return panel("Zone flows", el("div", { class: "table-wrap" },
    el("table", { class: "data" }, [
      el("thead", {}, el("tr", {}, [
        el("th", {}, "Source → destination"),
        el("th", { class: "num" }, "Rules"),
        el("th", { class: "num" }, "With critical"),
        el("th", { class: "num" }, "Mean risk"),
        el("th", { class: "num" }, "Max risk"),
      ])),
      el("tbody", {}, flows.map((f) => el("tr", {}, [
        el("td", {}, zonePath([f.src], [f.dst])),
        el("td", { class: "num" }, fmtNumber(f.rules)),
        el("td", {
          class: "num heat-cell", style: heatStyle(f.critical_rules, peak),
          "data-tip": `${f.src} → ${f.dst}: ${rules(f.critical_rules)} with a critical finding`,
        }, f.critical_rules ? fmtNumber(f.critical_rules) : el("span", { class: "muted" }, "0")),
        el("td", { class: "num" }, fmtNumber(f.mean_risk)),
        el("td", { class: "num muted" }, fmtNumber(f.max_risk)),
      ]))),
    ])
  ), {
    sub: `${flows.length < d.zone_flow_count ? `top ${flows.length} of ` : ""}${fmtNumber(d.zone_flow_count)} pairs · from each rule's own zones`,
  });
}

function populationPanel(d) {
  const r = d.rules;
  const segments = [
    ...severitySegments(r.by_worst, { suffix: " rules" }),
    { label: "No issues", value: r.by_worst.clean || 0, color: cssVar("--muted"),
      tip: `No issues: ${rules(r.by_worst.clean || 0)}` },
  ];
  const kv = [
    ["Rules in file", r.in_file],
    ["Assessed", r.assessed],
    ["  allow / deny", `${fmtNumber(r.allow)} / ${fmtNumber(r.deny)}`],
    ["Disabled (skipped)", r.disabled],
    ["Catch-all deny (skipped)", r.cleanup_excluded],
    ["Never hit", d.cleanup.unused],
  ];
  return panel("Rule population", [
    el("div", { class: "section-label", style: "margin-top:0" }, "Assessed rules by worst finding"),
    stackedBar(segments, { height: 14, label: "Assessed rules by worst finding" }),
    el("div", { class: "chart-legend", style: "margin-top:.6rem" }, segments
      .filter((seg) => seg.value > 0 || seg.label === "No issues").map((seg) =>
      el("span", { class: "item" }, [
        el("span", { class: "swatch", style: `background:${seg.color}` }),
        el("span", { class: "lg-label" }, seg.label),
        el("span", { class: "lg-value" }, fmtNumber(seg.value)),
      ]))),
    el("div", { class: "section-label" }, "Composition"),
    el("dl", { class: "kv kv--tight" }, kv.flatMap(([k, v]) => [
      el("dt", { class: k.startsWith("  ") ? "kv-indent" : null }, k.trim()),
      el("dd", { class: "num-dd" }, typeof v === "number" ? fmtNumber(v) : v),
    ])),
  ]);
}
