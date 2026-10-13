// Composes the assessment report from the analysis data already in the API.
//
// Deliberately NOT a filter over the engine's own 3 MB HTML file. Rebuilding
// from the structured data is what makes the report composable at all: sections
// can be toggled, reordered and restyled, and the same renderers produce both
// the on-screen preview and the downloaded file — so what you approve is what
// the client receives.

import { el, fmtNumber, fmtDate, titleCase } from "./ui.js";

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

// Fixed report ink. These are NOT the app's theme tokens: a report is read on
// white or on paper, so it never follows the viewer's dark mode.
const SEV_INK = {
  critical: "#B3122F", high: "#B5440F", medium: "#8A6100",
  low: "#137A47", info: "#1268A3",
};

/**
 * The sections a user can include, in report order.
 * `always: true` marks the cover, which is the document's identity.
 * `needs` names the data a section requires, so a section with nothing to show
 * can be disabled in the picker rather than rendering an empty heading.
 */
export const SECTIONS = [
  { id: "cover",       label: "Cover page",            always: true,
    hint: "Client, firewall, vendor and run date" },
  { id: "summary",     label: "Executive summary",     needs: "summary",
    hint: "Verdict, headline counts and what they mean" },
  { id: "severity",    label: "Severity breakdown",    needs: "facets",
    hint: "Distribution across critical to low" },
  { id: "categories",  label: "Findings by category",  needs: "facets",
    hint: "Ranked count per issue type" },
  { id: "compliance",  label: "Compliance",            needs: "compliance",
    hint: "Every framework assessed for this run" },
  { id: "toprules",    label: "Highest risk rules",    needs: "rules",
    hint: "The rules carrying the most risk score" },
  { id: "critical",    label: "Critical & high findings", needs: "findings",
    hint: "Every finding at high severity or above" },
  { id: "allfindings", label: "Full findings register", needs: "findings",
    hint: "Every finding raised — can be long" },
  { id: "inventory",   label: "Rule inventory",        needs: "rules",
    hint: "Every rule in the file, disabled ones included" },
  { id: "zones",       label: "Zone traffic matrix",   needs: "zones",
    hint: "Rule counts between configured zones" },
  { id: "logging",     label: "Logging gaps",          needs: "findings",
    hint: "Rules whose traffic is not auditable" },
  { id: "method",      label: "Scoring methodology",   always: false,
    hint: "How scores and thresholds are derived" },
  { id: "caveats",     label: "Scope & caveats",       always: false,
    hint: "What was excluded from analysis and why" },
];

export const DEFAULT_SELECTION = [
  "cover", "summary", "severity", "categories", "compliance", "toprules",
  "critical", "zones", "logging", "method", "caveats",
];

/** Which sections actually have data behind them for this analysis. */
export function availability(data) {
  const has = {
    summary: !!data.analysis?.summary,
    facets: Object.keys(data.facets?.by_risk || {}).length > 0,
    findings: (data.findings || []).length > 0,
    rules: (data.rules || []).length > 0,
    zones: Object.keys(data.analysis?.zone_summary || {}).length > 0,
    // At least one framework with a real result; planned ones have none.
    compliance: assessedFrameworks(data.analysis).length > 0,
  };
  const out = {};
  for (const section of SECTIONS) {
    out[section.id] = section.needs ? !!has[section.needs] : true;
  }
  return out;
}

/**
 * Build the report as a DOM node.
 * `selected` is an array of section ids; order comes from SECTIONS, not from
 * the array, so the document reads consistently however the boxes were ticked.
 */
export function buildReport(data, selected) {
  const doc = el("div", { class: "report-doc" });
  const chosen = SECTIONS.filter((s) => s.always || selected.includes(s.id));

  // The cover sits outside the numbered body.
  if (chosen.some((s) => s.id === "cover")) doc.append(renderCover(data));

  const body = el("div", { class: "r-body" });
  let index = 0;
  for (const section of chosen) {
    if (section.id === "cover") continue;
    const node = RENDERERS[section.id]?.(data, ++index, section);
    if (node) body.append(node);
    else index--;   // renderer declined; don't burn a section number
  }

  body.append(el("div", { class: "r-foot" }, [
    el("span", {}, "PwC Firewall Analyzer"),
    el("span", {}, `Generated ${fmtDate(new Date().toISOString())}`),
  ]));

  doc.append(body);
  return doc;
}

// ── Shared pieces ────────────────────────────────────────────────

function section(number, title, note, children) {
  return el("section", { class: "r-section" }, [
    el("div", { class: "r-section__head" }, [
      el("span", { class: "r-section__num" }, String(number).padStart(2, "0")),
      el("h2", {}, title),
      note ? el("span", { class: "r-section__note" }, note) : null,
    ]),
    ...[].concat(children),
  ]);
}

function sevChip(level) {
  const key = SEV_ORDER.includes(level) ? level : "info";
  return el("span", { class: `r-sev r-sev--${key}` }, key);
}

function table(headers, rows) {
  return el("div", { class: "r-table-wrap" },
    el("table", {}, [
      el("thead", {}, el("tr", {}, headers.map((h) =>
        el("th", h.num ? { class: "r-num" } : {}, h.label ?? h)))),
      el("tbody", {}, rows),
    ])
  );
}

// ── Sections ─────────────────────────────────────────────────────

function renderCover(data) {
  const a = data.analysis;
  const summary = a.summary || {};
  const stats = a.stats || {};

  return el("header", { class: "r-cover" }, [
    // The real brand asset, never a drawn approximation. toStandaloneHtml
    // swaps this src for a data URI so the downloaded file carries the mark
    // with it and renders correctly with no network.
    el("div", { class: "r-cover__mark" },
      el("img", { class: "r-cover__logo", src: "/img/pwc-logo-dark.png", alt: "PwC" })),
    el("div", { class: "r-cover__kicker" }, "Firewall rule base assessment"),
    el("h1", {}, a.label || "Firewall Analysis"),
    el("p", { class: "r-cover__sub" },
      `${fmtNumber(stats.total_rules)} rules assessed · ${fmtNumber(summary.total_issues)} findings · ` +
      `risk rating: ${summary.overall_health || "—"}` +
      (summary.posture?.score != null ? ` (${summary.posture.score}/100)` : "")),
    el("dl", { class: "r-cover__meta" }, [
      el("div", {}, [el("dt", {}, "Client / project"), el("dd", {}, a.project_name || "—")]),
      el("div", {}, [el("dt", {}, "Platform"), el("dd", {}, titleCase(a.vendor || "—"))]),
      el("div", {}, [el("dt", {}, "Source file"), el("dd", {}, a.filename || "—")]),
      el("div", {}, [el("dt", {}, "Analysed"), el("dd", {}, fmtDate(a.created_at))]),
      el("div", {}, [el("dt", {}, "Reference"), el("dd", {}, a.id)]),
    ]),
  ]);
}

function renderSummary(data, n) {
  const a = data.analysis;
  const summary = a.summary || {};
  const stats = a.stats || {};
  const byRisk = data.facets?.by_risk || {};
  const bands = data.facets?.rule_bands || {};
  const total = Object.values(byRisk).reduce((x, y) => x + y, 0);

  const verdict = summary.overall_health || "—";
  const verdictInk = SEV_INK[String(verdict).toLowerCase()] || SEV_INK.info;
  const score = summary.posture?.score;
  const critical = byRisk.critical || 0;

  return section(n, "Executive summary", null, [
    el("p", { class: "r-lede" },
      `The rule base for ${a.label} was assessed against ${fmtNumber(stats.total_rules)} active rules ` +
      `drawn from a file of ${fmtNumber(stats.all_rules_total)}. ` +
      `${fmtNumber(total)} findings were raised, of which ${fmtNumber(critical)} are critical. ` +
      `${fmtNumber(bands.high || 0)} rules score at or above the high-risk threshold of 70.`),

    el("div", { class: "r-tiles" }, [
      tile("Risk rating", verdict, score != null ? `posture score ${score}/100` : "not scored", verdictInk),
      tile("Findings", fmtNumber(total), "across all categories"),
      tile("Critical", fmtNumber(critical),
        total ? `${((critical / total) * 100).toFixed(1)}% of findings` : "—", SEV_INK.critical),
      tile("Rules assessed", fmtNumber(stats.total_rules), `of ${fmtNumber(stats.all_rules_total)} in file`),
      tile("High-risk rules", fmtNumber(bands.high || 0), "score ≥ 70"),
    ]),

    critical > 0
      ? el("div", { class: "r-callout" }, [
          el("h4", {}, "Priority"),
          el("p", {}, `${fmtNumber(critical)} critical findings should be triaged before any ` +
            `lower-severity remediation begins. These are concentrated in the rules listed under ` +
            `"Highest risk rules"; fixing the top entries clears a disproportionate share of the total.`),
        ])
      : null,
  ]);
}

function tile(key, value, note, ink) {
  return el("div", { class: "r-tile" }, [
    el("div", { class: "r-tile__k" }, key),
    el("div", { class: "r-tile__v", style: ink ? `color:${ink}` : null }, value),
    note ? el("div", { class: "r-tile__n" }, note) : null,
  ]);
}

function renderSeverity(data, n) {
  const byRisk = data.facets?.by_risk || {};
  const total = Object.values(byRisk).reduce((x, y) => x + y, 0);
  if (!total) return null;

  const present = SEV_ORDER.filter((s) => byRisk[s]);

  return section(n, "Severity breakdown", `${fmtNumber(total)} findings`, [
    el("div", { class: "r-dist" }, present.map((level) =>
      el("span", {
        style: `width:${(byRisk[level] / total) * 100}%;background:${SEV_INK[level]}`,
        title: `${titleCase(level)}: ${byRisk[level]}`,
      })
    )),
    el("div", { class: "r-dist__key" }, present.map((level) =>
      el("span", {}, [
        el("i", { style: `background:${SEV_INK[level]}` }),
        `${titleCase(level)} — ${fmtNumber(byRisk[level])} (${((byRisk[level] / total) * 100).toFixed(1)}%)`,
      ])
    )),
    el("p", { class: "r-lede", style: "margin-top:1rem" },
      "Severity reflects the exposure a finding represents, not the effort to remediate it. " +
      "A critical finding on a single rule can usually be closed with one change."),
  ]);
}

function renderCategories(data, n) {
  const byType = data.facets?.by_type || {};
  const entries = Object.entries(byType);
  if (!entries.length) return null;
  const peak = Math.max(...entries.map(([, v]) => v));

  return section(n, "Findings by category", null,
    el("div", { class: "r-bars" }, entries.map(([type, count]) =>
      el("div", { class: "r-bar" }, [
        el("span", {}, titleCase(type)),
        el("span", { class: "r-bar__t" },
          el("span", { class: "r-bar__f", style: `width:${(count / peak) * 100}%` })),
        el("span", { class: "r-bar__v" }, fmtNumber(count)),
      ])
    ))
  );
}

function renderTopRules(data, n) {
  const rules = (data.rules || [])
    .filter((r) => r.risk_score > 0)
    .sort((a, b) => b.risk_score - a.risk_score)
    .slice(0, 15);
  if (!rules.length) return null;

  return section(n, "Highest risk rules", `top ${rules.length}`, [
    el("p", { class: "r-lede" },
      "Ranked by total risk score — the sum of every finding raised against the rule. " +
      "Remediating from the top of this list clears the most exposure per change."),
    table(
      [{ label: "#", num: true }, "Rule", "Action", "Source", "Destination", "Service",
       { label: "Score", num: true }, { label: "Findings", num: true }],
      rules.map((r) => el("tr", {}, [
        el("td", { class: "r-num" }, r.seq),
        el("td", { class: "r-rule-name r-wrap" }, r.name),
        el("td", {}, el("span", { class: `r-pill r-pill--${r.action}` }, r.action)),
        el("td", { class: "r-mono r-wrap" }, (r.src_addresses || []).slice(0, 2).join(", ")),
        el("td", { class: "r-mono r-wrap" }, (r.dst_addresses || []).slice(0, 2).join(", ")),
        el("td", { class: "r-mono r-wrap" }, (r.services || []).slice(0, 2).join(", ")),
        el("td", { class: "r-num" }, el("strong", {}, fmtNumber(r.risk_score))),
        el("td", { class: "r-num" }, r.finding_count),
      ]))
    ),
  ]);
}

function findingsTable(findings) {
  return table(
    ["Severity", "Rule", "Category", { label: "Score", num: true }, "Finding", "Recommendation"],
    findings.map((f) => el("tr", {}, [
      el("td", {}, sevChip(f.risk_level)),
      el("td", { class: "r-rule-name r-wrap" }, f.rule_name),
      el("td", {}, titleCase(f.issue_type)),
      el("td", { class: "r-num" }, f.score),
      el("td", { class: "r-wrap" }, f.description),
      el("td", { class: "r-wrap" }, f.recommendation),
    ]))
  );
}

function renderCritical(data, n) {
  const findings = (data.findings || [])
    .filter((f) => f.risk_level === "critical" || f.risk_level === "high")
    .sort((a, b) => b.score - a.score);
  if (!findings.length) return null;

  return section(n, "Critical and high findings", `${fmtNumber(findings.length)} findings`, [
    el("p", { class: "r-lede" },
      "Every finding at high severity or above, worst first. These represent exposure that " +
      "should be scheduled rather than queued."),
    findingsTable(findings.slice(0, 250)),
    findings.length > 250
      ? el("p", { class: "r-empty" }, `Showing the 250 highest-scoring of ${fmtNumber(findings.length)}. Use the CSV export for the complete set.`)
      : null,
  ]);
}

function renderAllFindings(data, n) {
  const findings = [...(data.findings || [])].sort((a, b) => b.score - a.score);
  if (!findings.length) return null;

  return section(n, "Full findings register", `${fmtNumber(findings.length)} findings`, [
    el("p", { class: "r-lede" },
      "The complete set of findings raised across the rule base, ordered by score."),
    findingsTable(findings.slice(0, 500)),
    findings.length > 500
      ? el("p", { class: "r-empty" }, `Showing the 500 highest-scoring of ${fmtNumber(findings.length)}. Use the CSV export for the complete set.`)
      : null,
  ]);
}

function renderInventory(data, n) {
  const rules = data.rules || [];
  if (!rules.length) return null;

  return section(n, "Rule inventory", `${fmtNumber(rules.length)} rules`, [
    el("p", { class: "r-lede" },
      "Every rule in the source file, in file order — including disabled rules, which are " +
      "excluded from scoring but remain part of the configuration."),
    table(
      [{ label: "#", num: true }, "Rule", "Action", "State", "Source", "Destination",
       "Service", { label: "Score", num: true }],
      rules.slice(0, 500).map((r) => el("tr", {}, [
        el("td", { class: "r-num" }, r.seq),
        el("td", { class: "r-rule-name r-wrap" }, r.name),
        el("td", {}, el("span", { class: `r-pill r-pill--${r.action}` }, r.action)),
        el("td", {}, r.disabled ? el("span", { class: "r-pill" }, "disabled") : "active"),
        el("td", { class: "r-mono r-wrap" }, (r.src_addresses || []).slice(0, 2).join(", ")),
        el("td", { class: "r-mono r-wrap" }, (r.dst_addresses || []).slice(0, 2).join(", ")),
        el("td", { class: "r-mono r-wrap" }, (r.services || []).slice(0, 2).join(", ")),
        el("td", { class: "r-num" }, r.risk_score || "—"),
      ]))
    ),
    rules.length > 500
      ? el("p", { class: "r-empty" }, `Showing the first 500 of ${fmtNumber(rules.length)} rules.`)
      : null,
  ]);
}

function renderZones(data, n) {
  const zones = data.analysis?.zone_summary || {};
  const pairs = Object.entries(zones);
  if (!pairs.length) return null;

  const peak = Math.max(...pairs.map(([, v]) => v.total_rules), 1);
  const sorted = pairs.sort((a, b) => b[1].total_rules - a[1].total_rules);

  return section(n, "Zone traffic matrix", `${pairs.length} zone pairs`, [
    el("p", { class: "r-lede" },
      "Rule counts between zones, resolved by matching each rule's addresses against the " +
      "configured zone subnets. Traffic reaching a critical zone from an external one warrants " +
      "the closest review."),
    el("div", { class: "r-table-wrap" },
      el("table", { class: "r-matrix" }, [
        el("thead", {}, el("tr", {}, [
          el("th", {}, "Zone pair"),
          el("th", { class: "r-num" }, "Rules"),
          el("th", { class: "r-num" }, "Allow"),
          el("th", { class: "r-num" }, "Deny"),
        ])),
        el("tbody", {}, sorted.map(([pair, v]) => el("tr", {}, [
          el("td", { class: "r-rule-name" }, pair),
          el("td", {
            class: "r-heat",
            style: `background:rgba(208,74,2,${(0.06 + (v.total_rules / peak) * 0.4).toFixed(2)})`,
          }, fmtNumber(v.total_rules)),
          el("td", { class: "r-num" }, fmtNumber(v.allow_rules)),
          el("td", { class: "r-num" }, fmtNumber(v.deny_rules)),
        ]))),
      ])
    ),
  ]);
}

function renderLogging(data, n) {
  const findings = (data.findings || []).filter((f) => f.issue_type === "missing_logging");
  if (!findings.length) return null;

  return section(n, "Logging gaps", `${fmtNumber(findings.length)} rules`, [
    el("p", { class: "r-lede" },
      "Rules with logging disabled. Traffic matching these rules leaves no record, so it can be " +
      "neither alerted on nor reconstructed during an investigation. An allow rule without " +
      "logging is the more serious case."),
    table(
      ["Severity", "Rule", "Action", "Impact"],
      findings.slice(0, 200).map((f) => el("tr", {}, [
        el("td", {}, sevChip(f.risk_level)),
        el("td", { class: "r-rule-name r-wrap" }, f.rule_name),
        el("td", {}, el("span", { class: `r-pill r-pill--${(f.details?.action || "").toLowerCase()}` },
          f.details?.action || "—")),
        el("td", { class: "r-wrap" }, f.description),
      ]))
    ),
  ]);
}

const COMPLIANCE_LABEL = {
  FULLY_COMPLIANT: "Fully compliant", COMPLIANT: "Compliant",
  PARTIALLY_COMPLIANT: "Partially compliant", PARTIAL: "Partial",
  NON_COMPLIANT: "Non-compliant", NOT_APPLICABLE: "Not applicable",
};
const COMPLIANCE_INK = {
  FULLY_COMPLIANT: "#137A47", COMPLIANT: "#137A47",
  PARTIALLY_COMPLIANT: "#8A6100", PARTIAL: "#8A6100",
  NON_COMPLIANT: "#B3122F", NOT_APPLICABLE: "#6B635D",
};

function complianceChip(status) {
  return el("span", {
    class: "r-sev",
    style: `color:${COMPLIANCE_INK[status] || COMPLIANCE_INK.NOT_APPLICABLE}`,
  }, COMPLIANCE_LABEL[status] || status);
}

/** Frameworks with a real result, in the order they were requested. */
function assessedFrameworks(analysis) {
  const c = analysis?.compliance || {};
  return (c.frameworks || []).map((key) => ({ key, ...(c.assessments?.[key] || {}) }))
    .filter((f) => f.status === "assessed" && f.controls);
}

function renderCompliance(data, n) {
  const c = data.analysis?.compliance || {};
  const all = (c.frameworks || []).map((key) => ({ key, ...(c.assessments?.[key] || {}) }));
  const done = assessedFrameworks(data.analysis);
  if (!done.length) return null;
  const pending = all.filter((f) => f.status !== "assessed");
  const short = (f) => f.short || String(f.key).toUpperCase();

  return section(n, "Regulatory compliance", done.map(short).join(" · "), [
    done.length > 1
      ? el("p", { class: "r-lede" },
          `This rule base was assessed against ${done.length} frameworks: ` +
          `${done.map((f) => `${short(f)} (${f.compliance_pct}%)`).join(", ")}. Each is reported separately below.`)
      : null,
    ...done.map((f) => complianceBlock(f, short(f), done.length > 1)),
    pending.length
      ? el("p", { class: "r-lede", style: "color:#6B635D" },
          `Also requested but not assessed on this run: ${pending.map((f) => `${short(f)} — ${f.name || ""}`).join("; ")}. ` +
          "No result is shown for these rather than one borrowed from another framework.")
      : null,
  ]);
}

function complianceBlock(c, short, titled) {
  const controls = Object.values(c.controls);
  const group = c.group_label || "Subdomain";
  return el("div", { class: "r-fw" }, [
    titled ? el("h3", {}, `${short} — ${c.framework || c.name}`) : null,
    el("p", { class: "r-lede" },
      `Assessed against ${c.framework || c.name}${c.domain ? `, domain ${c.domain}` : ""}. ` +
      `${fmtNumber(c.passed_checks)} of ${fmtNumber(c.total_checks)} control checks pass ` +
      `across ${fmtNumber(c.evaluated_rules)} rules, giving an overall position of ` +
      `${(COMPLIANCE_LABEL[c.overall_status] || c.overall_status).toLowerCase()}. ` +
      `${fmtNumber(c.na_checks)} checks are not applicable.`),

    el("div", { class: "r-tiles" }, [
      tile("Overall", `${c.compliance_pct}%`,
        COMPLIANCE_LABEL[c.overall_status] || c.overall_status,
        COMPLIANCE_INK[c.overall_status]),
      tile("Checks passed", fmtNumber(c.passed_checks), `of ${fmtNumber(c.total_checks)}`),
      tile("Rules fully compliant", fmtNumber(c.rules_fully_compliant),
        `of ${fmtNumber(c.evaluated_rules)} evaluated`),
      tile("Rules with gaps", fmtNumber(c.rules_with_issues),
        "at least one control failing", COMPLIANCE_INK.NON_COMPLIANT),
    ]),

    table(
      ["Control", group, "Requirement", { label: "Applicable", num: true },
       { label: "Pass", num: true }, { label: "Fail", num: true },
       { label: "N/A", num: true }, "Status"],
      controls.map((ctrl) => el("tr", {}, [
        el("td", { class: "r-mono" }, ctrl.id),
        el("td", { class: "r-wrap" }, ctrl.subdomain_name),
        el("td", { class: "r-wrap" }, ctrl.title),
        el("td", { class: "r-num" }, fmtNumber(ctrl.applicable)),
        el("td", { class: "r-num" }, fmtNumber(ctrl.compliant)),
        el("td", { class: "r-num" }, fmtNumber(ctrl.non_compliant)),
        el("td", { class: "r-num" }, fmtNumber(ctrl.na)),
        el("td", {}, complianceChip(ctrl.status)),
      ]))
    ),

    el("div", { class: "r-callout", style: "margin-top:1.1rem" }, [
      el("h4", {}, `Remediation by control${titled ? ` (${short})` : ""}`),
      ...controls
        .filter((ctrl) => ctrl.non_compliant > 0)
        .map((ctrl) => el("p", { style: "margin:0 0 .5em" }, [
          el("strong", {}, `${ctrl.id} — `),
          ctrl.recommendation,
          el("span", { style: "color:#6B635D" },
            ` (${fmtNumber(ctrl.non_compliant)} of ${fmtNumber(ctrl.applicable)} rules failing)`),
        ])),
    ]),
  ]);
}

function renderMethod(data, n) {
  return section(n, "Scoring methodology", null, [
    el("p", {},
      "Each check emits findings carrying a score derived from fixed, published weights. A rule's " +
      "risk score is the sum of the scores of every finding raised against it — so a rule with " +
      "several moderate problems can outrank one with a single severe problem, which is the " +
      "intended behaviour."),
    el("div", { class: "r-callout" }, [
      el("h4", {}, "Risk thresholds"),
      el("p", {}, "A rule scoring 70 or above is high risk. Between 40 and 69 is medium. " +
        "Below 40 the rule is recorded but not prioritised."),
    ]),
    el("p", {},
      "Severity on an individual finding is assigned by the check that raised it and reflects " +
      "exposure, not remediation effort. Where a score is composed of several factors, the " +
      "arithmetic is shown against the finding in the platform, so any number in this report can " +
      "be traced back to its components."),
    el("dl", { class: "r-kv" }, [
      el("dt", {}, "Checks applied"), el("dd", {}, "12 — seven per rule, five across the rule base"),
      el("dt", {}, "High-risk threshold"), el("dd", {}, "70"),
      el("dt", {}, "Medium threshold"), el("dd", {}, "40"),
      el("dt", {}, "Application signatures"), el("dd", {}, "5,271 Palo Alto App-ID entries"),
    ]),
  ]);
}

function renderCaveats(data, n) {
  const stats = data.analysis?.stats || {};
  return section(n, "Scope and caveats", null, [
    el("p", {},
      "This assessment reads an exported rule base. It does not connect to the device, and " +
      "therefore does not observe live traffic, routing, NAT, or whether a rule is reachable in " +
      "practice given the topology."),
    el("dl", { class: "r-kv" }, [
      el("dt", {}, "Rules in file"), el("dd", {}, fmtNumber(stats.all_rules_total)),
      el("dt", {}, "Rules assessed"), el("dd", {}, fmtNumber(stats.total_rules)),
      el("dt", {}, "Disabled, excluded"), el("dd", {},
        `${fmtNumber(stats.disabled_rules_excluded)} — retained in the inventory but not scored`),
      el("dt", {}, "Catch-all denies excluded"), el("dd", {},
        `${fmtNumber(stats.deny_any_rules_excluded)} — a deny-any-any is assessed for placement, not scored as permissive`),
    ]),
    el("p", { style: "margin-top:.8rem" },
      "Findings are derived from the configuration as exported on the date shown on the cover. " +
      "Any change made after that export is out of scope."),
  ]);
}

const RENDERERS = {
  summary: renderSummary,
  compliance: renderCompliance,
  severity: renderSeverity,
  categories: renderCategories,
  toprules: renderTopRules,
  critical: renderCritical,
  allfindings: renderAllFindings,
  inventory: renderInventory,
  zones: renderZones,
  logging: renderLogging,
  method: renderMethod,
  caveats: renderCaveats,
};

/**
 * Serialise the composed report into a standalone HTML file.
 * The stylesheet is fetched and inlined so the download opens correctly on a
 * machine with no network — which is where a client will open it.
 */
export async function toStandaloneHtml(data, selected) {
  const node = buildReport(data, selected);

  let css = "";
  try {
    css = await (await fetch("/css/report.css")).text();
  } catch {
    css = ""; // still produces a readable document, just unstyled
  }

  // Inline the brand mark. A downloaded report is opened from disk, often with
  // no network and never with this server running, so an /img/ reference would
  // render as a broken image on the cover.
  try {
    const logo = await fetchAsDataUri("/img/pwc-logo-dark.png");
    if (logo) {
      node.querySelectorAll("img.r-cover__logo").forEach((img) => { img.src = logo; });
    }
  } catch { /* the cover simply carries no mark */ }

  const title = `${data.analysis.label || "Firewall analysis"} — assessment report`;
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
body { margin: 0; background: #F3EFEB; }
.report-doc { max-width: 1100px; margin: 0 auto; box-shadow: 0 2px 24px rgba(0,0,0,.1); }
@media print { body { background: #fff; } .report-doc { max-width: none; box-shadow: none; } }
${css}
</style>
</head>
<body>
${node.outerHTML}
</body>
</html>`;
}

/** Fetch a binary asset and return it as a base64 data URI. */
async function fetchAsDataUri(url) {
  const response = await fetch(url);
  if (!response.ok) return null;
  const blob = await response.blob();
  return await new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = reject;
    reader.readAsDataURL(blob);
  });
}


function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
