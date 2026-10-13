// Compliance — the rule base measured against every framework chosen for the
// run, one tab each.
//
// Reads the assessments stored on the analysis (computed by the engine's
// framework registry, analysis/frameworks.py), so the figures here are the
// same ones the report and the findings list use. Nothing is recalculated in
// the browser. A framework that was requested but is not implemented yet gets
// a tab that says so, rather than a result borrowed from another framework.

import { el, clear, panel, empty, fmtNumber, titleCase, svgIcon } from "../ui.js";
import { getState } from "../state.js";
import { navigate, parseRoute, setQuery } from "../router.js";
import { mayWrite } from "../session.js";

// Compliance status is a STATUS palette: four reserved states, each shown with
// its label, never colour alone.
// `ink` colours text (chips, figures); `fill` colours bars and meters. Fills
// only need 3:1 against the surface, text needs 4.5:1, so they differ.
export const STATUS = {
  FULLY_COMPLIANT:     { label: "Fully compliant",     ink: "--sev-low-ink", fill: "--sev-low" },
  COMPLIANT:           { label: "Compliant",           ink: "--sev-low-ink", fill: "--sev-low" },
  PARTIALLY_COMPLIANT: { label: "Partially compliant", ink: "--sev-medium-ink", fill: "--sev-medium" },
  PARTIAL:             { label: "Partial",             ink: "--sev-medium-ink", fill: "--sev-medium" },
  NON_COMPLIANT:       { label: "Non-compliant",       ink: "--sev-critical-ink", fill: "--sev-critical" },
  NOT_APPLICABLE:      { label: "Not applicable",      ink: "--muted", fill: "--muted" },
};

const CHECK = ["M20 6 9 17l-5-5"];
const CROSS = ["M18 6 6 18", "M6 6l12 12"];
const DASH = ["M5 12h14"];

export function statusChip(status) {
  const meta = STATUS[status] || STATUS.NOT_APPLICABLE;
  return el("span", {
    class: "sev-badge",
    style: `color:var(${meta.ink})`,
  }, [el("span", { class: "sev-dot" }), meta.label]);
}

const WARN = ["M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"];

const short = (f) => f.short || String(f.key).toUpperCase();
/** "Subdomain" -> "subdomains", for the framework's own grouping level. */
const groupPlural = (f, n = 2) => {
  const label = (f.group_label || "Group").toLowerCase();
  return n === 1 ? label : `${label}s`;
};

export async function render(host) {
  const { current } = getState();
  if (!current || current.status !== "succeeded") {
    host.append(empty("No completed analysis selected"));
    return;
  }

  const c = current.compliance || {};
  const list = (c.frameworks || []).map((key) => ({ key, ...(c.assessments?.[key] || { status: "missing" }) }));

  if (!list.length) {
    host.append(panel("Compliance", [
      empty("No compliance framework was assessed for this analysis",
        "Frameworks are chosen in the first step of Run New Analysis; select one or more there."),
      mayWrite()
        ? el("div", { style: "text-align:center;margin-top:-1rem" },
            el("button", { class: "btn primary small", onclick: () => navigate("/new") }, "Run New Analysis"))
        : null,
    ]));
    return;
  }

  // Open the framework named in the URL, else the first one with a result.
  const wanted = parseRoute().query.get("fw");
  let active = list.some((f) => f.key === wanted) ? wanted
    : (list.find((f) => f.status === "assessed") || list[0]).key;

  const tabs = el("div", { class: "fw-tabs", role: "tablist", "aria-label": "Compliance frameworks" });
  const body = el("div");
  host.append(tabs, body);
  paint();

  function paint() {
    tabs.replaceChildren(...list.map((f) => frameworkTab(f, f.key === active, () => {
      active = f.key;
      setQuery({ fw: f.key });
      paint();
    })));
    const f = list.find((x) => x.key === active);
    clear(body);
    if (f.status === "assessed") {
      body.append(buildKpis(f));
      body.append(el("div", { style: "height:1rem" }));
      body.append(buildSubdomains(f));
      body.append(el("div", { style: "height:1rem" }));
      body.append(buildControls(f));
    } else {
      body.append(buildUnavailable(f));
    }
  }
}

function frameworkTab(f, selected, onclick) {
  const assessed = f.status === "assessed";
  const meta = STATUS[f.overall_status] || STATUS.NOT_APPLICABLE;
  return el("button", {
    class: `fw-tab${selected ? " is-active" : ""}`, type: "button", role: "tab",
    "aria-selected": String(selected), onclick,
  }, [
    el("span", { class: "fw-tab__top" }, [
      el("span", { class: "fw-badge" }, short(f)),
      assessed
        ? el("span", { class: "fw-tab__pct", style: `color:var(${meta.ink})` }, `${Math.round(f.compliance_pct ?? 0)}%`)
        : el("span", { class: "pill" },
            f.status === "error" ? "Failed" : f.status === "missing" ? "No result" : "Not yet available"),
    ]),
    el("span", { class: "fw-tab__name" }, f.name || short(f)),
    el("span", { class: "panel-sub" }, assessed ? meta.label : "no assessment on this run"),
  ]);
}

function buildUnavailable(f) {
  const failed = f.status === "error";
  return panel(f.name || short(f), el("div", { class: `notice ${failed ? "bad" : "warn"}` }, [
    svgIcon(WARN),
    el("div", {}, [
      el("div", { style: "font-weight:650;margin-bottom:.2rem" },
        failed ? `The ${short(f)} assessment failed on this run`
          : f.status === "missing" ? `No ${short(f)} result is stored for this run`
          : `${short(f)} was requested, but it is not implemented yet`),
      el("div", { class: "muted" }, f.message ||
        "No assessment was produced for this framework on this run."),
      f.status === "missing" ? null : el("div", { class: "muted", style: "margin-top:.5rem" }, failed
        ? "The other frameworks on this run are unaffected. Re-run the export once the cause is fixed."
        : "Its tab will fill in on the next run of this export after the framework's controls are added."),
    ]),
  ]), { sub: short(f) });
}

/**
 * Headline figures for one framework. The framework's name and overall status
 * are already on its tab, so they are not repeated in a header here.
 */
function buildKpis(c) {
  const meta = STATUS[c.overall_status] || STATUS.NOT_APPLICABLE;
  const pct = c.compliance_pct ?? 0;

  return el("div", {}, [
    el("div", { class: "kpi-grid" }, [
      kpi("Compliance", el("div", {
        class: "kpi-value", style: `color:var(${meta.ink})`,
      }, `${pct}%`), `${fmtNumber(c.passed_checks)} of ${fmtNumber(c.total_checks)} checks passed`),
      kpi("Controls assessed", el("div", { class: "kpi-value" }, fmtNumber(Object.keys(c.controls).length)),
        `across ${fmtNumber(Object.keys(c.subdomains || {}).length)} ` +
        groupPlural(c, Object.keys(c.subdomains || {}).length)),
      kpi("Rules evaluated", el("div", { class: "kpi-value brand" }, fmtNumber(c.evaluated_rules)),
        `${fmtNumber(c.rules_fully_compliant)} fully compliant`),
      kpi("Rules with gaps", el("div", {
        class: "kpi-value", style: "color:var(--sev-high-ink)",
      }, fmtNumber(c.rules_with_issues)), "at least one control failing"),
      kpi("Not applicable", el("div", { class: "kpi-value muted" }, fmtNumber(c.na_checks)),
        "checks that do not apply"),
    ]),
  ]);
}

function kpi(label, valueNode, foot) {
  return el("div", { class: "kpi" }, [
    el("span", { class: "kpi-label" }, label),
    valueNode,
    el("span", { class: "kpi-foot" }, foot),
  ]);
}

function buildSubdomains(c) {
  const rows = Object.values(c.subdomains || {}).map((sd) => {
    const total = sd.applicable || 0;
    const pct = total ? Math.round((sd.compliant / total) * 100) : 0;
    return el("div", { class: "compl-sub" }, [
      el("div", { class: "compl-sub__head" }, [
        el("div", {}, [
          el("div", { class: "compl-sub__id" }, sd.id),
          el("div", { class: "compl-sub__name" }, sd.name),
        ]),
        el("span", { style: "flex:1" }),
        statusChip(sd.status),
      ]),
      el("div", { class: "compl-bar" },
        el("div", {
          class: "compl-bar__fill",
          style: `width:${pct}%;background:var(${pct === 100 ? "--sev-low" : pct === 0 ? "--sev-critical" : "--sev-medium"})`,
        })),
      el("div", { class: "panel-sub" },
        `${fmtNumber(sd.compliant)} of ${fmtNumber(total)} checks passed · ` +
        `${sd.controls.length} control${sd.controls.length === 1 ? "" : "s"}`),
    ]);
  });

  const plural = groupPlural(c);
  return panel(plural[0].toUpperCase() + plural.slice(1), el("div", { class: "compl-subs" }, rows),
    { sub: `grouped by ${short(c)} ${groupPlural(c, 1)}` + (c.domain ? ` · Domain ${c.domain}` : "") });
}

function buildControls(c) {
  const cards = Object.values(c.controls).map((ctrl) => {
    const total = ctrl.applicable || 0;
    const pct = total ? Math.round((ctrl.compliant / total) * 100) : 0;
    const violating = ctrl.violating_rules || [];

    const body = el("div", { class: "compl-ctrl__body" }, [
      el("div", { class: "compl-counts" }, [
        count(CHECK, "Compliant", ctrl.compliant, "--sev-low-ink"),
        count(CROSS, "Non-compliant", ctrl.non_compliant, "--sev-critical-ink"),
        count(DASH, "Not applicable", ctrl.na, "--muted"),
      ]),
      el("div", { class: "compl-bar", style: "margin:.7rem 0 .5rem" },
        el("div", {
          class: "compl-bar__fill",
          style: `width:${pct}%;background:var(${pct === 100 ? "--sev-low" : pct === 0 ? "--sev-critical" : "--sev-medium"})`,
        })),
      el("div", { class: "panel-sub" }, `${pct}% of ${fmtNumber(total)} applicable rules pass`),

      el("div", { class: "section-label" }, "What to do"),
      el("p", { class: "panel-sub", style: "margin:0 0 .3rem" }, ctrl.recommendation),
      ctrl.na > 0
        ? el("p", { class: "panel-sub", style: "margin:.45rem 0 0;font-style:italic" },
            `Not applicable (${fmtNumber(ctrl.na)}): ${ctrl.na_recommendation}`)
        : null,
    ]);

    if (violating.length) {
      body.append(el("div", { class: "section-label" },
        `Rules failing this control (${fmtNumber(violating.length)})`));
      const shown = violating.slice(0, 40);
      body.append(el("div", { class: "tag-list" },
        shown.map((r) => el("button", {
          class: "tag tag--link",
          title: `Open ${r.name}`,
          onclick: () => navigate(`/rules?rule=${encodeURIComponent(r.id)}`),
        }, r.name || r.id))));
      if (violating.length > shown.length) {
        body.append(el("div", { class: "panel-sub", style: "margin-top:.4rem" },
          `and ${fmtNumber(violating.length - shown.length)} more`));
      }
    }

    return el("details", { class: "compl-ctrl", open: violating.length > 0 }, [
      el("summary", {}, [
        el("span", { class: "compl-ctrl__id" }, ctrl.id),
        el("span", { class: "compl-ctrl__title" }, ctrl.title),
        el("span", { style: "flex:1" }),
        statusChip(ctrl.status),
      ]),
      body,
    ]);
  });

  return panel("Controls", el("div", { class: "compl-ctrls" }, cards),
    { sub: `${Object.keys(c.controls).length} controls · click a rule to open it` });
}

function count(icon, label, value, ink) {
  return el("div", { class: "compl-count", style: `color:var(${ink})` }, [
    svgIcon(icon, { size: 14 }),
    el("span", { class: "compl-count__v" }, fmtNumber(value || 0)),
    el("span", { class: "compl-count__l" }, label),
  ]);
}
