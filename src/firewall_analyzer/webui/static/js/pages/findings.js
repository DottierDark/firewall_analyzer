// Findings — every finding, filterable by severity and category, in two views:
//
//   Board (default)  one card per category present in this run, in lanes by the
//                    category's worst severity. Cards, lanes and every count come
//                    from the run's own facets, so they appear, disappear and
//                    change with each analysis. A card opens its list.
//   List             every finding, sorted and paged server-side, so it stays
//                    fast on a rulebase far larger than the demo set.
//
// Both views share the search box and the severity / category chips.

import { api } from "../api.js";
import { el, append, clear, panel, empty, loading, fmtNumber, titleCase, sevBadge,
         svgIcon, toastError, debounce, modal } from "../ui.js";
import { stackedBar, severitySegments, sevColor, SEV_ORDER, installTooltips } from "../charts.js";
import { getState } from "../state.js";
import { parseRoute, setQuery } from "../router.js";

const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };

/** One line on what each category means. Unknown categories just omit it. */
const CATEGORY_INFO = {
  overly_permissive: "Rules using 'any' in source, destination, service or application.",
  insecure_protocol: "Clear-text or legacy protocols such as Telnet, FTP, HTTP and SNMP.",
  application_risk: "Applications with a high Applipedia risk rating allowed through.",
  management_access: "Remote administration (RDP, SSH, VNC…) reachable across zones.",
  missing_logging: "Allowed traffic that leaves no log, so it cannot be audited.",
  shadowed: "Rules an earlier rule already covers — they never match.",
  redundant: "Exact duplicates of another rule.",
  unused: "Rules with no recorded hits.",
  expired: "Past their expiry date, or not changed in over a year.",
  misconfigured: "Profile, deny-all and compliance-control checks. Includes pass records.",
  disabled: "Rules switched off but still in the rule base.",
  weak_authentication: "Rules relying on weak or no authentication.",
  lateral_movement: "Paths that allow movement between internal segments.",
  unencrypted_traffic: "Traffic permitted without encryption.",
  weak_crypto: "Weak cipher or protocol versions.",
  broad_application_allow: "Broad application groups allowed in one rule.",
  missing_time_restrictions: "Temporary access without a schedule or expiry.",
};

const SEARCH_ICON = ["M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16z", "m21 21-4.35-4.35"];
const PAGE_SIZE = 25;

export async function render(host) {
  const { current } = getState();
  if (!current || current.status !== "succeeded") {
    host.append(empty("No completed analysis selected"));
    return;
  }

  const q = parseRoute().query;
  const filters = {
    risk: q.getAll("risk"),
    issue_type: q.getAll("type"),
    search: q.get("q") || "",
    sort: q.get("sort") || "score",
    direction: q.get("dir") || "desc",
    offset: 0,
    // Board unless asked otherwise. A link that already carries a filter (the
    // dashboards deep-link to "/findings?type=...") means "show me those
    // findings", so it opens the list.
    view: q.get("view") || (q.has("type") || q.has("risk") || q.has("q") ? "list" : "board"),
  };

  const toolbar = el("div", { class: "toolbar" });
  const chipRow = el("div", { class: "chip-row", style: "margin-bottom:.9rem" });
  const results = el("div");
  host.append(toolbar, chipRow, results);

  let facets;
  try {
    facets = await api.facets(current.id);
  } catch (err) {
    toastError(err);
    host.replaceChildren(empty("Could not load findings"));
    return;
  }

  installTooltips();
  buildToolbar();
  buildChips();
  await load();

  function setView(view) {
    if (filters.view === view) return;
    filters.view = view;
    filters.offset = 0;
    buildToolbar();
    load();
  }

  function buildToolbar() {
    clear(toolbar);
    append(toolbar, [
      el("div", { class: "seg", role: "tablist", "aria-label": "Findings view" }, [
        el("button", { type: "button", role: "tab", "aria-pressed": String(filters.view === "board"),
          onclick: () => setView("board") }, "Board"),
        el("button", { type: "button", role: "tab", "aria-pressed": String(filters.view === "list"),
          onclick: () => setView("list") }, "List"),
      ]),
      el("div", { class: "search-wrap" }, [
        svgIcon(SEARCH_ICON),
        el("input", {
          type: "search", placeholder: "Search rule name or description…",
          value: filters.search,
          oninput: debounce((e) => { filters.search = e.target.value; filters.offset = 0; load(); }, 280),
        }),
      ]),
      el("span", { style: "flex:1" }),
      el("a", {
        class: "btn ghost small", href: api.exportUrl(current.id, "csv"), download: "",
      }, "Export CSV"),
      el("a", {
        class: "btn ghost small", href: api.exportUrl(current.id, "json"), download: "",
      }, "Export JSON"),
    ]);
  }

  function buildChips() {
    clear(chipRow);
    // Severity chips, worst first
    for (const level of ["critical", "high", "medium", "low", "info"]) {
      const n = facets.by_risk?.[level];
      if (!n) continue;
      chipRow.append(chip(titleCase(level), n, filters.risk.includes(level), () => {
        toggle(filters.risk, level);
        filters.offset = 0;
        buildChips();
        load();
      }));
    }
    chipRow.append(el("span", { style: "width:.8rem" }));
    // Category chips
    for (const [type, n] of Object.entries(facets.by_type || {}).slice(0, 8)) {
      chipRow.append(chip(titleCase(type), n, filters.issue_type.includes(type), () => {
        toggle(filters.issue_type, type);
        filters.offset = 0;
        buildChips();
        load();
      }));
    }
    if (filters.risk.length || filters.issue_type.length || filters.search) {
      chipRow.append(el("button", {
        class: "chip", style: "border-style:dashed",
        onclick: () => {
          filters.risk = []; filters.issue_type = []; filters.search = ""; filters.offset = 0;
          buildToolbar(); buildChips(); load();
        },
      }, "Clear filters"));
    }
  }

  async function load() {
    setQuery({
      view: filters.view, risk: filters.risk, type: filters.issue_type, q: filters.search,
      sort: filters.view === "list" ? filters.sort : null,
      dir: filters.view === "list" ? filters.direction : null,
    });
    if (filters.view === "board") return loadBoard();
    results.replaceChildren(loading());
    try {
      const data = await api.findings(current.id, {
        ...filters, limit: PAGE_SIZE,
      });
      results.replaceChildren(buildTable(data));
    } catch (err) {
      toastError(err);
      results.replaceChildren(empty("Could not load findings", err.message));
    }
  }

  // ── Board ───────────────────────────────────────────────────────────
  async function loadBoard() {
    // Hold the previous board while refetching, rather than flashing a spinner.
    if (!results.firstChild) results.replaceChildren(loading());
    results.style.opacity = ".55";
    try {
      const data = filters.search ? await api.facets(current.id, { search: filters.search }) : facets;
      results.replaceChildren(buildBoard(data.categories || []));
    } catch (err) {
      toastError(err);
      results.replaceChildren(empty("Could not load findings", err.message));
    } finally {
      results.style.opacity = "";
    }
  }

  /** Categories after the chips: severity chips narrow the counts, category chips the cards. */
  function visibleCategories(categories) {
    return categories
      .filter((c) => !filters.issue_type.length || filters.issue_type.includes(c.type))
      .map((c) => {
        const byRisk = {};
        for (const [level, n] of Object.entries(c.by_risk || {})) {
          if (!filters.risk.length || filters.risk.includes(level)) byRisk[level] = n;
        }
        const total = Object.values(byRisk).reduce((a, b) => a + b, 0);
        const worst = SEV_ORDER.find((level) => byRisk[level]);
        // Pass records are all low; they only count while Low is in view.
        const passes = !filters.risk.length || filters.risk.includes("low") ? c.pass_records : 0;
        return { ...c, byRisk, total, worst, passes };
      })
      .filter((c) => c.total > 0);
  }

  function buildBoard(categories) {
    const cats = visibleCategories(categories);
    if (!cats.length) {
      return panel("Findings", empty("Nothing matches these filters", "Clear a filter or widen the search."));
    }

    const totals = {};
    for (const c of cats) for (const [level, n] of Object.entries(c.byRisk)) totals[level] = (totals[level] || 0) + n;
    const grand = Object.values(totals).reduce((a, b) => a + b, 0);
    const passes = cats.reduce((a, c) => a + c.passes, 0);

    // Lanes exist only for severities this run (and these filters) produced.
    const lanes = SEV_ORDER
      .map((level) => ({ level, cards: cats.filter((c) => c.worst === level).sort((a, b) => b.total - a.total) }))
      .filter((lane) => lane.cards.length);

    return el("div", { class: "board" }, [
      boardSummary(totals, grand, cats.length, passes),
      el("div", { class: "board-lanes", style: `--lanes:${lanes.length}` }, lanes.map(boardLane)),
    ]);
  }

  function boardSummary(totals, grand, categoryCount, passes) {
    const segments = severitySegments(totals, { suffix: " findings" });
    return el("section", { class: "panel board-summary" }, [
      el("div", { class: "board-summary__total" }, [
        el("span", { class: "board-summary__n" }, fmtNumber(grand)),
        el("span", { class: "panel-sub" },
          `finding${grand === 1 ? "" : "s"} across ${categoryCount} categor${categoryCount === 1 ? "y" : "ies"}`),
      ]),
      el("div", { class: "board-summary__mix" }, [
        stackedBar(segments, { height: 12, label: "Findings by severity" }),
        el("div", { class: "board-summary__levels" }, SEV_ORDER.filter((l) => totals[l]).map((level) =>
          el("button", {
            type: "button", class: "board-level",
            "aria-pressed": String(filters.risk.includes(level)),
            title: `Show only ${SEV_LABEL[level].toLowerCase()} findings`,
            onclick: () => { toggle(filters.risk, level); buildChips(); load(); },
          }, [
            el("span", { class: "sev-dot", style: `background:${sevColor(level)}` }),
            el("span", { class: "board-level__label" }, SEV_LABEL[level]),
            el("strong", {}, fmtNumber(totals[level])),
            el("span", { class: "board-level__pct" }, `${Math.round((totals[level] / grand) * 100)}%`),
          ]))),
      ]),
      passes ? el("p", { class: "panel-sub board-summary__note" },
        `${fmtNumber(passes)} of these are pass records — a profile or cleanup rule confirmed in place, not an issue.`) : null,
    ]);
  }

  function boardLane({ level, cards }) {
    const findings = cards.reduce((a, c) => a + c.total, 0);
    return el("section", { class: "board-lane", "aria-label": `Worst severity ${SEV_LABEL[level]}` }, [
      el("header", { class: "board-lane__head" }, [
        sevBadge(level),
        el("span", { class: "panel-sub" },
          `${cards.length} categor${cards.length === 1 ? "y" : "ies"} · ${fmtNumber(findings)} findings`),
      ]),
      ...cards.map(boardCard),
    ]);
  }

  function boardCard(c) {
    const openList = (risk) => {
      filters.issue_type = [c.type];
      if (risk) filters.risk = [risk];
      filters.view = "list";
      filters.offset = 0;
      buildToolbar(); buildChips(); load();
    };
    const levels = SEV_ORDER.filter((l) => c.byRisk[l]);
    return el("article", { class: "board-card" }, [
      el("button", { type: "button", class: "board-card__main", onclick: () => openList(null),
        "aria-label": `${titleCase(c.type)}: ${c.total} findings. Open the list.` }, [
        el("div", { class: "board-card__top" }, [
          el("span", { class: "board-card__title" }, titleCase(c.type)),
          el("span", { class: "board-card__n" }, fmtNumber(c.total)),
        ]),
        CATEGORY_INFO[c.type] ? el("p", { class: "board-card__info" }, CATEGORY_INFO[c.type]) : null,
        stackedBar(severitySegments(c.byRisk, { suffix: " findings" }), { height: 8, label: titleCase(c.type) }),
      ]),
      el("div", { class: "board-card__levels" }, levels.map((level) =>
        el("button", {
          type: "button", class: "board-card__level",
          title: `Open ${SEV_LABEL[level].toLowerCase()} ${titleCase(c.type).toLowerCase()} findings`,
          onclick: () => openList(level),
        }, [
          el("span", { class: "sev-dot", style: `background:${sevColor(level)}` }),
          SEV_LABEL[level],
          el("strong", {}, fmtNumber(c.byRisk[level])),
        ]))),
      el("div", { class: "board-card__foot" }, [
        el("span", {}, `${fmtNumber(c.rules)} rule${c.rules === 1 ? "" : "s"}`),
        c.passes ? el("span", {}, `${fmtNumber(c.passes)} pass record${c.passes === 1 ? "" : "s"}`) : null,
        el("button", { type: "button", class: "linklike", onclick: () => openList(null) }, "View findings →"),
      ]),
    ]);
  }

  function buildTable(data) {
    if (!data.total) {
      return panel("Findings", empty("Nothing matches these filters",
        "Clear a filter or widen the search."));
    }

    const header = (label, key, cls = "") =>
      el("th", {
        class: `sortable ${cls}`,
        onclick: () => {
          filters.direction = filters.sort === key && filters.direction === "desc" ? "asc" : "desc";
          filters.sort = key;
          filters.offset = 0;
          load();
        },
      }, [label, filters.sort === key
        ? el("span", { class: "arrow" }, filters.direction === "desc" ? "▾" : "▴") : null]);

    const table = el("div", { class: "table-wrap" },
      el("table", { class: "data" }, [
        el("thead", {}, el("tr", {}, [
          header("Severity", "risk"),
          header("Rule", "rule"),
          header("Category", "type"),
          header("Score", "score", "num"),
          el("th", {}, "Finding"),
        ])),
        el("tbody", {}, data.items.map((f) =>
          el("tr", { class: "clickable", onclick: () => showDetail(f) }, [
            el("td", {}, sevBadge(f.risk_level)),
            el("td", { class: "rule-name truncate", title: f.rule_name }, f.rule_name),
            el("td", { class: "muted" }, titleCase(f.issue_type)),
            el("td", { class: "num" }, el("strong", {}, f.score)),
            el("td", { class: "truncate", style: "max-width:38ch", title: f.description }, f.description),
          ])
        )),
      ])
    );

    const shown = Math.min(filters.offset + PAGE_SIZE, data.total);
    const pager = el("div", { class: "pager" }, [
      `${fmtNumber(filters.offset + 1)}–${fmtNumber(shown)} of ${fmtNumber(data.total)}`,
      el("button", {
        class: "btn ghost small", disabled: filters.offset === 0,
        onclick: () => { filters.offset = Math.max(0, filters.offset - PAGE_SIZE); load(); },
      }, "Previous"),
      el("button", {
        class: "btn ghost small", disabled: shown >= data.total,
        onclick: () => { filters.offset += PAGE_SIZE; load(); },
      }, "Next"),
    ]);

    return panel("Findings", [table, pager],
      { sub: `${fmtNumber(data.total)} matching` });
  }
}

function chip(label, count, active, onclick) {
  return el("button", { class: "chip", "aria-pressed": String(active), onclick }, [
    label, el("span", { class: "n" }, count),
  ]);
}

function toggle(list, value) {
  const i = list.indexOf(value);
  if (i >= 0) list.splice(i, 1);
  else list.push(value);
}

/** Finding detail: what was found, why it scored, and what to do about it. */
function showDetail(f) {
  modal((box, close) => {
    box.append(el("div", { style: "display:flex;align-items:center;gap:.6rem;margin-bottom:.3rem" }, [
      sevBadge(f.risk_level),
      el("span", { class: "pill" }, titleCase(f.issue_type)),
      el("span", { style: "flex:1" }),
      el("span", { class: "panel-sub" }, `Score ${f.score}`),
    ]));
    box.append(el("h3", {}, f.rule_name));
    box.append(el("p", { style: "margin:.6rem 0 0" }, f.description));

    box.append(el("div", { class: "section-label" }, "Recommendation"));
    box.append(el("p", { style: "margin:0" }, f.recommendation));

    if (f.formula) {
      box.append(el("div", { class: "section-label" }, "How this score was reached"));
      box.append(el("p", { class: "mono", style: "margin:0" }, f.formula));
    }

    const details = Object.entries(f.details || {}).filter(([, v]) =>
      v != null && v !== "" && !(Array.isArray(v) && !v.length));
    if (details.length) {
      box.append(el("div", { class: "section-label" }, "Details"));
      box.append(el("dl", { class: "kv" }, details.flatMap(([k, v]) => [
        el("dt", {}, titleCase(k)),
        el("dd", { class: "mono" }, Array.isArray(v) ? v.join(", ") : String(v)),
      ])));
    }

    box.append(el("div", { class: "actions" },
      el("button", { class: "btn primary", onclick: close }, "Close")));
  });
}
