// Rule Explorer — every rule in the file, including the disabled and
// filtered-out ones the analyzers never scored, so "why isn't this flagged?"
// has an answer on screen.

import { api } from "../api.js";
import {
  el, append, clear, panel, empty, loading, fmtNumber, titleCase, sevBadge, tagList,
  svgIcon, toastError, debounce, modal
} from "../ui.js";
import { getState } from "../state.js";
import { parseRoute, setQuery } from "../router.js";

const SEARCH_ICON = ["M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16z", "m21 21-4.35-4.35"];
const PAGE_SIZE = 25;

export async function render(host) {
  const { current } = getState();
  if (!current || current.status !== "succeeded") {
    host.append(empty("No completed analysis selected"));
    return;
  }

  const DEFAULT_SORT = { sort: "seq", direction: "asc" };

  const q = parseRoute().query;
  const filters = {
    search: q.get("q") || "",
    action: q.get("action") || "",
    with_findings_only: q.get("flagged") === "1",
    sort: q.get("sort") || DEFAULT_SORT.sort,
    direction: q.get("dir") || DEFAULT_SORT.direction,
    offset: 0,
  };

  const toolbar = el("div", { class: "toolbar" });
  const results = el("div");
  host.append(toolbar, results);

  buildToolbar();
  await load();

  // Deep link from the dashboard: /rules?rule=<id> opens that rule directly.
  const deepLink = q.get("rule");
  if (deepLink) openRule(current.id, deepLink);

  function buildToolbar() {
    clear(toolbar);
    // append() from ui.js, not the DOM's: the native one writes a null
    // argument (the hidden reset chip) as the literal text "null".
    append(toolbar, [
      el("div", { class: "search-wrap" }, [
        svgIcon(SEARCH_ICON),
        el("input", {
          type: "search", placeholder: "Search name, ID or address…", value: filters.search,
          oninput: debounce((e) => { filters.search = e.target.value; filters.offset = 0; load(); }, 280),
        }),
      ]),
      el("select", {
        onchange: (e) => { filters.action = e.target.value; filters.offset = 0; load(); },
        style: "font:inherit;font-size:.84rem;padding:.44rem .6rem;border:1px solid var(--line);border-radius:7px;background:var(--surface);color:var(--text)",
      }, [
        el("option", { value: "" }, "All actions"),
        el("option", { value: "allow", selected: filters.action === "allow" }, "Allow only"),
        el("option", { value: "deny", selected: filters.action === "deny" }, "Deny only"),
      ]),
      el("button", {
        class: "chip", "aria-pressed": String(filters.with_findings_only),
        onclick: () => {
          filters.with_findings_only = !filters.with_findings_only;
          filters.offset = 0; buildToolbar(); load();
        },
      }, "With findings only"),
      (filters.sort !== DEFAULT_SORT.sort || filters.direction !== DEFAULT_SORT.direction)
        ? el("button", {
          class: "chip", style: "border-style:dashed",
          onclick: () => {
            filters.sort = DEFAULT_SORT.sort;
            filters.direction = DEFAULT_SORT.direction;
            filters.offset = 0;
            buildToolbar(); load();
          },
        }, "Reset to rule order")
        : null,
    ]);
  }

  async function load() {
    setQuery({
      q: filters.search, action: filters.action,
      flagged: filters.with_findings_only ? "1" : "", sort: filters.sort, dir: filters.direction,
    });
    results.replaceChildren(loading());
    try {
      const data = await api.rules(current.id, { ...filters, limit: PAGE_SIZE });
      results.replaceChildren(buildTable(data));
    } catch (err) {
      toastError(err);
      results.replaceChildren(empty("Could not load rules", err.message));
    }
  }

  function buildTable(data) {
    if (!data.total) return panel("Rules", empty("No rules match these filters"));

    const header = (label, key, cls = "") => {
      const active = filters.sort === key;
      return el("th", {
        class: `sortable ${cls}${active ? " sorted" : ""}`,
        "aria-sort": active ? (filters.direction === "desc" ? "descending" : "ascending") : "none",
        title: `Sort by ${label}`,
        onclick: () => {
          // Re-clicking the active column flips it; a new column starts in
          // the direction that column is most useful in — position ascending
          // (1, 2, 3…), everything else worst-first.
          if (active) {
            filters.direction = filters.direction === "desc" ? "asc" : "desc";
          } else {
            filters.sort = key;
            filters.direction = key === "seq" || key === "name" ? "asc" : "desc";
          }
          filters.offset = 0;
          load();
        },
      }, [
        label,
        el("span", { class: "arrow" },
          active ? (filters.direction === "desc" ? "▾" : "▴") : "⇅"),
      ]);
    };

    const table = el("div", { class: "table-wrap" },
      el("table", { class: "data" }, [
        el("thead", {}, el("tr", {}, [
          header("#", "seq", "num"),
          header("Rule", "name"),
          header("Action", "action"),
          el("th", {}, "Source"),
          el("th", {}, "Destination"),
          el("th", {}, "Service"),
          header("Risk", "risk", "num"),
          header("Findings", "findings", "num"),
        ])),
        el("tbody", {}, data.items.map((r) =>
          el("tr", {
            class: `clickable${r.disabled ? " is-disabled" : ""}`,
            onclick: () => openRule(current.id, r.rule_id),
          }, [
            el("td", { class: "num muted" }, r.seq),
            el("td", {}, [
              el("div", { class: "rule-name truncate", style: "max-width:20ch", title: r.name }, r.name),
              r.disabled ? el("span", { class: "pill" }, "disabled") : null,
            ]),
            el("td", {}, el("span", { class: `pill ${r.action}` }, r.action)),
            el("td", {}, tagList(r.src_addresses, { max: 2 })),
            el("td", {}, tagList(r.dst_addresses, { max: 2 })),
            el("td", {}, tagList(r.services, { max: 2 })),
            el("td", { class: "num" }, r.risk_score != null
              ? el("strong", {}, r.risk_score)
              : el("span", { class: "muted" }, "—")),
            el("td", { class: "num muted" }, r.finding_count ?? "—"),
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

    return panel("Rules", [table, pager], { sub: `${fmtNumber(data.total)} rules` });
  }
}

async function openRule(analysisId, ruleId) {
  let rule;
  try {
    rule = await api.rule(analysisId, ruleId);
  } catch (err) {
    toastError(err);
    return;
  }

  modal((box, close) => {
    box.append(el("div", { style: "display:flex;align-items:center;gap:.5rem;margin-bottom:.3rem" }, [
      el("span", { class: `pill ${rule.action}` }, rule.action),
      rule.disabled ? el("span", { class: "pill" }, "disabled") : null,
      el("span", { style: "flex:1" }),
      el("span", { class: "panel-sub" }, `Risk score ${rule.risk_score}`),
    ]));
    box.append(el("h3", {}, rule.name));
    box.append(el("p", { class: "modal-sub" }, `Rule ID ${rule.rule_id} · position #${rule.seq}`));

    box.append(el("div", { class: "section-label" }, "Match criteria"));
    box.append(el("dl", { class: "kv" }, [
      el("dt", {}, "Source zones"), el("dd", {}, tagList(rule.src_zones, { max: 8 })),
      el("dt", {}, "Source"), el("dd", {}, tagList(rule.src_addresses, { max: 8 })),
      el("dt", {}, "Destination zones"), el("dd", {}, tagList(rule.dst_zones, { max: 8 })),
      el("dt", {}, "Destination"), el("dd", {}, tagList(rule.dst_addresses, { max: 8 })),
      el("dt", {}, "Services"), el("dd", {}, tagList(rule.services, { max: 8 })),
      el("dt", {}, "Applications"), el("dd", {}, tagList(rule.applications, { max: 8 })),
      el("dt", {}, "Logging"), el("dd", {}, rule.logging || el("span", { class: "muted" }, "not set")),
      el("dt", {}, "Usage"), el("dd", {}, rule.rule_usage || el("span", { class: "muted" }, "—")),
    ]));

    box.append(el("div", { class: "section-label" },
      `Findings (${rule.findings.length})`));
    if (!rule.findings.length) {
      box.append(el("p", { class: "muted", style: "margin:0" },
        rule.disabled
          ? "Disabled rules are excluded from analysis."
          : "No findings were raised against this rule."));
    } else {
      box.append(el("div", { class: "table-wrap" },
        el("table", { class: "data" }, [
          el("thead", {}, el("tr", {}, [
            el("th", {}, "Severity"), el("th", {}, "Category"),
            el("th", { class: "num" }, "Score"), el("th", {}, "Description"),
          ])),
          el("tbody", {}, rule.findings.map((f) =>
            el("tr", {}, [
              el("td", {}, sevBadge(f.risk_level)),
              el("td", { class: "muted" }, titleCase(f.issue_type)),
              el("td", { class: "num" }, f.score),
              el("td", {}, f.description),
            ])
          )),
        ])
      ));
    }

    box.append(el("div", { class: "actions" },
      el("button", { class: "btn primary", onclick: close }, "Close")));
  });
}
