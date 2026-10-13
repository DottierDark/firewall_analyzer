// History — every analysis, and the place you switch which one the workspace
// is pointed at. Live-polls while any run is still in flight.

import { api } from "../api.js";
import { el, panel, empty, loading, fmtDate, fmtNumber, titleCase, relativeTime,
         toast, toastError, confirmDialog, statusPill, sevBadge } from "../ui.js";
import { getState, selectAnalysis, refreshAnalyses } from "../state.js";
import { navigate } from "../router.js";

let poller = null;

export function teardown() {
  clearInterval(poller);
  poller = null;
}

export async function render(host) {
  host.append(loading("Loading analyses…"));
  await draw(host);

  // Poll only while something is actually running.
  teardown();
  poller = setInterval(async () => {
    const items = getState().analyses;
    if (!items.some((a) => a.status === "queued" || a.status === "running")) return;
    await draw(host);
  }, 2500);
}

async function draw(host) {
  let items;
  try {
    items = await refreshAnalyses();
  } catch (err) {
    toastError(err);
    host.replaceChildren(empty("Could not load analyses"));
    return;
  }

  if (!items.length) {
    host.replaceChildren(panel("Analyses", empty(
      "No analyses yet",
      "Upload a firewall rule export to run the first one."
    ), {
      actions: el("button", { class: "btn primary small", onclick: () => navigate("/new") },
        "Run New Analysis"),
    }));
    return;
  }

  const { current } = getState();
  const table = el("div", { class: "table-wrap" },
    el("table", { class: "data" }, [
      el("thead", {}, el("tr", {}, [
        el("th", {}, "Analysis"),
        el("th", {}, "Project"),
        el("th", {}, "Vendor"),
        el("th", {}, "Status"),
        el("th", { class: "num" }, "Findings"),
        el("th", { class: "num" }, "Critical"),
        el("th", {}, "Run"),
        el("th", {}, ""),
      ])),
      el("tbody", {}, items.map((a) => row(a, current))),
    ])
  );

  host.replaceChildren(panel("Analyses", table, {
    sub: `${fmtNumber(items.length)} total`,
    actions: el("button", { class: "btn primary small", onclick: () => navigate("/new") },
      "Run New Analysis"),
  }));
}

function row(a, current) {
  const isCurrent = current && current.id === a.id;
  const summary = a.summary || {};

  return el("tr", {
    class: "clickable",
    style: isCurrent ? "background:var(--surface-soft)" : null,
    onclick: async () => {
      if (a.status !== "succeeded") return;
      await selectAnalysis(a.id);
      navigate("/overview");
    },
  }, [
    el("td", {}, [
      el("div", { class: "rule-name" }, a.label),
      el("div", { class: "panel-sub truncate", style: "max-width:20ch" }, a.filename),
    ]),
    el("td", { class: "muted" }, a.project_name),
    el("td", { class: "muted" }, titleCase(a.vendor || "—")),
    el("td", {}, [
      statusPill(a.status),
      a.status === "running" && a.progress
        ? el("div", { class: "panel-sub", style: "margin-top:.2rem" }, a.progress) : null,
      a.status === "failed" && a.error
        ? el("div", { class: "panel-sub truncate", style: "max-width:24ch", title: a.error }, a.error) : null,
    ]),
    el("td", { class: "num" }, a.status === "succeeded" ? fmtNumber(summary.total_issues) : "—"),
    el("td", { class: "num" }, a.status === "succeeded" && summary.critical_issues
      ? sevBadge("critical") : el("span", { class: "muted" }, "—")),
    el("td", { class: "muted", title: fmtDate(a.created_at) }, relativeTime(a.created_at)),
    el("td", {}, el("div", { style: "display:flex;gap:.3rem;justify-content:flex-end" }, [
      isCurrent ? el("span", { class: "pill state-succeeded" }, "selected") : null,
      el("button", {
        class: "btn ghost small",
        onclick: async (e) => {
          e.stopPropagation();
          const ok = await confirmDialog("Delete this analysis?",
            `"${a.label}" and its findings will be removed. This cannot be undone.`,
            { danger: true, confirmLabel: "Delete" });
          if (!ok) return;
          try {
            await api.del(`/analyses/${a.id}`);
            if (current && current.id === a.id) await selectAnalysis(null);
            toast("Analysis deleted");
            await refreshAnalyses();
            navigate("/analyses");
          } catch (err) { toastError(err); }
        },
      }, "Delete"),
    ])),
  ]);
}
