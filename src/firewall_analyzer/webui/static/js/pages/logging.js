// Logging & Audit — rules with logging disabled, worst first. An ALLOW rule
// with no logging is unauditable traffic, which is why it scores critical.

import { api } from "../api.js";
import { el, panel, empty, loading, fmtNumber, sevBadge, toastError } from "../ui.js";
import { getState } from "../state.js";
import { severityDonut, severityLegend } from "../charts.js";

export async function render(host) {
  const { current } = getState();
  if (!current || current.status !== "succeeded") {
    host.append(empty("No completed analysis selected"));
    return;
  }

  host.append(loading());
  try {
    const data = await api.findings(current.id, {
      issue_type: ["missing_logging"], limit: 500, sort: "score",
    });
    host.replaceChildren(build(data));
  } catch (err) {
    toastError(err);
    host.replaceChildren(empty("Could not load logging audit"));
  }
}

function build(data) {
  const frag = document.createDocumentFragment();

  if (!data.total) {
    frag.append(panel("Logging & Audit", empty(
      "Every analyzed rule has logging enabled",
      "Nothing to remediate here."
    )));
    return frag;
  }

  const byRisk = data.items.reduce((acc, f) => {
    acc[f.risk_level] = (acc[f.risk_level] || 0) + 1;
    return acc;
  }, {});

  frag.append(el("div", { class: "grid dash-2" }, [
    panel("Rules without logging", el("div", { class: "table-wrap" },
      el("table", { class: "data" }, [
        el("thead", {}, el("tr", {}, [
          el("th", {}, "Severity"), el("th", {}, "Rule"),
          el("th", {}, "Action"), el("th", {}, "Impact"),
        ])),
        el("tbody", {}, data.items.slice(0, 100).map((f) =>
          el("tr", {}, [
            el("td", {}, sevBadge(f.risk_level)),
            el("td", { class: "rule-name" }, f.rule_name),
            el("td", {}, el("span", { class: `pill ${(f.details?.action || "").toLowerCase()}` },
              f.details?.action || "—")),
            el("td", { class: "muted" }, f.description),
          ])
        )),
      ])
    ), { sub: `${fmtNumber(data.total)} rules` }),

    panel("Severity split", el("div", {
      style: "display:flex;flex-direction:column;align-items:center;gap:.7rem",
    }, [
      severityDonut(byRisk, { size: 160, stroke: 22 }),
      severityLegend(byRisk),
    ])),
  ]));

  return frag;
}
