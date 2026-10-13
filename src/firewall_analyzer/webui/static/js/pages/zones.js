// Zone Analysis — the zone-to-zone traffic matrix the analyzer builds by
// resolving rule addresses against the configured subnets.

import { el, panel, empty, fmtNumber } from "../ui.js";
import { getState } from "../state.js";

export async function render(host) {
  const { current } = getState();
  if (!current || current.status !== "succeeded") {
    host.append(empty("No completed analysis selected"));
    return;
  }

  const zones = current.zone_summary || {};
  const pairs = Object.entries(zones);
  if (!pairs.length) {
    host.append(panel("Zone Analysis", empty(
      "No zone pairs resolved",
      "Rule addresses did not match any configured zone subnet. Adjust zone_config.json to describe this network."
    )));
    return;
  }

  // Pairs arrive as "src → dst"; split them back out into a matrix.
  const sources = [...new Set(pairs.map(([k]) => k.split("→")[0].trim()))].sort();
  const dests = [...new Set(pairs.map(([k]) => k.split("→")[1].trim()))].sort();
  const lookup = new Map(pairs.map(([k, v]) => [k.replace(/\s*→\s*/, "→"), v]));
  const peak = Math.max(...pairs.map(([, v]) => v.total_rules), 1);

  const table = el("div", { class: "table-wrap" },
    el("table", { class: "data" }, [
      el("thead", {}, el("tr", {}, [
        el("th", {}, "From \\ To"),
        ...dests.map((d) => el("th", { class: "num" }, d)),
      ])),
      el("tbody", {}, sources.map((src) =>
        el("tr", {}, [
          el("td", { class: "rule-name" }, src),
          ...dests.map((dst) => {
            const cell = lookup.get(`${src}→${dst}`);
            if (!cell) return el("td", { class: "num muted" }, "—");
            // One hue, opacity carries magnitude — a sequential job.
            const alpha = 0.12 + (cell.total_rules / peak) * 0.55;
            return el("td", {
              class: "num",
              style: `background:rgba(208,74,2,${alpha.toFixed(2)});font-weight:650`,
              title: `${cell.allow_rules} allow · ${cell.deny_rules} deny`,
            }, fmtNumber(cell.total_rules));
          }),
        ])
      )),
    ])
  );

  host.append(panel("Zone Traffic Matrix", table, {
    sub: `${pairs.length} zone pairs · cell shade is rule count`,
  }));

  const rows = pairs
    .sort((a, b) => b[1].total_rules - a[1].total_rules)
    .map(([pair, v]) => el("tr", {}, [
      el("td", { class: "rule-name" }, pair),
      el("td", { class: "num" }, fmtNumber(v.total_rules)),
      el("td", { class: "num" }, el("span", { class: "pill allow" }, v.allow_rules)),
      el("td", { class: "num" }, el("span", { class: "pill deny" }, v.deny_rules)),
    ]));

  host.append(el("div", { style: "height:1rem" }));
  host.append(panel("Zone Pairs", el("div", { class: "table-wrap" },
    el("table", { class: "data" }, [
      el("thead", {}, el("tr", {}, [
        el("th", {}, "Pair"), el("th", { class: "num" }, "Rules"),
        el("th", { class: "num" }, "Allow"), el("th", { class: "num" }, "Deny"),
      ])),
      el("tbody", {}, rows),
    ])
  )));
}
