// External Communications — allow rules that touch a zone the user nominates
// as external. The zone list is the user's call, so this asks for it rather
// than guessing which names mean "outside".

import { api } from "../api.js";
import { el, clear, panel, empty, loading, fmtNumber, tagList, toastError } from "../ui.js";
import { getState } from "../state.js";

const KEY = "fwa-external-zones";

export async function render(host) {
  const { current } = getState();
  if (!current || current.status !== "succeeded") {
    host.append(empty("No completed analysis selected"));
    return;
  }

  let zones = [];
  try { zones = JSON.parse(localStorage.getItem(KEY) || "[]"); } catch { zones = []; }

  const controls = el("div", { class: "panel", style: "margin-bottom:1rem" });
  const results = el("div");
  host.append(controls, results);

  let rules = [];
  host.append(loading());
  try {
    const data = await api.rules(current.id, { limit: 500 });
    rules = data.items;
  } catch (err) {
    toastError(err);
    host.replaceChildren(empty("Could not load rules"));
    return;
  }
  host.replaceChildren(controls, results);

  paint();

  function paint() {
    clear(controls);
    const input = el("input", {
      type: "text", placeholder: "e.g. wan, untrust, internet",
      style: "font:inherit;font-size:.86rem;padding:.47rem .6rem;border:1px solid var(--line);border-radius:7px;background:var(--surface);color:var(--text);min-width:16rem",
      onkeydown: (e) => { if (e.key === "Enter") add(input.value); },
    });

    controls.append(
      el("div", { class: "panel-head" }, el("span", { class: "panel-title" }, "External zones")),
      el("p", { class: "panel-sub", style: "margin:-.5rem 0 .8rem" },
        "Name the zones that face outside your perimeter. Enabled ALLOW rules touching them are listed below; rules using 'any' are flagged separately as potentially external."),
      el("div", { class: "toolbar", style: "margin:0" }, [
        input,
        el("button", { class: "btn", onclick: () => add(input.value) }, "Add zone"),
        el("span", { style: "flex:1" }),
        el("div", { class: "chip-row" }, zones.map((z) =>
          el("button", {
            class: "chip", "aria-pressed": "true",
            title: "Remove", onclick: () => remove(z),
          }, [z, el("span", { class: "n" }, "×")])
        )),
      ])
    );
    renderResults();
  }

  function add(value) {
    const z = String(value || "").trim().toLowerCase();
    if (!z || zones.includes(z)) return;
    zones.push(z);
    localStorage.setItem(KEY, JSON.stringify(zones));
    paint();
  }

  function remove(z) {
    zones = zones.filter((x) => x !== z);
    localStorage.setItem(KEY, JSON.stringify(zones));
    paint();
  }

  function renderResults() {
    clear(results);
    if (!zones.length) {
      results.append(panel("Results", empty("Add at least one external zone to begin")));
      return;
    }

    const external = [];
    const potential = [];
    for (const r of rules) {
      if (r.disabled || r.action !== "allow") continue;
      const all = [...r.src_zones, ...r.dst_zones].map((z) => String(z).toLowerCase());
      if (all.some((z) => z === "any")) potential.push(r);
      else if (all.some((z) => zones.includes(z))) external.push(r);
    }

    results.append(el("div", { class: "kpi-grid", style: "grid-template-columns:repeat(2,1fr)" }, [
      el("div", { class: "kpi" }, [
        el("span", { class: "kpi-label" }, "External allow rules"),
        el("div", { class: "kpi-value sev-critical" }, fmtNumber(external.length)),
        el("span", { class: "kpi-foot" }, `matching ${zones.join(", ")}`),
      ]),
      el("div", { class: "kpi" }, [
        el("span", { class: "kpi-label" }, "Potentially external"),
        el("div", { class: "kpi-value" }, fmtNumber(potential.length)),
        el("span", { class: "kpi-foot" }, "zone set to 'any'"),
      ]),
    ]));

    results.append(table("External communication rules", external));
    results.append(el("div", { style: "height:1rem" }));
    results.append(table("Potentially external (zone = any)", potential));
  }

  function table(title, list) {
    if (!list.length) return panel(title, empty("None found"));
    return panel(title, el("div", { class: "table-wrap" },
      el("table", { class: "data" }, [
        el("thead", {}, el("tr", {}, [
          el("th", {}, "Rule"), el("th", {}, "Source zone"), el("th", {}, "Dest zone"),
          el("th", {}, "Service"), el("th", { class: "num" }, "Risk"),
        ])),
        el("tbody", {}, list.slice(0, 100).map((r) =>
          el("tr", {}, [
            el("td", { class: "rule-name" }, r.name),
            el("td", {}, tagList(r.src_zones, { max: 2 })),
            el("td", {}, tagList(r.dst_zones, { max: 2 })),
            el("td", {}, tagList(r.services, { max: 2 })),
            el("td", { class: "num" }, r.risk_score ?? "—"),
          ])
        )),
      ])
    ), { sub: `${fmtNumber(list.length)} rules` });
  }
}
