// Full Report — compose, preview, then download.
//
// Previously this page pointed an iframe at the engine's generated HTML, which
// the server sent with Content-Disposition: attachment — so it downloaded
// instead of displaying and the frame stayed blank. It now renders the report
// in the page from the analysis data, with each section switchable, and only
// writes a file when the user asks for one.

import { api } from "../api.js";
import { el, clear, empty, loading, panel, toast, toastError, fmtNumber, svgIcon } from "../ui.js";
import { getState } from "../state.js";
import { getUser } from "../session.js";
import {
  SECTIONS, DEFAULT_SELECTION, availability, buildReport, toStandaloneHtml,
} from "../report-builder.js";

const STORAGE_KEY = "fwa-report-sections";
const DOWNLOAD_ICON = ["M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4", "M7 10l5 5 5-5", "M12 15V3"];
const PRINT_ICON = ["M6 9V2h12v7", "M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2", "M6 14h12v8H6z"];

export async function render(host) {
  const { current } = getState();
  if (!current || current.status !== "succeeded") {
    host.append(empty("No completed analysis selected",
      "Pick a finished analysis to compose a report from it."));
    return;
  }

  host.append(loading("Loading analysis data…"));

  let data;
  try {
    // Pull enough to compose every section. Limits are generous but bounded —
    // a report is a document, not a database dump.
    const [facets, findings, rules] = await Promise.all([
      api.facets(current.id),
      api.findings(current.id, { limit: 500, sort: "score", direction: "desc" }),
      api.rules(current.id, { limit: 500, sort: "risk", direction: "desc" }),
    ]);
    data = {
      analysis: current,
      facets,
      findings: findings.items,
      rules: rules.items,
      totals: { findings: findings.total, rules: rules.total },
    };
  } catch (err) {
    toastError(err);
    host.replaceChildren(empty("Could not load the report data", err.message));
    return;
  }

  const can = availability(data);
  let selected = restoreSelection(can);

  const picker = el("aside", { class: "report-picker" });
  const preview = el("div", { class: "report-preview" });
  host.replaceChildren(el("div", { class: "report-layout" }, [picker, preview]));

  paintPicker();
  paintPreview();

  function paintPicker() {
    clear(picker);

    picker.append(el("div", { class: "report-picker__head" }, [
      el("div", { class: "panel-title" }, "Report sections"),
      el("p", { class: "panel-sub" },
        "Tick what belongs in this deliverable. The preview updates as you go — what you see is exactly what downloads."),
    ]));

    const list = el("div", { class: "report-sections" });
    for (const section of SECTIONS) {
      const available = can[section.id];
      const isOn = section.always || selected.includes(section.id);

      const box = el("input", {
        type: "checkbox",
        id: `sec-${section.id}`,
        checked: isOn,
        disabled: section.always || !available,
        onchange: (e) => {
          if (e.target.checked) selected = [...new Set([...selected, section.id])];
          else selected = selected.filter((id) => id !== section.id);
          persist(selected);
          paintPreview();
          updateCount();
        },
      });

      list.append(el("label", {
        class: `report-section${!available ? " is-unavailable" : ""}${section.always ? " is-locked" : ""}`,
        for: `sec-${section.id}`,
      }, [
        box,
        el("span", { class: "report-section__text" }, [
          el("span", { class: "report-section__name" }, [
            section.label,
            section.always ? el("span", { class: "report-section__lock" }, "always") : null,
          ]),
          el("span", { class: "report-section__hint" },
            available ? section.hint : "No data for this analysis"),
        ]),
      ]));
    }
    picker.append(list);

    const count = el("div", { class: "report-picker__count" });
    picker.append(count);
    updateCount();

    picker.append(el("div", { class: "report-picker__actions" }, [
      el("button", {
        class: "btn primary", onclick: (e) => download(e.currentTarget),
      }, [svgIcon(DOWNLOAD_ICON, { size: 14 }), "Download HTML"]),
      el("button", {
        class: "btn ghost", onclick: () => printReport(),
      }, [svgIcon(PRINT_ICON, { size: 14 }), "Print / PDF"]),
    ]));

    picker.append(el("div", { class: "report-picker__foot" }, [
      el("button", {
        class: "linklike",
        onclick: () => { selected = [...DEFAULT_SELECTION]; persist(selected); paintPicker(); paintPreview(); },
      }, "Reset to default"),
      el("span", {}, " · "),
      el("button", {
        class: "linklike",
        onclick: () => {
          selected = SECTIONS.filter((s) => can[s.id]).map((s) => s.id);
          persist(selected); paintPicker(); paintPreview();
        },
      }, "Select all"),
    ]));

    // The engine's own report is raw, unbranded and 3 MB; it is kept for
    // continuity with the CLI but is not a client deliverable, so only an
    // administrator is offered it.
    if (getUser()?.is_admin) picker.append(el("details", { class: "report-original" }, [
      el("summary", {}, "Original analyzer report"),
      el("p", { class: "panel-sub" },
        "The engine's own generated report, unchanged. Kept for continuity with the command-line output."),
      el("a", {
        class: "btn ghost small",
        href: api.reportUrl(current.id), target: "_blank", rel: "noopener",
      }, "Open in new tab"),
      el("a", {
        class: "btn ghost small", style: "margin-top:.4rem",
        href: `${api.reportUrl(current.id)}?download=1`,
      }, "Download original"),
    ]));

    function updateCount() {
      const active = SECTIONS.filter((s) => s.always || selected.includes(s.id)).length;
      clear(count);
      count.append(`${active} of ${SECTIONS.length} sections included`);
    }
  }

  function paintPreview() {
    clear(preview);
    preview.append(el("div", { class: "report-preview__bar" }, [
      el("span", { class: "panel-sub" }, "Preview"),
      el("span", { style: "flex:1" }),
      el("span", { class: "panel-sub" },
        `${fmtNumber(data.totals.findings)} findings · ${fmtNumber(data.totals.rules)} rules available`),
    ]));
    preview.append(el("div", { class: "report-preview__page", id: "report-page" },
      buildReport(data, selected)));
  }

  async function download(button) {
    const original = button.textContent;
    button.disabled = true;
    clear(button);
    button.append(el("span", { class: "spinner" }), document.createTextNode(" Building…"));
    try {
      const html = await toStandaloneHtml(data, selected);
      const blob = new Blob([html], { type: "text/html;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const link = el("a", {
        href: url,
        download: `${safeName(current.label)}_assessment.html`,
      });
      document.body.append(link);
      link.click();
      link.remove();
      // Revoke on the next tick — revoking synchronously can cancel the save
      // in some browsers before the download has started.
      setTimeout(() => URL.revokeObjectURL(url), 2000);
      toast("Report downloaded");
    } catch (err) {
      toastError(err);
    } finally {
      button.disabled = false;
      clear(button);
      button.append(svgIcon(DOWNLOAD_ICON, { size: 14 }), document.createTextNode("Download HTML"));
    }
  }

  function printReport() {
    // Print the composed report on its own, not the whole app shell: a class on
    // <html> hides everything except the preview page (see the print rules in
    // app.css), so Print-to-PDF produces the deliverable rather than a
    // screenshot of the tool.
    document.documentElement.classList.add("printing-report");
    const cleanup = () => {
      document.documentElement.classList.remove("printing-report");
      window.removeEventListener("afterprint", cleanup);
    };
    window.addEventListener("afterprint", cleanup);
    window.print();
    setTimeout(cleanup, 1000);
  }
}

function safeName(value) {
  return String(value || "report").replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 60);
}

function persist(selected) {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(selected)); } catch { /* private mode */ }
}

function restoreSelection(can) {
  let saved = null;
  try { saved = JSON.parse(localStorage.getItem(STORAGE_KEY) || "null"); } catch { saved = null; }
  const base = Array.isArray(saved) && saved.length ? saved : DEFAULT_SELECTION;
  // Drop anything this particular analysis has no data for, so a remembered
  // choice never produces an empty section.
  return base.filter((id) => can[id]);
}
