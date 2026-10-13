// "Run New Analysis" — the wizard that replaces the command line.
//
// Vendor is chosen FIRST, before any file is picked — not guessed from headers
// after the fact. Two reasons:
//
//  1. The analyzer's own header auto-detection misidentifies a FortiGate export
//     as Cisco ASA (its Cisco indicator list is matched with any() rather than
//     all(), and is tested first), which silently reads the wrong columns and
//     skips disabled rules. Asking upfront sidesteps that bug entirely.
//  2. Once the export is known, the upload step can validate the real required
//     columns for that vendor (from field_mapping_schema.json, via /api/meta)
//     and tell the user immediately if the file doesn't match — rather than
//     running the analysis first and having them discover it in the results.

import { api } from "../api.js";
import { el, clear, panel, svgIcon, toast, toastError, fmtNumber } from "../ui.js";
import { navigate } from "../router.js";
import { loadMeta, selectAnalysis, refreshAnalyses } from "../state.js";

const UPLOAD_ICON = ["M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4", "M17 8l-5-5-5 5", "M12 3v12"];
const CHECK_ICON = ["M20 6 9 17l-5-5"];
const CROSS_ICON = ["M18 6 6 18", "M6 6l12 12"];
const ALERT_ICON = ["M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"];
// A literal brick wall — stands in for vendors with no logo file (Generic/
// Other) and as the fallback if a logo image ever fails to load.
const WALL_ICON = [
  "M5 4h14a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1z",
  "M4 9h16", "M4 14h16",
  "M12 4v5", "M8 9v5", "M16 9v5", "M12 14v6",
];
// Compliance frameworks come from the backend registry via /api/meta
// (analysis/frameworks.py), so a framework added there appears here with no
// frontend change. Several can be chosen for one run; each gets its own tab on
// the Compliance page. Planned ones can be chosen too - the run records the
// request and the tab says it is not available yet.

// null   = not chosen yet
// ""     = explicit "not sure, try auto-detect"
// value  = a real VendorType
const state = {
  frameworks: [],          // registry keys, in the order chosen
  frameworksDone: false,   // step 1 confirmed
  vendor: null,
  file: null,
  headers: [],
  fieldCheck: null,
  allRequiredFound: null,
  project: "Default Project",
  label: "",
};

export async function render(host) {
  const meta = await loadMeta();
  const FRAMEWORKS = meta.frameworks || [];
  state.frameworks = [];
  state.frameworksDone = false;
  state.vendor = null;
  state.file = null;
  state.headers = [];
  state.fieldCheck = null;
  state.allRequiredFound = null;

  const stepper = el("div", { class: "stepper" });
  const frameworkPanel = el("div");
  const solutionPanel = el("div");
  const uploadPanel = el("div");
  const detectedPanel = el("div");

  host.append(
    stepper,
    frameworkPanel,
    solutionPanel,
    el("div", { class: "grid cols-2" }, [uploadPanel, detectedPanel])
  );

  paint();

  function chosenVendor() {
    // "" (auto-detect) is a valid, deliberate choice — not "unset".
    return state.vendor === null ? null : state.vendor;
  }

  function paint() {
    renderStepper(stepper, state);
    renderFrameworkStep();
    renderSolutionStep();
    renderUploadStep();
    renderDetectedStep();
  }
  // ── Step 1: choose the frameworks ────────────────────────────────────
  function renderFrameworkStep() {
    clear(frameworkPanel);
    const chosen = state.frameworks.map((key) => FRAMEWORKS.find((f) => f.key === key)).filter(Boolean);

    if (state.frameworksDone) {
      // Collapse to a summary bar, same pattern as the solution step.
      frameworkPanel.append(el("div", { class: "panel", style: "margin-bottom:1rem;padding:.7rem 1rem" },
        el("div", { style: "display:flex;align-items:center;gap:.6rem;flex-wrap:wrap" }, [
          el("span", { class: "eyebrow" }, chosen.length === 1 ? "Framework" : "Frameworks"),
          ...chosen.map((f) => el("span", { class: "fw-badge", title: f.name }, f.short)),
          el("span", { class: "panel-sub" }, chosen.map((f) => f.name).join(" · ")),
          el("span", { style: "flex:1" }),
          el("button", { class: "btn ghost small", onclick: () => resetFramework() }, "Change"),
        ])
      ));
      return;
    }

    const count = state.frameworks.length;
    frameworkPanel.append(panel("1 · Choose the frameworks to assess against", [
      el("p", { class: "panel-sub", style: "margin:-.3rem 0 .9rem" },
        "Select one or more. Each framework is assessed separately and gets its own tab on the Compliance page. " +
        "This cannot be inferred from the export, so it is asked first."),
      el("div", { class: "grid cols-3" }, FRAMEWORKS.map((f) => frameworkCard(f))),
      el("div", { style: "display:flex;align-items:center;gap:.8rem;margin-top:.9rem" }, [
        el("button", {
          class: "btn primary small", disabled: !count,
          onclick: () => { state.frameworksDone = true; paint(); },
        }, count ? `Continue with ${count} framework${count === 1 ? "" : "s"}` : "Select at least one framework"),
        count && chosen.some((f) => !f.implemented)
          ? el("span", { class: "panel-sub" },
              "Frameworks marked “not yet available” are recorded on the run but not assessed.")
          : null,
      ]),
    ]));
  }

  function frameworkCard(f) {
    const selected = state.frameworks.includes(f.key);
    return el("button", {
      class: "btn fw-pick", type: "button", "aria-pressed": String(selected),
      onclick: () => toggleFramework(f.key),
    }, [
      el("span", { class: "fw-pick__top" }, [
        el("span", { class: "eyebrow" }, f.short),
        f.implemented ? null : el("span", { class: "pill" }, "Not yet available"),
        el("span", { class: "fw-pick__check", "aria-hidden": "true" }, selected ? svgIcon(CHECK_ICON, { size: 13 }) : null),
      ]),
      el("div", { style: "font-weight:700;font-size:.92rem" }, f.name),
      el("div", { class: "panel-sub", style: "font-weight:400;white-space:normal" }, f.description),
    ]);
  }

  function toggleFramework(key) {
    state.frameworks = state.frameworks.includes(key)
      ? state.frameworks.filter((k) => k !== key)
      : [...state.frameworks, key];
    paint();
  }

  function resetFramework() {
    state.frameworksDone = false;
    state.vendor = null;
    state.file = null;
    state.headers = [];
    state.fieldCheck = null;
    state.allRequiredFound = null;
    paint();
  }
  // ── Step 1: choose the solution ──────────────────────────────────────
  function renderSolutionStep() {
    clear(solutionPanel);

    // Locked until the frameworks are confirmed — same affordance the upload
    // step already uses when no vendor is set.
    if (!state.frameworksDone) {
      solutionPanel.append(panel("2 · Solution",
        el("p", { class: "panel-sub" }, "Choose the frameworks above to unlock the solution picker.")));
      return;
    }
    if (chosenVendor() !== null) {
      // Collapse to a summary bar with a change link, so the picker does not
      // dominate the page once a choice is made.
      const isAuto = state.vendor === "";
      const info = meta.vendors.find((v) => v.value === state.vendor);
      solutionPanel.append(el("div", { class: "panel", style: "margin-bottom:1rem;padding:.7rem 1rem" },
        el("div", { style: "display:flex;align-items:center;gap:.6rem" }, [
          el("span", { class: "eyebrow" }, "Solution"),
          el("strong", {}, isAuto ? "Auto-detect (not recommended)" : info.label),
          el("span", { style: "flex:1" }),
          el("button", { class: "btn ghost small", onclick: () => resetVendor() }, "Change"),
        ])
      ));
      return;
    }

    solutionPanel.append(panel("2 · Choose the solution you're analyzing", [
      el("p", { class: "panel-sub", style: "margin:-.3rem 0 .9rem" },
        "Pick the firewall this export came from. This decides which columns are read — choosing correctly avoids the export being silently misread as a different vendor's format."),
      el("div", { class: "grid cols-3" },
        meta.vendors.map((v) => vendorCard(v, () => pickVendor(v.value)))),
      el("button", {
        class: "btn ghost small", style: "margin-top:.9rem",
        onclick: () => pickVendor(""),
      }, "Not sure — try to detect it automatically"),
    ]));
  }

  function vendorCard(v, onclick) {
    return el("button", {
      class: "btn", style: "flex-direction:column;align-items:stretch;gap:.1rem;height:auto;padding:.85rem;text-align:left",
      onclick,
    }, [
      vendorLogo(v),
      el("div", { style: "font-weight:700;font-size:.92rem" }, v.label),
      el("div", { class: "panel-sub", style: "font-weight:400;white-space:normal" }, v.description),
      el("div", { class: "panel-sub" }, `${v.required_fields.length} required columns`),
    ]);
  }

  /**
   * Real vendor logos sit on a fixed white chip (see .vendor-logo-chip) so
   * they stay legible regardless of the app's own theme — third-party marks
   * come in every ink colour, and this app's cards go dark in dark mode.
   * Generic/Other, and any vendor whose image fails to load, gets the wall
   * glyph instead of a broken-image icon.
   */
  function vendorLogo(v) {
    const chip = el("div", { class: "vendor-logo-chip" });
    if (v.value === "generic") {
      chip.append(svgIcon(WALL_ICON, { size: 24 }));
      return chip;
    }
    chip.append(el("img", {
      src: `/img/${v.value}.png`,
      alt: `${v.label} logo`,
      onerror: (e) => { clear(chip); chip.append(svgIcon(WALL_ICON, { size: 24 })); },
    }));
    return chip;
  }

  function pickVendor(value) {
    state.vendor = value;
    // A file chosen before switching vendor is no longer validated against
    // anything meaningful — start the upload step over.
    state.file = null;
    state.headers = [];
    state.fieldCheck = null;
    state.allRequiredFound = null;
    paint();
  }

  function resetVendor() {
    state.vendor = null;
    state.file = null;
    state.headers = [];
    state.fieldCheck = null;
    state.allRequiredFound = null;

    paint();
  }

  // ── Step 2: upload ────────────────────────────────────────────────────
  function renderUploadStep() {
    clear(uploadPanel);
    if (chosenVendor() === null) {
      uploadPanel.append(panel("3 · Rule export",
        el("p", { class: "panel-sub" }, "Choose a solution above to unlock the upload step.")));
      return;
    }

    const drop = buildDropzone();
    const form = el("div");
    uploadPanel.append(panel("3 · Rule export", [drop, form]));

    if (state.file) {
      form.append(el("div", { class: "section-label" }, "Analysis details"));
      form.append(field("Project", el("input", {
        type: "text", value: state.project,
        oninput: (e) => { state.project = e.target.value; },
      })));
      form.append(field("Analysis name", el("input", {
        type: "text", value: state.label,
        placeholder: "e.g. PA-Primary-FW01",
        oninput: (e) => { state.label = e.target.value; },
      })));

      const missing = (state.fieldCheck || [])
        .filter((f) => !f.found)
        .map((f) => f.field);
      const blocked = missing.length > 0;

      if (blocked) {
        form.append(el("div", { class: "notice bad", style: "margin-bottom:.9rem" }, [
          svgIcon(ALERT_ICON),
          el("div", {}, [
            el("div", { style: "font-weight:650;margin-bottom:.25rem" },
              `This export is missing ${missing.length} required column${missing.length > 1 ? "s" : ""}.`),
            el("div", { class: "muted" }, `Not found: ${missing.join(", ")}`),
            el("div", { class: "muted", style: "margin-top:.35rem" },
              "Analysis is disabled until the file matches, or you pick the solution this export actually came from."),
          ]),
        ]));
      }

      form.append(el("button", {
        class: "btn primary",
        style: "width:100%",
        disabled: blocked,
        title: blocked ? `Missing required columns: ${missing.join(", ")}` : null,
        onclick: (e) => submit(e.currentTarget),
      }, blocked ? "Cannot run — columns do not match" : "Run analysis"));
    }
  }

  function buildDropzone() {
    const input = el("input", {
      type: "file", accept: ".csv,.xlsx,.xls,.xlsm,.txt", hidden: true,
      onchange: (e) => e.target.files[0] && accept(e.target.files[0]),
    });

    const zone = el("div", { class: "dropzone" }, [
      svgIcon(UPLOAD_ICON, { size: 34 }),
      el("div", { class: "dz-main" }, "Drop a rule export here"),
      el("div", { class: "dz-sub" }, "CSV or Excel (.xlsx) — Excel is converted automatically"),
      el("button", { class: "btn", style: "margin-top:.8rem", onclick: () => input.click() },
        "Choose file"),
      input,
    ]);

    for (const evt of ["dragenter", "dragover"]) {
      zone.addEventListener(evt, (e) => { e.preventDefault(); zone.classList.add("over"); });
    }
    for (const evt of ["dragleave", "drop"]) {
      zone.addEventListener(evt, (e) => { e.preventDefault(); zone.classList.remove("over"); });
    }
    zone.addEventListener("drop", (e) => {
      const file = e.dataTransfer?.files?.[0];
      if (file) accept(file);
    });

    if (state.file) {
      clear(zone);
      zone.append(
        el("div", { class: "file-chip" }, [
          svgIcon(["M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z", "M14 2v6h6"]),
          state.file.name,
        ]),
        el("div", { style: "margin-top:.7rem" },
          el("button", { class: "btn ghost small", onclick: () => { state.file = null; state.headers = []; paint(); } },
            "Choose a different file"))
      );
    }

    return zone;
  }

  async function accept(file) {
    state.file = file;
    state.label = state.label || file.name.replace(/\.[^.]+$/, "");
    state.headers = [];
    state.fieldCheck = null;
    state.allRequiredFound = null;
    paint();

    const form = new FormData();
    form.append("file", file);
    if (chosenVendor()) form.append("vendor", chosenVendor());

    try {
      const info = await api.postForm("/analyses/preview", form);
      state.headers = info.headers || [];
      state.fieldCheck = info.field_check || null;
      state.allRequiredFound = info.all_required_found ?? true;
    } catch (err) {
      toastError(err);
    }
    paint();
  }

  // ── Step 3: what was detected ────────────────────────────────────────
  function renderDetectedStep() {
    clear(detectedPanel);
    detectedPanel.append(panel("4 · What was detected", buildDetectedBody()));
  }

  function buildDetectedBody() {
    if (!state.file) {
      return el("p", { class: "panel-sub" },
        "Columns are read and checked against the chosen solution's required fields before anything runs.");
    }
    if (!state.headers.length) {
      return el("p", { class: "panel-sub" }, "Reading columns…");
    }

    const parts = [
      el("dl", { class: "kv" }, [
        el("dt", {}, "File"), el("dd", {}, state.file.name),
        el("dt", {}, "Size"), el("dd", {}, `${(state.file.size / 1024).toFixed(0)} KB`),
        el("dt", {}, "Columns"), el("dd", {}, fmtNumber(state.headers.length)),
      ]),
    ];

    if (state.fieldCheck) {
      parts.push(el("div", { class: "section-label" }, "Required columns for this solution"));
      parts.push(el("div", { style: "display:flex;flex-direction:column;gap:.3rem" },
        state.fieldCheck.map((f) =>
          el("div", { style: `display:flex;align-items:center;gap:.5rem;color:${f.found ? "var(--ok)" : "var(--sev-critical)"}` }, [
            svgIcon(f.found ? CHECK_ICON : CROSS_ICON, { size: 14 }),
            el("span", { style: "color:var(--text)" }, f.field),
          ])
        )));
      if (state.allRequiredFound) {
        parts.push(el("div", { class: "notice", style: "margin-top:.8rem;border-color:var(--ok);color:var(--ok)" }, [
          svgIcon(CHECK_ICON, { size: 15 }),
          el("div", { style: "color:var(--text)" }, "All required columns for this solution were found."),
        ]));
      }
    } else {
      // Auto-detect was chosen — nothing to validate against.
      parts.push(el("div", { class: "notice warn" }, [
        svgIcon(["M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"]),
        el("div", {}, "No solution was chosen, so columns cannot be checked in advance. Auto-detection may pick the wrong vendor and silently misread this file."),
      ]));
    }

    parts.push(el("div", { class: "section-label" }, "All columns found"));
    parts.push(el("div", { class: "tag-list" },
      state.headers.map((h) => el("span", { class: "tag" }, h))));

    return parts;
  }

  async function submit(button) {
    if (!state.file) return;
    // Second gate: the button can be re-enabled by devtools, and paint() may
    // race a preview response. Never POST a file we know is mismatched.
    if (state.fieldCheck && !state.allRequiredFound) {
      toast("This export is missing required columns — analysis was not started.",
        { error: true, title: "Column mismatch" });
      return;
    }
    button.disabled = true;
    button.replaceChildren(el("span", { class: "spinner" }), document.createTextNode(" Uploading…"));

    const form = new FormData();
    form.append("file", state.file);
    form.append("project", state.project || "Default Project");
    form.append("label", state.label || state.file.name.replace(/\.[^.]+$/, ""));
    state.frameworks.forEach((key) => form.append("frameworks", key));
    if (chosenVendor()) form.append("vendor", chosenVendor());

    try {
      const { id } = await api.postForm("/analyses", form);
      toast("Analysis queued");
      await refreshAnalyses();
      await selectAnalysis(id);
      navigate("/analyses");
    } catch (err) {
      toastError(err);
      button.disabled = false;
      button.replaceChildren(document.createTextNode("Run analysis"));
    }
  }
}

function field(label, input, hint) {
  return el("div", { class: "field" }, [
    el("label", {}, label), input,
    hint ? el("span", { class: "field-hint" }, hint) : null,
  ]);
}

function renderStepper(host, s) {
  const steps = [
    { name: "Choose frameworks", done: s.frameworksDone },
    { name: "Choose solution", done: s.frameworksDone && s.vendor !== null },
    { name: "Upload export", done: !!s.file },
    { name: "Confirm columns", done: !!s.headers.length && s.allRequiredFound !== false },
    { name: "Run", done: false },
  ];
  const current = steps.findIndex((x) => !x.done);
  clear(host);
  steps.forEach((step, i) => {
    if (i) host.append(el("span", { class: "step-line" }));
    host.append(el("span", {
      class: `step${step.done ? " done" : ""}${i === current ? " current" : ""}`,
    }, [
      el("span", { class: "step-num" }, step.done ? "✓" : String(i + 1)),
      step.name,
    ]));
  });
}
