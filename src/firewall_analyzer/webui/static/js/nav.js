// Sidebar navigation and the "current selection" card beneath it.

import { el, clear, svgIcon, fmtDate } from "./ui.js";
import { navigate, parseRoute } from "./router.js";
import { getState } from "./state.js";
import { allowedSections } from "./session.js";

// Static icon path constants — never built from data.
const ICONS = {
  overview:  ["M3 13h8V3H3zM13 21h8V11h-8zM13 3v6h8V3zM3 21h8v-6H3z"],
  findings:  ["M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"],
  rules:     ["M3 6h18M3 12h18M3 18h18"],
  zones:     ["M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zM2 12h20M12 2a15 15 0 0 1 0 20a15 15 0 0 1 0-20z"],
  external:  ["M4 12a8 8 0 0 1 8-8m8 8a8 8 0 0 1-8 8", "M12 2v20M2 12h20"],
  logging:   ["M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z", "M14 2v6h6M8 13h8M8 17h5"],
  report:    ["M9 11H5a2 2 0 0 0-2 2v7h6zM15 4h-6v16h6zM21 9h-4v11h4a2 2 0 0 0 0-2z"],
  history:   ["M3 3v5h5", "M3.05 13A9 9 0 1 0 6 5.3L3 8", "M12 7v5l4 2"],
  run:       ["M5 3l14 9-14 9V3z"],
  compliance: ["M9 11l3 3L22 4", "M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"],
  admin:     ["M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2", "M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z", "M22 21v-2a4 4 0 0 0-3-3.87", "M16 3.13a4 4 0 0 1 0 7.75"],
  settings:  ["M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z", "M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.6h.09A1.65 1.65 0 0 0 10 3.09V3a2 2 0 0 1 4 0v.09A1.65 1.65 0 0 0 15 4.6a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9v.09a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"],
};

/**
 * Route table. `key` is the section name the role matrix gates on (see
 * auth.ROLE_SECTIONS server-side): an Executive is granted "dashboard" and
 * "analysis" only, so Configuration and History never render for them.
 * `needsAnalysis` pages are dimmed until an analysis is selected.
 */
export const NAV = [
  { section: "Dashboard", key: "dashboard", items: [
    { path: "/overview", label: "Overview", icon: "overview", needsAnalysis: true },
  ]},
  { section: "Analysis", key: "analysis", items: [
    { path: "/findings", label: "Findings", icon: "findings", needsAnalysis: true },
    { path: "/rules", label: "Rule Explorer", icon: "rules", needsAnalysis: true },
    { path: "/zones", label: "Zone Analysis", icon: "zones", needsAnalysis: true },
    { path: "/compliance", label: "Compliance", icon: "compliance", needsAnalysis: true },
    { path: "/external", label: "External Communications", icon: "external", needsAnalysis: true },
    { path: "/logging", label: "Logging & Audit", icon: "logging", needsAnalysis: true },
    { path: "/report", label: "Full Report", icon: "report", needsAnalysis: true },
  ]},
  { section: "Configuration", key: "configuration", items: [
    { path: "/new", label: "Run New Analysis", icon: "run" },
    { path: "/settings", label: "Settings", icon: "settings" },
  ]},
  { section: "History", key: "history", items: [
    { path: "/analyses", label: "Analyses", icon: "history" },
  ]},
  // Granted only to roles the server considers administrators; public_user()
  // appends the "administration" section for those.
  { section: "Administration", key: "administration", items: [
    { path: "/admin", label: "Users & Roles", icon: "admin" },
  ]},
];

/** The nav groups this role may see. */
export function visibleNav() {
  const allowed = allowedSections();
  return NAV.filter((group) => allowed.includes(group.key));
}

/** Every route path the current role may reach — used to guard the router. */
export function allowedPaths() {
  return visibleNav().flatMap((group) => group.items.map((item) => item.path));
}

export function renderNav() {
  const container = document.getElementById("side-nav");
  const { path } = parseRoute();
  const { current } = getState();
  clear(container);

  for (const group of visibleNav()) {
    container.append(el("div", { class: "side-section" }, group.section));
    for (const item of group.items) {
      const disabled = item.needsAnalysis && !current;
      const link = el("a", {
        class: `side-link${path === item.path ? " active" : ""}`,
        href: `#${item.path}`,
        title: disabled ? "Select or run an analysis first" : item.label,
        style: disabled ? "opacity:.45" : null,
        onclick: (e) => {
          e.preventDefault();
          if (disabled) return;
          navigate(item.path);
        },
      }, [
        el("span", { class: "side-ico" }, svgIcon(ICONS[item.icon])),
        item.label,
      ]);
      container.append(link);
    }
  }
}

export function renderSelectionCard() {
  const host = document.getElementById("selection-card");
  const { current } = getState();
  clear(host);

  const card = el("div", { class: "selection-card" });
  card.append(el("div", { class: "selection-title" }, "Current Selection"));

  if (!current) {
    card.append(el("div", { class: "selection-empty" },
      "No analysis selected. Upload a rule export to begin."));
    card.append(el("button", {
      class: "btn primary small",
      style: "width:100%;margin-top:.6rem",
      onclick: () => navigate("/new"),
    }, "Run New Analysis"));
  } else {
    const rows = [
      ["Project", current.project_name],
      ["Analysis", current.label],
      ["Vendor", (current.vendor || "—").replace(/_/g, " ")],
      ["File", current.filename],
      ["Date", fmtDate(current.created_at)],
    ];
    const dl = el("dl", { style: "margin:0" });
    for (const [key, value] of rows) {
      dl.append(el("div", { class: "selection-row" }, [
        el("dt", {}, key),
        el("dd", { title: String(value) }, value || "—"),
      ]));
    }
    card.append(dl);
    card.append(el("button", {
      class: "btn ghost small",
      style: "width:100%;margin-top:.6rem;color:var(--side-text);border-color:var(--side-line)",
      onclick: () => navigate("/analyses"),
    }, "Change Selection"));
  }
  host.append(card);
}
