// App bootstrap: route table, page mounting, topbar, and the live refresh that
// keeps a running analysis moving without the user reloading.

import { el, clear, svgIcon, toastError, toast } from "./ui.js";
import { wirePwcLogo, applyPwcLogo } from "./brand.js";
import { parseRoute, onRoute, navigate } from "./router.js";
import { renderNav, renderSelectionCard, allowedPaths } from "./nav.js";
import { loadSession, showLogin, renderUserCard, maySwitchView, defaultView } from "./session.js";
import { restoreSelection, refreshCurrent, getState, subscribe, loadMeta } from "./state.js";
import { api } from "./api.js";

const ROUTES = {
  "/overview":  { title: "Overview", sub: "Executive summary of the selected analysis", mod: () => import("./pages/overview.js") },
  "/findings":  { title: "Findings", sub: "Every finding, filterable by severity and category", mod: () => import("./pages/findings.js") },
  "/rules":     { title: "Rule Explorer", sub: "Every rule in the file, including disabled ones", mod: () => import("./pages/rules.js") },
  "/zones":     { title: "Zone Analysis", sub: "Traffic between configured network zones", mod: () => import("./pages/zones.js") },
  "/compliance": { title: "Compliance", sub: "Every framework assessed for the selected analysis", mod: () => import("./pages/compliance.js") },
  "/external":  { title: "External Communications", sub: "Allow rules crossing your perimeter", mod: () => import("./pages/external.js") },
  "/logging":   { title: "Logging & Audit", sub: "Rules whose traffic is not auditable", mod: () => import("./pages/logging.js") },
  "/report":    { title: "Full Report", sub: "The complete generated analyzer report", mod: () => import("./pages/report.js") },
  "/new":       { title: "Run New Analysis", sub: "Choose a solution, upload its export, and analyze it", mod: () => import("./pages/new-analysis.js") },
  "/analyses":  { title: "Analyses", sub: "History across every project", mod: () => import("./pages/analyses.js") },
  "/admin":     { title: "Users & Roles", sub: "Accounts, role definitions and the activity log", mod: () => import("./pages/admin.js") },
  "/settings":  { title: "Settings", sub: "Deployment configuration and known behaviour", mod: () => import("./pages/settings.js") },
};

let activeModule = null;
let pollTimer = null;

const SUN = ["M12 2v2m0 16v2M4.9 4.9l1.4 1.4m11.4 11.4 1.4 1.4M2 12h2m16 0h2M4.9 19.1l1.4-1.4m11.4-11.4 1.4-1.4"];
const MOON = ["M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"];
const DOWNLOAD = ["M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4", "M7 10l5 5 5-5", "M12 15V3"];

async function mount() {
  let { path } = parseRoute();

  // A role that may not reach this route is sent to the first one it can.
  // The server enforces the same rules on every endpoint; this only keeps the
  // UI from rendering a page whose data would come back 401/403.
  const permitted = allowedPaths();
  if (!permitted.includes(path)) {
    const fallback = permitted[0] || "/overview";
    if (path !== fallback) { navigate(fallback); return; }
    path = fallback;
  }

  const route = ROUTES[path] || ROUTES["/overview"];
  const host = document.getElementById("page");

  document.getElementById("page-title").textContent = route.title;
  document.getElementById("page-sub").textContent = route.sub;
  renderNav();
  renderTopbar();

  // Let the previous page cancel its timers before the next one mounts.
  if (activeModule?.teardown) {
    try { activeModule.teardown(); } catch { /* non-fatal */ }
  }

  clear(host);
  try {
    activeModule = await route.mod();
    await activeModule.render(host);
  } catch (err) {
    console.error(err);
    toastError(err);
    host.replaceChildren(el("div", { class: "empty" }, [
      el("div", { class: "empty-title" }, "This page failed to load"),
      el("div", {}, err.message || String(err)),
    ]));
  }
}

function renderTopbar() {
  const host = document.getElementById("topbar-actions");
  const { current } = getState();
  const { path } = parseRoute();
  clear(host);

  // Audience selector — only on the dashboard, and only for the administrator.
  // Every other role is locked to the preset its role maps to, so the control
  // would be a no-op with three options.
  if (path === "/overview" && current?.status === "succeeded" && maySwitchView()) {
    import("./pages/overview.js").then(({ VIEWS, getView, setView }) => {
      const seg = el("div", { class: "seg" },
        Object.entries(VIEWS).map(([key, view]) =>
          el("button", {
            type: "button",
            "aria-pressed": String(getView() === key),
            onclick: () => { setView(key); mount(); },
          }, view.label)
        )
      );
      host.prepend(seg);
    });
  }

  if (current?.status === "succeeded") {
    host.append(el("a", {
      class: "btn ghost small", href: api.exportUrl(current.id, "json"), download: "",
    }, [svgIcon(DOWNLOAD, { size: 14 }), "Export"]));
  }

  host.append(el("button", {
    class: "btn primary small", onclick: () => navigate("/new"),
  }, "Run New Analysis"));

  host.append(el("button", {
    class: "icon-btn", type: "button", "aria-label": "Toggle dark mode",
    onclick: () => {
      const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
      document.documentElement.dataset.theme = next;
      localStorage.setItem("fwa-theme", next);
      applyPwcLogo();   // re-resolves any logo whose surface follows the theme
      mount();          // charts read their colours from CSS variables
    },
  }, [svgIcon(SUN, { size: 16 }), svgIcon(MOON, { size: 16 })]));

  // Mark the sun/moon so CSS can show one at a time.
  const [sun, moon] = host.lastChild.querySelectorAll("svg");
  sun.classList.add("icon-sun");
  moon.classList.add("icon-moon");
}

/**
 * While the selected analysis is queued or running, poll it and re-render the
 * moment it finishes — so the dashboard fills in without a manual reload.
 */
function watchCurrent() {
  clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    const { current } = getState();
    if (!current || (current.status !== "queued" && current.status !== "running")) return;
    const before = current.status;
    try {
      const after = await refreshCurrent();
      if (after && after.status !== before) {
        if (after.status === "succeeded") toast("Analysis complete");
        if (after.status === "failed") toast(after.error || "Analysis failed", { error: true });
        mount();
      }
    } catch { /* transient; try again next tick */ }
  }, 2000);
}

// A session that lapses while the tab is open returns to the gate once, rather
// than letting every subsequent request fail in the background.
let expiring = false;
window.addEventListener("fwa-session-expired", () => {
  if (expiring) return;
  expiring = true;
  toast("Your session expired. Signing you back in…", { error: true });
  setTimeout(() => { location.href = "/app"; }, 1200);
});

async function boot() {
  wirePwcLogo();   // swaps the inline SVG placeholder for the real PwC logo, if present

  // Nothing renders until there is a session.
  let user = await loadSession();
  if (!user) user = await showLogin();

  document.getElementById("login-view").hidden = true;
  document.getElementById("app-view").hidden = false;

  // Non-admin roles are pinned to their role's dashboard preset.
  const { setView } = await import("./pages/overview.js");
  if (!maySwitchView()) setView(defaultView());

  subscribe(() => { renderNav(); renderSelectionCard(); });
  renderUserCard();

  try {
    await loadMeta();
    await restoreSelection();
  } catch (err) {
    toastError(err);
  }

  renderSelectionCard();
  onRoute(mount);
  watchCurrent();

  const landing = allowedPaths();
  if (!location.hash) {
    navigate(getState().current ? "/overview" : (landing.includes("/new") ? "/new" : landing[0]));
  } else {
    await mount();
  }
}

boot();
