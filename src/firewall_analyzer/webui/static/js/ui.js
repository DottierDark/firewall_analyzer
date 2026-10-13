// DOM helpers — no framework. Text always goes through createTextNode, so a
// rule name or address out of a customer's export can never become markup.

export function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "dataset") Object.assign(node.dataset, v);
    else if (k === "style") node.style.cssText = v;
    else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : v);
  }
  append(node, children);
  return node;
}

export function append(node, children) {
  for (const child of [].concat(children)) {
    if (child == null || child === false) continue;
    node.append(child.nodeType ? child : document.createTextNode(String(child)));
  }
  return node;
}

export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
  return node;
}

/** Inline SVG from a path spec. Icons are static constants defined in icons.js. */
export function svgIcon(paths, { size = 16, fill = "none", viewBox = "0 0 24 24" } = {}) {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", viewBox);
  svg.setAttribute("width", size);
  svg.setAttribute("height", size);
  svg.setAttribute("fill", fill);
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  for (const d of [].concat(paths)) {
    const p = document.createElementNS(ns, "path");
    p.setAttribute("d", d);
    svg.append(p);
  }
  return svg;
}

// ─────────────────────────────────────────────── formatting

export function fmtDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, {
    year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

export function fmtNumber(n) {
  return n == null ? "—" : Number(n).toLocaleString();
}

export function titleCase(s) {
  return String(s || "").replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

export function relativeTime(iso) {
  if (!iso) return "—";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "—";
  const secs = Math.round((Date.now() - then) / 1000);
  if (secs < 60) return "just now";
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

// ─────────────────────────────────────────────── components

export const RISK_ORDER = ["critical", "high", "medium", "low", "info"];

/** Severity badge: colour + dot + the word. Status colour never travels alone. */
export function sevBadge(level) {
  const key = RISK_ORDER.includes(level) ? level : "info";
  return el("span", { class: `sev-badge sev-${key}` }, [
    el("span", { class: "sev-dot" }),
    key,
  ]);
}

export function actionPill(action) {
  const a = String(action || "").toLowerCase();
  return el("span", { class: `pill ${a === "allow" ? "allow" : a === "deny" ? "deny" : ""}` }, a || "—");
}

export function statusPill(status) {
  return el("span", { class: `pill state-${status}` }, [
    status === "running" || status === "queued" ? el("span", { class: "spinner" }) : null,
    status,
  ]);
}

/** A list of values as tags; "any" is called out because it drives most findings. */
export function tagList(values, { max = 4 } = {}) {
  const items = [].concat(values || []);
  const shown = items.slice(0, max);
  const wrap = el("div", { class: "tag-list" },
    shown.map((v) => el("span", { class: `tag${String(v).toLowerCase() === "any" ? " any" : ""}` }, v))
  );
  if (items.length > max) {
    wrap.append(el("span", { class: "tag", title: items.join(", ") }, `+${items.length - max}`));
  }
  return wrap;
}

export function panel(title, children, { actions = null, sub = null } = {}) {
  const head = el("div", { class: "panel-head" }, [
    el("span", { class: "panel-title" }, title),
    sub ? el("span", { class: "panel-sub" }, sub) : null,
    el("span", { class: "spacer" }),
    actions,
  ]);
  return el("section", { class: "panel" }, [head, ...[].concat(children)]);
}

export function empty(title, detail) {
  return el("div", { class: "empty" }, [
    el("div", { class: "empty-title" }, title),
    detail ? el("div", {}, detail) : null,
  ]);
}

export function loading(label = "Loading…") {
  return el("div", { class: "empty" }, [el("span", { class: "spinner" }), " ", label]);
}

const TOAST = () => document.getElementById("toast");

export function toast(message, { error = false, title = null } = {}) {
  const t = TOAST();
  clear(t);
  t.className = "toast" + (error ? " error" : "");
  if (title) t.append(el("div", { class: "t-title" }, title));
  t.append(el("div", { class: "t-detail" }, message));
  t.hidden = false;
  clearTimeout(t._timer);
  t._timer = setTimeout(() => { t.hidden = true; }, error ? 8000 : 3500);
}

export function toastError(err) {
  toast(err.detail || err.message || "Request failed", { error: true, title: "Error" });
}

export function modal(build) {
  const backdrop = el("div", { class: "modal-backdrop" });
  const box = el("div", { class: "modal" });
  backdrop.append(box);
  const close = () => { backdrop.remove(); document.removeEventListener("keydown", onKey); };
  const onKey = (e) => { if (e.key === "Escape") close(); };
  backdrop.addEventListener("click", (e) => { if (e.target === backdrop) close(); });
  document.addEventListener("keydown", onKey);
  build(box, close);
  document.body.append(backdrop);
  return { box, close };
}

export function confirmDialog(title, message, { danger = false, confirmLabel = "Confirm" } = {}) {
  return new Promise((resolve) => {
    modal((box, close) => {
      box.append(el("h3", {}, title));
      if (message) box.append(el("p", { class: "modal-sub" }, message));
      box.append(el("div", { class: "actions" }, [
        el("button", { class: "btn ghost", onclick: () => { close(); resolve(false); } }, "Cancel"),
        el("button", {
          class: `btn ${danger ? "danger" : "primary"}`,
          onclick: () => { close(); resolve(true); },
        }, confirmLabel),
      ]));
    });
  });
}

/** Debounce for search inputs so a keystroke does not become a request. */
export function debounce(fn, ms = 250) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
}
