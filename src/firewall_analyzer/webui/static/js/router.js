// Hash router. Routes are plain and readable — this tool runs against a team's
// own exports, so there is nothing gained by obscuring the address bar.

const listeners = [];

export function currentRoute() {
  return location.hash || "#/overview";
}

/** "#/findings?risk=critical" -> { path: "/findings", query: URLSearchParams } */
export function parseRoute(hash = currentRoute()) {
  const raw = hash.startsWith("#") ? hash.slice(1) : hash;
  const [path, search = ""] = raw.split("?");
  return { path: path || "/overview", query: new URLSearchParams(search) };
}

export function navigate(path) {
  const target = path.startsWith("#") ? path : `#${path}`;
  if (location.hash === target) onChange();
  else location.hash = target;
}

/** Replace the query string without adding a history entry. */
export function setQuery(params) {
  const { path } = parseRoute();
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v == null || v === "" || (Array.isArray(v) && !v.length)) continue;
    if (Array.isArray(v)) v.forEach((i) => sp.append(k, i));
    else sp.append(k, v);
  }
  const s = sp.toString();
  history.replaceState(null, "", `#${path}${s ? `?${s}` : ""}`);
}

export function onRoute(fn) { listeners.push(fn); }
function onChange() { listeners.forEach((fn) => fn(parseRoute())); }
window.addEventListener("hashchange", onChange);
