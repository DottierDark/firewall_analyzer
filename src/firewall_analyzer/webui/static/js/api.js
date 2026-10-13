// Structured-error-aware fetch wrapper. Same-origin: in development the API
// serves the frontend itself; in the container split nginx proxies /api.

const BASE = "/api";

export class ApiError extends Error {
  constructor(payload, status) {
    super((payload && (payload.title || payload.detail)) || `HTTP ${status}`);
    this.status = status;
    this.detail = payload && payload.detail;
    this.title = payload && payload.title;
  }
}

async function request(path, { method = "GET", json = null, form = null, signal } = {}) {
  const opts = { method, headers: {}, signal };
  if (form) {
    opts.body = form;                       // FormData: browser sets the boundary
  } else if (json !== null) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(json);
  }
  const res = await fetch(BASE + path, opts);

  // A session that expires mid-use would otherwise surface as a wall of failed
  // panels. Send the user back to the gate instead — except for /auth/me and
  // /auth/login, where a 401 is the expected "not signed in" answer.
  if (res.status === 401 && !path.startsWith("/auth/")) {
    window.dispatchEvent(new CustomEvent("fwa-session-expired"));
  }

  let data = null;
  const text = await res.text();
  if (text) {
    try { data = JSON.parse(text); } catch { data = text; }
  }
  if (!res.ok) throw new ApiError(typeof data === "object" ? data || {} : {}, res.status);
  return data;
}

/** Build a query string, dropping empties and expanding arrays into repeats. */
export function qs(params) {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params || {})) {
    if (v == null || v === "" || v === false) continue;
    if (Array.isArray(v)) v.forEach((item) => sp.append(k, item));
    else sp.append(k, v);
  }
  const s = sp.toString();
  return s ? `?${s}` : "";
}

export const api = {
  get: (p, signal) => request(p, { signal }),
  post: (p, json) => request(p, { method: "POST", json }),
  patch: (p, json) => request(p, { method: "PATCH", json }),
  putJson: (p, json) => request(p, { method: "PUT", json }),
  postForm: (p, form) => request(p, { method: "POST", form }),
  del: (p) => request(p, { method: "DELETE" }),

  meta: () => request("/meta"),
  analyses: (limit = 50) => request(`/analyses${qs({ limit })}`),
  analysis: (id) => request(`/analyses/${id}`),
  facets: (id, params) => request(`/analyses/${id}/facets${qs(params)}`),
  dashboard: (id) => request(`/analyses/${id}/dashboard`),
  findings: (id, params) => request(`/analyses/${id}/findings${qs(params)}`),
  rules: (id, params) => request(`/analyses/${id}/rules${qs(params)}`),
  rule: (id, ruleId) => request(`/analyses/${id}/rules/${encodeURIComponent(ruleId)}`),
  reportUrl: (id) => `${BASE}/analyses/${id}/report`,
  exportUrl: (id, kind) => `${BASE}/analyses/${id}/export.${kind}`,
};
