// Sign-in gate and the role rules the shell reads.
//
// The server is the authority on permissions — every protected route checks the
// session cookie itself. What lives here only decides what to *render*, so a
// role never sees controls that would fail server-side anyway.

import { api } from "./api.js";
import { el, clear } from "./ui.js";

let user = null;

export function getUser() { return user; }
export function isSignedIn() { return !!user; }

/** Sections this role may see in the sidebar. */
export function allowedSections() {
  return user?.sections || [];
}

/** Only the administrator may switch dashboard presets. */
export function maySwitchView() {
  return !!user?.may_switch_view;
}

/** The preset this role lands on — and is locked to, unless admin. */
export function defaultView() {
  return user?.view || "executive";
}

export function mayWrite() {
  return !!user?.may_write;
}

/** Ask the server who we are. Returns null when signed out. */
export async function loadSession() {
  try {
    const { user: found } = await api.get("/auth/me");
    user = found;
  } catch {
    user = null;
  }
  return user;
}

export async function signOut() {
  try { await api.post("/auth/logout"); } catch { /* going to the gate regardless */ }
  user = null;
  // Full reload rather than a re-render: it clears every page's cached state
  // and in-flight timer in one step.
  location.href = "/app";
}

/**
 * Render the sign-in form and resolve once authenticated.
 * The app shell is not rendered at all until this resolves.
 */
export function showLogin() {
  return new Promise((resolve) => {
    const gate = document.getElementById("login-view");
    const shell = document.getElementById("app-view");
    gate.hidden = false;
    shell.hidden = true;

    const form = document.getElementById("login-form");
    const username = document.getElementById("login-username");
    const password = document.getElementById("login-password");
    const errorBox = document.getElementById("login-error");
    const submit = document.getElementById("login-submit");
    const toggle = document.getElementById("pw-toggle");

    username.focus();

    toggle.onclick = () => {
      const showing = password.type === "text";
      password.type = showing ? "password" : "text";
      toggle.textContent = showing ? "Show" : "Hide";
      toggle.setAttribute("aria-label", showing ? "Show password" : "Hide password");
    };

    form.onsubmit = async (event) => {
      event.preventDefault();
      errorBox.hidden = true;
      submit.disabled = true;
      clear(submit);
      submit.append(el("span", { class: "spinner" }), document.createTextNode(" Signing in…"));

      try {
        const result = await api.post("/auth/login", {
          username: username.value.trim(),
          password: password.value,
        });
        user = result.user;
        gate.hidden = true;
        shell.hidden = false;
        resolve(user);
      } catch (err) {
        errorBox.textContent = err.detail || "Sign-in failed. Try again.";
        errorBox.hidden = false;
        password.value = "";
        password.focus();
        submit.disabled = false;
        clear(submit);
        submit.append(document.createTextNode("Sign in"));
      }
    };
  });
}

/** The signed-in identity card pinned under the sidebar. */
export function renderUserCard() {
  const host = document.getElementById("user-card");
  if (!host || !user) return;
  clear(host);

  const initials = (user.display_name || user.username)
    .split(/\s+/).slice(0, 2).map((w) => w[0]).join("").toUpperCase();

  host.append(el("div", { class: "user-card" }, [
    el("div", { class: "user-avatar" }, initials),
    el("div", { class: "user-meta" }, [
      el("div", { class: "user-name" }, user.display_name),
      el("div", { class: "user-role" }, user.role_label),
    ]),
    el("button", {
      class: "user-signout",
      type: "button",
      title: "Sign out",
      "aria-label": "Sign out",
      onclick: signOut,
    }, "Sign out"),
  ]));
}
