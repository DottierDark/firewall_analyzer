// Administration — accounts, roles, and the activity log.
//
// Only reachable by a role the server considers an administrator; every route
// behind this page re-checks that, so the tab is convenience, not the control.

import { api, qs } from "../api.js";
import {
  el, clear, panel, empty, loading, fmtDate, relativeTime, titleCase,
  toast, toastError, modal, confirmDialog, debounce, svgIcon, fmtNumber,
} from "../ui.js";
import { getUser } from "../session.js";

const SEARCH_ICON = ["M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16z", "m21 21-4.35-4.35"];
const TABS = [
  { id: "users", label: "Accounts" },
  { id: "roles", label: "Roles" },
  { id: "activity", label: "Activity log" },
];

let activeTab = "users";

export async function render(host) {
  const me = getUser();
  if (!me?.is_admin) {
    host.append(empty("Administrator access required",
      "Your role does not include user or role administration."));
    return;
  }

  const tabs = el("div", { class: "seg", style: "margin-bottom:1rem" },
    TABS.map((t) => el("button", {
      type: "button",
      "aria-pressed": String(activeTab === t.id),
      onclick: () => { activeTab = t.id; paint(); },
    }, t.label)));

  const body = el("div");
  host.append(tabs, body);
  paint();

  function paint() {
    [...tabs.children].forEach((b, i) =>
      b.setAttribute("aria-pressed", String(TABS[i].id === activeTab)));
    clear(body);
    body.append(loading());
    const render = { users: renderUsers, roles: renderRoles, activity: renderActivity }[activeTab];
    render(body).catch((err) => {
      toastError(err);
      body.replaceChildren(empty("Could not load", err.message));
    });
  }

  // ── Accounts ───────────────────────────────────────────────────────
  async function renderUsers(host) {
    const [{ items: users }, { items: roles }] = await Promise.all([
      api.get("/admin/users"), api.get("/admin/roles"),
    ]);

    const rows = users.map((u) => el("tr", {}, [
      el("td", {}, [
        el("div", { class: "rule-name" }, u.display_name),
        el("div", { class: "panel-sub mono" }, u.username),
      ]),
      el("td", {}, el("select", {
        class: "mini-select",
        onchange: (e) => changeRole(u, e.target.value, e.target),
      }, roles.map((r) => el("option", {
        value: r.name, selected: r.name === u.role,
      }, r.label)))),
      el("td", {}, u.may_write
        ? el("span", { class: "pill allow" }, "can run")
        : el("span", { class: "pill" }, "read only")),
      el("td", { class: "muted", title: u.last_login ? fmtDate(u.last_login) : "" },
        u.last_login ? relativeTime(u.last_login) : "never signed in"),
      el("td", { class: "muted" }, fmtDate(u.created_at)),
      el("td", {}, el("div", { style: "display:flex;gap:.3rem;justify-content:flex-end" }, [
        el("button", { class: "btn ghost small", onclick: () => resetPassword(u) }, "Reset password"),
        el("button", {
          class: "btn ghost small",
          disabled: u.id === me.id,
          title: u.id === me.id ? "You cannot delete your own account" : "Delete",
          onclick: () => removeUser(u),
        }, "Delete"),
      ])),
    ]));

    host.replaceChildren(panel("Accounts",
      el("div", { class: "table-wrap" }, el("table", { class: "data" }, [
        el("thead", {}, el("tr", {}, [
          el("th", {}, "User"), el("th", {}, "Role"), el("th", {}, "Access"),
          el("th", {}, "Last sign-in"), el("th", {}, "Created"), el("th", {}, ""),
        ])),
        el("tbody", {}, rows),
      ])),
      {
        sub: `${fmtNumber(users.length)} accounts`,
        actions: el("button", { class: "btn primary small", onclick: () => newUser(roles) },
          "Add account"),
      }));
  }

  async function changeRole(user, role, select) {
    if (role === user.role) return;
    const previous = user.role;
    try {
      await api.patch(`/admin/users/${user.id}/role`, { role });
      user.role = role;
      toast(`${user.username} is now ${role.replace(/_/g, " ")}`);
      paint();
    } catch (err) {
      select.value = previous;      // put the control back where it was
      toastError(err);
    }
  }

  function newUser(roles) {
    modal((box, close) => {
      box.append(el("h3", {}, "Add account"));
      box.append(el("p", { class: "modal-sub" },
        "Leave the password blank and one will be generated and shown once."));

      const username = el("input", { type: "text", autocapitalize: "none", spellcheck: "false" });
      const display = el("input", { type: "text", placeholder: "e.g. Dana Whitfield" });
      const password = el("input", { type: "text", placeholder: "auto-generate" });
      const role = el("select", {}, roles.map((r) =>
        el("option", { value: r.name }, r.label)));

      box.append(
        field("Username", username),
        field("Display name", display),
        field("Role", role),
        field("Password", password, "Minimum 8 characters if you set one."),
      );
      box.append(el("div", { class: "actions" }, [
        el("button", { class: "btn ghost", onclick: close }, "Cancel"),
        el("button", {
          class: "btn primary",
          onclick: async (e) => {
            const btn = e.currentTarget;
            btn.disabled = true;
            try {
              const result = await api.post("/admin/users", {
                username: username.value.trim(),
                display_name: display.value.trim() || username.value.trim(),
                role: role.value,
                password: password.value.trim() || null,
              });
              close();
              showCredentials("Account created", result);
              paint();
            } catch (err) {
              toastError(err);
              btn.disabled = false;
            }
          },
        }, "Create account"),
      ]));
    });
  }

  async function resetPassword(user) {
    const ok = await confirmDialog("Reset password?",
      `A new password will be generated for ${user.username} and shown once.`,
      { confirmLabel: "Reset" });
    if (!ok) return;
    try {
      const result = await api.post(`/admin/users/${user.id}/password`, { password: null });
      showCredentials("Password reset", result);
    } catch (err) { toastError(err); }
  }

  async function removeUser(user) {
    const ok = await confirmDialog("Delete this account?",
      `${user.display_name} (${user.username}) will be removed. Their activity log entries are kept.`,
      { danger: true, confirmLabel: "Delete" });
    if (!ok) return;
    try {
      await api.del(`/admin/users/${user.id}`);
      toast("Account deleted");
      paint();
    } catch (err) { toastError(err); }
  }

  /** Shown once — the server never stores or returns this again. */
  function showCredentials(title, result) {
    modal((box, close) => {
      box.append(el("h3", {}, title));
      box.append(el("p", { class: "modal-sub" },
        "Copy this now. Only the hash is stored, so it cannot be shown again."));
      box.append(el("div", { class: "cred-box" }, [
        el("div", {}, [el("span", { class: "cred-k" }, "Username"),
                       el("span", { class: "cred-v mono" }, result.username)]),
        el("div", {}, [el("span", { class: "cred-k" }, "Password"),
                       el("span", { class: "cred-v mono" }, result.password)]),
      ]));
      box.append(el("div", { class: "actions" }, [
        el("button", {
          class: "btn ghost",
          onclick: () => {
            navigator.clipboard?.writeText(`${result.username} / ${result.password}`)
              .then(() => toast("Copied"), () => toast("Copy failed", { error: true }));
          },
        }, "Copy"),
        el("button", { class: "btn primary", onclick: close }, "Done"),
      ]));
    });
  }

  // ── Roles ──────────────────────────────────────────────────────────
  async function renderRoles(host) {
    const data = await api.get("/admin/roles");

    const cards = data.items.map((role) => el("div", { class: "role-card" }, [
      el("div", { class: "role-card__head" }, [
        el("div", {}, [
          el("div", { class: "role-card__name" }, [
            role.label,
            role.is_builtin ? el("span", { class: "pill" }, "built-in") : null,
          ]),
          el("div", { class: "panel-sub mono" }, role.name),
        ]),
        el("span", { style: "flex:1" }),
        el("span", { class: "panel-sub" },
          `${role.user_count} ${role.user_count === 1 ? "account" : "accounts"}`),
      ]),
      role.description ? el("p", { class: "panel-sub", style: "margin:.4rem 0 .6rem" }, role.description) : null,
      el("div", { class: "tag-list" }, [
        ...data.all_sections.map((section) =>
          el("span", {
            class: `tag${role.sections.includes(section) ? " tag--on" : " tag--off"}`,
          }, titleCase(section))),
        el("span", { class: "tag" }, `view: ${role.view}`),
        role.may_write ? el("span", { class: "tag tag--on" }, "can run") : null,
        role.may_switch_view ? el("span", { class: "tag tag--on" }, "switches views") : null,
      ]),
      el("div", { style: "display:flex;gap:.4rem;margin-top:.7rem" }, [
        el("button", { class: "btn ghost small", onclick: () => editRole(role, data) }, "Edit"),
        role.is_builtin ? null : el("button", {
          class: "btn ghost small", onclick: () => removeRole(role),
        }, "Delete"),
      ]),
    ]));

    host.replaceChildren(panel("Roles", [
      el("p", { class: "panel-sub", style: "margin:-.4rem 0 .9rem" },
        "A role grants sidebar sections, a dashboard preset, and whether its holders can run analyses. Built-in roles can be edited but not removed."),
      el("div", { class: "role-grid" }, cards),
    ], {
      actions: el("button", { class: "btn primary small", onclick: () => editRole(null, data) },
        "New role"),
    }));
  }

  function editRole(role, data) {
    const isNew = !role;
    modal((box, close) => {
      box.append(el("h3", {}, isNew ? "New role" : `Edit ${role.label}`));
      box.append(el("p", { class: "modal-sub" },
        isNew
          ? "Roles are stored in the database, so this takes effect immediately — no restart."
          : "Changes apply the next time a holder of this role loads the app."));

      const name = el("input", {
        type: "text", value: role?.name || "", disabled: !isNew,
        placeholder: "e.g. auditor", autocapitalize: "none", spellcheck: "false",
      });
      const label = el("input", { type: "text", value: role?.label || "", placeholder: "e.g. External Auditor" });
      const description = el("input", { type: "text", value: role?.description || "" });
      const view = el("select", {}, data.all_views.map((v) =>
        el("option", { value: v, selected: v === (role?.view || "executive") }, titleCase(v))));

      const boxes = {};
      const sectionList = el("div", { style: "display:flex;flex-direction:column;gap:.3rem" },
        data.all_sections.map((section) => {
          const input = el("input", {
            type: "checkbox",
            checked: role ? role.sections.includes(section) : section !== "configuration" && section !== "history",
          });
          boxes[section] = input;
          return el("label", { class: "check-row" }, [
            input,
            el("span", {}, [
              el("strong", {}, titleCase(section)),
              el("span", { class: "panel-sub" }, " " + SECTION_HINT[section]),
            ]),
          ]);
        }));

      const mayWrite = el("input", { type: "checkbox", checked: !!role?.may_write });
      const maySwitch = el("input", { type: "checkbox", checked: !!role?.may_switch_view });

      box.append(
        field("Role name", name, isNew ? "Lowercase identifier. Cannot be changed later." : "Fixed once created."),
        field("Display label", label),
        field("Description", description),
      );
      box.append(el("div", { class: "section-label" }, "Sidebar sections"), sectionList);
      box.append(el("div", { class: "section-label" }, "Permissions"));
      box.append(el("div", { style: "display:flex;flex-direction:column;gap:.3rem" }, [
        el("label", { class: "check-row" }, [mayWrite,
          el("span", {}, [el("strong", {}, "Can run analyses"),
            el("span", { class: "panel-sub" }, " — upload files and delete runs")])]),
        el("label", { class: "check-row" }, [maySwitch,
          el("span", {}, [el("strong", {}, "Can switch dashboard views"),
            el("span", { class: "panel-sub" }, " — otherwise locked to the preset below")])]),
      ]));
      box.append(field("Default dashboard view", view));

      box.append(el("div", { class: "actions" }, [
        el("button", { class: "btn ghost", onclick: close }, "Cancel"),
        el("button", {
          class: "btn primary",
          onclick: async (e) => {
            const btn = e.currentTarget;
            btn.disabled = true;
            const payload = {
              name: name.value.trim().toLowerCase().replace(/\s+/g, "_"),
              label: label.value.trim() || name.value.trim(),
              sections: Object.entries(boxes).filter(([, i]) => i.checked).map(([k]) => k),
              view: view.value,
              may_write: mayWrite.checked,
              may_switch_view: maySwitch.checked,
              description: description.value.trim(),
            };
            try {
              if (isNew) await api.post("/admin/roles", payload);
              else await api.putJson(`/admin/roles/${role.name}`, payload);
              close();
              toast(isNew ? "Role created" : "Role updated");
              paint();
            } catch (err) {
              toastError(err);
              btn.disabled = false;
            }
          },
        }, isNew ? "Create role" : "Save changes"),
      ]));
    });
  }

  async function removeRole(role) {
    const ok = await confirmDialog("Delete this role?",
      `${role.label} will be removed. Accounts using it must be reassigned first.`,
      { danger: true, confirmLabel: "Delete" });
    if (!ok) return;
    try {
      await api.del(`/admin/roles/${role.name}`);
      toast("Role deleted");
      paint();
    } catch (err) { toastError(err); }
  }

  // ── Activity ───────────────────────────────────────────────────────
  async function renderActivity(host) {
    const filters = { limit: 100, offset: 0, action: "", search: "", outcome: "" };
    const toolbar = el("div", { class: "toolbar" });
    const results = el("div");
    host.replaceChildren(toolbar, results);

    await load();

    async function load() {
      results.replaceChildren(loading());
      const data = await api.get(`/admin/audit${qs(filters)}`);
      buildToolbar(data.actions);
      results.replaceChildren(buildTable(data));
    }

    function buildToolbar(actions) {
      clear(toolbar);
      toolbar.append(
        el("div", { class: "search-wrap" }, [
          svgIcon(SEARCH_ICON),
          el("input", {
            type: "search", placeholder: "Search user, target or detail…",
            value: filters.search,
            oninput: debounce((e) => { filters.search = e.target.value; filters.offset = 0; load(); }, 280),
          }),
        ]),
        el("select", {
          class: "mini-select",
          onchange: (e) => { filters.action = e.target.value; filters.offset = 0; load(); },
        }, [
          el("option", { value: "" }, "All events"),
          ...actions.map((a) => el("option", { value: a, selected: a === filters.action }, a)),
        ]),
        el("button", {
          class: "chip", "aria-pressed": String(filters.outcome === "denied"),
          onclick: () => {
            filters.outcome = filters.outcome === "denied" ? "" : "denied";
            filters.offset = 0; load();
          },
        }, "Denied only"),
      );
    }

    function buildTable(data) {
      if (!data.total) {
        return panel("Activity log", empty("Nothing recorded yet",
          "Sign-ins, analyses and administrative changes appear here."));
      }
      const rows = data.items.map((entry) => el("tr", {}, [
        el("td", { class: "muted", title: fmtDate(entry.ts), style: "white-space:nowrap" },
          relativeTime(entry.ts)),
        el("td", {}, entry.actor_name
          ? el("div", {}, [
              el("div", { class: "rule-name" }, entry.actor_name),
              entry.actor_role ? el("div", { class: "panel-sub" }, titleCase(entry.actor_role)) : null,
            ])
          : el("span", { class: "muted" }, "—")),
        el("td", {}, el("span", { class: "mono", style: "font-size:.78rem" }, entry.action)),
        el("td", { class: "truncate", style: "max-width:22ch", title: entry.target || "" },
          entry.target || "—"),
        el("td", {}, entry.outcome === "ok"
          ? el("span", { class: "pill allow" }, "ok")
          : el("span", { class: "pill deny" }, entry.outcome)),
        el("td", { class: "muted mono", style: "font-size:.75rem" }, entry.ip || "—"),
        el("td", { class: "muted truncate", style: "max-width:28ch", title: entry.detail || "" },
          entry.detail || "—"),
      ]));

      const shown = Math.min(filters.offset + filters.limit, data.total);
      return panel("Activity log", [
        el("div", { class: "table-wrap" }, el("table", { class: "data" }, [
          el("thead", {}, el("tr", {}, [
            el("th", {}, "When"), el("th", {}, "Who"), el("th", {}, "Event"),
            el("th", {}, "Target"), el("th", {}, "Outcome"), el("th", {}, "From"),
            el("th", {}, "Detail"),
          ])),
          el("tbody", {}, rows),
        ])),
        el("div", { class: "pager" }, [
          `${fmtNumber(filters.offset + 1)}–${fmtNumber(shown)} of ${fmtNumber(data.total)}`,
          el("button", {
            class: "btn ghost small", disabled: filters.offset === 0,
            onclick: () => { filters.offset = Math.max(0, filters.offset - filters.limit); load(); },
          }, "Newer"),
          el("button", {
            class: "btn ghost small", disabled: shown >= data.total,
            onclick: () => { filters.offset += filters.limit; load(); },
          }, "Older"),
        ]),
      ], { sub: `${fmtNumber(data.total)} events` });
    }
  }
}

const SECTION_HINT = {
  dashboard: "— the Overview screen",
  analysis: "— findings, rules, zones, logging, report",
  configuration: "— run new analyses and change settings",
  history: "— the list of past analyses",
};

function field(label, input, hint) {
  return el("div", { class: "field" }, [
    el("label", {}, label), input,
    hint ? el("span", { class: "field-hint" }, hint) : null,
  ]);
}
