// Settings — what this deployment is pointed at, and the analyzer quirks the
// team needs to know about.

import { el, panel, toast } from "../ui.js";
import { loadMeta } from "../state.js";

export async function render(host) {
  const meta = await loadMeta();

  host.append(panel("Appearance", el("div", { class: "toolbar", style: "margin:0" }, [
    el("span", { class: "panel-sub" }, "Theme"),
    el("button", {
      class: "btn small",
      onclick: () => setTheme("light"),
    }, "Light"),
    el("button", { class: "btn small", onclick: () => setTheme("dark") }, "Dark"),
    el("button", {
      class: "btn small ghost",
      onclick: () => {
        localStorage.removeItem("fwa-theme");
        document.documentElement.dataset.theme =
          window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
        toast("Following system theme");
      },
    }, "Match system"),
  ])));

  host.append(el("div", { style: "height:1rem" }));

  host.append(panel("Supported vendors", el("div", { class: "tag-list" },
    meta.vendors.map((v) => el("span", { class: "tag" }, v.label))
  ), { sub: "column mappings are defined in field_mapping_schema.json" }));

  host.append(el("div", { style: "height:1rem" }));

  host.append(panel("Known analyzer behaviour", el("div", { style: "display:flex;flex-direction:column;gap:.8rem" }, [
    note("Vendor auto-detection is unreliable",
      "A FortiGate export is claimed by the Cisco ASA matcher, which tests its indicators with any() rather than all() and runs first. The wrong column mapping is then used and disabled rules are audited as if live. The wizard therefore asks for the vendor explicitly."),
    note("Application risk scoring depends on the config in use",
      "This service loads the full scoring config that ships inside the package. Running the CLI from the repo root instead picks up a minimal analysis_config.json that disables application risk scoring, which drops roughly a hundred findings on the sample ruleset."),
    note("Excel input is converted server-side",
      "The analyzer's parser reads CSV only; handing it a .xlsx produces a UTF-8 decode error. Uploads are converted before parsing, so either format works here."),
  ])));
}

function note(title, body) {
  return el("div", { class: "notice" }, el("div", {}, [
    el("div", { style: "font-weight:650;margin-bottom:.2rem" }, title),
    el("div", { class: "muted" }, body),
  ]));
}

function setTheme(t) {
  document.documentElement.dataset.theme = t;
  localStorage.setItem("fwa-theme", t);
  toast(`${t[0].toUpperCase() + t.slice(1)} theme applied`);
}
