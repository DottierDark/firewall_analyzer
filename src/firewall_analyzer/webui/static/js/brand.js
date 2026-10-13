// Picks the right PwC logo file for the surface each mark sits on.
//
// The marks are real <img> elements in the markup — nothing is drawn. This only
// swaps the file, because the wordmark is dark ink on pwc-logo-light.png and
// white on pwc-logo-dark.png, and the two surfaces in this app differ:
//
//   * the sidebar is a FIXED dark surface in both themes, so it is pinned with
//     data-surface="dark" and never changes;
//   * the login card is a themed surface, so its mark follows the theme.

const CANDIDATES = {
  light: ["/img/pwc-logo-light.svg", "/img/pwc-logo-light.png", "/img/pwc-logo.png"],
  dark:  ["/img/pwc-logo-dark.svg", "/img/pwc-logo-dark.png", "/img/pwc-logo.png"],
};

const resolved = { light: null, dark: null };

function probe(src) {
  return new Promise((resolve) => {
    const image = new Image();
    image.onload = () => resolve(src);
    image.onerror = () => resolve(null);
    image.src = src;
  });
}

function surfaceFor(node) {
  const explicit = node.dataset?.surface;
  if (explicit === "light" || explicit === "dark") return explicit;
  return document.documentElement.dataset.theme === "dark" ? "dark" : "light";
}

export function applyPwcLogo() {
  document.querySelectorAll("img.pwc-logo").forEach((img) => {
    const src = resolved[surfaceFor(img)];
    if (src && img.getAttribute("src") !== src) img.src = src;
  });
}

export async function wirePwcLogo() {
  for (const surface of ["light", "dark"]) {
    for (const src of CANDIDATES[surface]) {
      const ok = await probe(src);
      if (ok) { resolved[surface] = ok; break; }
    }
  }
  applyPwcLogo();
}
