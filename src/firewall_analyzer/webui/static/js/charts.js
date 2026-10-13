// Inline-SVG charts — no chart library, so the app stays self-contained and
// works offline under a strict CSP.
//
// Colour rules this file follows:
//  * Severity is a STATUS palette (reserved roles) — it is always paired with a
//    text label in the legend, never left to carry meaning by hue alone.
//  * The ranked category list is a MAGNITUDE job — one hue for every bar.
//    Giving each category its own colour would imply identity that isn't there.
//  * The trend chart is the only CATEGORICAL use: two fixed series colours,
//    validated for CVD separation and assigned in fixed order.
//  * Stacked severity bars and meters are STATUS jobs too: a segment's colour
//    is its severity, and every one ships with a legend or a label.
//
// Hover: DOM and SVG marks carry `data-tip`; one shared tooltip (installed
// once) reads it on pointer hover and on keyboard focus. Tooltips enhance -
// every value is also printed in a legend, label or table beside the chart.
//
// Every colour is read from a CSS custom property so both themes come from the
// same stylesheet and dark mode is a selected palette, not an inverted one.

import { el } from "./ui.js";

const NS = "http://www.w3.org/2000/svg";

export function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function svg(w, h, { responsive = true } = {}) {
  const s = document.createElementNS(NS, "svg");
  s.setAttribute("viewBox", `0 0 ${w} ${h}`);
  if (responsive) {
    s.setAttribute("width", "100%");
    s.style.maxWidth = `${w}px`;
  } else {
    s.setAttribute("width", w);
    s.setAttribute("height", h);
  }
  s.setAttribute("role", "img");
  return s;
}

function node(name, attrs) {
  const n = document.createElementNS(NS, name);
  for (const [k, v] of Object.entries(attrs)) if (v != null) n.setAttribute(k, v);
  return n;
}

function svgText(x, y, content, { size = 11, cls = "ch-muted", weight = null, anchor = "middle" } = {}) {
  const t = node("text", { x, y, "text-anchor": anchor, "font-size": size, class: cls });
  if (weight) t.setAttribute("font-weight", weight);
  t.textContent = content;
  return t;
}

export const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
export const sevColor = (level) => cssVar(`--sev-${level}`) || cssVar("--muted");

// ───────────────────────────────────────────────── donut

/**
 * Severity donut. `counts` is { critical: n, high: n, ... }.
 * A 2px surface-coloured gap separates adjacent segments so they stay legible
 * where two similar steps meet. The centre carries the headline number.
 */
export function severityDonut(counts, { size = 190, stroke = 26 } = {}) {
  const slices = SEV_ORDER
    .map((level) => ({ level, count: Number(counts?.[level] || 0) }))
    .filter((s) => s.count > 0);
  const total = slices.reduce((a, s) => a + s.count, 0);

  const r = (size - stroke) / 2 - 2;
  const cx = size / 2, cy = size / 2;
  const s = svg(size, size);
  s.setAttribute("aria-label", `Findings by severity, ${total} total`);

  const circumference = 2 * Math.PI * r;
  const GAP = 2; // px of surface between segments

  if (total === 0) {
    s.append(node("circle", { cx, cy, r, fill: "none", "stroke-width": stroke, class: "ch-track" }));
  } else {
    let offset = 0;
    for (const slice of slices) {
      const len = (slice.count / total) * circumference;
      const dash = Math.max(len - GAP, 1);
      s.append(node("circle", {
        cx, cy, r, fill: "none",
        stroke: sevColor(slice.level),
        "stroke-width": stroke,
        "stroke-dasharray": `${dash} ${circumference - dash}`,
        "stroke-dashoffset": -offset,
        transform: `rotate(-90 ${cx} ${cy})`,
      }));
      offset += len;
    }
  }

  s.append(svgText(cx, cy - 2, total.toLocaleString(), { size: 30, cls: "ch-text", weight: 700 }));
  s.append(svgText(cx, cy + 17, "findings", { size: 11 }));
  return s;
}

/** Legend rows: swatch + label + count + share. Identity never rests on colour. */
export function severityLegend(counts) {
  const total = SEV_ORDER.reduce((a, l) => a + Number(counts?.[l] || 0), 0);
  return el("div", { class: "chart-legend" },
    SEV_ORDER.filter((l) => Number(counts?.[l] || 0) > 0).map((level) => {
      const n = Number(counts[level]);
      const pct = total ? ((n / total) * 100).toFixed(1) : "0.0";
      return el("span", { class: "item" }, [
        el("span", { class: "swatch", style: `background:${sevColor(level)}` }),
        el("span", { class: "lg-label" }, level[0].toUpperCase() + level.slice(1)),
        el("span", { class: "lg-value" }, `${n.toLocaleString()} (${pct}%)`),
      ]);
    })
  );
}

// ───────────────────────────────────────────── ranked bars

/**
 * Ranked magnitude bars, built in DOM rather than SVG so the labels wrap and
 * truncate with normal CSS. One hue for every bar — see the note at the top.
 *
 * Rows may carry `onClick` (the row becomes a button) and `display` (the
 * printed value, when it should read differently from the raw number).
 * `peak` fixes the scale — pass the population size to show shares rather
 * than lengths relative to the largest row.
 */
export function rankedBars(items, { max = 6, labelKey = "label", valueKey = "value",
                                    sort = true, peak = null } = {}) {
  const rows = (sort ? [...items].sort((a, b) => b[valueKey] - a[valueKey]) : [...items]).slice(0, max);
  const top = peak || Math.max(...rows.map((r) => r[valueKey]), 1);
  return el("div", { class: "hbars" },
    rows.map((row) => {
      const value = Number(row[valueKey]) || 0;
      const pct = value ? Math.min(Math.max((value / top) * 100, 1.5), 100) : 0;
      const shown = row.display ?? value.toLocaleString();
      return el(row.onClick ? "button" : "div", {
        class: `hbar-row${row.onClick ? " is-link" : ""}`,
        type: row.onClick ? "button" : null,
        onclick: row.onClick || null,
        "data-tip": row.tip || `${row[labelKey]}: ${shown}`,
      }, [
        el("span", { class: "hbar-label" }, row[labelKey]),
        el("span", { class: "hbar-track" },
          el("span", { class: "hbar-fill", style: pct ? `width:${pct}%` : "width:0;min-width:0" })),
        el("span", { class: "hbar-val" }, shown),
      ]);
    })
  );
}

// ──────────────────────────────────────────────── trend

/**
 * Multi-series line chart with a crosshair + tooltip.
 *
 * `series` is [{ name, values: number[], color }] and `labels` the x labels.
 * One y-axis only: both series are finding counts, so they share a scale. Two
 * measures of different scale would need two charts, never a second axis.
 */
export function trendChart(labels, series, { width = 520, height = 190 } = {}) {
  const pad = { top: 14, right: 14, bottom: 26, left: 40 };
  const plotW = width - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;

  const all = series.flatMap((s) => s.values);
  const maxY = Math.max(...all, 1);
  const niceMax = Math.ceil(maxY / 5) * 5 || 5;
  const n = labels.length;

  const x = (i) => pad.left + (n <= 1 ? plotW / 2 : (i / (n - 1)) * plotW);
  const y = (v) => pad.top + plotH - (v / niceMax) * plotH;

  const s = svg(width, height);
  s.setAttribute("aria-label", `Trend of ${series.map((v) => v.name).join(" and ")}`);

  // Recessive gridlines and y ticks
  for (let t = 0; t <= 4; t++) {
    const value = (niceMax / 4) * t;
    const yy = y(value);
    s.append(node("line", { x1: pad.left, y1: yy, x2: width - pad.right, y2: yy, class: "ch-grid" }));
    s.append(svgText(pad.left - 7, yy + 3.5, String(Math.round(value)), { size: 10, anchor: "end" }));
  }

  // X labels: first, last and middle only, so they never collide
  // The end labels anchor inward so a long date never runs off the plot.
  labels.forEach((label, i) => {
    if (n > 3 && i !== 0 && i !== n - 1 && i !== Math.floor(n / 2)) return;
    const anchor = n > 1 && i === 0 ? "start" : n > 1 && i === n - 1 ? "end" : "middle";
    s.append(svgText(x(i), height - 8, label, { size: 10, anchor }));
  });

  for (const item of series) {
    const points = item.values.map((v, i) => `${x(i)},${y(v)}`).join(" ");
    s.append(node("polyline", {
      points, fill: "none", stroke: item.color,
      "stroke-width": 2, "stroke-linejoin": "round", "stroke-linecap": "round",
    }));
    // Markers are >=8px across and carry a surface ring so overlaps stay readable
    item.values.forEach((v, i) => {
      s.append(node("circle", {
        cx: x(i), cy: y(v), r: 4, fill: item.color,
        stroke: cssVar("--surface"), "stroke-width": 2,
      }));
    });
  }

  // ── hover layer: crosshair + tooltip, on by default
  const crosshair = node("line", {
    y1: pad.top, y2: pad.top + plotH, class: "ch-axis", "stroke-dasharray": "3 3", opacity: 0,
  });
  s.append(crosshair);

  const wrap = el("div", { style: "position:relative;width:100%" }, s);
  const tip = el("div", {
    style: `position:absolute;pointer-events:none;opacity:0;transition:opacity .1s;
            background:var(--surface);border:1px solid var(--line);border-radius:7px;
            box-shadow:var(--card-shadow);padding:.45rem .6rem;font-size:.78rem;white-space:nowrap;z-index:5`,
  });
  wrap.append(tip);

  s.addEventListener("mousemove", (event) => {
    const box = s.getBoundingClientRect();
    const scale = width / box.width;
    const px = (event.clientX - box.left) * scale;
    let idx = Math.round(((px - pad.left) / plotW) * (n - 1));
    idx = Math.max(0, Math.min(n - 1, idx));

    crosshair.setAttribute("x1", x(idx));
    crosshair.setAttribute("x2", x(idx));
    crosshair.setAttribute("opacity", 1);

    tip.replaceChildren(
      el("div", { style: "font-weight:700;margin-bottom:.2rem" }, labels[idx]),
      ...series.map((item) =>
        el("div", { style: "display:flex;align-items:center;gap:.4rem" }, [
          el("span", { style: `width:8px;height:8px;border-radius:2px;background:${item.color}` }),
          `${item.name}: ${item.values[idx]}`,
        ])
      )
    );
    tip.style.opacity = 1;
    const leftPx = (x(idx) / width) * box.width;
    tip.style.left = `${Math.min(Math.max(leftPx - 40, 0), box.width - 130)}px`;
    tip.style.top = "4px";
  });
  s.addEventListener("mouseleave", () => {
    crosshair.setAttribute("opacity", 0);
    tip.style.opacity = 0;
  });

  return wrap;
}

/** Legend for the trend chart — always present because there are 2 series. */
export function seriesLegend(series) {
  return el("div", { class: "chart-legend", style: "flex-direction:row;gap:1rem" },
    series.map((item) =>
      el("span", { class: "item" }, [
        el("span", { class: "swatch", style: `background:${item.color}` }),
        el("span", { class: "lg-label" }, item.name),
      ])
    )
  );
}

// ─────────────────────────────────────────── stacked bar

/**
 * Horizontal part-to-whole bar. `segments` is [{ label, value, color }].
 * Segments are separated by a 2px surface gap (the flex gap), square at the
 * baseline and rounded only at the data end. `scale` (0–1) shortens the whole
 * bar so several stacks can share one magnitude axis.
 */
export function stackedBar(segments, { height = 12, scale = 1, label = "Breakdown" } = {}) {
  const shown = segments.filter((seg) => Number(seg.value) > 0);
  const bar = el("div", {
    class: "stack",
    role: "img",
    style: `height:${height}px;width:${Math.max(Math.min(scale, 1), 0.02) * 100}%`,
    "aria-label": `${label}: ${shown.map((seg) => `${seg.label} ${seg.value}`).join(", ") || "none"}`,
  });
  shown.forEach((seg, i) => {
    bar.append(el("span", {
      class: `stack-seg${i === shown.length - 1 ? " is-end" : ""}`,
      style: `flex:${seg.value} 1 0;background:${seg.color}`,
      "data-tip": seg.tip || `${seg.label}: ${Number(seg.value).toLocaleString()}`,
    }));
  });
  return bar;
}

/** Severity counts -> stacked-bar segments, worst first. */
export function severitySegments(counts, { suffix = "" } = {}) {
  return SEV_ORDER.map((level) => ({
    label: level[0].toUpperCase() + level.slice(1),
    value: Number(counts?.[level] || 0),
    color: sevColor(level),
    tip: `${level[0].toUpperCase() + level.slice(1)}: ${Number(counts?.[level] || 0).toLocaleString()}${suffix}`,
  }));
}

/** Inline legend for a stacked bar — swatch, label, count. */
export function inlineLegend(segments) {
  return el("div", { class: "chart-legend chart-legend--inline" },
    segments.filter((seg) => Number(seg.value) > 0 || seg.always).map((seg) =>
      el("span", { class: "item" }, [
        el("span", { class: "swatch", style: `background:${seg.color}` }),
        el("span", { class: "lg-label" }, seg.label),
        el("span", { class: "lg-value" }, Number(seg.value).toLocaleString()),
      ])
    )
  );
}

// ────────────────────────────────────────────────── meter

/**
 * A single share against its whole. The track is a light step of the fill's
 * own hue, so the state reads across the full width, not just the filled part.
 */
export function meter(value, total, { color = null, label = "", height = 8 } = {}) {
  const hue = color || cssVar("--ok");
  const pct = total ? Math.min((value / total) * 100, 100) : 0;
  return el("div", {
    class: "meter",
    role: "meter",
    "aria-valuemin": "0",
    "aria-valuemax": String(total || 0),
    "aria-valuenow": String(value || 0),
    "aria-label": label || `${value} of ${total}`,
    "data-tip": label || `${Number(value).toLocaleString()} of ${Number(total).toLocaleString()} (${Math.round(pct)}%)`,
    style: `height:${height}px;background:color-mix(in srgb, ${hue} 16%, transparent)`,
  }, el("span", { class: "meter-fill", style: `width:${pct}%;background:${hue}` }));
}

// ───────────────────────────────────────────── histogram

/**
 * Columns over ordered bands. `bins` is [{ label, count, emphasis }]: the
 * emphasised columns take the magnitude hue and the rest the de-emphasis gray,
 * so the story ("most rules sit above the line") reads without a legend.
 * `markAfter` draws a labelled reference line after that column index.
 */
export function histogram(bins, { width = 400, height = 200, markAfter = null, markLabel = "" } = {}) {
  const pad = { top: 26, right: 6, bottom: 28, left: 6 };
  const plotW = width - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;
  const n = bins.length;
  const band = plotW / n;
  const barW = Math.min(24, band - 6);
  const peak = Math.max(...bins.map((b) => b.count), 1);

  const s = svg(width, height);
  s.setAttribute("aria-label", bins.map((b) => `${b.label}: ${b.count}`).join(", "));

  const baseY = pad.top + plotH;
  s.append(node("line", { x1: pad.left, x2: width - pad.right, y1: baseY, y2: baseY, class: "ch-axis" }));

  bins.forEach((b, i) => {
    const cx = pad.left + band * i + band / 2;
    const h = b.count ? Math.max((b.count / peak) * plotH, 3) : 0;
    const y = baseY - h;
    if (h) {
      // Rounded data end, square at the baseline.
      const r = Math.min(4, h, barW / 2);
      const x0 = cx - barW / 2, x1 = cx + barW / 2;
      s.append(node("path", {
        d: `M${x0},${baseY} V${y + r} Q${x0},${y} ${x0 + r},${y} H${x1 - r} Q${x1},${y} ${x1},${y + r} V${baseY} Z`,
        fill: b.emphasis ? cssVar("--magnitude") : cssVar("--muted"),
        opacity: b.emphasis ? 1 : 0.45,
      }));
    }
    s.append(svgText(cx, y - 6, b.count.toLocaleString(), { size: 10.5, cls: "ch-text", weight: 650 }));
    s.append(svgText(cx, height - 9, b.label, { size: 9.5 }));

    // Hit target: the whole band, not just the column.
    const hit = node("rect", {
      x: pad.left + band * i, y: pad.top, width: band, height: plotH,
      fill: "transparent", "data-tip": b.tip || `${b.label}: ${b.count.toLocaleString()}`,
    });
    s.append(hit);
  });

  if (markAfter != null && markAfter >= 0 && markAfter < n - 1) {
    const x = pad.left + band * (markAfter + 1);
    s.append(node("line", {
      x1: x, x2: x, y1: pad.top - 12, y2: baseY,
      class: "ch-axis", "stroke-dasharray": "3 3", "stroke-width": 1.2,
    }));
    s.append(svgText(x + 5, pad.top - 14, markLabel, { size: 9.5, anchor: "start" }));
  }
  return s;
}

// ─────────────────────────────────────────────── heat cell

/** Background for a sequential heat cell: one hue, opacity carries magnitude. */
export function heatStyle(value, peak) {
  if (!value) return "";
  const share = 8 + Math.round((value / Math.max(peak, 1)) * 42);
  return `background:color-mix(in srgb, var(--magnitude) ${share}%, transparent)`;
}

// ───────────────────────────────────────────────── tooltip

let tipNode = null;

/** Install the shared tooltip once. Safe to call on every render. */
export function installTooltips() {
  if (tipNode) return;
  tipNode = el("div", { class: "ch-tip", role: "tooltip", hidden: true });
  document.body.append(tipNode);

  const place = (x, y) => {
    const box = tipNode.getBoundingClientRect();
    const left = Math.min(x + 14, window.innerWidth - box.width - 8);
    const top = y + 16 + box.height > window.innerHeight ? y - box.height - 12 : y + 16;
    tipNode.style.left = `${Math.max(left, 8)}px`;
    tipNode.style.top = `${Math.max(top, 8)}px`;
  };
  const show = (target, x, y) => {
    tipNode.textContent = target.getAttribute("data-tip");
    tipNode.hidden = false;
    place(x, y);
  };
  const hide = () => { tipNode.hidden = true; };
  const tipTarget = (node) => (node && node.closest ? node.closest("[data-tip]") : null);

  document.addEventListener("pointerover", (e) => {
    const t = tipTarget(e.target);
    if (t) show(t, e.clientX, e.clientY);
  });
  document.addEventListener("pointermove", (e) => {
    if (!tipNode.hidden && tipTarget(e.target)) place(e.clientX, e.clientY);
  });
  document.addEventListener("pointerout", (e) => {
    if (tipTarget(e.target) && !tipTarget(e.relatedTarget)) hide();
  });
  document.addEventListener("focusin", (e) => {
    const t = tipTarget(e.target);
    if (!t) return;
    const r = t.getBoundingClientRect();
    show(t, r.left, r.bottom - 10);
  });
  document.addEventListener("focusout", hide);
  window.addEventListener("hashchange", hide);
  window.addEventListener("scroll", hide, { passive: true });
}
