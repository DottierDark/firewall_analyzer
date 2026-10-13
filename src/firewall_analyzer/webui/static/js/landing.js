// Landing page behaviour: reveal on scroll, nav state, and the ambient grid.
// Everything degrades to a static page if JavaScript never runs — content is
// visible by default and only *enhanced* here.

const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

// ── Reveal on scroll ──────────────────────────────────────────────
// Elements start faded in CSS; if the observer is unavailable we show them all
// immediately rather than leaving the page blank.
const revealables = document.querySelectorAll(".reveal");

if (reduceMotion || !("IntersectionObserver" in window)) {
  revealables.forEach((node) => node.classList.add("is-in"));
} else {
  const observer = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      entry.target.classList.add("is-in");
      observer.unobserve(entry.target);
    }
  }, { rootMargin: "0px 0px -8% 0px", threshold: 0.06 });

  revealables.forEach((node) => observer.observe(node));

  // Anything already on screen at load should not wait for a scroll event —
  // the first frame a visitor sees must be the finished one.
  requestAnimationFrame(() => {
    revealables.forEach((node) => {
      if (node.getBoundingClientRect().top < window.innerHeight) node.classList.add("is-in");
    });
  });
}

// ── Nav: shadow once scrolled, highlight the section in view ──────
const nav = document.getElementById("nav");
const onScroll = () => nav.classList.toggle("is-stuck", window.scrollY > 8);
onScroll();
window.addEventListener("scroll", onScroll, { passive: true });

const links = [...document.querySelectorAll('.nav__links a[href^="#"]')];
const sections = links
  .map((link) => document.querySelector(link.getAttribute("href")))
  .filter(Boolean);

if ("IntersectionObserver" in window && sections.length) {
  const spy = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      links.forEach((link) =>
        link.classList.toggle("is-active", link.getAttribute("href") === `#${entry.target.id}`)
      );
    }
  }, { rootMargin: "-45% 0px -50% 0px" });
  sections.forEach((section) => spy.observe(section));
}

// ── Ambient grid ──────────────────────────────────────────────────
// A drifting lattice of nodes with links between near neighbours — a firewall
// reading as a mesh of permitted paths. Canvas rather than SVG because the
// point is motion, not shapes worth inspecting.
const canvas = document.getElementById("grid-canvas");

if (canvas && !reduceMotion) {
  const ctx = canvas.getContext("2d");
  let nodes = [];
  let raf = null;
  let width = 0;
  let height = 0;

  function size() {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    width = canvas.clientWidth;
    height = canvas.clientHeight;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    // Scale the node count to the area so a laptop is not drawing a
    // desktop's worth of geometry.
    const count = Math.min(58, Math.round((width * height) / 26000));
    nodes = Array.from({ length: count }, () => ({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.13,
      vy: (Math.random() - 0.5) * 0.13,
    }));
  }

  function frame() {
    ctx.clearRect(0, 0, width, height);

    for (const node of nodes) {
      node.x += node.vx;
      node.y += node.vy;
      if (node.x < 0 || node.x > width) node.vx *= -1;
      if (node.y < 0 || node.y > height) node.vy *= -1;
    }

    // Links first, so nodes sit on top of them.
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const dx = nodes[i].x - nodes[j].x;
        const dy = nodes[i].y - nodes[j].y;
        const distance = Math.hypot(dx, dy);
        if (distance > 132) continue;
        ctx.strokeStyle = `rgba(254, 81, 8, ${(1 - distance / 132) * 0.16})`;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(nodes[i].x, nodes[i].y);
        ctx.lineTo(nodes[j].x, nodes[j].y);
        ctx.stroke();
      }
    }

    ctx.fillStyle = "rgba(254, 81, 8, 0.42)";
    for (const node of nodes) {
      ctx.beginPath();
      ctx.arc(node.x, node.y, 1.5, 0, Math.PI * 2);
      ctx.fill();
    }

    raf = requestAnimationFrame(frame);
  }

  size();
  frame();

  let resizeTimer;
  window.addEventListener("resize", () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(size, 180);
  });

  // Stop animating while the tab is hidden — no reason to burn a laptop battery
  // drawing a background nobody is looking at.
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      cancelAnimationFrame(raf);
      raf = null;
    } else if (!raf) {
      frame();
    }
  });
}
