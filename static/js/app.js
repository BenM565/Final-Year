// STEP — shared UI interactivity
// Theme toggle, auto-dismiss alerts, live list filtering, password toggles,
// animated counters. Vanilla JS, no dependencies beyond Bootstrap's bundle.

(function () {
  "use strict";

  // ---------- Theme (light/dark) ----------
  const root = document.documentElement;

  function storedTheme() {
    try { return localStorage.getItem("step-theme"); } catch (e) { return null; }
  }

  function applyTheme(theme) {
    root.setAttribute("data-bs-theme", theme);
    document.querySelectorAll(".theme-toggle i").forEach(function (icon) {
      icon.className = theme === "dark" ? "bi bi-sun" : "bi bi-moon-stars";
    });
  }

  function initTheme() {
    const saved = storedTheme();
    const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    applyTheme(saved || (prefersDark ? "dark" : "light"));
  }

  initTheme();

  document.addEventListener("click", function (e) {
    const btn = e.target.closest(".theme-toggle");
    if (!btn) return;
    const next = root.getAttribute("data-bs-theme") === "dark" ? "light" : "dark";
    applyTheme(next);
    try { localStorage.setItem("step-theme", next); } catch (err) { /* private mode */ }
  });

  document.addEventListener("DOMContentLoaded", function () {

    // ---------- Auto-dismiss flash alerts ----------
    document.querySelectorAll(".flash-stack .alert").forEach(function (alert) {
      setTimeout(function () {
        if (!alert.isConnected) return;
        alert.style.transition = "opacity .4s ease, transform .4s ease";
        alert.style.opacity = "0";
        alert.style.transform = "translateY(-6px)";
        setTimeout(function () { alert.remove(); }, 450);
      }, 5000);
    });

    // ---------- Active nav link ----------
    const path = window.location.pathname;
    document.querySelectorAll(".step-nav .nav-link[href]").forEach(function (link) {
      const href = link.getAttribute("href");
      if (href && href !== "/" && path.startsWith(href)) link.classList.add("active");
    });

    // ---------- Live client-side filtering ----------
    // Any input with [data-live-filter="#containerSelector"] filters children
    // matching .search-highlightable inside that container as you type.
    document.querySelectorAll("[data-live-filter]").forEach(function (input) {
      const container = document.querySelector(input.getAttribute("data-live-filter"));
      if (!container) return;
      const counter = document.querySelector(input.getAttribute("data-live-count") || "");
      input.addEventListener("input", function () {
        const q = input.value.trim().toLowerCase();
        let visible = 0;
        container.querySelectorAll(".search-highlightable").forEach(function (item) {
          const match = !q || item.textContent.toLowerCase().includes(q);
          item.classList.toggle("d-none-by-filter", !match);
          if (match) visible++;
        });
        if (counter) counter.textContent = visible;
        const empty = container.querySelector("[data-live-empty]");
        if (empty) empty.classList.toggle("d-none", visible !== 0);
      });
    });

    // ---------- Password visibility toggles ----------
    document.querySelectorAll("[data-toggle-password]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        const target = document.querySelector(btn.getAttribute("data-toggle-password"));
        if (!target) return;
        const show = target.type === "password";
        target.type = show ? "text" : "password";
        const icon = btn.querySelector("i");
        if (icon) icon.className = show ? "bi bi-eye-slash" : "bi bi-eye";
      });
    });

    // ---------- Animated counters on stat tiles ----------
    const counters = document.querySelectorAll("[data-count-to]");
    if (counters.length && "IntersectionObserver" in window) {
      const seen = new WeakSet();
      const io = new IntersectionObserver(function (entries) {
        entries.forEach(function (entry) {
          if (!entry.isIntersecting || seen.has(entry.target)) return;
          seen.add(entry.target);
          animateCount(entry.target);
          io.unobserve(entry.target);
        });
      }, { threshold: 0.4 });
      counters.forEach(function (el) { io.observe(el); });
    } else {
      counters.forEach(function (el) { el.textContent = el.getAttribute("data-count-to"); });
    }

    function animateCount(el) {
      const target = parseInt(el.getAttribute("data-count-to"), 10) || 0;
      const duration = 700;
      const start = performance.now();
      function tick(now) {
        const p = Math.min((now - start) / duration, 1);
        const eased = 1 - Math.pow(1 - p, 3);
        el.textContent = Math.round(target * eased);
        if (p < 1) requestAnimationFrame(tick);
      }
      requestAnimationFrame(tick);
    }
  });
})();
