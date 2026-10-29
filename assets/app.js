/* CORD Reports: progressive enhancement only. The page renders and reads fully without this file.
   - theme toggle: sets data-theme on <html>, remembers the choice in localStorage (wrapped in try/catch)
   - reading progress: sets --p (0..1) on the progress bar as the page scrolls
   - TOC scrollspy: marks the entry for the section currently in view */
(function () {
  "use strict";

  // --- theme toggle ---
  var root = document.documentElement;
  var btn = document.querySelector(".theme-toggle");
  function stored() {
    try { return localStorage.getItem("cord-theme"); } catch (e) { return null; }
  }
  function save(v) {
    try { localStorage.setItem("cord-theme", v); } catch (e) { /* private mode, ignore */ }
  }
  if (btn) {
    btn.addEventListener("click", function () {
      var current = root.getAttribute("data-theme");
      if (!current) {
        // no explicit choice yet: flip away from what the OS is showing
        var dark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
        current = dark ? "dark" : "light";
      }
      var next = current === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      save(next);
    });
  }

  // --- reading progress ---
  var bar = document.querySelector(".progress");
  if (bar) {
    var tick = false;
    var update = function () {
      var h = document.documentElement;
      var max = h.scrollHeight - h.clientHeight;
      var p = max > 0 ? h.scrollTop / max : 0;
      bar.style.setProperty("--p", p.toFixed(4));
      tick = false;
    };
    var onScroll = function () {
      if (!tick) { tick = true; requestAnimationFrame(update); }
    };
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll, { passive: true });
    update();
  }

  // --- TOC scrollspy ---
  var toc = document.querySelector(".toc");
  if (toc && "IntersectionObserver" in window) {
    var links = {};
    toc.querySelectorAll('a[href^="#"]').forEach(function (a) {
      var id = decodeURIComponent(a.getAttribute("href").slice(1));
      if (id) links[id] = a;
    });
    var headings = Object.keys(links)
      .map(function (id) { return document.getElementById(id); })
      .filter(Boolean);
    if (headings.length) {
      var visible = new Set();
      var mark = function () {
        toc.querySelectorAll("a.active").forEach(function (a) { a.classList.remove("active"); });
        if (!visible.size) return;
        // highest heading currently in view
        var top = headings.filter(function (h) { return visible.has(h.id); })
          .sort(function (a, b) { return a.offsetTop - b.offsetTop; })[0];
        if (top && links[top.id]) links[top.id].classList.add("active");
      };
      var obs = new IntersectionObserver(function (entries) {
        entries.forEach(function (e) {
          if (e.isIntersecting) visible.add(e.target.id);
          else visible.delete(e.target.id);
        });
        mark();
      }, { rootMargin: "-20% 0px -70% 0px", threshold: 0 });
      headings.forEach(function (h) { obs.observe(h); });
    }
  }
})();
