// privnet UI behaviour. Everything degrades gracefully without JavaScript.
(function () {
  "use strict";

  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  // Screen-reader announcements (copy feedback etc.)
  const live = document.createElement("div");
  live.className = "sr-only";
  live.setAttribute("aria-live", "polite");
  document.body.appendChild(live);
  const announce = (msg) => { live.textContent = ""; setTimeout(() => (live.textContent = msg), 30); };

  // ---- copy ----
  function copyText(text, btn) {
    const done = () => {
      const old = btn.textContent;
      btn.textContent = "Copied";
      btn.classList.add("copied");
      announce("Copied to clipboard");
      setTimeout(() => { btn.textContent = old; btn.classList.remove("copied"); }, 1400);
    };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done, () => fallback());
    } else fallback();
    function fallback() {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy"); } catch (e) {}
      ta.remove();
      done();
    }
  }
  $$("pre.code").forEach((pre) => {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "copy-btn";
    b.textContent = "Copy";
    b.setAttribute("aria-label", "Copy to clipboard");
    b.addEventListener("click", () => {
      const clone = pre.cloneNode(true);
      clone.querySelectorAll(".copy-btn").forEach((x) => x.remove());
      copyText(clone.textContent.replace(/\n$/, ""), b);
    });
    pre.appendChild(b);
  });
  $$("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const el = $(btn.dataset.copy);
      if (!el) return;
      let text;
      if (el.tagName === "INPUT") text = el.value;
      else {
        const clone = el.cloneNode(true);
        clone.querySelectorAll(".copy-btn").forEach((x) => x.remove());
        text = clone.textContent;
      }
      copyText(text, btn);
    });
  });

  // ---- forms ----
  // Native confirm for destructive actions: <form data-confirm="...">
  $$("form[data-confirm]").forEach((f) => {
    f.addEventListener("submit", (e) => { if (!confirm(f.dataset.confirm)) e.preventDefault(); });
  });
  // Type-to-confirm: enable the button only when the input matches
  $$("form[data-confirm-match]").forEach((f) => {
    const input = $("input[name=confirm]", f), btn = $("button", f);
    if (!input || !btn) return;
    const upd = () => { btn.disabled = input.value.trim() !== f.dataset.confirmMatch; };
    input.addEventListener("input", upd);
    upd();
  });
  // Busy state: prevent double submits and show progress (runs after confirm handlers)
  document.addEventListener("submit", (e) => {
    if (e.defaultPrevented) return;
    const btn = e.submitter || $("button[data-busy]", e.target);
    if (!btn || !btn.dataset.busy) return;
    setTimeout(() => {
      btn.setAttribute("aria-busy", "true");
      btn.disabled = true;
      btn.textContent = btn.dataset.busy;
    }, 0);
  });
  // Pages restored from the back/forward cache must not keep disabled buttons
  window.addEventListener("pageshow", (e) => {
    if (!e.persisted) return;
    $$("button[aria-busy=true]").forEach((b) => { b.disabled = false; b.removeAttribute("aria-busy"); });
  });
  // Show / hide password
  $$("[data-pw-toggle]").forEach((t) => {
    t.addEventListener("click", () => {
      const input = t.previousElementSibling;
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      t.textContent = show ? "Hide" : "Show";
      t.setAttribute("aria-label", show ? "Hide password" : "Show password");
      input.focus();
    });
  });

  // ---- disclosure ----
  const openTarget = (sel, focusSel) => {
    let el;
    try { el = $(sel); } catch (e) { return; }
    if (!el) return;
    for (let d = el; d; d = d.parentElement) if (d.tagName === "DETAILS") d.open = true;
    el.scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
    const f = focusSel ? $(focusSel) : ($("input:not([type=hidden])", el) || $("summary", el));
    if (f) setTimeout(() => f.focus({ preventScroll: true }), 250);
  };
  $$("[data-open]").forEach((a) => {
    a.addEventListener("click", (e) => {
      e.preventDefault();
      history.replaceState(null, "", a.getAttribute("href"));
      openTarget(a.dataset.open, a.dataset.focus);
    });
  });
  const openFromHash = () => {
    if (!location.hash || location.hash.length < 2) return;
    let el;
    try { el = $(location.hash); } catch (e) { return; }
    for (let d = el; d; d = d.parentElement) if (d.tagName === "DETAILS") d.open = true;
  };
  openFromHash();
  window.addEventListener("hashchange", openFromHash);

  // ---- flash messages ----
  const flash = $("[data-flash]");
  if (flash) {
    $("[data-dismiss]", flash).addEventListener("click", () => flash.remove());
    // Drop ?done=… so a reload doesn't repeat the message
    const u = new URL(location.href);
    if (u.searchParams.has("done")) {
      u.searchParams.delete("done");
      history.replaceState(null, "", u.pathname + (u.search || "") + u.hash);
    }
  }

  // ---- usage meters ----
  $$(".meter[data-pct]").forEach((m) => {
    const s = $("span", m);
    if (s) s.style.width = Math.min(100, +m.dataset.pct) + "%";
  });

  // ---- tabs (one group per page; arrow keys move between tabs) ----
  const tabs = $$(".tab[data-tab]");
  if (tabs.length) {
    const show = (key, focus) => {
      tabs.forEach((t) => {
        const on = t.dataset.tab === key;
        t.setAttribute("aria-selected", on ? "true" : "false");
        t.tabIndex = on ? 0 : -1;
        if (on && focus) t.focus();
      });
      $$(".tab-panel").forEach((p) => p.classList.toggle("active", p.dataset.panel === key));
    };
    tabs.forEach((t, i) => {
      const panel = $('.tab-panel[data-panel="' + t.dataset.tab + '"]');
      t.id = t.id || "tab-" + t.dataset.tab;
      if (panel) {
        panel.id = panel.id || "panel-" + t.dataset.tab;
        panel.setAttribute("role", "tabpanel");
        panel.setAttribute("aria-labelledby", t.id);
        t.setAttribute("aria-controls", panel.id);
      }
      t.type = "button";
      t.addEventListener("click", () => show(t.dataset.tab));
      t.addEventListener("keydown", (e) => {
        let j = null;
        if (e.key === "ArrowRight") j = (i + 1) % tabs.length;
        else if (e.key === "ArrowLeft") j = (i - 1 + tabs.length) % tabs.length;
        else if (e.key === "Home") j = 0;
        else if (e.key === "End") j = tabs.length - 1;
        if (j !== null) { e.preventDefault(); show(tabs[j].dataset.tab, true); }
      });
    });
    const initial = $('.tab[aria-selected="true"]') || tabs[0];
    show(initial.dataset.tab);
  }

  // ---- network size preview ----
  const sizeInput = $("[data-size-input]");
  if (sizeInput) {
    const upd = () => {
      const n = +sizeInput.value;
      let hostBits = 0;
      while (1 << hostBits < n + 3) hostBits++;
      $("[data-size-value]").textContent = n;
      $("[data-size-prefix]").textContent = "/" + (32 - hostBits);
      $("[data-size-total]").textContent = 1 << hostBits;
      $("[data-size-layout]").textContent = "gateway + " + n + " devices";
      sizeInput.setAttribute("aria-valuetext", n + " devices");
    };
    sizeInput.addEventListener("input", upd);
    upd();
  }

  // ---- live status (paused while the tab is hidden) ----
  const poller = (url, every, onData) => {
    let timer = null;
    const tick = () => {
      fetch(url, { credentials: "same-origin", headers: { Accept: "application/json" } })
        .then((r) => (r.ok ? r.json() : null))
        .then((d) => d && onData(d))
        .catch(() => {});
    };
    const start = () => { if (!timer) timer = setInterval(tick, every); };
    const stop = () => { clearInterval(timer); timer = null; };
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) stop(); else { tick(); start(); }
    });
    start();
  };

  const table = $("table[data-status-url]");
  if (table) {
    const countEl = $("[data-online-count]"), countPill = $("[data-online-pill]");
    poller(table.dataset.statusUrl, 5000, (rows) => {
      let online = 0;
      rows.forEach((s) => {
        if (s.online) online++;
        const tr = $('tr[data-device="' + s.id + '"]', table);
        if (!tr) return;
        $('[data-field="pill"]', tr).classList.toggle("pill-ok", s.online);
        $('[data-field="state"]', tr).textContent = s.online ? "online" : "offline";
        $('[data-field="hs"]', tr).textContent = s.lastHandshake;
        $('[data-field="traffic"]', tr).textContent = s.rx + " / " + s.tx;
      });
      if (countEl) countEl.textContent = online;
      if (countPill) countPill.classList.toggle("pill-ok", online > 0);
    });
  }

  // Device page: watch for the first handshake while the user follows the guide
  const devStatus = $("[data-device-status]");
  if (devStatus) {
    const id = +devStatus.dataset.deviceId;
    const stateEl = $("[data-device-state]", devStatus);
    let wasOnline = devStatus.classList.contains("pill-ok");
    poller(devStatus.dataset.deviceStatus, 4000, (rows) => {
      const s = rows.find((r) => r.id === id);
      if (!s) return;
      devStatus.classList.toggle("pill-ok", s.online);
      stateEl.textContent = s.online ? "connected · " + s.lastHandshake : "not connected yet";
      if (s.online && !wasOnline) {
        const banner = $("[data-connected-banner]");
        if (banner) { banner.hidden = false; banner.scrollIntoView({ block: "nearest" }); }
      }
      wasOnline = s.online;
    });
  }

  // ---- HTTPS form: show the proxy fields only in proxy mode ----
  const modeRadios = $$("input[data-mode]");
  const proxyFields = $("[data-proxy-fields]");
  if (modeRadios.length && proxyFields) {
    const upd = () => {
      const sel = $("input[data-mode]:checked");
      proxyFields.hidden = !sel || sel.value !== "proxy";
    };
    modeRadios.forEach((r) => r.addEventListener("change", upd));
    upd();
  }

  // Reload while the server prepares something (e.g. certificate issuance),
  // but not while the user is typing in a form.
  const auto = $("[data-autoreload]");
  if (auto) {
    const ms = (+auto.dataset.autoreload || 5) * 1000;
    const again = () => setTimeout(() => {
      const a = document.activeElement;
      if (a && /^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName)) return again();
      location.reload();
    }, ms);
    again();
  }
})();
