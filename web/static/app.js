// privnet UI behaviour: tabs, copy buttons, size preview, live status.
(function () {
  "use strict";

  function copyText(text, btn) {
    const done = () => {
      const old = btn.textContent;
      btn.textContent = "Copied";
      setTimeout(() => (btn.textContent = old), 1400);
    };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done);
    } else {
      const ta = document.createElement("textarea");
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
      done();
    }
  }

  // Copy buttons on every code block.
  document.querySelectorAll("pre.code").forEach((pre) => {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "copy-btn";
    b.textContent = "Copy";
    b.addEventListener("click", () => {
      const clone = pre.cloneNode(true);
      clone.querySelectorAll(".copy-btn").forEach((x) => x.remove());
      copyText(clone.textContent.replace(/\n$/, ""), b);
    });
    pre.appendChild(b);
  });

  // Explicit copy buttons: data-copy="#selector"
  document.querySelectorAll("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const el = document.querySelector(btn.dataset.copy);
      if (!el) return;
      let text = "value" in el && el.tagName === "INPUT" ? el.value : el.cloneNode(true);
      if (typeof text !== "string") {
        text.querySelectorAll(".copy-btn").forEach((x) => x.remove());
        text = text.textContent;
      }
      copyText(text, btn);
    });
  });

  // Confirm dialogs: <form data-confirm="...">
  document.querySelectorAll("form[data-confirm]").forEach((f) => {
    f.addEventListener("submit", (e) => {
      if (!confirm(f.dataset.confirm)) e.preventDefault();
    });
  });

  // Usage meters
  document.querySelectorAll(".meter[data-pct]").forEach((m) => {
    const s = m.querySelector("span");
    if (s) s.style.width = Math.min(100, +m.dataset.pct) + "%";
  });

  // Tabs (remember the last chosen platform per browser)
  const tabs = document.querySelectorAll(".tab[data-tab]");
  if (tabs.length) {
    const show = (key) => {
      tabs.forEach((t) => t.setAttribute("aria-selected", t.dataset.tab === key ? "true" : "false"));
      document.querySelectorAll(".tab-panel").forEach((p) => p.classList.toggle("active", p.dataset.panel === key));
    };
    tabs.forEach((t) => t.addEventListener("click", () => show(t.dataset.tab)));
    const initial = document.querySelector('.tab[aria-selected="true"]') || tabs[0];
    show(initial.dataset.tab);
  }

  // Network size preview
  const sizeInput = document.querySelector("[data-size-input]");
  if (sizeInput) {
    const upd = () => {
      const n = +sizeInput.value;
      let hostBits = 0;
      while (1 << hostBits < n + 3) hostBits++;
      const total = 1 << hostBits;
      document.querySelector("[data-size-value]").textContent = n;
      document.querySelector("[data-size-prefix]").textContent = "/" + (32 - hostBits);
      document.querySelector("[data-size-total]").textContent = total;
      document.querySelector("[data-size-layout]").textContent = "gateway + " + n + " devices";
    };
    sizeInput.addEventListener("input", upd);
    upd();
  }

  // Live device status
  const table = document.querySelector("table[data-status-url]");
  if (table) {
    const poll = () => {
      fetch(table.dataset.statusUrl, { credentials: "same-origin" })
        .then((r) => (r.ok ? r.json() : []))
        .then((rows) => {
          rows.forEach((s) => {
            const tr = table.querySelector('tr[data-device="' + s.id + '"]');
            if (!tr) return;
            tr.querySelector('[data-field="pill"]').classList.toggle("pill-ok", s.online);
            tr.querySelector('[data-field="state"]').textContent = s.online ? "online" : "offline";
            tr.querySelector('[data-field="hs"]').textContent = s.lastHandshake;
            tr.querySelector('[data-field="traffic"]').textContent = s.rx + " / " + s.tx;
          });
        })
        .catch(() => {});
    };
    setInterval(poll, 5000);
  }
})();
