// honeypot.uig.me/reports.html: renders one weekly report (reports/YYYY-Www.json
// in the data repo) and the owner's optional notes (notes/YYYY-Www.md here).
// Report strings are attacker-controlled: only ever set with textContent. The
// notes are rendered by a small Markdown subset that builds DOM nodes, never HTML.
"use strict";

(function () {
  const params = new URLSearchParams(location.search);
  const DATA = params.get("data") || "https://raw.githubusercontent.com/estul-lachin/uig-honeypot-data/main/";
  const WEEK_RE = /^\d{4}-W\d{2}$/;
  const fmt = new Intl.NumberFormat("en");
  const $ = (id) => document.getElementById(id);
  const regionName = (() => {
    try { const d = new Intl.DisplayNames(["en"], { type: "region" }); return (cc) => d.of(cc); }
    catch (e) { return (cc) => cc; }
  })();
  const countryLabel = (cc) => (!cc || cc === "??") ? "Unknown" : (regionName(cc) || cc);

  const get = (url, as) => fetch(url, { cache: "no-cache" }).then((r) => {
    if (!r.ok) throw Object.assign(new Error(url + ": " + r.status), { status: r.status });
    return as === "text" ? r.text() : r.json();
  });

  // ---------- tables (same layout as the live page) ----------
  function fillTable(id, rows, render, key = "count") {
    const table = $(id);
    table.replaceChildren();
    if (!rows || !rows.length) {
      const td = table.insertRow().insertCell();
      td.className = "none";
      td.textContent = "Nothing this week";
      return;
    }
    const max = Math.max(...rows.map((r) => r[key]));
    for (const r of rows) {
      const tr = table.insertRow();
      const v = tr.insertCell();
      v.className = "v";
      render(v, r);
      const n = tr.insertCell();
      n.className = "n";
      n.textContent = fmt.format(r[key]);
      const b = tr.insertCell();
      b.className = "b";
      const i = document.createElement("i");
      i.style.width = (100 * r[key] / max).toFixed(1) + "%";
      b.appendChild(i);
    }
  }
  const textCell = (td, r) => { td.textContent = r.value === "" ? "(empty)" : r.value; td.title = td.textContent; };

  function ttpCell(td, r) {
    const a = document.createElement("a");
    a.href = "https://attack.mitre.org/techniques/" + r.id.replace(".", "/") + "/";
    a.rel = "noopener";
    a.textContent = r.id;
    const tactic = document.createElement("span");
    tactic.className = "tactic";
    tactic.textContent = r.tactic;
    td.append(a, " ", r.name, " ", tactic);
    td.title = r.id + " " + r.name + " (" + r.tactic + ")";
  }

  function downloadCell(td, r) {
    const a = document.createElement("a");
    a.href = "https://www.virustotal.com/gui/file/" + encodeURIComponent(r.sha256);
    a.rel = "noopener";
    a.textContent = r.sha256.slice(0, 12) + "…";
    td.append(a, " ", r.url);
    td.title = r.url;
  }

  // ---------- AbuseIPDB reputation (lookups only; no IPs in the data) ----------
  function renderReputation(r, fill, fmtN) {
    const card = document.getElementById("rep-card");
    if (!r || !r.checked) { card.hidden = true; return; }
    const pct = (n) => Math.round(100 * n / r.checked) + "%";
    document.getElementById("rep-summary").textContent =
      fmtN(r.checked) + " of " + fmtN(r.sources) + " sources looked up in AbuseIPDB. " +
      pct(r.never_reported) + " had never been reported by anyone: new infrastructure, not yet on blocklists." +
      (r.tor ? " " + fmtN(r.tor) + (r.tor === 1 ? " was a Tor exit node." : " were Tor exit nodes.") : "");
    const labels = { "0": "0 (no reports)", "1-24": "1–24", "25-74": "25–74", "75-100": "75–100 (known bad)" };
    fill("t-rep-scores", r.scores.map((b) => ({ value: labels[b.range] || b.range, count: b.sources })),
      (td, x) => { td.textContent = x.value; });
    fill("t-rep-usage", r.usage_types, (td, x) => { td.textContent = x.value; td.title = x.value; });
    card.hidden = false;
  }

  // ---------- KPIs ----------
  function renderStats(w) {
    for (const el of document.querySelectorAll("#stats .num")) el.textContent = fmt.format(w.totals[el.dataset.k] || 0);
    for (const el of document.querySelectorAll("#stats .delta")) {
      const now = w.totals[el.dataset.k] || 0, before = w.previous ? w.previous[el.dataset.k] || 0 : null;
      if (before === null) { el.textContent = w.partial ? "partial week" : ""; continue; }
      if (before === 0) { el.textContent = now ? "new vs last week" : "same as last week"; continue; }
      const pct = Math.round(100 * (now - before) / before);
      el.textContent = pct ? (pct > 0 ? "+" : "−") + Math.abs(pct) + "% vs last week" : "same as last week";
    }
  }

  function renderHours(w) {
    const box = $("hours");
    box.replaceChildren();
    const max = Math.max(1, ...w.hours_utc.map((h) => h.sessions));
    for (const h of w.hours_utc) {
      const col = document.createElement("div");
      col.className = "h";
      col.title = h.hour + ":00 UTC: " + fmt.format(h.sessions) + " sessions";
      const bar = document.createElement("i");
      bar.style.height = (100 * h.sessions / max).toFixed(1) + "%";
      const lab = document.createElement("span");
      lab.textContent = Number(h.hour) % 3 === 0 ? h.hour : "";
      col.append(bar, lab);
      box.appendChild(col);
    }
  }

  // ---------- notes: a Markdown subset, rendered as DOM nodes ----------
  function inline(parent, text) {
    const re = /`([^`]+)`|\*\*([^*]+)\*\*|\[([^\]]+)\]\((https:\/\/[^\s)]+)\)/g;
    let last = 0, m;
    while ((m = re.exec(text))) {
      if (m.index > last) parent.append(text.slice(last, m.index));
      let el;
      if (m[1] !== undefined) { el = document.createElement("code"); el.textContent = m[1]; }
      else if (m[2] !== undefined) { el = document.createElement("strong"); el.textContent = m[2]; }
      else { el = document.createElement("a"); el.href = m[4]; el.rel = "noopener"; el.textContent = m[3]; }
      parent.append(el);
      last = re.lastIndex;
    }
    if (last < text.length) parent.append(text.slice(last));
  }

  function renderMarkdown(box, md) {
    box.replaceChildren();
    const lines = md.replace(/\r\n?/g, "\n").split("\n");
    let para = null, list = null;
    const close = () => { para = null; list = null; };
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (/^```/.test(line)) {
        close();
        const pre = document.createElement("pre"), code = document.createElement("code"), body = [];
        while (++i < lines.length && !/^```/.test(lines[i])) body.push(lines[i]);
        code.textContent = body.join("\n");
        pre.appendChild(code);
        box.appendChild(pre);
      } else if (/^#{1,3}\s/.test(line)) {
        close();
        const level = line.match(/^#+/)[0].length;
        const h = document.createElement("h" + (level + 2)); // # → h3, the page already has h1/h2
        inline(h, line.replace(/^#+\s+/, ""));
        box.appendChild(h);
      } else if (/^\s*[-*]\s+/.test(line)) {
        para = null;
        if (!list) { list = document.createElement("ul"); box.appendChild(list); }
        const li = document.createElement("li");
        inline(li, line.replace(/^\s*[-*]\s+/, ""));
        list.appendChild(li);
      } else if (!line.trim()) {
        close();
      } else {
        list = null;
        if (!para) { para = document.createElement("p"); box.appendChild(para); }
        else para.append(" ");
        inline(para, line.trim());
      }
    }
  }

  // notes/index.json (written by the Pages workflow) lists the weeks that have a notes file, so a week
  // without one costs no failed request. The whole card stays hidden unless there are notes to show.
  const noteWeeks = get("notes/index.json").then((idx) => idx.weeks || []).catch(() => []);

  function renderNotes(week) {
    const box = $("notes"), card = box.closest(".notes");
    box.replaceChildren();
    card.hidden = true;
    noteWeeks.then((weeks) => {
      if (!weeks.includes(week)) return;
      return get("notes/" + week + ".md", "text").then((md) => {
        if (!md.trim() || $("week").value !== week) return;
        renderMarkdown(box, md);
        card.hidden = false;
      });
    }).catch((e) => console.warn(e));
  }

  // ---------- one week ----------
  function show(week) {
    $("status").textContent = "Loading " + week + "…";
    get(DATA + "reports/" + week + ".json").then((w) => {
      $("title").textContent = "Week " + w.week;
      $("range").textContent = w.from + " to " + w.to + " (UTC)" + (w.partial ? ", partial: the honeypot started mid-week" : "");
      renderStats(w);
      renderNotes(w.week);
      fillTable("t-ttps", w.ttps, ttpCell, "sessions");
      renderHours(w);
      renderReputation(w.reputation, fillTable, (n) => fmt.format(n));
      fillTable("t-new-passwords", w.new.passwords, textCell);
      fillTable("t-new-commands", w.new.commands, textCell);
      fillTable("t-downloads", w.downloads.filter((d) => d.new), downloadCell);
      fillTable("t-countries", w.countries.map((c) => ({ cc: c.cc, count: c.sessions })),
        (td, r) => { td.textContent = countryLabel(r.cc); });
      fillTable("t-pairs", w.top.pairs, textCell);
      fillTable("t-commands", w.top.commands, textCell);
      fillTable("t-usernames", w.top.usernames, textCell);
      fillTable("t-clients", w.top.clients, textCell);
      $("generated").textContent = "Generated " + w.generated_at.replace("T", " ").replace("Z", " UTC");
      $("report").hidden = false;
      $("status").textContent = "";
    }).catch((e) => {
      $("report").hidden = true;
      $("status").textContent = "Could not load the report for " + week + ".";
      console.error(e);
    });
  }

  get(DATA + "reports/index.json").then((idx) => {
    const weeks = (idx.weeks || []).filter((w) => WEEK_RE.test(w));
    const sel = $("week");
    sel.replaceChildren();
    if (!weeks.length) {
      sel.appendChild(new Option("None yet"));
      $("status").textContent = "The first report appears after the first full week (Monday 02:00 UTC).";
      return;
    }
    for (const w of weeks) sel.appendChild(new Option(w, w));
    const want = params.get("week");
    sel.value = WEEK_RE.test(want || "") && weeks.includes(want) ? want : weeks[0];
    sel.disabled = false;
    sel.addEventListener("change", () => {
      params.set("week", sel.value);
      history.replaceState(null, "", "?" + params.toString());
      show(sel.value);
    });
    show(sel.value);
  }).catch((e) => {
    $("week").replaceChildren(new Option("None yet"));
    $("status").textContent = "No reports yet. The first one appears after the first full week.";
    console.error(e);
  });
})();
