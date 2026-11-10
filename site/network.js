// honeypot.uig.me/network.html: renders network.json (Suricata IDS alerts, counts only) from the data
// repo. Signature names and other strings are only ever set with textContent.
"use strict";

(function () {
  const params = new URLSearchParams(location.search);
  const DATA = params.get("data") || "https://raw.githubusercontent.com/estul-lachin/uig-honeypot-data/main/";
  const fmt = new Intl.NumberFormat("en");
  const $ = (id) => document.getElementById(id);
  const regionName = (() => {
    try { const d = new Intl.DisplayNames(["en"], { type: "region" }); return (cc) => d.of(cc); }
    catch (e) { return (cc) => cc; }
  })();
  const countryLabel = (cc) => (!cc || cc === "??") ? "Unknown" : (regionName(cc) || cc);
  // Well-known services, for labels only (Suricata's own protocol guess is unreliable on scans).
  const PORTS = {
    20: "FTP data", 21: "FTP", 22: "SSH (Cowrie)", 23: "Telnet (Cowrie)", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 123: "NTP", 135: "MS RPC", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 587: "SMTP", 993: "IMAPS", 1080: "SOCKS", 1433: "MS SQL", 1521: "Oracle",
    2375: "Docker API", 3306: "MySQL", 3389: "RDP", 5060: "SIP", 5432: "PostgreSQL", 5555: "ADB",
    5900: "VNC", 6379: "Redis", 8080: "HTTP alt", 8443: "HTTPS alt", 8888: "HTTP alt", 9200: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB",
  };
  const SEV = { 1: "high", 2: "medium", 3: "low" };

  function fillTable(id, rows, render, key = "count") {
    const table = $(id);
    table.replaceChildren();
    if (!rows || !rows.length) {
      const td = table.insertRow().insertCell();
      td.className = "none";
      td.textContent = "None in this period";
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
  const text = (s) => (td) => { td.textContent = s; td.title = s; };

  function link(href, label) {
    const a = document.createElement("a");
    a.href = href;
    a.rel = "noopener";
    a.textContent = label;
    return a;
  }

  function chip(label) {
    const s = document.createElement("span");
    s.className = "tactic";
    s.textContent = label;
    return s;
  }

  function renderDaily(d) {
    const box = $("per-day");
    box.replaceChildren();
    const days = d.daily;
    box.style.gridTemplateColumns = "repeat(" + Math.max(days.length, 1) + ", minmax(0, 1fr))";
    const max = Math.max(1, ...days.map((x) => x.alerts));
    const every = Math.ceil(days.length / 8);
    days.forEach((x, i) => {
      const col = document.createElement("div");
      col.className = "h";
      col.title = x.day + ": " + fmt.format(x.alerts) + " alerts from " + fmt.format(x.sources) + " sources" +
        (x.high ? ", " + fmt.format(x.high) + " high severity" : "");
      const bar = document.createElement("i");
      bar.style.height = (100 * x.alerts / max).toFixed(1) + "%";
      if (x.high) bar.className = "hi";
      const lab = document.createElement("span");
      lab.textContent = i % every === 0 ? x.day.slice(5) : "";
      col.append(bar, lab);
      box.appendChild(col);
    });
    box.setAttribute("aria-label", "Alerts per day, " + (days[0] ? days[0].day : "") + " to " +
      (days.length ? days[days.length - 1].day : ""));
    const hi = days.filter((x) => x.high).length;
    $("per-day-note").textContent = days.length < d.days
      ? "The sensor started on " + d.first_day + "; the chart fills up to " + d.days + " days."
      : (hi ? "Darker bars: days with a high-severity alert." : "");
  }

  function renderOverlap(c) {
    if (!c || !c.sources) return;
    const pct = Math.round(100 * c.suricata_only / c.sources);
    $("overlap-text").textContent = pct + "% of the sources Suricata flagged (" + fmt.format(c.suricata_only) +
      " of " + fmt.format(c.sources) + ") never opened a session on the SSH/Telnet honeypot: database and RDP " +
      "scanners, web exploits and blocklisted hosts that Cowrie alone would not have seen.";
    const bar = $("overlap-bar"), legend = $("overlap-legend");
    bar.replaceChildren();
    legend.replaceChildren();
    for (const [k, n, label] of [["only", c.suricata_only, "Suricata only"], ["both", c.also_cowrie, "Also in Cowrie"]]) {
      const key = document.createElement("span");
      key.className = "key";
      const sw = document.createElement("i");
      sw.className = "sw " + k;
      key.append(sw, label + ": " + fmt.format(n));
      legend.appendChild(key);
      if (!n) continue;
      const s = document.createElement("span");
      s.className = k;
      s.style.flexGrow = n;
      bar.appendChild(s);
    }
    bar.setAttribute("aria-label", fmt.format(c.suricata_only) + " sources seen by Suricata only, " +
      fmt.format(c.also_cowrie) + " also in Cowrie");
    $("overlap-card").hidden = false;
  }

  function render(d) {
    $("days").textContent = d.days;
    for (const el of document.querySelectorAll(".stat .num")) el.textContent = fmt.format(d.totals[el.dataset.k] || 0);
    renderOverlap(d.cowrie);
    renderDaily(d);

    fillTable("t-ports", d.ports, (td, r) => {
      const name = PORTS[r.port];
      td.append(String(r.port) + "/" + r.proto.toLowerCase());
      if (name) td.append(" ", chip(name));
      td.title = r.port + "/" + r.proto + (name ? " " + name : "") + ": " + fmt.format(r.count) + " alerts";
    }, "sources");
    fillTable("t-cats", d.categories, (td, r) => text(r.value)(td));
    fillTable("t-sigs", d.signatures, (td, r) => {
      td.append(r.value, " ", chip(SEV[r.severity] || "other"));
      td.title = r.sid + " " + r.value + " (" + r.category + "), " + fmt.format(r.sources) + " sources";
    });
    fillTable("t-cves", d.cves, (td, r) => {
      td.append(link("https://nvd.nist.gov/vuln/detail/" + encodeURIComponent(r.cve), r.cve));
      td.title = r.cve + ": " + r.signature + " (" + r.first_day + (r.last_day !== r.first_day ? " to " + r.last_day : "") + ")";
    }, "sources");
    const cc = Object.entries(d.countries || {}).map(([value, count]) => ({ value, count })).slice(0, 15);
    fillTable("t-countries", cc, (td, r) => text(countryLabel(r.value))(td));
    if (d.ttps && d.ttps.length) {
      fillTable("t-ttps", d.ttps, (td, r) => {
        td.append(link("https://attack.mitre.org/techniques/" + r.id.replace(".", "/") + "/", r.id));
      }, "sources");
      $("ttp-card").hidden = false;
    }

    const e = d.engine;
    $("engine").textContent = e
      ? "Suricata 7 on the VPS's network interface, " + fmt.format(e.rules_loaded || 0) + " rules loaded. Since its last " +
        "restart (the daily rule update) it has inspected " + fmt.format(e.packets || 0) + " packets and dropped " +
        fmt.format(e.drops || 0) + (e.drop_pct != null ? " (" + e.drop_pct + "%)" : "") + "."
      : "Suricata 7 on the VPS's network interface.";
    $("outbound").textContent = d.totals.outbound_alerts ? " (" + fmt.format(d.totals.outbound_alerts) + " in this period)" : "";
    $("generated").textContent = "Generated " + d.generated_at.replace("T", " ").replace("Z", " UTC");
    $("status").textContent = d.totals.alerts ? "" : "No alerts in this period yet.";
    $("view").hidden = false;
  }

  fetch(DATA + "network.json", { cache: "no-cache" })
    .then((r) => { if (!r.ok) throw new Error(r.status); return r.json(); })
    .then(render)
    .catch((e) => {
      $("status").textContent = e.message === "404"
        ? "No network data published yet."
        : "Could not load the data (" + e.message + ").";
    });
})();
