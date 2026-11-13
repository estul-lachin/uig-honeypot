// honeypot.uig.me: renders stats.json and replays recent.json on a world map.
// Every string from the data is attacker-controlled: it is only ever set with
// textContent / d3 .text(), never as HTML.
"use strict";

(function () {
  const params = new URLSearchParams(location.search);
  // ?data=data/ for a local preview (./hp fetch); otherwise the data repo.
  const DATA = params.get("data") || "https://raw.githubusercontent.com/estul-lachin/uig-honeypot-data/main/";
  const TARGET = [114.1, 22.5]; // honeypot, rounded to the region
  // Pacific-centred, like maps printed in China: the seam runs through the Atlantic (30°W), so no
  // continent is cut in half and arcs from the Americas cross the Pacific instead of wrapping.
  const CENTRAL_MERIDIAN = 150;
  const BINS = [1, 10, 100, 1000]; // session thresholds for the shading
  const FEED_MAX = 8;
  const MAX_GAP = 3; // seconds of real time
  const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const regionName = (() => {
    try { const d = new Intl.DisplayNames(["en"], { type: "region" }); return (cc) => d.of(cc); }
    catch (e) { return (cc) => cc; }
  })();
  const fmt = new Intl.NumberFormat("en");
  const $ = (id) => document.getElementById(id);

  const getJSON = (url, init) => fetch(url, Object.assign({ cache: "no-cache" }, init)).then((r) => {
    if (!r.ok) throw new Error(url + ": " + r.status);
    return r.json();
  });

  // recent.json changes every minute. raw.githubusercontent.com caches files for about five minutes;
  // the contents API serves the pushed file within a minute (60 requests/hour per visitor, so the page
  // polls once a minute and falls back to the raw file when the limit is hit).
  const RECENT_API = "https://api.github.com/repos/estul-lachin/uig-honeypot-data/contents/recent.json";
  function getRecent() {
    if (params.get("data")) return getJSON(DATA + "recent.json");
    return getJSON(RECENT_API, { headers: { Accept: "application/vnd.github.raw+json" } })
      .catch(() => getJSON(DATA + "recent.json"));
  }

  function countryLabel(cc) {
    if (!cc || cc === "??") return "Unknown";
    return regionName(cc) || cc;
  }

  function hhmmss(t) {
    return new Date(t * 1000).toISOString().slice(11, 19);
  }

  // ---------- stats ----------
  function renderStats(s) {
    const known = Object.keys(s.countries || {}).filter((c) => c !== "??").length;
    const vals = Object.assign({}, s.totals, { countries: known });
    document.querySelectorAll("#stats .num").forEach((el) => {
      el.textContent = fmt.format(vals[el.dataset.k] || 0);
    });
    if (s.first_day) $("since").textContent = "Since " + s.first_day + " (UTC).";
    $("generated").textContent = "Updated " + s.generated_at.replace("T", " ").replace("Z", " UTC");
  }

  function fillTable(id, rows, render, key = "count") {
    const table = $(id);
    table.replaceChildren();
    if (!rows.length) {
      const td = table.insertRow().insertCell();
      td.className = "none";
      td.textContent = "Nothing yet";
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

  function renderTables(s) {
    const countries = Object.entries(s.countries || {})
      .map(([cc, count]) => ({ cc, count })).slice(0, 20);
    renderPorts(s.ports);
    fillTable("t-countries", countries, (td, r) => { td.textContent = countryLabel(r.cc); });
    fillTable("t-ttps", s.ttps || [], (td, r) => {
      const a = document.createElement("a");
      a.href = "https://attack.mitre.org/techniques/" + r.id.replace(".", "/") + "/";
      a.rel = "noopener";
      a.textContent = r.id;
      const t = document.createElement("span");
      t.className = "tactic";
      t.textContent = r.tactic;
      td.append(a, " ", r.name, " ", t);
      td.title = r.id + " " + r.name + " (" + r.tactic + ")";
    }, "sessions");
    fillTable("t-usernames", s.top.usernames, textCell);
    renderReputation(s.reputation, fillTable, (n) => fmt.format(n));
    fillTable("t-passwords", s.top.passwords, textCell);
    fillTable("t-pairs", s.top.pairs, textCell);
    fillTable("t-commands", s.top.commands, textCell);
    fillTable("t-clients", s.top.clients, textCell);
    fillTable("t-downloads", s.downloads || [], (td, r) => {
      const a = document.createElement("a");
      a.href = "https://www.virustotal.com/gui/file/" + encodeURIComponent(r.sha256);
      a.rel = "noopener";
      a.textContent = r.sha256.slice(0, 12) + "…";
      td.append(a, " ", r.url);
      td.title = r.url;
    });
  }

  // ---------- sessions per honeypot port ----------
  const PORT_COLS = [["Port", "port"], ["Protocol", "proto"], ["Sessions", "sessions"],
    ["Sources", "unique_sources"], ["Logged in", "logged_in"], ["Commands / session", "cps"], ["Since", "first_day"]];
  function renderPorts(rows) {
    const table = $("t-ports");
    table.replaceChildren();
    rows = rows || [];
    if (!rows.length) {
      const td = table.insertRow().insertCell();
      td.className = "none";
      td.textContent = "Nothing yet";
      return;
    }
    const cols = PORT_COLS.filter(([, k]) => k !== "first_day" || rows.some((r) => r.first_day));
    const head = table.createTHead().insertRow();
    for (const [label] of cols) {
      const th = document.createElement("th");
      th.scope = "col";
      th.textContent = label;
      head.appendChild(th);
    }
    const body = table.createTBody();
    for (const r of rows) {
      const tr = body.insertRow();
      for (const [, k] of cols) {
        const td = tr.insertCell();
        if (k === "port") td.textContent = String(r.port);
        else if (k === "proto") td.textContent = (r.proto || "").toUpperCase();
        else if (k === "first_day") td.textContent = r.first_day || "";
        else if (k === "cps") td.textContent = r.sessions ? (r.commands_run / r.sessions).toFixed(1) : "0";
        else if (k === "logged_in") {
          td.textContent = fmt.format(r.logged_in) + (r.sessions ? " (" + Math.round(100 * r.logged_in / r.sessions) + "%)" : "");
        } else td.textContent = fmt.format(r[k] || 0);
      }
    }
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

  // ---------- daily columns ----------
  function renderDaily(s) {
    const svg = d3.select("#daily");
    const W = svg.node().clientWidth || 600, H = 200, m = { t: 10, r: 8, b: 24, l: 40 };
    svg.attr("viewBox", `0 0 ${W} ${H}`).selectAll("*").remove();
    const data = s.daily;
    if (!data.length) return;
    const x = d3.scaleBand().domain(data.map((d) => d.day)).range([m.l, W - m.r]).padding(0.25);
    const y = d3.scaleLinear().domain([0, d3.max(data, (d) => d.sessions) || 1]).nice().range([H - m.b, m.t]);
    svg.append("g").attr("class", "grid").attr("transform", `translate(${m.l},0)`)
      .call(d3.axisLeft(y).ticks(4).tickSize(-(W - m.l - m.r)).tickFormat(""))
      .call((g) => g.select(".domain").remove());
    const every = Math.ceil(data.length / Math.max(1, Math.floor((W - m.l) / 70)));
    svg.append("g").attr("class", "axis").attr("transform", `translate(0,${H - m.b})`)
      .call(d3.axisBottom(x).tickValues(x.domain().filter((d, i) => i % every === 0)).tickFormat((d) => d.slice(5)));
    svg.append("g").attr("class", "axis").attr("transform", `translate(${m.l},0)`)
      .call(d3.axisLeft(y).ticks(4).tickFormat(d3.format("~s"))).call((g) => g.select(".domain").remove());
    const bw = Math.min(x.bandwidth(), 40);
    // 4px rounded data end, square at the baseline
    svg.append("g").selectAll("path").data(data).join("path")
      .attr("class", "bar")
      .attr("d", (d) => {
        const x0 = x(d.day) + (x.bandwidth() - bw) / 2, y0 = y(d.sessions), h = y(0) - y0, r = Math.min(4, h, bw / 2);
        if (h <= 0) return "";
        return `M${x0},${y(0)}V${y0 + r}Q${x0},${y0} ${x0 + r},${y0}H${x0 + bw - r}Q${x0 + bw},${y0} ${x0 + bw},${y0 + r}V${y(0)}Z`;
      })
      .on("pointerenter pointermove", (ev, d) => showDailyTip(ev, d))
      .on("pointerleave", () => { dailyTip.hidden = true; });
  }

  let dailyTip;
  function showDailyTip(ev, d) {
    if (!dailyTip) {
      dailyTip = document.createElement("div");
      dailyTip.className = "tooltip";
      $("daily").parentElement.style.position = "relative";
      $("daily").parentElement.appendChild(dailyTip);
    }
    const box = $("daily").parentElement.getBoundingClientRect();
    dailyTip.replaceChildren(d.day + ": ", Object.assign(document.createElement("b"), { textContent: fmt.format(d.sessions) }),
      " sessions, " + fmt.format(d.login_attempts) + " logins");
    dailyTip.style.left = (ev.clientX - box.left) + "px";
    dailyTip.style.top = (ev.clientY - box.top) + "px";
    dailyTip.hidden = false;
  }

  // ---------- map ----------
  let projection, path, gEvents, targetRing;

  function shade(n) {
    if (!n) return "var(--land)";
    let i = 0;
    while (i < BINS.length - 1 && n >= BINS[i + 1]) i++;
    return `var(--seq-${i + 1})`;
  }

  function renderLegend() {
    const labels = ["1–9", "10–99", "100–999", "1000+"];
    $("bins").replaceChildren(...labels.map((l, i) => {
      const s = document.createElement("span");
      const sw = document.createElement("i");
      sw.style.background = `var(--seq-${i + 1})`;
      s.append(sw, l);
      return s;
    }));
  }

  function renderMap(world, iso, s) {
    const svg = d3.select("#map");
    const n3ToA2 = {};
    for (const [a2, n3] of Object.entries(iso)) n3ToA2[n3] = a2;
    const land = topojson.feature(world, world.objects.countries);
    land.features = land.features.filter((f) => f.id !== "010"); // Antarctica
    projection = d3.geoEqualEarth().rotate([-CENTRAL_MERIDIAN, 0]).fitWidth(952, land);
    path = d3.geoPath(projection);
    const [[, y0], [, y1]] = path.bounds(land);
    svg.attr("viewBox", `-4 ${Math.floor(y0) - 4} 960 ${Math.ceil(y1 - y0) + 8}`);
    const counts = s.countries || {};
    const tip = $("tooltip"), wrap = $("map-wrap");
    const gBase = svg.append("g").attr("aria-hidden", "true");
    gBase.append("path").attr("class", "sphere").attr("d", path({ type: "Sphere" }));
    gBase.append("path").attr("class", "graticule").attr("d", path(d3.geoGraticule10()));
    svg.append("g").selectAll("path").data(land.features).join("path")
      .attr("class", "country")
      .attr("d", path)
      .style("fill", (f) => shade(counts[n3ToA2[f.id]]))
      .on("pointerenter pointermove", (ev, f) => {
        const cc = n3ToA2[f.id], n = counts[cc] || 0;
        const box = wrap.getBoundingClientRect();
        tip.replaceChildren((cc ? countryLabel(cc) : f.properties.name) + ": ",
          Object.assign(document.createElement("b"), { textContent: fmt.format(n) }), n === 1 ? " session" : " sessions");
        tip.style.left = (ev.clientX - box.left) + "px";
        tip.style.top = (ev.clientY - box.top) + "px";
        tip.hidden = false;
      })
      .on("pointerleave", () => { tip.hidden = true; });
    // Countries too small to see as a shape (e.g. Singapore) get a dot.
    svg.append("g").selectAll("circle")
      .data(land.features.filter((f) => counts[n3ToA2[f.id]] && path.area(f) < 12))
      .join("circle")
      .attr("class", "tiny")
      .attr("r", 4)
      .attr("transform", (f) => `translate(${path.centroid(f)})`)
      .style("fill", (f) => shade(counts[n3ToA2[f.id]]))
      .append("title").text((f) => countryLabel(n3ToA2[f.id]) + ": " + fmt.format(counts[n3ToA2[f.id]]) + " sessions");
    gEvents = svg.append("g");
    const [tx, ty] = projection(TARGET);
    const gt = svg.append("g").attr("aria-hidden", "true");
    targetRing = gt.append("circle").attr("class", "target-ring").attr("cx", tx).attr("cy", ty).attr("r", 5);
    gt.append("circle").attr("class", "target").attr("cx", tx).attr("cy", ty).attr("r", 5);
    gt.append("text").attr("class", "target-label").attr("x", tx + 9).attr("y", ty + 4).text("honeypot");
    renderLegend();
  }

  function fireOnMap(e) {
    if (e.lat == null || e.lon == null) return;
    const [sx, sy] = projection([e.lon, e.lat]);
    if (e.kind === "connect") {
      const arc = gEvents.append("path").attr("class", "arc")
        .attr("d", path({ type: "LineString", coordinates: [[e.lon, e.lat], TARGET] }));
      const len = arc.node().getTotalLength();
      arc.attr("stroke-dasharray", `${len} ${len}`).attr("stroke-dashoffset", len)
        .transition().duration(900).ease(d3.easeCubicOut).attr("stroke-dashoffset", 0)
        .on("end", hitTarget)
        .transition().duration(1600).style("opacity", 0).remove();
    }
    gEvents.append("circle").attr("class", "pulse").attr("cx", sx).attr("cy", sy).attr("r", 3)
      .transition().duration(1400).attr("r", 14).style("opacity", 0).remove();
    gEvents.append("circle").attr("class", "src").attr("cx", sx).attr("cy", sy).attr("r", 3.5)
      .transition().delay(1800).duration(600).style("opacity", 0).remove();
  }

  // The honeypot ring flashes when an arc lands on it.
  function hitTarget() {
    targetRing.interrupt().attr("r", 5).style("opacity", 1)
      .transition().duration(900).ease(d3.easeCubicOut).attr("r", 16).style("opacity", 0);
  }

  const KIND = { connect: "connect", login: "login", command: "command", download: "download" };

  function feedItem(e) {
    const li = document.createElement("li");
    const t = document.createElement("span"); t.className = "t"; t.textContent = hhmmss(e.t);
    const w = document.createElement("span"); w.className = "where";
    w.textContent = e.cc ? (e.city ? e.city + ", " : "") + countryLabel(e.cc) : "Unknown";
    w.title = w.textContent;
    const k = document.createElement("span"); k.className = "kind";
    k.textContent = e.kind === "login" ? (e.ok ? "login ✓" : "login ✗") : (KIND[e.kind] || e.kind);
    const x = document.createElement("span"); x.className = "what";
    // the port only when it is not the protocol's standard one (2222, 2323)
    const std = e.proto === "telnet" ? 23 : 22;
    x.textContent = e.kind === "connect"
      ? (e.proto || "").toUpperCase() + (e.port && e.port !== std ? " :" + e.port : "") : (e.text || "");
    x.title = x.textContent;
    li.append(t, w, k, x);
    return li;
  }

  function pushFeed(e) {
    const feed = $("feed");
    feed.querySelector(".empty")?.remove();
    feed.prepend(feedItem(e));
    while (feed.children.length > FEED_MAX) feed.lastElementChild.remove();
  }

  // ---------- live + replay ----------
  // The VPS republishes recent.json (the last hour of events) every minute. Live mode polls it and plays
  // new events in real time, LIVE_DELAY seconds behind the clock so each minute's batch has arrived
  // before its events are due. Replay mode plays the newest hour on a loop, faster than real time.
  const LIVE_POLL = 60 * 1000;
  const STALE = 15 * 60; // seconds: older data means the VPS stopped publishing
  const keyOf = (e) => [e.t, e.kind, e.text || e.proto || "", e.lat, e.lon].join("|");

  function startPlayer(first) {
    let latest = first;                  // newest recent.json
    let events = (first.events || []).slice();
    let seen = new Set(events.map(keyOf));
    let liveDelay = 150;                 // seconds behind real time, grows if the data arrives later
    let mode = "live", speed = 10, playing = !reduceMotion;
    let lastFired = -Infinity;           // live: newest event already shown
    let rep = null;                      // replay: { events, from, to, head, next }
    let last = null;
    const clock = $("clock"), bar = $("progress"), playBtn = $("play"), title = $("map-h");
    const replayCtl = $("replay-controls");

    const nowSec = () => Date.now() / 1000;
    const age = () => nowSec() - latest.to;

    function adaptDelay() {
      // Data that is a minute or two old on arrival is normal; leave 30 s of slack on top.
      if (age() < STALE) liveDelay = Math.min(600, Math.max(liveDelay, Math.ceil(age()) + 30));
    }

    function merge(r) {
      if (!r || !Array.isArray(r.events) || r.to <= latest.to) return;
      latest = r;
      const from = r.to - 3600;
      for (const e of r.events) {
        const k = keyOf(e);
        if (!seen.has(k)) { seen.add(k); events.push(e); }
      }
      events = events.filter((e) => e.t >= from).sort((x, y) => x.t - y.t);
      seen = new Set(events.map(keyOf));
      adaptDelay();
    }

    function clearMap() { gEvents.selectAll("*").interrupt().remove(); }

    function quiet(text) {
      const li = document.createElement("li"); li.className = "empty"; li.textContent = text;
      $("feed").replaceChildren(li);
    }

    function show(e, animate) {
      if (animate && !reduceMotion) fireOnMap(e);
      else if (e.kind === "connect" && e.lat != null && reduceMotion) {
        const [x, y] = projection([e.lon, e.lat]);
        gEvents.append("circle").attr("class", "src").attr("cx", x).attr("cy", y).attr("r", 3.5);
      }
      pushFeed(e);
    }

    // ----- live -----
    function enterLive() {
      mode = "live";
      clearMap();
      const head = nowSec() - liveDelay;
      const past = events.filter((e) => e.t <= head);
      lastFired = past.length ? past[past.length - 1].t : head;
      if (past.length) {
        $("feed").replaceChildren();
        past.slice(-FEED_MAX).forEach((e) => show(e, false));
      } else quiet("Waiting for the next session…");
    }

    function tickLive(now) {
      const head = nowSec() - liveDelay;
      // After a background tab (no frames), list what was missed without a burst of arcs.
      const resumed = last !== null && now - last > 2000;
      for (const e of events) {
        if (e.t > lastFired && e.t <= head) {
          $("feed").querySelector(".empty")?.remove();
          show(e, !resumed);
          lastFired = e.t;
        }
      }
      const behind = Math.round(liveDelay / 60);
      if (age() > STALE) {
        clock.textContent = `Live feed paused: the newest data is ${Math.round(age() / 60)} min old.`;
      } else {
        clock.textContent = `Live, about ${behind} min behind · ${hhmmss(head)} UTC`;
      }
      bar.style.width = "100%";
    }

    // ----- replay -----
    function enterReplay() {
      mode = "replay";
      clearMap();
      const evs = events.filter((e) => e.t >= latest.to - 3600);
      rep = { events: evs, from: latest.to - 3600, to: latest.to, head: latest.to, next: evs.length };
      if (!evs.length) { quiet("Quiet hour: nothing to replay."); return; }
      $("feed").replaceChildren();
      if (reduceMotion && !playing) {
        // No animation: show where the hour's sessions came from and the newest events.
        evs.forEach((e) => { if (e.kind === "connect") show(e, false); });
        $("feed").replaceChildren();
        evs.slice(-FEED_MAX).forEach(pushFeed);
      } else {
        // Start just before the first event so the replay never opens on a long silence.
        rep.head = Math.max(rep.from, evs[0].t - 2);
        rep.next = 0;
      }
    }

    function tickReplay(now) {
      const r = rep, span = Math.max(1, r.to - r.from);
      if (last !== null && playing && r.events.length) {
        r.head += ((now - last) / 1000) * speed;
        // Skip quiet stretches: never more than MAX_GAP real seconds of nothing.
        if (r.next < r.events.length && r.events[r.next].t - r.head > MAX_GAP * speed) r.head = r.events[r.next].t - speed;
        while (r.next < r.events.length && r.events[r.next].t <= r.head) show(r.events[r.next++], true);
        if (r.head >= r.to) { enterReplay(); return; } // loop, picking up the newest hour
      }
      clock.textContent = r.events.length
        ? `Replaying ${hhmmss(r.head)} UTC · ${fmt.format(r.events.length)} events in the hour ending ${hhmmss(r.to)} UTC`
        : `No events in the hour ending ${hhmmss(r.to)} UTC.`;
      bar.style.width = (100 * (r.head - r.from) / span).toFixed(2) + "%";
    }

    function tick(now) {
      if (mode === "live") tickLive(now); else tickReplay(now);
      last = now;
      requestAnimationFrame(tick);
    }

    function setMode(m) {
      document.querySelectorAll("[data-mode]").forEach((b) => b.setAttribute("aria-checked", String(b.dataset.mode === m)));
      replayCtl.hidden = m !== "replay";
      title.textContent = m === "live" ? "Live attack map" : "Last hour, replayed";
      bar.parentElement.classList.toggle("live", m === "live");
      if (m === "live") enterLive(); else enterReplay();
    }

    adaptDelay();
    if (age() > STALE) {
      // The VPS has not published for a while: replaying the last hour we have is more useful.
      setMode("replay");
    } else setMode("live");
    playBtn.textContent = playing ? "Pause" : "Play";
    playBtn.setAttribute("aria-pressed", String(playing));
    requestAnimationFrame(tick);

    setInterval(() => {
      if (document.hidden) return;
      getRecent().then(merge).catch((err) => console.warn(err));
    }, LIVE_POLL);

    document.querySelectorAll("[data-mode]").forEach((b) => b.addEventListener("click", () => {
      if (b.dataset.mode !== mode) setMode(b.dataset.mode);
    }));
    playBtn.addEventListener("click", () => {
      playing = !playing;
      playBtn.textContent = playing ? "Pause" : "Play";
      playBtn.setAttribute("aria-pressed", String(playing));
    });
    document.querySelectorAll("[data-speed]").forEach((b) => b.addEventListener("click", () => {
      speed = Number(b.dataset.speed);
      document.querySelectorAll("[data-speed]").forEach((o) => o.setAttribute("aria-checked", String(o === b)));
    }));
  }

  // ---------- boot ----------
  Promise.all([getJSON(DATA + "stats.json"), getRecent(),
    getJSON("countries-50m.json"), getJSON("iso-a2-to-n3.json")])
    .then(([stats, recent, world, iso]) => {
      renderStats(stats);
      renderTables(stats);
      renderDaily(stats);
      renderMap(world, iso, stats);
      startPlayer(recent);
      let w = innerWidth;
      addEventListener("resize", () => { if (innerWidth !== w) { w = innerWidth; renderDaily(stats); } });
    })
    .catch((err) => {
      $("clock").textContent = "Could not load the data. Try again later.";
      console.error(err);
    });
})();
