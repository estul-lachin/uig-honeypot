// honeypot.uig.me: renders stats.json and replays recent.json on a world map.
// Every string from the data is attacker-controlled: it is only ever set with
// textContent / d3 .text(), never as HTML.
"use strict";

(function () {
  const params = new URLSearchParams(location.search);
  // ?data=data/ for a local preview (./hp fetch); otherwise the data repo.
  const DATA = params.get("data") || "https://raw.githubusercontent.com/estul-lachin/uig-honeypot-data/main/";
  const TARGET = [114.1, 22.5]; // honeypot, rounded to the region
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

  const getJSON = (url) => fetch(url, { cache: "no-cache" }).then((r) => {
    if (!r.ok) throw new Error(url + ": " + r.status);
    return r.json();
  });

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
  let projection, path, gEvents;

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
    projection = d3.geoEqualEarth().fitWidth(952, land);
    path = d3.geoPath(projection);
    const [[, y0], [, y1]] = path.bounds(land);
    svg.attr("viewBox", `-4 ${Math.floor(y0) - 4} 960 ${Math.ceil(y1 - y0) + 8}`);
    const counts = s.countries || {};
    const tip = $("tooltip"), wrap = $("map-wrap");
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
        .transition().duration(1600).style("opacity", 0).remove();
    }
    gEvents.append("circle").attr("class", "pulse").attr("cx", sx).attr("cy", sy).attr("r", 3)
      .transition().duration(1400).attr("r", 14).style("opacity", 0).remove();
    gEvents.append("circle").attr("class", "src").attr("cx", sx).attr("cy", sy).attr("r", 3.5)
      .transition().delay(1800).duration(600).style("opacity", 0).remove();
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
    x.textContent = e.kind === "connect" ? (e.proto || "").toUpperCase() : (e.text || "");
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

  // ---------- replay ----------
  function startReplay(r) {
    const events = r.events || [];
    const span = Math.max(1, r.to - r.from);
    let speed = 10, playing = !reduceMotion, head = r.from, next = 0, last = null;
    const clock = $("clock"), bar = $("progress"), playBtn = $("play");

    function label() {
      clock.textContent = events.length
        ? `Replaying ${hhmmss(head)} UTC · ${fmt.format(events.length)} events in the hour ending ${hhmmss(r.to)} UTC`
        : `No events in the hour ending ${hhmmss(r.to)} UTC.`;
      bar.style.width = (100 * (head - r.from) / span).toFixed(2) + "%";
    }

    if (!events.length) {
      const li = document.createElement("li"); li.className = "empty"; li.textContent = "Quiet hour: nothing to replay.";
      $("feed").replaceChildren(li);
      label();
      return;
    }

    if (reduceMotion) {
      // No animation: show where the hour's sessions came from and the newest events.
      events.forEach((e) => { if (e.kind === "connect" && e.lat != null) {
        const [x, y] = projection([e.lon, e.lat]);
        gEvents.append("circle").attr("class", "src").attr("cx", x).attr("cy", y).attr("r", 3.5);
      } });
      events.slice(-FEED_MAX).forEach(pushFeed);
      head = r.to;
      playBtn.textContent = "Play";
      playBtn.setAttribute("aria-pressed", "false");
    }

    // Start just before the first event so the page never opens on a long silence.
    if (!reduceMotion) head = Math.max(r.from, events[0].t - 2);

    function tick(now) {
      if (last !== null && playing) {
        head += ((now - last) / 1000) * speed;
        // Skip quiet stretches: never more than MAX_GAP real seconds of nothing.
        if (next < events.length && events[next].t - head > MAX_GAP * speed) head = events[next].t - speed;
        while (next < events.length && events[next].t <= head) {
          const e = events[next++];
          fireOnMap(e);
          pushFeed(e);
        }
        if (head >= r.to) { head = Math.max(r.from, events[0].t - 2); next = 0; }
      }
      last = now;
      label();
      requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);

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
  Promise.all([getJSON(DATA + "stats.json"), getJSON(DATA + "recent.json"),
    getJSON("countries-50m.json"), getJSON("iso-a2-to-n3.json")])
    .then(([stats, recent, world, iso]) => {
      renderStats(stats);
      renderTables(stats);
      renderDaily(stats);
      renderMap(world, iso, stats);
      startReplay(recent);
      let w = innerWidth;
      addEventListener("resize", () => { if (innerWidth !== w) { w = innerWidth; renderDaily(stats); } });
    })
    .catch((err) => {
      $("clock").textContent = "Could not load the data. Try again later.";
      console.error(err);
    });
})();
