"use strict";
/* Shared chrome: icons, toasts, skeletons, badges, header, sidebar, command palette, router.
   Everything is built with DOM APIs (never innerHTML) so agent-supplied text cannot inject markup. */

/* ---------- icons (tiny declarative spec -> SVG) ---------- */
const ICONS = {
  grid: [["r", 3, 3, 7, 7, 1], ["r", 14, 3, 7, 7, 1], ["r", 14, 14, 7, 7, 1], ["r", 3, 14, 7, 7, 1]],
  bell: ["M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9", "M13.73 21a2 2 0 0 1-3.46 0"],
  flag: ["M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z", ["l", 4, 22, 4, 15]],
  server: [["r", 2, 2, 20, 8, 2], ["r", 2, 14, 20, 8, 2], ["l", 6, 6, 6.01, 6], ["l", 6, 18, 6.01, 18]],
  search: [["c", 11, 11, 8], ["l", 21, 21, 16.65, 16.65]],
  target: [["c", 12, 12, 10], ["c", 12, 12, 6], ["c", 12, 12, 2]],
  layers: [["g", "12 2 2 7 12 12 22 7 12 2"], ["p", "2 17 12 22 22 17"], ["p", "2 12 12 17 22 12"]],
  book: ["M4 19.5A2.5 2.5 0 0 1 6.5 17H20", "M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"],
  shield: ["M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"],
  network: [["p", "22 12 18 12 15 21 9 3 6 12 2 12"]],
  clipboard: ["M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2", ["r", 8, 2, 8, 4, 1], ["p", "9 14 11 16 15 12"]],
  wrench: ["M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"],
  heart: ["M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"],
  lock: [["r", 3, 11, 18, 11, 2], "M7 11V7a5 5 0 0 1 10 0v4"],
  file: ["M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z", ["p", "14 2 14 8 20 8"], ["l", 16, 13, 8, 13], ["l", 16, 17, 8, 17]],
  sun: [["c", 12, 12, 5], ["l", 12, 1, 12, 3], ["l", 12, 21, 12, 23], ["l", 4.22, 4.22, 5.64, 5.64], ["l", 18.36, 18.36, 19.78, 19.78], ["l", 1, 12, 3, 12], ["l", 21, 12, 23, 12], ["l", 4.22, 19.78, 5.64, 18.36], ["l", 18.36, 5.64, 19.78, 4.22]],
  moon: ["M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"],
  menu: [["l", 3, 12, 21, 12], ["l", 3, 6, 21, 6], ["l", 3, 18, 21, 18]],
  x: [["l", 18, 6, 6, 18], ["l", 6, 6, 18, 18]],
  chevR: [["p", "9 18 15 12 9 6"]], chevD: [["p", "6 9 12 15 18 9"]],
  chevsL: [["p", "11 17 6 12 11 7"], ["p", "18 17 13 12 18 7"]], chevsR: [["p", "13 17 18 12 13 7"], ["p", "6 17 11 12 6 7"]],
  download: ["M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4", ["p", "7 10 12 15 17 10"], ["l", 12, 15, 12, 3]],
  copy: [["r", 9, 9, 13, 13, 2], "M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"],
  check: [["p", "20 6 9 17 4 12"]],
  info: [["c", 12, 12, 10], ["l", 12, 16, 12, 12], ["l", 12, 8, 12.01, 8]],
  alert: ["M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z", ["l", 12, 9, 12, 13], ["l", 12, 17, 12.01, 17]],
  external: ["M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6", ["p", "15 3 21 3 21 9"], ["l", 10, 14, 21, 3]],
  user: ["M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2", ["c", 12, 7, 4]],
  pause: [["r", 6, 4, 4, 16, 1], ["r", 14, 4, 4, 16, 1]],
  density: [["l", 3, 6, 21, 6], ["l", 3, 12, 21, 12], ["l", 3, 18, 21, 18]],
  refresh: ["M23 4v6h-6", "M20.49 15a9 9 0 1 1-2.12-9.36L23 10"],
  link: ["M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71", "M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"],
  save: ["M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z", ["p", "17 21 17 13 7 13 7 21"], ["p", "7 3 7 8 15 8"]],
  table: [["r", 3, 3, 18, 18, 2], ["l", 3, 9, 21, 9], ["l", 3, 15, 21, 15], ["l", 9, 3, 9, 21]],
};
function icon(name, cls) {
  const s = svg("svg", { viewBox: "0 0 24 24", class: "icon" + (cls ? " " + cls : ""), "aria-hidden": "true", focusable: "false" });
  for (const part of ICONS[name] || []) {
    if (typeof part === "string") { s.append(svg("path", { d: part })); continue; }
    const [t, ...a] = part;
    if (t === "r") s.append(svg("rect", { x: a[0], y: a[1], width: a[2], height: a[3], rx: a[4] || 0 }));
    else if (t === "c") s.append(svg("circle", { cx: a[0], cy: a[1], r: a[2] }));
    else if (t === "l") s.append(svg("line", { x1: a[0], y1: a[1], x2: a[2], y2: a[3] }));
    else if (t === "p") s.append(svg("polyline", { points: a[0] }));
    else if (t === "g") s.append(svg("polygon", { points: a[0] }));
  }
  return s;
}
const ico = name => h("span", { class: "ico" }, icon(name));

/* ---------- small shared components ---------- */
function toast(msg, kind) {
  const box = document.getElementById("toasts"); if (!box) return;
  const t = h("div", { class: "toast " + (kind || ""), role: "status" }, icon(kind === "err" ? "alert" : kind === "info" ? "info" : "check", "sm"), h("span", {}, msg));
  box.append(t); announce(msg);
  setTimeout(() => t.remove(), kind === "err" ? 6000 : 3200);
}
function skeleton(rows) {
  return h("div", { class: "skeleton", "aria-busy": "true", "aria-label": "Loading" },
    h("div", { class: "cards" }, [0, 1, 2, 3].map(() => h("div", { class: "skel skelcard" }))),
    Array.from({ length: rows || 6 }, () => h("div", { class: "skel" })));
}
const levelClass = n => n <= 6 ? "low" : n <= 9 ? "medium" : n <= 11 ? "high" : "critical";
const levelBadge = n => h("span", { class: "lvl lvl-" + levelClass(n), title: "Rule level " + n + " (" + levelClass(n) + ")" }, n);
function pageHeader(title, sub, actions, crumbs) {
  return h("div", { class: "pagehead" },
    h("div", { class: "t" },
      crumbs && crumbs.length ? h("div", { class: "crumbs" }, crumbs.map((c, i) => [i ? icon("chevR", "sm") : null, c.go ? h("button", { class: "link", onclick: c.go }, c.label) : h("span", {}, c.label)])) : null,
      h("h2", {}, title), sub ? h("div", { class: "sub" }, sub) : null),
    actions ? h("div", { class: "bar", style: null }, actions) : null);
}
function gauge(score, rating, label) {
  const len = Math.PI * 52, dash = Math.max(0.5, score / 100 * len);
  const g = svg("svg", { viewBox: "0 0 130 82", role: "img", "aria-label": (label || "Score") + " " + score + " of 100, " + rating, class: "rk-" + rating });
  g.append(svg("path", { d: "M13 68 A52 52 0 0 1 117 68", class: "trk" }), svg("path", { d: "M13 68 A52 52 0 0 1 117 68", class: "val", "stroke-dasharray": dash + " " + len }));
  const n = svg("text", { x: 65, y: 62, "text-anchor": "middle", class: "num" }); n.textContent = score;
  const l = svg("text", { x: 65, y: 78, "text-anchor": "middle", class: "lbl" }); l.textContent = rating;
  g.append(n, l);
  return h("div", { class: "gauge" }, g);
}

/* ---------- navigation model (sidebar, palette and router all use this) ---------- */
const PAGES = [
  { id: "overview", path: "overview", label: "Overview", icon: "grid", group: "Monitor" },
  { id: "alerts", path: "alerts", label: "Alerts", icon: "bell", group: "Monitor", badge: () => S.openAlerts, bad: true },
  { id: "incidents", path: "incidents", label: "Incidents", icon: "flag", group: "Monitor", badge: () => S.openIncidents, bad: true },
  { id: "hostlist", path: "hosts", label: "Hosts", icon: "server", group: "Monitor", badge: () => S.hosts.length },
  { id: "events", path: "events", label: "Event explorer", icon: "search", group: "Detect" },
  { id: "threats", path: "threats", label: "Threat sources", icon: "target", group: "Detect", badge: () => S.threatSources },
  { id: "mitre", path: "mitre", label: "MITRE ATT&CK", icon: "layers", group: "Detect" },
  { id: "rules", path: "rules", label: "Detection rules", icon: "book", group: "Detect" },
  { id: "exposure", path: "exposure", label: "Exposure", icon: "shield", group: "Assess", badge: () => S.riskyExposed, bad: true },
  { id: "traffic", path: "traffic", label: "Traffic", icon: "network", group: "Assess" },
  { id: "compliance", path: "compliance", label: "Compliance", icon: "clipboard", group: "Assess", admin: true },
  { id: "maint", path: "maintenance", label: "Maintenance", icon: "wrench", group: "Manage" },
  { id: "health", path: "health", label: "System health", icon: "heart", group: "Manage", admin: true },
  { id: "sessions", path: "sessions", label: "Sessions", icon: "lock", group: "Account", bottom: true },
  { id: "audit", path: "audit", label: "Audit log", icon: "file", group: "Account", admin: true, bottom: true },
];
const pageById = id => PAGES.find(p => p.id === id);
const pageTitles = { search: "Search", hosts: "Host" };

/* ---------- global time range, refresh and the context bar ---------- */
const RANGE_OPTS = ["1h", "24h", "7d", "30d", "90d"];
const RANGE_NAMES = { "1h": "Last hour", "24h": "Last 24 hours", "7d": "Last 7 days", "30d": "Last 30 days", "90d": "Last 90 days" };
const TIMED_VIEWS = ["overview", "alerts", "incidents", "events", "threats", "mitre", "rules", "compliance"];
const isTimed = () => TIMED_VIEWS.includes(S.view) || (S.view === "hosts" && S.sel && S.tab === "alerts");
function applyRange(r) {
  if (!RANGE_OPTS.includes(r)) return;
  S.range = S.ovRange = S.evRange = S.incRange = S.mitreRange = S.rulesRange = S.compRange = S.tRange = S.aRange = r;
  try { localStorage.setItem("nw_range", r); } catch (e) {}
}
function setRange(r) { if (r === S.range) return; applyRange(r); setHash(); reload(); }
/* Refetching holds the previous render (dimmed) instead of flashing a skeleton or jumping the layout. */
function reload() { S.stale = true; const c = document.getElementById("content"); if (c) c.classList.add("stale"); refresh(); }
function setRefresh(sec) {
  S.refreshSec = sec; if (sec) S.lastSec = sec;
  try { localStorage.setItem("nw_refresh", String(sec)); } catch (e) {}
  schedule(); announce(sec ? "Auto refresh every " + sec + " seconds" : "Auto refresh off"); render();
}
function schedule() {
  clearInterval(S.timer);
  if (!S.refreshSec) return;
  S.timer = setInterval(() => {
    const id = document.activeElement?.id, tag = document.activeElement?.tagName;
    // Don't rebuild the page under the user's hands: typing in a query/filter box, choosing from a dropdown, or reading a chart tooltip.
    if (document.hidden || ["filter", "gsearch", "evq", "pin", "svname"].includes(id) || tag === "SELECT" || tag === "TEXTAREA" || S.view === "search" || document.querySelector(".chart:hover")) return;
    refresh();
  }, S.refreshSec * 1000);
}
(function restoreRangePrefs() {
  try {
    const r = localStorage.getItem("nw_range"); if (RANGE_OPTS.includes(r)) applyRange(r);
    const f = localStorage.getItem("nw_refresh"); if (f !== null && ["0", "5", "10", "30", "60"].includes(f)) { S.refreshSec = +f; if (+f) S.lastSec = +f; }
  } catch (e) {}
})();
const updatedText = () => !S.updatedAt ? "" : (() => { const d = Math.max(0, Math.floor(Date.now() / 1000 - S.updatedAt)); return "Updated " + (d < 2 ? "just now" : d < 60 ? d + " s ago" : Math.floor(d / 60) + " min ago"); })();
setInterval(() => { const e = document.getElementById("updated"); if (e) e.textContent = updatedText(); }, 1000);

function breadcrumbs() {
  const pg = pageById(S.view), out = [];
  if (S.view === "hosts") { out.push({ label: "Monitor" }, { label: "Hosts", go: () => go("hostlist") }, { label: S.data && S.data.host ? S.data.host.name : "Host", here: true }); }
  else if (S.view === "search") out.push({ label: "Search" }, { label: S.q ? "“" + S.q.trim() + "”" : "Results", here: true });
  else if (pg) {
    out.push({ label: pg.group });
    if (S.view === "threats" && S.source) out.push({ label: pg.label, go: () => { S.source = null; S.srcData = null; go("threats"); } }, { label: S.source, here: true });
    else out.push({ label: pg.label, here: true });
  }
  return out;
}
function renderContext() {
  const ctx = document.getElementById("ctx"); if (!ctx) return;
  const crumbs = breadcrumbs();
  ctx.replaceChildren(...[
    h("nav", { class: "crumbs", "aria-label": "Breadcrumb" }, crumbs.map((c, i) => [i ? icon("chevR", "sm") : null, c.go ? h("button", { class: "link", onclick: c.go }, c.label) : h("span", { class: c.here ? "here" : "" }, c.label)])),
    h("div", { class: "grow" }),
    isTimed() ? h("div", { class: "seg", role: "group", "aria-label": "Time range for every chart and table on this page" }, RANGE_OPTS.map(r => h("button", { class: S.range === r ? "on" : "", "aria-pressed": String(S.range === r), title: RANGE_NAMES[r], onclick: () => setRange(r) }, r.replace(/^(\d+)([hd])$/, "$1 $2")))) : null,
    h("label", { class: "refresh" }, "Refresh", sel([["0", "Off"], ["5", "5 s"], ["10", "10 s"], ["30", "30 s"], ["60", "1 min"]], String(S.refreshSec), v => setRefresh(+v), "Auto-refresh interval")),
    h("button", { class: "icon", title: "Refresh now", "aria-label": "Refresh now", onclick: reload }, icon("refresh")),
    h("span", { class: "updated", id: "updated", "aria-hidden": "true" }, updatedText())].filter(x => x != null && x !== false));
}

/* ---------- header ---------- */
function renderHeader() {
  const hdr = document.getElementById("hdr");
  const up = S.hosts.filter(x => x.status === "up").length;
  const keep = document.activeElement && document.activeElement.id === "gsearch";
  const box = h("input", { type: "search", id: "gsearch", class: "gsearch", placeholder: "Search hosts, ports, IPs, alerts…", value: S.q, "aria-label": "Search",
    oninput: e => { S.q = e.target.value; }, onkeydown: e => { if (e.key === "Enter") runSearch(); } });
  const paused = !S.refreshSec;
  const live = h("button", { class: "livepill " + (paused ? "off" : S.online ? "" : "dead"), title: paused ? "Auto-refresh is off: click to resume" : "Auto-refresh every " + S.refreshSec + " s: click to pause", "aria-pressed": String(paused),
    onclick: () => setRefresh(paused ? (S.lastSec || 10) : 0) },
    h("span", { class: "d" }), " ", h("span", { class: "t" }, !S.online ? "Offline" : paused ? "Paused" : "Live"));
  hdr.replaceChildren(
    h("button", { id: "burger", class: "burger icon", "aria-label": "Open menu", "aria-expanded": String(S.nav), "aria-controls": "side", onclick: () => setNav(!S.nav) }, icon("menu")),
    h("div", { class: "brand" }, icon("shield"), h("span", { class: "wm" }, "net", h("span", {}, "watch"))),
    h("div", { class: "searchwrap" }, ico("search"), box, h("kbd", { title: "Command palette" }, "Ctrl K")),
    h("div", { class: "grow" }),
    h("div", { class: "stat" }, h("b", {}, up + "/" + S.hosts.length), "hosts up"),
    h("div", { class: "stat" + (S.openIncidents ? " bad" : "") }, h("b", {}, S.openIncidents), "incidents"),
    h("div", { class: "stat" + (S.openAlerts ? " warn" : "") }, h("b", {}, S.openAlerts), "open alerts"),
    live,
    h("div", { class: "userbox" },
      h("button", { class: "icon", title: "Command palette (Ctrl K)", "aria-label": "Command palette", onclick: openPalette }, icon("search")),
      h("button", { class: "icon", title: "Keyboard shortcuts (?)", "aria-label": "Keyboard shortcuts", onclick: toggleHelp }, "?"),
      h("button", { class: "icon", title: "Switch theme (t)", "aria-label": "Switch to " + (curTheme() === "light" ? "dark" : "light") + " theme", onclick: () => setTheme(curTheme() === "light" ? "dark" : "light") }, icon(curTheme() === "light" ? "moon" : "sun")),
      h("span", { class: "uname" }, S.me.username), h("span", { class: "role " + S.me.role }, S.me.role),
      h("button", { onclick: async () => { await api("/api/logout", {}).catch(() => {}); showLogin(); } }, "Sign out")));
  if (keep) { box.focus(); box.setSelectionRange(box.value.length, box.value.length); }
}

/* ---------- sidebar ---------- */
function renderSidebar() {
  const side = document.getElementById("side"), admin = S.me.role === "admin";
  const tags = [...new Set(S.hosts.flatMap(x => x.tags))].sort();
  const shown = S.hosts.filter(x => !S.tag || x.tags.includes(S.tag));
  const nav = p => {
    const n = p.badge ? p.badge() : 0;
    return h("div", { class: "navitem" + (S.view === p.id ? " sel" : ""), tabindex: "0", role: "button", title: p.label, "aria-current": S.view === p.id ? "page" : null,
      onclick: () => { S.source = null; go(p.id); }, onkeydown: e => { if (e.key === "Enter") { S.source = null; go(p.id); } } },
      ico(p.icon), h("span", { class: "grow" }, p.label), n ? h("span", { class: p.bad ? "badge" : "count" }, n) : null);
  };
  const hostItem = x => h("div", { class: "host" + (S.view === "hosts" && S.sel === x.id ? " sel" : ""), tabindex: "0", role: "button", title: x.name, "aria-current": S.view === "hosts" && S.sel === x.id ? "page" : null, onclick: () => go("hosts", x.id),
    onkeydown: e => { if (e.key === "Enter") go("hosts", x.id); } }, dot(x.status), h("div", { class: "n" }, h("div", {}, x.name), h("div", { class: "sub" }, x.status === "up" ? x.addr : x.status + " · " + ago(x.last_seen))), x.open_alerts ? h("span", { class: "badge" }, x.open_alerts) : null);
  const visible = PAGES.filter(p => !p.admin || admin), out = [];
  if (tags.length) out.push(h("div", { class: "tagbar" }, h("span", { class: "chip" + (S.tag ? "" : " on"), onclick: () => { S.tag = null; refresh(); } }, "all"),
    tags.map(t => h("span", { class: "chip" + (S.tag === t ? " on" : ""), onclick: () => { S.tag = S.tag === t ? null : t; refresh(); } }, t))));
  let last = "";
  for (const p of visible.filter(p => !p.bottom)) { if (p.group !== last) { out.push(h("div", { class: "navgroup" }, p.group)); last = p.group; } out.push(nav(p)); }
  out.push(h("div", { class: "navgroup" }, "Hosts" + (S.tag ? " · " + S.tag : "")), ...shown.map(hostItem));
  out.push(h("div", { class: "side-nav" }, ...visible.filter(p => p.bottom).map(nav),
    h("button", { class: "collapse", title: "Collapse or expand the sidebar", onclick: toggleNavMini }, icon(document.documentElement.dataset.nav === "mini" ? "chevsR" : "chevsL"), h("span", {}, "Collapse"))));
  side.replaceChildren(...out);
}
function toggleNavMini() {
  const mini = document.documentElement.dataset.nav !== "mini";
  if (mini) document.documentElement.dataset.nav = "mini"; else delete document.documentElement.dataset.nav;
  try { localStorage.setItem("nw_nav", mini ? "mini" : "full"); } catch (e) {}
  render();
}
function toggleDensity() {
  const compact = document.documentElement.dataset.density !== "compact";
  if (compact) document.documentElement.dataset.density = "compact"; else delete document.documentElement.dataset.density;
  try { localStorage.setItem("nw_density", compact ? "compact" : "comfortable"); } catch (e) {}
  toast(compact ? "Compact density" : "Comfortable density", "info");
}
(function restorePrefs() {
  try {
    if (localStorage.getItem("nw_nav") === "mini") document.documentElement.dataset.nav = "mini";
    if (localStorage.getItem("nw_density") === "compact") document.documentElement.dataset.density = "compact";
  } catch (e) {}
})();

/* ---------- command palette ---------- */
let pal = { open: false, items: [], sel: 0, q: "" };
function paletteItems(q) {
  const admin = S.me && S.me.role === "admin", items = [];
  const add = (group, label, ic, hint, run, key) => items.push({ group, label, ic, hint, run, key: (key || label).toLowerCase() });
  PAGES.filter(p => !p.admin || admin).forEach(p => add("Go to", p.label, p.icon, "", () => { S.source = null; go(p.id); }));
  S.hosts.forEach(x => add("Hosts", x.name, "server", x.addr + " · " + x.status, () => go("hosts", x.id), x.name + " " + x.addr + " " + x.tags.join(" ")));
  add("Actions", "Toggle light / dark theme", curTheme() === "light" ? "moon" : "sun", "t", () => setTheme(curTheme() === "light" ? "dark" : "light"));
  RANGE_OPTS.forEach(r => add("Time range", RANGE_NAMES[r], "refresh", "", () => setRange(r), "time range " + RANGE_NAMES[r] + " " + r));
  add("Actions", "Toggle compact density", "density", "", toggleDensity);
  add("Actions", "Collapse / expand sidebar", "chevsL", "", toggleNavMini);
  add("Actions", "Pause / resume live refresh", "pause", "", () => setRefresh(S.refreshSec ? 0 : (S.lastSec || 10)));
  add("Actions", "Keyboard shortcuts", "info", "?", toggleHelp);
  const t = q.trim();
  const out = [];
  if (t) {
    const words = t.toLowerCase().split(/\s+/);
    const scored = items.map(i => ({ i, s: words.every(w => i.key.includes(w)) ? (i.key.startsWith(words[0]) ? 2 : 1) : 0 })).filter(x => x.s).sort((a, b) => b.s - a.s).map(x => x.i);
    out.push(...scored);
    out.push({ group: "Search", label: "Hunt events for: " + t, ic: "search", hint: "Event explorer", run: () => goEvents(t.includes(":") || /[<>=]/.test(t) ? t : "\"" + t.replace(/"/g, "") + "\"") });
    out.push({ group: "Search", label: "Search everything for: " + t, ic: "search", hint: "hosts, ports, alerts", run: () => { S.q = t; runSearch(); } });
  } else out.push(...items);
  return out.slice(0, 40);
}
function openPalette() {
  if (!S.me || S.me.must_change) return;
  pal = { open: true, items: [], sel: 0, q: "" }; drawPalette(true);
}
function closePalette() { pal.open = false; const b = document.getElementById("palette"); if (b) b.replaceChildren(); if (pal.ret && document.contains(pal.ret)) pal.ret.focus(); }
function drawPalette(first) {
  const box = document.getElementById("palette"); if (!box) return;
  if (first) pal.ret = document.activeElement;
  pal.items = paletteItems(pal.q); pal.sel = Math.min(pal.sel, Math.max(0, pal.items.length - 1));
  const input = first ? h("input", { id: "pin", type: "text", placeholder: "Type a page, host or query…  (↑↓ to move, Enter to open)", "aria-label": "Command palette", autocomplete: "off", spellcheck: "false",
    oninput: e => { pal.q = e.target.value; pal.sel = 0; drawPalette(false); }, onkeydown: e => {
      if (e.key === "ArrowDown") { e.preventDefault(); pal.sel = Math.min(pal.items.length - 1, pal.sel + 1); drawPalette(false); }
      else if (e.key === "ArrowUp") { e.preventDefault(); pal.sel = Math.max(0, pal.sel - 1); drawPalette(false); }
      else if (e.key === "Enter") { e.preventDefault(); const it = pal.items[pal.sel]; closePalette(); if (it) it.run(); }
      else if (e.key === "Escape") { e.preventDefault(); closePalette(); } } }) : document.getElementById("pin");
  const list = h("div", { class: "plist", role: "listbox" });
  let lastGroup = "";
  pal.items.forEach((it, i) => {
    if (it.group !== lastGroup) { list.append(h("div", { class: "pgroup" }, it.group)); lastGroup = it.group; }
    list.append(h("div", { class: "pitem" + (i === pal.sel ? " sel" : ""), role: "option", "aria-selected": String(i === pal.sel), onclick: () => { closePalette(); it.run(); } }, icon(it.ic), h("span", {}, it.label), it.hint ? h("span", { class: "h" }, it.hint) : null));
  });
  if (!pal.items.length) list.append(h("div", { class: "pgroup" }, "No matches"));
  if (first) {
    box.replaceChildren(h("div", { class: "palette", onclick: e => { if (e.target.classList.contains("palette")) closePalette(); } },
      h("div", { class: "pbox", role: "dialog", "aria-modal": "true", "aria-label": "Command palette" }, input, list,
        h("div", { class: "pfoot" }, h("span", {}, h("kbd", {}, "↑"), " ", h("kbd", {}, "↓"), " navigate"), h("span", {}, h("kbd", {}, "Enter"), " open"), h("span", {}, h("kbd", {}, "Esc"), " close")))));
    input.focus();
  } else { box.querySelector(".plist").replaceWith(list); const s = list.querySelector(".pitem.sel"); if (s) s.scrollIntoView({ block: "nearest" }); }
}
document.addEventListener("keydown", e => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); if (pal.open) closePalette(); else openPalette(); }
});

/* ---------- hash router: every view is a shareable URL and Back/Forward work ---------- */
function hashFromState() {
  let p, qs = {};
  if (S.view === "hosts") p = S.sel ? "host/" + S.sel + (S.tab && S.tab !== "alerts" ? "/" + S.tab : "") : "overview";
  else if (S.view === "threats" && S.source) p = "threats/" + encodeURIComponent(S.source);
  else { const pg = pageById(S.view); p = pg ? pg.path : S.view; }
  if (S.view === "events") { if (S.evq) qs.q = S.evq; if (S.range !== "24h") qs.range = S.range; }
  if (S.view === "search" && S.q) qs.q = S.q;
  const q = new URLSearchParams(qs).toString();
  return "#/" + p + (q ? "?" + q : "");
}
function setHash() {
  if (S.applying) return;
  const hh = hashFromState();
  if (location.hash !== hh) { S.settingHash = true; location.hash = hh; setTimeout(() => { S.settingHash = false; }, 0); }
  const pg = pageById(S.view);
  document.title = (S.view === "hosts" ? (S.data && S.data.host ? S.data.host.name : "Host") : pg ? pg.label : pageTitles[S.view] || "netwatch") + " · netwatch";
}
function applyHash() {
  if (!S.me || S.me.must_change) return;
  const raw = location.hash.replace(/^#\/?/, ""), [path, query] = raw.split("?"), seg = path.split("/").filter(Boolean), qs = new URLSearchParams(query || "");
  S.applying = true;
  try {
    const first = seg[0] || "overview";
    if (first === "host" && seg[1]) { S.view = "hosts"; S.sel = seg[1]; S.tab = seg[2] || "alerts"; S.source = null; }
    else if (first === "threats" && seg[1]) { S.view = "threats"; S.source = decodeURIComponent(seg[1]); S.srcData = null; S.sel = null; }
    else if (first === "search") { S.view = "search"; S.q = qs.get("q") || ""; if (S.q) { runSearch(); return; } }
    else {
      const pg = PAGES.find(p => p.path === first);
      S.view = pg ? pg.id : "overview"; S.sel = null; S.source = null;
      if (pg && pg.admin && S.me.role !== "admin") S.view = "overview";
      if (S.view === "events") { S.evq = qs.get("q") || ""; if (qs.get("range")) applyRange(qs.get("range")); S.events = null; }
    }
    S.data = null; S.filter = ""; setNav(false);
    refresh();
  } finally { S.applying = false; }
}
window.addEventListener("hashchange", () => { if (!S.settingHash) applyHash(); });
