"use strict";
// All dynamic content goes through textContent (never innerHTML), so agent-supplied data cannot inject markup.
const $app = document.getElementById("app");
const S = { me: null, view: "overview", hosts: [], openAlerts: 0, sel: null, tab: "alerts", tag: null,
  showAcked: false, filter: "", data: null, alerts: [], online: true, timer: null, sessions: [], audit: null,
  risk: null, ov: null, ovRange: "24h", exposure: null, traffic: null, threats: null, tRange: "24h", source: null, srcData: null, health: null, expanded: {}, expOnly: true, expRisky: false, hSort: { k: "status", dir: 1 }, riskyExposed: 0, threatSources: 0, nav: false, aRange: "24h", aSev: "", aMine: false, cRange: "6h", metrics: null, timeline: null, mutes: [], q: "", search: null, drawer: null, editTags: false,
  ruleMap: null, ruleList: null, evq: "", evRange: "24h", events: null, incidents: null, incRange: "7d", incidentsOv: null, ovEvents: null, riskScores: null, mitre: null, mitreRange: "7d", rules: null, rulesRange: "7d", compliance: null, compRange: "30d", fw: "pci_dss", expandedInc: {}, expandedRule: {}, openIncidents: 0, refreshSec: 10, lastSec: 10, range: "24h", updatedAt: 0, stale: false, expandedEv: {}, saveOpen: false, applying: false, settingHash: false };
const canAck = () => S.me && (S.me.role === "operator" || S.me.role === "admin");
const RANGES = { "1h": 3600, "24h": 86400, "7d": 604800, "30d": 2592000, "90d": 7776000, "all": 0 };
const KINDS = ["NEW_LISTENER", "PORT_SCAN", "BRUTE_FORCE", "CONN_BURST", "CONN_FLOOD", "SYN_FLOOD", "SYN_COOKIES", "LISTEN_OVERFLOW", "RST_STORM", "HOST_DOWN", "HOST_UP"];
const tbl = (...kids) => h("div", { class: "tablewrap" }, h("table", {}, ...kids));
const dot = status => h("span", { class: "dot " + status, role: "img", "aria-label": "status: " + status, title: status });
function announce(msg) { const l = document.getElementById("live"); if (l) { l.textContent = ""; setTimeout(() => { l.textContent = msg; }, 30); } }
const curTheme = () => document.documentElement.dataset.theme;
function setTheme(t) { document.documentElement.dataset.theme = t; try { localStorage.setItem("nw_theme", t); } catch (e) {} announce(t + " theme"); render(); }
if (window.matchMedia) matchMedia("(prefers-color-scheme: light)").addEventListener("change", e => { let s = null; try { s = localStorage.getItem("nw_theme"); } catch (x) {} if (!s) { document.documentElement.dataset.theme = e.matches ? "light" : "dark"; } });
function sel(options, value, onchange, label) {
  const s = h("select", { "aria-label": label || "", onchange: e => onchange(e.target.value) }, options.map(([v, t]) => h("option", { value: v }, t)));
  s.value = value; return s;
}


function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) e.setAttribute(k, v === true ? "" : v);
  }
  for (const c of kids.flat(Infinity)) if (c != null && c !== false) e.append(c.nodeType ? c : document.createTextNode(String(c)));
  return e;
}
function svg(tag, attrs) {
  const e = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  return e;
}
async function api(path, body) {
  const opt = { headers: { "X-Requested-With": "netwatch" }, credentials: "same-origin" };
  if (body !== undefined) { opt.method = "POST"; opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
  const r = await fetch(path, opt);
  if (r.status === 401 && path !== "/api/login") { showLogin(); throw new Error("login"); }
  const j = await r.json().catch(() => ({}));
  if (r.status === 403 && j.must_change) { S.me = { ...(S.me || {}), must_change: true }; showChangePassword(); throw new Error("login"); }
  if (!r.ok) { const e = new Error(j.error || r.statusText); e.data = j; throw e; }
  return j;
}
const ago = ts => { const d = Math.max(0, Math.floor(Date.now() / 1000 - ts)); return d < 60 ? d + "s ago" : d < 3600 ? Math.floor(d / 60) + "m ago" : d < 86400 ? Math.floor(d / 3600) + "h ago" : Math.floor(d / 86400) + "d ago"; };
const when = ts => new Date(ts * 1000).toLocaleString();

/* ---------- login ---------- */
function showLogin(msg) {
  clearInterval(S.timer); S.me = null;
  const err = h("div", { class: "err" }, msg || "");
  const user = h("input", { type: "text", name: "username", autocomplete: "username", required: true, autocapitalize: "none", spellcheck: "false" });
  const pw = h("input", { type: "password", name: "password", autocomplete: "current-password", required: true });
  const code = h("input", { type: "text", name: "code", inputmode: "numeric", autocomplete: "one-time-code", maxlength: "6", pattern: "[0-9]{6}" });
  const codeRow = h("label", { hidden: true }, "Two-factor code", code);
  const form = h("form", {}, h("h1", {}, icon("shield"), h("span", { class: "wm" }, "net", h("span", {}, "watch"))), h("div", { class: "tag" }, "Network security monitoring"),
    h("label", {}, "Username", user), h("label", {}, "Password", pw), codeRow,
    h("button", { class: "primary", type: "submit" }, "Sign in"), err);
  form.addEventListener("submit", async e => {
    e.preventDefault(); err.textContent = "";
    try { await api("/api/login", { username: user.value, password: pw.value, code: code.value }); start(); }
    catch (x) {
      err.textContent = x.message;
      if (x.data && x.data.need_code) { codeRow.hidden = false; code.value = ""; code.focus(); } else { pw.select(); }
    }
  });
  $app.replaceChildren(h("div", { class: "login" }, form));
  user.focus();
}

function showChangePassword() {
  clearInterval(S.timer);
  const err = h("div", { class: "err" });
  const f = n => h("input", { type: "password", autocomplete: n, required: true });
  const old = f("current-password"), n1 = f("new-password"), n2 = f("new-password");
  const form = h("form", { class: "gate" }, h("h2", {}, "Change your password"),
    h("div", { class: "note" }, "You must set a new password before continuing (at least 12 characters, not containing your username)."),
    h("label", {}, "Current password", old), h("label", {}, "New password", n1), h("label", {}, "Repeat new password", n2),
    h("button", { class: "primary", type: "submit" }, "Change password"), err);
  form.addEventListener("submit", async e => {
    e.preventDefault(); err.textContent = "";
    if (n1.value !== n2.value) { err.textContent = "the new passwords do not match"; return; }
    try { await api("/api/password", { old: old.value, new: n1.value }); start(); }
    catch (x) { if (x.message !== "login") err.textContent = x.message; }
  });
  $app.replaceChildren(h("div", { class: "login" }, form));
  old.focus();
}

/* ---------- data ---------- */
const sinceParam = r => RANGES[r] ? "&since=" + (Math.floor(Date.now() / 1000) - RANGES[r]) : "";
function alertQuery(extra) {
  return "/api/alerts?limit=500" + (S.showAcked ? "&all=1" : "") + sinceParam(S.aRange) + (S.aSev ? "&severity=" + S.aSev : "") +
    (S.aMine ? "&assignee=me" : "") + (S.tag ? "&tag=" + encodeURIComponent(S.tag) : "") + (extra || "");
}
async function loadOverview() {
  const [risk, ov, ev, rs, inc] = await Promise.all([api("/api/risk"), api("/api/insights/overview?range=" + S.ovRange), api("/api/events?range=" + S.ovRange), api("/api/insights/risk"), api("/api/insights/incidents?range=" + S.ovRange)]);
  S.risk = risk; S.ov = ov; S.ovEvents = ev; S.riskScores = rs; S.incidentsOv = inc;
}
async function loadEvents() {
  try { return await api("/api/events?range=" + S.evRange + "&q=" + encodeURIComponent(S.evq)); }
  catch (e) {
    if (e.message === "login") throw e;   // a bad query is shown inline, it must not look like a server outage
    return { error: e.message, rows: [], total: 0, shown: 0, warnings: [], facets: { level: [], rule: [], host: [], source: [], mitre: [] }, histogram: { since: 0, bucket: 3600, t: [], low: [], medium: [], high: [], critical: [] } };
  }
}
async function refresh() {
  try {
    if (!S.me || S.me.must_change === undefined) S.me = await api("/api/me");
    if (S.me.must_change) return showChangePassword();
    const sum = await api("/api/summary");
    S.hosts = sum.hosts; S.openAlerts = sum.open_alerts; S.riskyExposed = sum.risky_exposed || 0; S.threatSources = sum.threat_sources || 0; S.openIncidents = sum.open_incidents || 0;
    if (!S.online) announce("Connection restored");
    S.online = true;
    if (S.tag && !S.hosts.some(x => x.tags.includes(S.tag))) S.tag = null;
    await loadRules();
    switch (S.view) {
      case "sessions": S.sessions = (await api("/api/sessions")).sessions; break;
      case "audit": S.audit = await api("/api/audit?limit=500"); break;
      case "maint": S.mutes = (await api("/api/mutes")).mutes; break;
      case "search": break;
      case "hostlist": S.riskScores = await api("/api/insights/risk"); break;
      case "overview": await loadOverview(); break;
      case "alerts": S.alerts = (await api(alertQuery())).alerts; break;
      case "incidents": S.incidents = await api("/api/insights/incidents?range=" + S.incRange); break;
      case "events": S.events = await loadEvents(); break;
      case "mitre": S.mitre = await api("/api/insights/mitre?range=" + S.mitreRange); break;
      case "rules": S.rules = await api("/api/rules?range=" + S.rulesRange); break;
      case "compliance": if (S.me.role === "admin") S.compliance = await api("/api/insights/compliance?range=" + S.compRange); break;
      case "threats":
        if (S.source) { S.srcData = await api("/api/insights/source?ip=" + encodeURIComponent(S.source)); }
        else S.threats = (await api("/api/insights/threats?range=" + S.tRange)).sources;
        break;
      case "exposure": S.exposure = await api("/api/insights/exposure"); break;
      case "traffic": S.traffic = await api("/api/insights/traffic"); break;
      case "health": S.health = await api("/api/insights/health"); break;
      default:
        if (S.sel && !S.hosts.some(x => x.id === S.sel)) S.sel = null;
        if (!S.sel) { S.view = "overview"; await loadOverview(); break; }
        S.data = await api("/api/host/" + S.sel);
        S.riskScores = await api("/api/insights/risk");
        if (S.tab === "alerts") S.alerts = (await api(alertQuery("&host=" + S.sel))).alerts;
        else if (S.tab === "trends") S.metrics = await api("/api/host/" + S.sel + "/metrics?range=" + S.cRange);
        else if (S.tab === "timeline") S.timeline = (await api("/api/host/" + S.sel + "/timeline")).events;
    }
    S.updatedAt = Math.floor(Date.now() / 1000);
  } catch (e) { if (e.message === "login") { S.stale = false; return; } if (S.online) announce("Server unreachable"); S.online = false; }
  S.stale = false;
  render();
}
async function runSearch() {
  const q = S.q.trim();
  if (q.length < 2) { S.search = { error: "Type at least 2 characters." }; S.view = "search"; return render(); }
  S.view = "search"; S.search = { loading: true }; render();
  try { S.search = await api("/api/search?q=" + encodeURIComponent(q)); } catch (e) { if (e.message === "login") return; S.search = { error: e.message }; }
  render();
}
function setNav(open) { S.nav = open; document.body.classList.toggle("nav-open", open); const b = document.getElementById("burger"); if (b) b.setAttribute("aria-expanded", String(open)); }
const go = (view, sel, tab) => {
  setNav(false);
  if (view === "hosts" && !sel) view = "overview";
  const pg = pageById(view); if (pg && pg.admin && S.me && S.me.role !== "admin") view = "overview";
  if (view !== "threats") S.source = null;
  S.view = view; S.sel = sel ?? null; S.tab = tab || "alerts"; S.filter = ""; S.data = null; S.editTags = false;
  setHash(); refresh();
};
const goSource = ip => { S.source = ip; S.srcData = null; go("threats"); };

/* ---------- rendering ---------- */
function shell() {
  if (document.getElementById("shell")) return;
  $app.replaceChildren(h("div", { id: "shell", class: "shell" }, h("header", { id: "hdr" }), h("div", { id: "ctx" }),
    h("main", {}, h("aside", { id: "side", "aria-label": "Primary" }), h("section", { id: "content", class: "content", tabindex: "-1", "aria-label": "Main content" })),
    h("div", { id: "drawer" }), h("div", { id: "navscrim", onclick: () => setNav(false) }), h("div", { id: "help" }), h("div", { id: "palette" }), h("div", { id: "toasts" }),
    h("div", { id: "live", class: "sr", role: "status", "aria-live": "polite" })));
}
/* The page re-renders on every poll; remember which control had keyboard focus and put it back,
   otherwise keyboard-only users lose their place every few seconds. */
const FOCUSABLE = "[tabindex='0'], button, select, a[href], input, textarea";
function saveFocus() {
  const a = document.activeElement; if (!a || a === document.body) return null;
  for (const id of ["content", "side", "hdr"]) {
    const root = document.getElementById(id);
    if (root && root.contains(a)) { const i = [...root.querySelectorAll(FOCUSABLE)].indexOf(a); if (i >= 0) return { id, i, tag: a.tagName }; }
  }
  return null;
}
function restoreFocus(f) {
  if (!f) return;
  const root = document.getElementById(f.id); if (!root) return;
  const list = [...root.querySelectorAll(FOCUSABLE)], el = list[Math.min(f.i, list.length - 1)];
  if (el && el.tagName === f.tag && el !== document.activeElement) el.focus({ preventScroll: true });
}
function render() {
  shell();
  const savedFocus = saveFocus();
  renderHeader(); renderSidebar(); renderContext();
  const admin = S.me.role === "admin";
  const c = document.getElementById("content"), keep = c.scrollTop;
  let kids;
  const VIEWS = { overview: overviewView, alerts: alertsPage, incidents: incidentsView, hostlist: hostsPage, events: eventsView, threats: threatsView, mitre: mitreView, rules: rulesView, exposure: exposureView, traffic: trafficView, compliance: complianceView, health: healthView, maint: maintView, sessions: sessionsView, search: searchView };
  if (S.view === "audit" && admin) kids = auditView();
  else if (S.view === "health" && !admin) kids = [h("div", { class: "empty" }, "System health is available to admins.")];
  else if (S.view === "hosts" && S.sel && S.data) kids = hostView();
  else if (!S.hosts.length && ["overview", "alerts", "hostlist", "incidents"].includes(S.view)) kids = [h("div", { class: "empty" }, h("div", { class: "big" }, "No agents enrolled yet"), "Run ", h("code", {}, "netwatch server token"), " on the server and follow the printed command on a host to monitor.")];
  else kids = (VIEWS[S.view] || overviewView)();
  c.replaceChildren(...kids.filter(k => k != null && k !== false));
  c.classList.toggle("stale", !!S.stale);
  c.scrollTop = keep;
  restoreFocus(savedFocus);
}

/* ----- alerts ----- */
function alertsBar() {
  const q = (fmt) => alertQuery("&format=" + fmt + (S.sel ? "&host=" + S.sel : "")).replace("/api/alerts?", "/api/alerts/export?");
  return h("div", { class: "bar" },
    sel([["", "All severities"], ["HIGH", "High"], ["MEDIUM", "Medium"], ["INFO", "Info"]], S.aSev, v => { S.aSev = v; refresh(); }, "Severity"),
    h("label", {}, h("input", { type: "checkbox", checked: S.aMine, onchange: e => { S.aMine = e.target.checked; refresh(); } }), "assigned to me"),
    h("label", {}, h("input", { type: "checkbox", checked: S.showAcked, onchange: e => { S.showAcked = e.target.checked; refresh(); } }), "show acknowledged"),
    h("div", { class: "grow" }),
    h("a", { class: "btn", href: q("csv"), download: "netwatch-alerts.csv" }, "CSV"), h("a", { class: "btn", href: q("json"), download: "netwatch-alerts.json" }, "JSON"),
    canAck() && h("button", { onclick: async () => { await api("/api/ack", { all: true, host: S.sel }); toast("All shown alerts acknowledged"); refresh(); } }, "Acknowledge all"));
}
function alertsTable(withHost, rows = S.alerts) {
  if (!rows.length) return h("div", { class: "empty" }, "No alerts match. ✔");
  return tbl(h("thead", {}, h("tr", {}, h("th", {}, "Time"), withHost && h("th", {}, "Host"), h("th", {}, "Severity"), h("th", {}, "Type"), h("th", {}, "Message"), h("th", {}, "Assigned"), h("th", {}, ""))),
    h("tbody", {}, rows.map(a => h("tr", { class: "click" + (a.acked || a.muted ? " acked" : ""), tabindex: "0", onclick: () => openAlert(a.id), onkeydown: e => { if (e.key === "Enter") openAlert(a.id); } },
      h("td", { title: when(a.ts) }, ago(a.ts)), withHost && h("td", {}, a.host), h("td", {}, levelBadge(a.level ?? 0), " ", h("span", { class: "sev " + a.severity }, a.severity)),
      h("td", { class: "mono" }, a.kind), h("td", {}, a.message, a.muted && h("span", { class: "tagpill" }, "muted")), h("td", {}, a.assignee || ""),
      h("td", {}, a.acked || !canAck() ? "" : h("button", { onclick: async e => { e.stopPropagation(); await api("/api/ack", { id: a.id }); toast("Alert acknowledged"); refresh(); } }, "Ack"))))));
}

/* ----- alert drawer (assign + comments) ----- */
function closeDrawer() { S.drawer = null; document.getElementById("drawer").replaceChildren(); if (S.returnFocus && document.contains(S.returnFocus)) S.returnFocus.focus(); S.returnFocus = null; }
async function openAlert(id) {
  if (!S.drawer) S.returnFocus = document.activeElement;
  S.drawer = id;
  let d, users = [];
  try { d = await api("/api/alert/" + id); if (canAck()) users = (await api("/api/users")).users; } catch (e) { return; }
  const a = d.alert, box = document.getElementById("drawer");
  const ta = h("textarea", { rows: "3", maxlength: "1000", placeholder: "Add a note: what did you find, what was done?", "aria-label": "Comment" });
  const err = h("div", { class: "err" });
  const act = async fn => { try { await fn(); toast("Saved"); await openAlert(id); refresh(); } catch (e) { err.textContent = e.message; } };
  box.replaceChildren(h("div", { class: "scrim", onclick: closeDrawer }), h("aside", { class: "drawer", role: "dialog", "aria-label": "Alert details" },
    h("div", { class: "dhead" }, h("h3", {}, levelBadge(a.level ?? 0), " ", a.kind), h("button", { onclick: closeDrawer, "aria-label": "Close", class: "icon" }, icon("x"))),
    h("div", { class: "kv" }, h("span", { class: "sev " + a.severity }, a.severity), h("span", {}, a.host), h("span", { class: "dim" }, when(a.ts) + " (" + ago(a.ts) + ")"),
      a.muted && h("span", { class: "tagpill" }, "muted"), a.acked && h("span", { class: "tagpill" }, "acknowledged")),
    h("p", { class: "msg" }, a.message), ruleBlock(a),
    canAck() && h("div", { class: "bar" },
      h("label", {}, "Assigned to ", sel([["", "(nobody)"], ...users.map(u => [u.username, u.username + " (" + u.role + ")"])], a.assignee, v => act(() => api("/api/alert/assign", { id, assignee: v })), "Assignee")),
      h("div", { class: "grow" }), !a.acked && h("button", { onclick: () => act(() => api("/api/ack", { id })) }, "Acknowledge")),
    h("h4", {}, "Notes"),
    d.comments.length ? d.comments.map(c => h("div", { class: "comment" }, h("div", { class: "dim" }, c.author + " · " + when(c.ts)), h("div", { class: "cbody" }, c.body))) : h("div", { class: "dim" }, "No notes yet."),
    canAck() && h("div", { class: "cform" }, ta, h("button", { class: "primary", onclick: () => act(async () => { if (!ta.value.trim()) throw new Error("write something first"); await api("/api/alert/comment", { id, body: ta.value }); }) }, "Add note"), err)));
  const dr = box.querySelector(".drawer");
  dr.addEventListener("keydown", e => {
    if (e.key !== "Tab") return;
    const f = [...dr.querySelectorAll("button, select, textarea, input, a[href]")].filter(x => !x.disabled && x.offsetParent !== null);
    if (!f.length) return;
    const first = f[0], last = f[f.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  });
  dr.querySelector("button").focus();
}
const SHORTCUTS = [["Ctrl K", "Command palette: jump anywhere, search anything"], ["/", "Focus the search box"], ["g o", "Overview"], ["g a", "Alerts"], ["g i", "Incidents"], ["g h", "Hosts"], ["g v", "Event explorer"],
  ["g t", "Threat sources"], ["g k", "MITRE ATT&CK"], ["g l", "Detection rules"], ["g e", "Exposure"], ["g n", "Traffic"], ["g c", "Compliance (admins)"], ["g m", "Maintenance"], ["g y", "System health (admins)"],
  ["g s", "Sessions"], ["g u", "Audit log (admins)"], ["j / k", "Next / previous row in a table"], ["Enter", "Open the focused row"], ["t", "Switch light / dark theme"], ["?", "Show or hide this help"], ["Esc", "Close the open panel"]];
function toggleHelp() {
  const box = document.getElementById("help");
  if (box.firstChild) { box.replaceChildren(); if (S.helpReturn) S.helpReturn.focus(); return; }
  S.helpReturn = document.activeElement;
  const close = h("button", { class: "primary", onclick: toggleHelp }, "Close");
  box.replaceChildren(h("div", { class: "help", onclick: e => { if (e.target.classList.contains("help")) toggleHelp(); } },
    h("div", { class: "helpbox", role: "dialog", "aria-modal": "true", "aria-label": "Keyboard shortcuts" }, h("h3", {}, "Keyboard shortcuts"),
      tbl(h("tbody", {}, SHORTCUTS.map(([k, t]) => h("tr", {}, h("td", {}, k.split(" ").map(x => x === "/" && k.length > 1 ? " / " : h("kbd", {}, x))), h("td", {}, t))))), close)));
  close.focus();
}
let gAt = 0;
document.addEventListener("keydown", e => {
  if (e.key === "Escape") { if (document.getElementById("help").firstChild) toggleHelp(); else if (S.drawer) closeDrawer(); else if (S.nav) setNav(false); return; }
  if (!S.me || e.metaKey || e.ctrlKey || e.altKey) return;
  const t = e.target;
  if (t && (/^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName) || t.isContentEditable)) return;
  if (S.me.must_change) return;
  const k = e.key;
  if (Date.now() - gAt < 1200) {
    gAt = 0;
    const dest = { o: () => go("overview"), a: () => go("alerts"), i: () => go("incidents"), v: () => go("events"), k: () => go("mitre"), l: () => go("rules"), c: () => S.me.role === "admin" && go("compliance"), h: () => go("hostlist"), t: () => { S.source = null; go("threats"); }, e: () => go("exposure"), n: () => go("traffic"), m: () => go("maint"), y: () => S.me.role === "admin" && go("health"), s: () => go("sessions"), u: () => S.me.role === "admin" && go("audit") }[k];
    if (dest) { e.preventDefault(); dest(); return; }
  }
  if (k === "g") { gAt = Date.now(); return; }
  if (k === "/") { e.preventDefault(); const b = document.getElementById("gsearch"); if (b) { setNav(false); b.focus(); b.select(); } }
  else if (k === "?") { e.preventDefault(); toggleHelp(); }
  else if (k === "t") setTheme(curTheme() === "light" ? "dark" : "light");
  else if (k === "j" || k === "k") {
    const rows = [...document.querySelectorAll("#content tr.click")]; if (!rows.length) return;
    const i = rows.indexOf(document.activeElement), n = k === "j" ? Math.min(rows.length - 1, i + 1) : Math.max(0, i < 0 ? 0 : i - 1);
    e.preventDefault(); rows[n].focus(); rows[n].scrollIntoView({ block: "nearest" });
  }
});

/* ----- host page ----- */
const card = (k, v, bad) => h("div", { class: "card" + (bad ? " bad" : "") }, h("div", { class: "k" }, k), h("div", { class: "v" }, v));
const TABS = [["alerts", "Alerts"], ["trends", "Trends"], ["ports", "Listening ports"], ["conns", "Connections"], ["changes", "Changes"], ["timeline", "Timeline"]];
function tagEditor(x) {
  if (!S.editTags) return h("div", { class: "tagrow" }, x.tags.length ? x.tags.map(t => h("span", { class: "tagpill" }, t)) : h("span", { class: "dim" }, "no tags"),
    canAck() && h("button", { class: "link", onclick: () => { S.editTags = true; render(); } }, "edit tags"));
  const inp = h("input", { type: "text", value: x.tags.join(", "), placeholder: "prod, web, eu-west", "aria-label": "Tags", maxlength: "300" }), err = h("span", { class: "err" });
  const save = async () => { try { await api("/api/host/tags", { id: x.id, tags: inp.value.split(",").map(t => t.trim()).filter(Boolean) }); S.editTags = false; refresh(); } catch (e) { err.textContent = e.message; } };
  inp.addEventListener("keydown", e => { if (e.key === "Enter") save(); });
  return h("div", { class: "tagrow" }, inp, h("button", { class: "primary", onclick: save }, "Save"), h("button", { onclick: () => { S.editTags = false; render(); } }, "Cancel"), err);
}
function hostView() {
  const d = S.data, x = d.host, q = S.filter.toLowerCase();
  const match = (...f) => !q || f.some(v => String(v ?? "").toLowerCase().includes(q));
  const search = h("input", { type: "search", id: "filter", placeholder: "Filter…", value: S.filter, "aria-label": "Filter", oninput: e => { S.filter = e.target.value; const p = e.target.selectionStart; render(); const n = document.getElementById("filter"); n.focus(); n.setSelectionRange(p, p); } });
  let body;
  if (S.tab === "alerts") body = [alertsBar(), alertsTable(false)];
  else if (S.tab === "trends") body = trendsView();
  else if (S.tab === "timeline") body = timelineView();
  else if (S.tab === "ports") {
    const rows = d.listeners.filter(l => match(l.proto, l.addr, l.port, l.process, l.user, l.pid));
    body = [h("div", { class: "bar" }, search), rows.length ? tbl(h("thead", {}, h("tr", {}, ["Proto", "Address", "Port", "PID", "Process", "User", "Scope", "Open for"].map(t => h("th", {}, t)))),
      h("tbody", {}, rows.map(l => { const ext = !(l.addr.startsWith("127.") || l.addr === "::1");
        return h("tr", {}, h("td", {}, l.proto), h("td", { class: "mono" }, l.addr), h("td", { class: "mono" }, l.port), h("td", {}, l.pid ?? "-"), h("td", {}, l.process), h("td", {}, l.user), h("td", { class: ext ? "ext" : "" }, ext ? "external" : "local"), h("td", {}, ago(l.first_seen))); }))) : h("div", { class: "empty" }, "No listeners.")];
  } else if (S.tab === "conns") {
    const rows = d.conns.filter(c => match(c.proto, c.state, c.local, c.remote, c.process, c.pid));
    body = [h("div", { class: "bar" }, search, h("span", { class: "note" }, `${rows.length} of ${d.conns_total}`)), rows.length ? tbl(h("thead", {}, h("tr", {}, ["Proto", "State", "Local", "Remote", "PID", "Process"].map(t => h("th", {}, t)))),
      h("tbody", {}, rows.slice(0, 1500).map(c => h("tr", {}, h("td", {}, c.proto), h("td", { class: "st-" + c.state }, c.state), h("td", { class: "mono" }, c.local), h("td", { class: "mono" }, c.remote), h("td", {}, c.pid ?? "-"), h("td", {}, c.process))))) : h("div", { class: "empty" }, "No connections.")];
  } else {
    const rows = d.events.filter(e => match(e.what, e.event));
    body = [h("div", { class: "bar" }, search), rows.length ? tbl(h("thead", {}, h("tr", {}, ["Time", "Event", "Listener"].map(t => h("th", {}, t)))),
      h("tbody", {}, rows.map(e => h("tr", {}, h("td", {}, when(e.ts)), h("td", { class: "ev-" + e.event }, e.event.toUpperCase()), h("td", { class: "mono" }, e.what))))) : h("div", { class: "empty" }, "No listener changes recorded yet."),
      h("div", { class: "note" }, "Ports that opened or closed after the agent's first report: the first thing to check in an investigation.")];
  }
  return [
    h("div", { class: "title" }, dot(x.status), h("h2", {}, x.name), h("span", { class: "pill" }, x.status), h("span", { class: "pill" }, "seen " + ago(x.last_seen)), h("span", { class: "pill" }, x.addr)),
    tagEditor(x), h("div", { class: "note" }, `${x.os} · agent ${x.version} · id ${x.id}`),
    !x.is_root && h("div", { class: "warnbar" }, "Agent is not running as root: process names are missing for other users' sockets."),
    h("div", { class: "cards" }, card("Listening", x.listeners), card("Established", x.established), card("SYN_RECV", x.syn_recv, x.syn_recv > 10), card("TIME_WAIT", x.time_wait), card("Total sockets", x.total), card("Open alerts", x.open_alerts, x.open_alerts > 0)),
    hostRiskBox(x.id),
    h("div", { class: "tabs", role: "tablist" }, TABS.map(([k, label]) => h("div", { class: "tab" + (S.tab === k ? " sel" : ""), role: "tab", "aria-selected": String(S.tab === k), tabindex: "0", onclick: () => { S.tab = k; S.filter = ""; refresh(); }, onkeydown: e => { if (e.key === "Enter") { S.tab = k; S.filter = ""; refresh(); } } }, label))),
    ...body];
}

/* ----- trends: real axes, per-metric scales, hover read-out ----- */
/* A chart is never the only way to read its numbers: the "Table" toggle swaps the plot for the same data as a table. */
function chartTable(box, plot, head, rows) {
  const t = h("div", { class: "tablewrap", hidden: true }, h("table", {}, h("thead", {}, h("tr", {}, head.map(x => h("th", {}, x)))), h("tbody", {}, rows.map(r => h("tr", {}, r.map(c => h("td", {}, c)))))));
  const b = h("button", { class: "link tv", "aria-pressed": "false", onclick: () => { const on = t.hidden; t.hidden = !on; plot.forEach(p => p.toggleAttribute("hidden", on)); b.textContent = on ? "Chart" : "Table"; b.setAttribute("aria-pressed", String(on)); } }, "Table");
  box.append(t); return b;
}
function niceMax(v) { if (v <= 4) return 4; const p = Math.pow(10, Math.floor(Math.log10(v))); for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p; return 10 * p; }
function fmtTick(ts, span) { const d = new Date(ts * 1000); return span <= 86400 * 1.5 ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : d.toLocaleDateString([], { month: "short", day: "numeric" }) + " " + d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); }
function lineChart(title, color, t, vals, since, until, unit) {
  const W = 900, H = 150, L = 46, R = 12, T = 10, B = 24, box = h("div", { class: "chart" }), span = Math.max(until - since, 1);
  const head = h("div", { class: "ctitle" }, h("span", {}, title), h("span", { class: "dim" }, vals.length ? `now ${vals[vals.length - 1]} · peak ${Math.max(...vals)}` : ""));
  box.append(head);
  if (vals.length < 2) { box.append(h("div", { class: "note" }, "Not enough data in this window yet (reports arrive every few seconds).")); return box; }
  const ymax = niceMax(Math.max(...vals, 1)), X = ts => L + (ts - since) / span * (W - L - R), Y = v => T + (1 - v / ymax) * (H - T - B);
  const svgEl = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": title + " over time", class: color });
  for (let i = 0; i <= 4; i++) {
    const v = ymax * i / 4, y = Y(v);
    svgEl.append(svg("line", { x1: L, x2: W - R, y1: y, y2: y, class: "grid" }));
    const tx = svg("text", { x: L - 6, y: y + 4, "text-anchor": "end", class: "axis" }); tx.textContent = Number.isInteger(v) ? v : v.toFixed(1); svgEl.append(tx);
  }
  for (let i = 0; i <= 5; i++) {
    const ts = since + span * i / 5, tx = svg("text", { x: X(ts), y: H - 6, "text-anchor": i === 0 ? "start" : i === 5 ? "end" : "middle", class: "axis" }); tx.textContent = fmtTick(ts, span); svgEl.append(tx);
  }
  const pts = t.map((ts, i) => X(ts).toFixed(1) + "," + Y(vals[i]).toFixed(1));
  svgEl.append(svg("polygon", { points: `${X(t[0]).toFixed(1)},${Y(0)} ${pts.join(" ")} ${X(t[t.length - 1]).toFixed(1)},${Y(0)}`, class: "area" }),
    svg("polyline", { points: pts.join(" "), class: "ln" }));
  const guide = svg("line", { y1: T, y2: H - B, class: "guide", visibility: "hidden" }), dotEl = svg("circle", { r: "4", class: "dotp", visibility: "hidden" });
  svgEl.append(guide, dotEl);
  const tip = h("div", { class: "tip", hidden: true });
  svgEl.addEventListener("mousemove", ev => {
    const r = svgEl.getBoundingClientRect(), ts = since + ((ev.clientX - r.left) / r.width * W - L) / (W - L - R) * span;
    let best = 0; for (let i = 1; i < t.length; i++) if (Math.abs(t[i] - ts) < Math.abs(t[best] - ts)) best = i;
    const x = X(t[best]); guide.setAttribute("x1", x); guide.setAttribute("x2", x); guide.setAttribute("visibility", "visible");
    dotEl.setAttribute("cx", x); dotEl.setAttribute("cy", Y(vals[best])); dotEl.setAttribute("visibility", "visible");
    tip.hidden = false; tip.textContent = `${new Date(t[best] * 1000).toLocaleString()}  ·  ${vals[best]} ${unit}`;
    tip.style.left = Math.min(Math.max(x / W * r.width - 10, 0), r.width - 230) + "px";
  });
  svgEl.addEventListener("mouseleave", () => { tip.hidden = true; guide.setAttribute("visibility", "hidden"); dotEl.setAttribute("visibility", "hidden"); });
  box.append(svgEl, tip);
  head.append(chartTable(box, [svgEl, tip], ["Time", unit], t.map((ts, i) => [when(ts), vals[i]]).reverse().slice(0, 300)));
  return box;
}
function trendsView() {
  const m = S.metrics;
  const bar = h("div", { class: "bar" }, h("div", { class: "seg" }, ["1h", "6h", "24h", "7d"].map(r => h("button", { class: S.cRange === r ? "on" : "", onclick: () => { S.cRange = r; S.metrics = null; refresh(); } }, r))),
    h("span", { class: "note" }, "Each point is the highest value in its time bucket, so short spikes are never averaged away."));
  if (!m) return [bar, skeleton()];
  return [bar, lineChart("Established connections", "c-accent", m.t, m.established, m.since, m.until, "connections"),
    lineChart("Half-open connections (SYN_RECV): a flood shows up here", "c-bad", m.t, m.syn_recv, m.since, m.until, "half-open"),
    lineChart("TIME_WAIT", "c-warn", m.t, m.time_wait, m.since, m.until, "sockets"), lineChart("Listening sockets: a step up means a port was opened", "c-ok", m.t, m.listeners, m.since, m.until, "listeners")];
}

/* ----- timeline ----- */
function timelineView() {
  const ev = S.timeline; if (!ev) return [skeleton()];
  if (!ev.length) return [h("div", { class: "empty" }, "Nothing has happened on this host yet.")];
  return [h("div", { class: "note" }, "Everything on this host in one stream: alerts, host up/down and listener changes, newest first."),
    h("div", { class: "timeline" }, ev.map(e => h("div", { class: "tl" }, h("div", { class: "tldot " + e.severity }), h("div", { class: "tlbody" },
      h("div", {}, h("span", { class: "sev " + e.severity }, e.title), "  ", h("span", { class: "dim", title: when(e.ts) }, ago(e.ts) + " · " + when(e.ts))), h("div", { class: "mono" }, e.detail)))))];
}

/* ----- maintenance windows ----- */
function maintView() {
  const form = (() => {
    if (!canAck()) return h("div", { class: "note" }, "Your role is read-only; operators and admins can create maintenance windows.");
    const host = sel([["", "All hosts"], ...S.hosts.map(x => [x.id, x.name])], "", () => {}, "Host"), kind = sel([["", "Any alert type"], ...KINDS.map(k => [k, k])], "", () => {}, "Alert type");
    const dur = sel([["30", "30 minutes"], ["60", "1 hour"], ["240", "4 hours"], ["1440", "24 hours"], ["10080", "7 days"]], "60", () => {}, "Duration");
    const reason = h("input", { type: "text", placeholder: "Reason (recorded in the audit log), e.g. planned deploy", maxlength: "200", "aria-label": "Reason", class: "wide" }), err = h("span", { class: "err" });
    return h("div", { class: "panel" }, h("h4", {}, "New maintenance window"), h("div", { class: "bar" }, host, kind, dur, reason,
      h("button", { class: "primary", onclick: async () => { err.textContent = ""; try { await api("/api/mutes/add", { host: host.value || null, kind: kind.value || null, minutes: +dur.value, reason: reason.value }); reason.value = ""; refresh(); } catch (e) { err.textContent = e.message; } } }, "Start"), err),
      h("div", { class: "note" }, "Matching alerts are still recorded and shown (marked muted) but don't count as open alerts and aren't sent to the webhook."));
  })();
  return [h("div", { class: "title" }, h("h2", {}, "Maintenance windows")), form,
    S.mutes.length ? tbl(h("thead", {}, h("tr", {}, ["Status", "Scope", "Alert type", "Until", "Reason", "By", ""].map(t => h("th", {}, t)))),
      h("tbody", {}, S.mutes.map(m => h("tr", { class: m.active ? "" : "acked" }, h("td", {}, m.active ? h("span", { class: "sev MEDIUM" }, "ACTIVE") : "ended"), h("td", {}, m.host_id ? m.host || m.host_id : "all hosts"), h("td", { class: "mono" }, m.kind || "any"),
        h("td", { title: when(m.until) }, m.active ? "in " + untilStr(m.until) : when(m.until)), h("td", {}, m.reason), h("td", {}, m.created_by),
        h("td", {}, m.active && canAck() ? h("button", { class: "danger", onclick: async () => { await api("/api/mutes/end", { id: m.id }); refresh(); } }, "End now") : ""))))) : h("div", { class: "empty" }, "No maintenance windows yet.")];
}
const untilStr = ts => { const d = Math.max(0, ts - Math.floor(Date.now() / 1000)); return d < 3600 ? Math.ceil(d / 60) + "m" : d < 86400 ? Math.floor(d / 3600) + "h " + Math.floor(d % 3600 / 60) + "m" : Math.floor(d / 86400) + "d"; };

/* ----- search ----- */
function searchView() {
  const r = S.search || {};
  if (r.loading) return [h("div", { class: "empty" }, "Searching…")];
  if (r.error) return [h("div", { class: "title" }, h("h2", {}, "Search")), h("div", { class: "empty" }, r.error)];
  const sect = (title, rows, head, cells, target) => rows.length ? [h("h4", {}, `${title} (${rows.length}${rows.length >= 50 ? "+" : ""})`),
    tbl(h("thead", {}, h("tr", {}, head.map(t => h("th", {}, t)))), h("tbody", {}, rows.map(x => h("tr", { class: "click", tabindex: "0", onclick: () => target(x), onkeydown: e => { if (e.key === "Enter") target(x); } }, cells(x)))))] : [];
  const none = !(r.hosts.length || r.listeners.length || r.conns.length || r.alerts.length);
  return [h("div", { class: "title" }, h("h2", {}, `Search: “${S.q.trim()}”`)), none ? h("div", { class: "empty" }, "No matches in hosts, listening ports, connections or alerts.") : null,
    ...sect("Hosts", r.hosts, ["Host", "Address", "Tags"], x => [h("td", {}, x.name), h("td", { class: "mono" }, x.addr), h("td", {}, x.tags.join(", "))], x => go("hosts", x.id)),
    ...sect("Listening ports", r.listeners, ["Host", "Proto", "Address", "Port", "Process", "User"], x => [h("td", {}, x.host), h("td", {}, x.proto), h("td", { class: "mono" }, x.addr), h("td", { class: "mono" }, x.port), h("td", {}, x.process), h("td", {}, x.user)], x => go("hosts", x.host_id, "ports")),
    ...sect("Connections", r.conns, ["Host", "State", "Local", "Remote", "Process"], x => [h("td", {}, x.host), h("td", { class: "st-" + x.state }, x.state), h("td", { class: "mono" }, x.local), h("td", { class: "mono" }, x.remote), h("td", {}, x.process)], x => go("hosts", x.host_id, "conns")),
    ...sect("Alerts", r.alerts, ["Time", "Host", "Severity", "Type", "Message"], x => [h("td", {}, ago(x.ts)), h("td", {}, x.host), h("td", {}, h("span", { class: "sev " + x.severity }, x.severity)), h("td", { class: "mono" }, x.kind), h("td", {}, x.message)], x => openAlert(x.id))];
}

function sessionsView() {
  const admin = S.me.role === "admin";
  return [h("div", { class: "title" }, h("h2", {}, admin ? "Active sessions · all users" : "Your sessions")),
    h("div", { class: "bar" }, h("div", { class: "grow" }),
      h("button", { class: "danger", onclick: async () => { if (!confirm("Sign out of every session of your account, including this one?")) return; await api("/api/logout-all", {}).catch(() => {}); showLogin(); } }, "Sign out everywhere")),
    S.sessions.length ? tbl(h("thead", {}, h("tr", {}, ["User", "From", "Signed in", "Last active", ""].map(t => h("th", {}, t)))),
      h("tbody", {}, S.sessions.map(x => h("tr", {}, h("td", {}, x.user, x.current && h("span", { class: "cur" }, "  (this session)")), h("td", { class: "mono" }, x.ip), h("td", { title: when(x.created) }, ago(x.created)), h("td", {}, ago(x.last)),
        h("td", {}, x.current ? "" : h("button", { class: "danger", onclick: async () => { await api("/api/sessions/revoke", { id: x.id }); refresh(); } }, "Revoke")))))) : h("div", { class: "empty" }, "No sessions."),
    h("div", { class: "note" }, "Sessions end after inactivity or at the absolute lifetime. Changing your password ends your other sessions.")];
}

function auditView() {
  const d = S.audit; if (!d) return [skeleton()];
  const q = S.filter.toLowerCase();
  const rows = d.entries.filter(e => !q || [e.actor, e.action, e.target, e.detail, e.ip].some(v => String(v).toLowerCase().includes(q)));
  const search = h("input", { type: "search", id: "filter", placeholder: "Filter…", value: S.filter, "aria-label": "Filter", oninput: e => { S.filter = e.target.value; const p = e.target.selectionStart; render(); const n = document.getElementById("filter"); n.focus(); n.setSelectionRange(p, p); } });
  return [h("div", { class: "title" }, h("h2", {}, "Audit log")),
    h("div", { class: "integrity " + (d.integrity.ok ? "ok" : "bad") }, d.integrity.ok ? `✔ Integrity verified: ${d.integrity.entries} entries, hash chain intact` : "✖ INTEGRITY FAILURE: " + d.integrity.error),
    h("div", { class: "bar" }, search, h("div", { class: "grow" }), h("a", { class: "btn", href: "/api/audit?format=csv&limit=20000", download: "netwatch-audit.csv" }, "Export CSV"), h("a", { class: "btn", href: "/api/audit?format=json&limit=20000", download: "netwatch-audit.json" }, "Export JSON")),
    rows.length ? tbl(h("thead", {}, h("tr", {}, ["Time", "Actor", "Action", "Target", "Detail", "From"].map(t => h("th", {}, t)))),
      h("tbody", {}, rows.map(e => h("tr", {}, h("td", { title: String(e.ts) }, when(e.ts)), h("td", {}, e.actor), h("td", { class: "mono" }, e.action), h("td", {}, e.target), h("td", {}, e.detail), h("td", { class: "mono" }, e.ip))))) : h("div", { class: "empty" }, "No matching entries."),
    h("div", { class: "note" }, "Each entry commits to the hash of the one before it. Verify from the server with `netwatch server audit --verify`.")];
}


/* ===================== insight pages ===================== */
const pill = (text, cls) => h("span", { class: "tagpill " + (cls || "") }, text);
const intTag = internal => pill(internal ? "internal" : "external", internal ? "" : "warnpill");
const kindTags = kinds => h("span", {}, kinds.map(k => pill(k)));
const fmtBytes = n => n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : n < 1073741824 ? (n / 1048576).toFixed(1) + " MB" : (n / 1073741824).toFixed(2) + " GB";
const fmtDur = s => s < 60 ? s + "s" : s < 3600 ? Math.floor(s / 60) + "m" : s < 86400 ? Math.floor(s / 3600) + "h " + Math.floor(s % 3600 / 60) + "m" : Math.floor(s / 86400) + "d " + Math.floor(s % 86400 / 3600) + "h";
function copyBtn(text) {
  const b = h("button", { class: "link", onclick: async () => { try { await navigator.clipboard.writeText(text); b.textContent = "copied ✔"; announce("Copied"); } catch (e) { b.textContent = "copy failed"; } setTimeout(() => { b.textContent = "copy"; }, 1500); } }, "copy");
  return b;
}
const barList = (rows, label, count, cls) => { const max = Math.max(1, ...rows.map(count)); return rows.map(r => { const f = h("div", { class: "barfill " + (cls ? cls(r) : "") }); f.style.width = Math.max(2, count(r) / max * 100) + "%"; return h("div", { class: "barrow" }, h("span", { class: "mono" }, label(r)), h("div", { class: "bartrack" }, f), h("span", {}, count(r))); }); };
const rangeSeg = (opts, cur, on) => h("div", { class: "seg", role: "group" }, opts.map(r => h("button", { class: cur === r ? "on" : "", "aria-pressed": String(cur === r), onclick: () => on(r) }, r)));
const sortable = (cols, key, onsort) => h("tr", {}, cols.map(([k, label]) => h("th", { class: k ? "sortable" : "", tabindex: k ? "0" : null, "aria-sort": S[key].k === k ? (S[key].dir > 0 ? "ascending" : "descending") : null,
  onclick: k ? () => onsort(k) : null, onkeydown: k ? e => { if (e.key === "Enter") onsort(k); } : null }, label, S[key].k === k ? (S[key].dir > 0 ? " ▲" : " ▼") : "")));

/* stacked bars (alerts per bucket by severity) with the same axes/hover as the line charts */
function stackedBars(title, t, series, since, until, bucket, unit) {
  const W = 900, H = 170, L = 40, R = 10, T = 10, B = 24, box = h("div", { class: "chart" });
  const totals = t.map((_, i) => series.reduce((n, s) => n + s.vals[i], 0)), sum = totals.reduce((a, b) => a + b, 0);
  const head = h("div", { class: "ctitle" }, h("span", {}, title), h("span", { class: "legend" }, series.map(s => h("span", {}, h("i", { class: "sw " + s.cls }), s.name)), h("span", { class: "dim" }, sum + " total")));
  box.append(head);
  if (!sum) { box.append(h("div", { class: "note" }, "No alerts in this period ✔")); return box; }
  const span = Math.max(until - since, 1), ymax = niceMax(Math.max(...totals)), X = ts => L + (ts - since) / span * (W - L - R), Y = v => T + (1 - v / ymax) * (H - T - B);
  const bw = Math.max(3, bucket / span * (W - L - R) - 3), svgEl = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": title });
  for (let i = 0; i <= 4; i++) { const v = ymax * i / 4, y = Y(v); svgEl.append(svg("line", { x1: L, x2: W - R, y1: y, y2: y, class: "grid" })); const tx = svg("text", { x: L - 6, y: y + 4, "text-anchor": "end", class: "axis" }); tx.textContent = Number.isInteger(v) ? v : v.toFixed(1); svgEl.append(tx); }
  for (let i = 0; i <= 5; i++) { const ts = since + span * i / 5, tx = svg("text", { x: X(ts), y: H - 6, "text-anchor": i === 0 ? "start" : i === 5 ? "end" : "middle", class: "axis" }); tx.textContent = fmtTick(ts, span); svgEl.append(tx); }
  t.forEach((ts, i) => { let acc = 0; for (const s of series) { const v = s.vals[i]; if (!v) continue; const y1 = Y(acc + v), y0 = Y(acc); svgEl.append(svg("rect", { x: X(ts) + 1, y: y1, width: bw, height: Math.max(1, y0 - y1), class: s.cls })); acc += v; } });
  const tip = h("div", { class: "tip", hidden: true });
  svgEl.addEventListener("mousemove", ev => {
    const r = svgEl.getBoundingClientRect(), ts = since + ((ev.clientX - r.left) / r.width * W - L) / (W - L - R) * span;
    let best = -1; t.forEach((x, i) => { if (ts >= x && ts < x + bucket) best = i; });
    if (best < 0) { tip.hidden = true; return; }
    tip.hidden = false; tip.textContent = new Date(t[best] * 1000).toLocaleString() + "  ·  " + series.map(s => s.name + " " + s.vals[best]).join(", ");
    tip.style.left = Math.min(Math.max(X(t[best]) / W * r.width - 10, 0), r.width - 330) + "px";
  });
  svgEl.addEventListener("mouseleave", () => { tip.hidden = true; });
  box.append(svgEl, tip);
  head.querySelector(".legend").append(chartTable(box, [svgEl, tip], ["Time", ...series.map(s => s.name)], t.map((ts, i) => [when(ts), ...series.map(s => s.vals[i])]).reverse().slice(0, 300)));
  return box;
}

/* ---------- alerts page ---------- */
function alertsPage() {
  return [h("div", { class: "title" }, h("h2", {}, "Alerts" + (S.tag ? " · hosts tagged " + S.tag : ""))), alertsBar(), alertsTable(true)];
}

/* One whole split into a few parts: a tall segmented bar with a names-only legend (counts print inside blocks that are wide enough). */
function segBar(parts) {
  const total = parts.reduce((n, p) => n + p.value, 0) || 1;
  const bar = h("div", { class: "segbar", role: "img", "aria-label": parts.map(p => p.label + " " + p.value).join(", ") });
  parts.filter(p => p.value > 0).forEach(p => {
    const el = h("div", { class: "part " + p.cls, title: p.label + ": " + p.value }, p.value / total >= 0.12 ? String(p.value) : "");
    el.style.flex = p.value + " 1 0"; bar.append(el);
  });
  return h("div", {}, bar, h("div", { class: "legend names" }, parts.map(p => h("span", {}, h("i", { class: p.cls }), p.label + " " + p.value))));
}
const verKey = v => String(v).split(".").map(n => parseInt(n, 10) || 0);
const verCmp = (x, y) => { const a = verKey(x), b = verKey(y); for (let i = 0; i < Math.max(a.length, b.length); i++) { const d = (a[i] || 0) - (b[i] || 0); if (d) return d; } return 0; };
function agentSummary() {
  const hs = S.hosts, count = (f) => { const m = {}; hs.forEach(x => { const k = f(x) || "unknown"; m[k] = (m[k] || 0) + 1; }); return Object.entries(m).sort((p, q) => q[1] - p[1] || p[0].localeCompare(q[0])); };
  const up = hs.filter(x => x.status === "up").length, down = hs.filter(x => x.status === "down").length, pend = hs.length - up - down;
  const vers = count(x => x.version), newest = vers.map(v => v[0]).sort(verCmp).pop(), os = count(x => x.os);
  return h("div", { class: "riskgrid" },
    h("div", { class: "rpanel" }, h("h4", {}, "Agent status"), segBar([{ label: "Reporting", value: up, cls: "ok" }, { label: "Silent", value: down, cls: "bad" }, { label: "Pending", value: pend, cls: "warn" }])),
    h("div", { class: "rpanel" }, h("h4", {}, "Agent versions"), h("div", { class: "meterlist" }, barList(vers, r => r[0] + (r[0] === newest ? " (newest)" : ""), r => r[1], r => r[0] === newest ? "" : "warn")),
      vers.length > 1 ? h("div", { class: "note" }, "Older agents are amber. Upgrade them to match the server.") : null),
    h("div", { class: "rpanel" }, h("h4", {}, "Operating systems"), h("div", { class: "meterlist" }, barList(os.slice(0, 6), r => r[0], r => r[1]))));
}

/* ---------- hosts page ---------- */
function hostsPage() {
  const q = S.filter.toLowerCase(), { k, dir } = S.hSort;
  const key = { status: x => ({ down: 0, pending: 1, up: 2 }[x.status] ?? 3), name: x => x.name.toLowerCase(), addr: x => x.addr, os: x => x.os, version: x => x.version, listeners: x => x.listeners, established: x => x.established, syn_recv: x => x.syn_recv, open_alerts: x => x.open_alerts, risk: x => ((S.riskScores?.hosts || []).find(r => r.id === x.id) || { score: 0 }).score, last_seen: x => x.last_seen }[k] || (x => x.name);
  const rows = S.hosts.filter(x => (!S.tag || x.tags.includes(S.tag)) && (!q || [x.name, x.addr, x.os, x.tags.join(" "), x.status].some(v => String(v).toLowerCase().includes(q)))).sort((a, b) => { const A = key(a), B = key(b); return (A < B ? -1 : A > B ? 1 : 0) * dir; });
  const search = h("input", { type: "search", id: "filter", placeholder: "Filter hosts…", value: S.filter, "aria-label": "Filter hosts", oninput: e => { S.filter = e.target.value; const p = e.target.selectionStart; render(); const n = document.getElementById("filter"); n.focus(); n.setSelectionRange(p, p); } });
  const onsort = c => { S.hSort = { k: c, dir: S.hSort.k === c ? -S.hSort.dir : 1 }; render(); };
  return [h("div", { class: "title" }, h("h2", {}, "Hosts"), h("span", { class: "dim" }, rows.length + " of " + S.hosts.length)), agentSummary(), h("div", { class: "bar" }, search),
    tbl(h("thead", {}, sortable([["status", "Status"], ["name", "Host"], ["addr", "Address"], ["os", "OS"], ["version", "Agent"], ["listeners", "Listening"], ["established", "Established"], ["syn_recv", "SYN_RECV"], ["open_alerts", "Alerts"], ["risk", "Risk"], ["", "Tags"], ["last_seen", "Last seen"]], "hSort", onsort)),
      h("tbody", {}, rows.map(x => h("tr", { class: "click", tabindex: "0", onclick: () => go("hosts", x.id), onkeydown: e => { if (e.key === "Enter") go("hosts", x.id); } },
        h("td", {}, dot(x.status), " ", x.status), h("td", {}, x.name), h("td", { class: "mono" }, x.addr), h("td", {}, x.os), h("td", {}, x.version), h("td", {}, x.listeners), h("td", {}, x.established),
        h("td", { class: x.syn_recv > 10 ? "ext" : "" }, x.syn_recv), h("td", {}, x.open_alerts ? h("span", { class: "badge" }, x.open_alerts) : 0), h("td", {}, (() => { const r = (S.riskScores?.hosts || []).find(z => z.id === x.id); return r ? riskBar(r.score, r.rating) : ""; })()), h("td", {}, x.tags.map(t => pill(t))), h("td", { title: when(x.last_seen) }, ago(x.last_seen))))))];
}

/* ---------- threat sources ---------- */
function threatsView() {
  if (S.source) return sourceDetail();
  const rows = S.threats;
  const head = [h("div", { class: "title" }, h("h2", {}, "Threat sources")),
    h("div", { class: "note" }, "Addresses named in alerts: port scans, brute force, connection floods. Ranked by high-severity alerts. Click one to investigate and get containment commands.")];
  if (!rows) return [...head, skeleton()];
  if (!rows.length) return [...head, h("div", { class: "empty" }, "No attributed attacker activity in this period ✔")];
  return [...head, tbl(h("thead", {}, h("tr", {}, ["Source", "Scope", "High", "Alerts", "Types", "Hosts hit", "Live conns", "First seen", "Last seen"].map(t => h("th", {}, t)))),
    h("tbody", {}, rows.map(x => h("tr", { class: "click", tabindex: "0", onclick: () => goSource(x.ip), onkeydown: e => { if (e.key === "Enter") goSource(x.ip); } },
      h("td", { class: "mono" }, x.ip), h("td", {}, x.owner ? pill("this host: " + x.owner.host, "warnpill") : intTag(x.internal)), h("td", {}, x.high ? h("span", { class: "sev HIGH" }, x.high) : 0), h("td", {}, x.count), h("td", {}, kindTags(x.kinds)), h("td", {}, x.hosts),
      h("td", {}, x.connections_now || 0), h("td", { title: when(x.first) }, ago(x.first)), h("td", { title: when(x.last) }, ago(x.last))))))];
}
function sourceDetail() {
  const d = S.srcData, back = h("button", { onclick: () => { S.source = null; S.srcData = null; refresh(); } }, "← All sources");
  if (!d || d.ip !== S.source) return [h("div", { class: "title" }, back, h("h2", { class: "mono" }, S.source)), skeleton()];
  const hostsHit = Object.entries(d.hosts), high = d.alerts.filter(a => a.severity === "HIGH").length, first = d.alerts.length ? Math.min(...d.alerts.map(a => a.ts)) : 0, v6 = d.ip.includes(":");
  const cmds = d.internal || d.owner ? null : [["ufw", `sudo ufw deny from ${d.ip}`], ["iptables", `sudo ${v6 ? "ip6tables" : "iptables"} -I INPUT -s ${d.ip} -j DROP`], ["nftables", `sudo nft add rule inet filter input ${v6 ? "ip6" : "ip"} saddr ${d.ip} drop`]];
  return [h("div", { class: "title" }, back, h("h2", { class: "mono" }, d.ip), d.owner ? pill("belongs to " + d.owner.host, "warnpill") : intTag(d.internal)),
    h("div", { class: "cards" }, card("Alerts", d.alerts.length), card("High severity", high, high > 0), card("Hosts targeted", hostsHit.length), card("Connections now", d.conns_total, d.conns_total > 0), card("First seen", first ? ago(first) : "–")),
    h("div", { class: "riskgrid" },
      h("div", { class: "rpanel" }, h("h4", {}, "What it did"), Object.entries(d.kinds).sort((a, b) => b[1] - a[1]).map(([k, n]) => h("div", { class: "barrow" }, h("span", { class: "mono" }, k), h("div", { class: "bartrack" }, (() => { const f = h("div", { class: "barfill" }); f.style.width = Math.max(4, n / Math.max(...Object.values(d.kinds)) * 100) + "%"; return f; })()), h("span", {}, n)))),
      h("div", { class: "rpanel" }, h("h4", {}, "Hosts it touched"), hostsHit.length ? hostsHit.sort((a, b) => b[1] - a[1]).map(([n, c]) => h("div", { class: "ritem" }, h("b", {}, c + "×"), h("div", { class: "grow" }, n))) : h("div", { class: "dim" }, "–")),
      h("div", { class: "rpanel" }, h("h4", {}, "Containment"),
        cmds ? [h("div", { class: "note" }, "Run on the affected host(s) as root. netwatch is read-only and never changes your firewall itself."), ...cmds.map(([n, c]) => h("div", { class: "cmd" }, h("span", { class: "dim" }, n), h("code", {}, c), copyBtn(c)))]
          : d.owner ? [h("div", {}, h("b", {}, "This is one of your own hosts."), " ", d.ip, " is an address of the monitored host ", h("b", {}, d.owner.host), d.owner.last_seen + 600 < Math.floor(Date.now() / 1000) ? " (it held this address until " + ago(d.owner.last_seen) + "; addresses change with DHCP)." : " (currently its address)."),
              h("div", { class: "dim" }, "Traffic from a host to itself is usually a local test, a health check, a backup or monitoring job, or a misconfigured service. Blocking it would not stop an attacker. If you did not expect it, look at which process on " + d.owner.host + " is generating it.")]
          : h("div", { class: "dim" }, "This is an internal address (private/loopback/link-local) that does not belong to any monitored host: do not block it blindly. It may be a scanner you own, a misconfigured service, or a compromised machine on your network. Check your asset inventory first."))),
    h("h4", {}, "Alerts from this source"), alertsTable(true, d.alerts),
    h("h4", {}, "Current connections from this source (" + (d.conns_total > d.conns.length ? "showing " + d.conns.length + " of " + d.conns_total : d.conns_total) + ")"),
    d.conns.length ? tbl(h("thead", {}, h("tr", {}, ["Host", "Proto", "State", "Local", "Remote", "Process"].map(t => h("th", {}, t)))),
      h("tbody", {}, d.conns.map(c => h("tr", { class: "click", tabindex: "0", onclick: () => go("hosts", c.host_id, "conns") }, h("td", {}, c.host), h("td", {}, c.proto), h("td", { class: "st-" + c.state }, c.state), h("td", { class: "mono" }, c.local), h("td", { class: "mono" }, c.remote), h("td", {}, c.process))))) : h("div", { class: "dim" }, "None right now.")];
}

/* ---------- exposure ---------- */
function exposureView() {
  const d = S.exposure; if (!d) return [h("div", { class: "title" }, h("h2", {}, "Exposure")), skeleton()];
  const q = S.filter.toLowerCase(), sm = d.summary;
  const riskBadge = r => h("span", { class: "sev " + ["INFO", "MEDIUM", "HIGH"][r] }, ["OK", "REVIEW", "RISKY"][r]);
  const groups = d.groups.filter(g => (!S.expOnly || g.exposed_hosts > 0) && (!S.expRisky || g.risk === 2) && (!q || [g.port, g.service, g.why, g.proto, ...g.hosts.flatMap(x => [x.host, x.process, x.addr])].some(v => String(v ?? "").toLowerCase().includes(q))));
  const search = h("input", { type: "search", id: "filter", placeholder: "Filter port, service, host, process…", value: S.filter, "aria-label": "Filter", oninput: e => { S.filter = e.target.value; const p = e.target.selectionStart; render(); const n = document.getElementById("filter"); n.focus(); n.setSelectionRange(p, p); } });
  const rows = [];
  for (const g of groups) {
    const key = g.proto + g.port, open = !!S.expanded[key], toggle = () => { S.expanded[key] = !open; render(); };
    rows.push(h("tr", { class: "click", tabindex: "0", "aria-expanded": String(open), onclick: toggle, onkeydown: e => { if (e.key === "Enter") toggle(); } },
      h("td", {}, riskBadge(g.risk)), h("td", { class: "mono" }, (open ? "▾ " : "▸ ") + g.port + "/" + g.proto), h("td", {}, g.service || h("span", { class: "dim" }, "unknown")),
      h("td", {}, g.exposed_hosts + " / " + g.hosts.length), h("td", {}, g.why || "")));
    if (open) for (const x of g.hosts) rows.push(h("tr", { class: "subrow click", tabindex: "0", onclick: () => go("hosts", x.host_id, "ports") },
      h("td", {}), h("td", {}, "↳ ", x.host), h("td", { class: "mono" }, x.addr + " "), h("td", {}, x.scope === "loopback" ? pill("this machine only") : x.scope === "any" ? pill("all interfaces", "warnpill") : pill(x.internal_addr ? "LAN address" : "specific address", "warnpill"), x.new ? pill("new", "warnpill") : null),
      h("td", {}, x.process + (x.user ? " · " + x.user : "") + " · open " + ago(x.first_seen))));
  }
  return [h("div", { class: "title" }, h("h2", {}, "Exposure"), h("div", { class: "note" }, "Everything listening, across the fleet, grouped by port.")),
    h("div", { class: "cards" }, card("Listeners", sm.listeners), card("Reachable from the network", sm.exposed), card("Risky services exposed", sm.risky, sm.risky > 0), card("Opened in the last 24 h", sm.new24h)),
    h("div", { class: "bar" }, search, h("label", {}, h("input", { type: "checkbox", checked: S.expOnly, onchange: e => { S.expOnly = e.target.checked; render(); } }), "only network-reachable"),
      h("label", {}, h("input", { type: "checkbox", checked: S.expRisky, onchange: e => { S.expRisky = e.target.checked; render(); } }), "only risky"), h("div", { class: "grow" }),
      h("button", { onclick: () => { d.groups.forEach(g => { S.expanded[g.proto + g.port] = true; }); render(); } }, "Expand all"), h("button", { onclick: () => { S.expanded = {}; render(); } }, "Collapse")),
    groups.length ? tbl(h("thead", {}, h("tr", {}, ["Risk", "Port", "Service", "Exposed on", "Why it matters / process"].map(t => h("th", {}, t)))), h("tbody", {}, rows)) : h("div", { class: "empty" }, "Nothing matches. ✔"),
    h("div", { class: "note" }, "“Risky” means a service that is normally dangerous to expose (databases, remote desktop, clear-text protocols) and is bound to a non-loopback address. It is a heuristic: a firewall in front may already protect it.")];
}

/* ---------- traffic ---------- */
function trafficView() {
  const t = S.traffic; if (!t) return [h("div", { class: "title" }, h("h2", {}, "Traffic")), skeleton()];
  const peerTable = (rows, inbound) => rows.length ? tbl(h("thead", {}, h("tr", {}, [inbound ? "Source" : "Destination", "Conns", inbound ? "Ports hit" : "Ports", "Hosts"].map(x => h("th", {}, x)))),
    h("tbody", {}, rows.map(r => h("tr", { class: inbound ? "click" : "", tabindex: inbound ? "0" : null, onclick: inbound ? () => goSource(r.ip) : null, onkeydown: inbound ? e => { if (e.key === "Enter") goSource(r.ip); } : null },
      h("td", { class: "mono" }, r.ip, " ", intTag(r.internal)), h("td", {}, r.count), h("td", {}, r.port_count > 8 ? r.ports.join(", ") + " … (" + r.port_count + ")" : r.ports.join(", ")), h("td", {}, r.hosts.join(", ")))))) : h("div", { class: "dim" }, "None.");
  const spread = t.top_inbound.filter(r => r.port_count >= 5).length;
  return [h("div", { class: "title" }, h("h2", {}, "Traffic"), h("div", { class: "note" }, "Live view of current connections from the latest agent reports (up to 2000 per host). History and alerts live on the other pages.")),
    h("div", { class: "cards" }, card("Connections", t.total), card("Distinct inbound sources", t.top_inbound.length), card("Sources touching ≥ 5 ports", spread, spread > 0), card("SYN_RECV", (t.states.find(s => s.state === "SYN_RECV") || { count: 0 }).count, (t.states.find(s => s.state === "SYN_RECV") || { count: 0 }).count > 10)),
    h("div", { class: "riskgrid" },
      h("div", { class: "rpanel wide" }, h("h4", {}, "Top inbound sources"), peerTable(t.top_inbound, true)),
      h("div", { class: "rpanel wide" }, h("h4", {}, "Top outbound destinations"), peerTable(t.top_outbound, false))),
    h("div", { class: "riskgrid" },
      h("div", { class: "rpanel" }, h("h4", {}, "Most-hit local ports"), t.inbound_ports.length ? barList(t.inbound_ports, r => r.port + (r.service ? " " + r.service : ""), r => r.count) : h("div", { class: "dim" }, "None.")),
      h("div", { class: "rpanel" }, h("h4", {}, "Busiest processes"), t.processes.length ? barList(t.processes, r => r.process, r => r.count) : h("div", { class: "dim" }, "Process names need an agent running as root.")),
      h("div", { class: "rpanel" }, h("h4", {}, "Connection states"), barList(t.states, r => r.state, r => r.count, r => r.state === "SYN_RECV" ? "bad" : ""))),
    h("h4", {}, "Load per host"), tbl(h("thead", {}, h("tr", {}, ["Host", "Inbound", "Outbound"].map(x => h("th", {}, x)))), h("tbody", {}, t.hosts.map(x => h("tr", {}, h("td", {}, x.host), h("td", {}, x.inbound), h("td", {}, x.outbound)))))];
}

/* ---------- system health ---------- */
function healthView() {
  const d = S.health; if (!d) return [h("div", { class: "title" }, h("h2", {}, "System health")), skeleton()];
  const checks = [], add = (level, text) => checks.push({ level, text });
  const skew = d.agents.filter(a => !a.version_ok), noroot = d.agents.filter(a => !a.is_root && a.status !== "pending"), expiring = d.agents.filter(a => a.cert_days < 90), down = d.agents.filter(a => a.status === "down");
  down.length ? add("bad", down.length + " agent(s) not reporting: " + down.map(a => a.name).join(", ")) : add("ok", "All agents are reporting");
  skew.length ? add("warn", skew.length + " agent(s) run a different version than the server (" + d.server.version + "): " + skew.map(a => a.name + " " + a.version).join(", ")) : add("ok", "Agents match the server version");
  noroot.length ? add("warn", noroot.length + " agent(s) run without root, so process names are missing for other users' sockets") : add("ok", "All agents run with full visibility");
  expiring.length ? add("bad", expiring.length + " agent certificate(s) expire within 90 days: re-enroll with `netwatch agent enroll --force`") : add("ok", "No agent certificates expiring soon");
  d.webhook.configured ? add("ok", "Webhook alerts go to " + d.webhook.target + " (" + d.webhook.format + ", " + d.webhook.min_severity + "+)") : add("info", "No webhook configured: alerts are only visible here (netwatch server set webhook_url …)");
  d.users.admin > d.users.with_2fa ? add("warn", "Not every admin has two-factor login enabled (netwatch server user totp <name>)") : add("ok", "Two-factor is enabled for all admins");
  d.users.must_change ? add("info", d.users.must_change + " account(s) still must change their password") : null;
  d.server.tls ? add("ok", "Dashboard is served over HTTPS") : add("info", "Dashboard is plain HTTP (fine on loopback behind an SSH tunnel; use --tls or a proxy otherwise)");
  add(d.metrics_endpoint ? "ok" : "info", d.metrics_endpoint ? "Prometheus metrics endpoint is enabled" : "Prometheus endpoint is off (netwatch server metrics-token)");
  const icon = { ok: "✔", warn: "!", bad: "✖", info: "i" };
  return [h("div", { class: "title" }, h("h2", {}, "System health")),
    h("div", { class: "cards" }, card("Server version", d.server.version), card("Dashboard uptime", fmtDur(d.server.now - d.server.started)), card("Database size", fmtBytes(d.server.db_bytes)), card("Active maintenance", d.mutes_active)),
    h("div", { class: "rpanel wide" }, h("h4", {}, "Checks"), checks.map(c => h("div", { class: "check " + c.level }, h("span", { class: "ck", "aria-hidden": "true" }, icon[c.level]), h("span", { class: "sr" }, c.level + ": "), c.text))),
    h("div", { class: "riskgrid" },
      h("div", { class: "rpanel" }, h("h4", {}, "Accounts"), [["Admins", d.users.admin], ["Operators", d.users.operator], ["Viewers", d.users.viewer], ["Disabled", d.users.disabled], ["With two-factor", d.users.with_2fa]].map(([k, v]) => h("div", { class: "kv2" }, h("span", {}, k), h("b", {}, v)))),
      h("div", { class: "rpanel" }, h("h4", {}, "Stored data (retention: metrics " + d.retention.metrics_days + " d, alerts & audit " + d.retention.alerts_days + " d)"), d.tables.map(x => h("div", { class: "kv2" }, h("span", { class: "mono" }, x.table), h("b", {}, x.rows.toLocaleString())))),
      h("div", { class: "rpanel" }, h("h4", {}, "Settings"), [["Agent report interval", (d.server.report_interval || "10") + " s"], ["Host considered down after", (d.server.down_after || "90") + " s"]].map(([k, v]) => h("div", { class: "kv2" }, h("span", {}, k), h("b", {}, v))))),
    h("h4", {}, "Agents"), tbl(h("thead", {}, h("tr", {}, ["Host", "Status", "Version", "OS", "Root", "Last seen", "Cert expires in"].map(x => h("th", {}, x)))),
      h("tbody", {}, d.agents.map(a => h("tr", { class: "click", tabindex: "0", onclick: () => go("hosts", a.id), onkeydown: e => { if (e.key === "Enter") go("hosts", a.id); } },
        h("td", {}, a.name), h("td", {}, dot(a.status), " ", a.status), h("td", { class: a.version_ok ? "" : "ext" }, a.version), h("td", {}, a.os), h("td", {}, a.is_root ? "yes" : "no"), h("td", { title: when(a.last_seen) }, ago(a.last_seen)),
        h("td", { class: a.cert_days < 90 ? "ext" : "" }, a.cert_days < 0 ? "expired" : fmtDur(a.cert_days * 86400))))))];
}

/* ---------- session start (called by boot.js and after login) ---------- */
async function start() {
  clearInterval(S.timer); S.me = null; S.view = "overview";
  try { S.me = await api("/api/me"); } catch (e) { return; }   // api() shows the login form on 401
  if (S.me.must_change) return showChangePassword();
  if (location.hash.length > 2) applyHash(); else { setHash(); refresh(); }
  schedule();
}
