"use strict";
// All dynamic content goes through textContent (never innerHTML), so agent-supplied data cannot inject markup.
const $app = document.getElementById("app");
const S = { me: null, view: "hosts", hosts: [], openAlerts: 0, sel: null, tab: "alerts", tag: null,
  showAcked: false, filter: "", data: null, alerts: [], online: true, timer: null, sessions: [], audit: null,
  aRange: "24h", aSev: "", aMine: false, cRange: "6h", metrics: null, timeline: null, mutes: [], q: "", search: null, drawer: null, editTags: false };
const canAck = () => S.me && (S.me.role === "operator" || S.me.role === "admin");
const RANGES = { "1h": 3600, "24h": 86400, "7d": 604800, "30d": 2592000, "all": 0 };
const KINDS = ["NEW_LISTENER", "PORT_SCAN", "BRUTE_FORCE", "CONN_BURST", "CONN_FLOOD", "SYN_FLOOD", "SYN_COOKIES", "LISTEN_OVERFLOW", "RST_STORM", "HOST_DOWN", "HOST_UP"];
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
  for (const c of kids.flat()) if (c != null && c !== false) e.append(c.nodeType ? c : document.createTextNode(String(c)));
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
  const form = h("form", {}, h("h1", {}, "net", h("span", {}, "watch")),
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
async function refresh() {
  try {
    if (!S.me || S.me.must_change === undefined) S.me = await api("/api/me");
    if (S.me.must_change) return showChangePassword();
    const sum = await api("/api/summary");
    S.hosts = sum.hosts; S.openAlerts = sum.open_alerts; S.online = true;
    if (S.tag && !S.hosts.some(x => x.tags.includes(S.tag))) S.tag = null;
    if (S.view === "sessions") S.sessions = (await api("/api/sessions")).sessions;
    else if (S.view === "audit") S.audit = await api("/api/audit?limit=500");
    else if (S.view === "maint") S.mutes = (await api("/api/mutes")).mutes;
    else if (S.view === "search") { /* loaded on submit */ }
    else {
      if (S.sel && !S.hosts.some(x => x.id === S.sel)) S.sel = null;
      if (!S.sel) { S.data = null; S.alerts = (await api(alertQuery())).alerts; }
      else {
        S.data = await api("/api/host/" + S.sel);
        if (S.tab === "alerts") S.alerts = (await api(alertQuery("&host=" + S.sel))).alerts;
        else if (S.tab === "trends") S.metrics = await api("/api/host/" + S.sel + "/metrics?range=" + S.cRange);
        else if (S.tab === "timeline") S.timeline = (await api("/api/host/" + S.sel + "/timeline")).events;
      }
    }
  } catch (e) { if (e.message === "login") return; S.online = false; }
  render();
}
async function runSearch() {
  const q = S.q.trim();
  if (q.length < 2) { S.search = { error: "Type at least 2 characters." }; S.view = "search"; return render(); }
  S.view = "search"; S.search = { loading: true }; render();
  try { S.search = await api("/api/search?q=" + encodeURIComponent(q)); } catch (e) { if (e.message === "login") return; S.search = { error: e.message }; }
  render();
}
const go = (view, sel, tab) => { S.view = view; S.sel = sel ?? null; S.tab = tab || "alerts"; S.filter = ""; S.data = null; S.editTags = false; refresh(); };

/* ---------- rendering ---------- */
function shell() {
  if (document.getElementById("shell")) return;
  $app.replaceChildren(h("div", { id: "shell", class: "shell" }, h("header", { id: "hdr" }),
    h("main", {}, h("aside", { id: "side" }), h("section", { id: "content", class: "content" })), h("div", { id: "drawer" })));
}
function render() {
  shell();
  const up = S.hosts.filter(x => x.status === "up").length, down = S.hosts.filter(x => x.status === "down").length;
  const hdr = document.getElementById("hdr");
  const keepSearch = document.activeElement && document.activeElement.id === "gsearch";
  const box = h("input", { type: "search", id: "gsearch", class: "gsearch", placeholder: "Search hosts, ports, processes, IPs, alerts…", value: S.q, "aria-label": "Search",
    oninput: e => { S.q = e.target.value; }, onkeydown: e => { if (e.key === "Enter") runSearch(); } });
  hdr.replaceChildren(
    h("div", { class: "brand" }, "net", h("span", {}, "watch")),
    h("div", { class: "stat" }, h("b", {}, S.hosts.length), "hosts"),
    h("div", { class: "stat ok" }, h("b", {}, up), "up"),
    h("div", { class: "stat" + (down ? " bad" : "") }, h("b", {}, down), "down"),
    h("div", { class: "stat" + (S.openAlerts ? " warn" : "") }, h("b", {}, S.openAlerts), "open alerts"),
    box, h("div", { class: "grow" }),
    h("div", { class: "conn" + (S.online ? "" : " dead") }, S.online ? "● live" : "● server unreachable"),
    h("div", { class: "userbox" }, h("span", {}, S.me.username), h("span", { class: "role " + S.me.role }, S.me.role),
      h("button", { onclick: async () => { await api("/api/logout", {}).catch(() => {}); showLogin(); } }, "Sign out")));
  if (keepSearch) { box.focus(); box.setSelectionRange(box.value.length, box.value.length); }

  const side = document.getElementById("side");
  const tags = [...new Set(S.hosts.flatMap(x => x.tags))].sort();
  const shown = S.hosts.filter(x => !S.tag || x.tags.includes(S.tag));
  const item = (id, dot, name, sub, badge) => h("div", { class: "host" + (S.view === "hosts" && S.sel === id ? " sel" : ""), tabindex: "0", role: "button", onclick: () => go("hosts", id),
    onkeydown: e => { if (e.key === "Enter") go("hosts", id); } }, dot, h("div", { class: "n" }, h("div", {}, name), sub && h("div", { class: "sub" }, sub)), badge ? h("span", { class: "badge" }, badge) : null);
  const nav = (view, label) => h("div", { class: "navitem" + (S.view === view ? " sel" : ""), tabindex: "0", role: "button", onclick: () => go(view), onkeydown: e => { if (e.key === "Enter") go(view); } }, label);
  side.replaceChildren(...[
    tags.length ? h("div", { class: "tagbar" }, h("span", { class: "chip" + (S.tag ? "" : " on"), onclick: () => { S.tag = null; refresh(); } }, "all"),
      tags.map(t => h("span", { class: "chip" + (S.tag === t ? " on" : ""), onclick: () => { S.tag = S.tag === t ? null : t; S.sel = null; refresh(); } }, t))) : null,
    item(null, h("span", {}, "★"), S.tag ? "All hosts · " + S.tag : "All hosts", null, S.tag ? shown.reduce((n, x) => n + x.open_alerts, 0) : S.openAlerts),
    ...shown.map(x => item(x.id, h("span", { class: "dot " + x.status }), x.name, x.status === "up" ? x.addr : x.status + " · " + ago(x.last_seen), x.open_alerts)),
    h("div", { class: "side-nav" }, nav("maint", "Maintenance"), nav("sessions", "Sessions"), S.me.role === "admin" && nav("audit", "Audit log"))].filter(k => k != null && k !== false));

  const c = document.getElementById("content"), keep = c.scrollTop;
  let kids;
  if (S.view === "sessions") kids = sessionsView();
  else if (S.view === "audit" && S.me.role === "admin") kids = auditView();
  else if (S.view === "maint") kids = maintView();
  else if (S.view === "search") kids = searchView();
  else if (!S.hosts.length) kids = [h("div", { class: "empty" }, "No agents enrolled yet. Run ", h("code", {}, "netwatch server token"), " on the server and follow the printed command on a host to monitor.")];
  else kids = S.sel && S.data ? hostView() : [h("div", { class: "title" }, h("h2", {}, "Alert feed · " + (S.tag ? "hosts tagged " + S.tag : "all hosts"))), alertsBar(), alertsTable(true)];
  c.replaceChildren(...kids.filter(k => k != null && k !== false));
  c.scrollTop = keep;
}

/* ----- alerts ----- */
function alertsBar() {
  const q = (fmt) => alertQuery("&format=" + fmt + (S.sel ? "&host=" + S.sel : "")).replace("/api/alerts?", "/api/alerts/export?");
  return h("div", { class: "bar" },
    sel([["1h", "Last hour"], ["24h", "Last 24 hours"], ["7d", "Last 7 days"], ["30d", "Last 30 days"], ["all", "All time"]], S.aRange, v => { S.aRange = v; refresh(); }, "Time range"),
    sel([["", "All severities"], ["HIGH", "High"], ["MEDIUM", "Medium"], ["INFO", "Info"]], S.aSev, v => { S.aSev = v; refresh(); }, "Severity"),
    h("label", {}, h("input", { type: "checkbox", checked: S.aMine, onchange: e => { S.aMine = e.target.checked; refresh(); } }), "assigned to me"),
    h("label", {}, h("input", { type: "checkbox", checked: S.showAcked, onchange: e => { S.showAcked = e.target.checked; refresh(); } }), "show acknowledged"),
    h("div", { class: "grow" }),
    h("a", { class: "btn", href: q("csv"), download: "netwatch-alerts.csv" }, "CSV"), h("a", { class: "btn", href: q("json"), download: "netwatch-alerts.json" }, "JSON"),
    canAck() && h("button", { onclick: async () => { await api("/api/ack", { all: true, host: S.sel }); refresh(); } }, "Acknowledge all"));
}
function alertsTable(withHost) {
  if (!S.alerts.length) return h("div", { class: "empty" }, "No alerts match. ✔");
  return h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Time"), withHost && h("th", {}, "Host"), h("th", {}, "Severity"), h("th", {}, "Type"), h("th", {}, "Message"), h("th", {}, "Assigned"), h("th", {}, ""))),
    h("tbody", {}, S.alerts.map(a => h("tr", { class: "click" + (a.acked || a.muted ? " acked" : ""), tabindex: "0", onclick: () => openAlert(a.id), onkeydown: e => { if (e.key === "Enter") openAlert(a.id); } },
      h("td", { title: when(a.ts) }, ago(a.ts)), withHost && h("td", {}, a.host), h("td", {}, h("span", { class: "sev " + a.severity }, a.severity)),
      h("td", { class: "mono" }, a.kind), h("td", {}, a.message, a.muted && h("span", { class: "tagpill" }, "muted")), h("td", {}, a.assignee || ""),
      h("td", {}, a.acked || !canAck() ? "" : h("button", { onclick: async e => { e.stopPropagation(); await api("/api/ack", { id: a.id }); refresh(); } }, "Ack"))))));
}

/* ----- alert drawer (assign + comments) ----- */
function closeDrawer() { S.drawer = null; document.getElementById("drawer").replaceChildren(); }
async function openAlert(id) {
  S.drawer = id;
  let d, users = [];
  try { d = await api("/api/alert/" + id); if (canAck()) users = (await api("/api/users")).users; } catch (e) { return; }
  const a = d.alert, box = document.getElementById("drawer");
  const ta = h("textarea", { rows: "3", maxlength: "1000", placeholder: "Add a note: what did you find, what was done?", "aria-label": "Comment" });
  const err = h("div", { class: "err" });
  const act = async fn => { try { await fn(); await openAlert(id); refresh(); } catch (e) { err.textContent = e.message; } };
  box.replaceChildren(h("div", { class: "scrim", onclick: closeDrawer }), h("aside", { class: "drawer", role: "dialog", "aria-label": "Alert details" },
    h("div", { class: "dhead" }, h("h3", {}, a.kind), h("button", { onclick: closeDrawer, "aria-label": "Close" }, "✕")),
    h("div", { class: "kv" }, h("span", { class: "sev " + a.severity }, a.severity), h("span", {}, a.host), h("span", { class: "dim" }, when(a.ts) + " (" + ago(a.ts) + ")"),
      a.muted && h("span", { class: "tagpill" }, "muted"), a.acked && h("span", { class: "tagpill" }, "acknowledged")),
    h("p", { class: "msg" }, a.message),
    canAck() && h("div", { class: "bar" },
      h("label", {}, "Assigned to ", sel([["", "(nobody)"], ...users.map(u => [u.username, u.username + " (" + u.role + ")"])], a.assignee, v => act(() => api("/api/alert/assign", { id, assignee: v })), "Assignee")),
      h("div", { class: "grow" }), !a.acked && h("button", { onclick: () => act(() => api("/api/ack", { id })) }, "Acknowledge")),
    h("h4", {}, "Notes"),
    d.comments.length ? d.comments.map(c => h("div", { class: "comment" }, h("div", { class: "dim" }, c.author + " · " + when(c.ts)), h("div", { class: "cbody" }, c.body))) : h("div", { class: "dim" }, "No notes yet."),
    canAck() && h("div", { class: "cform" }, ta, h("button", { class: "primary", onclick: () => act(async () => { if (!ta.value.trim()) throw new Error("write something first"); await api("/api/alert/comment", { id, body: ta.value }); }) }, "Add note"), err)));
  box.querySelector(".drawer button").focus();
}
document.addEventListener("keydown", e => { if (e.key === "Escape" && S.drawer) closeDrawer(); });

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
    body = [h("div", { class: "bar" }, search), rows.length ? h("table", {}, h("thead", {}, h("tr", {}, ["Proto", "Address", "Port", "PID", "Process", "User", "Scope", "Open for"].map(t => h("th", {}, t)))),
      h("tbody", {}, rows.map(l => { const ext = !(l.addr.startsWith("127.") || l.addr === "::1");
        return h("tr", {}, h("td", {}, l.proto), h("td", { class: "mono" }, l.addr), h("td", { class: "mono" }, l.port), h("td", {}, l.pid ?? "-"), h("td", {}, l.process), h("td", {}, l.user), h("td", { class: ext ? "ext" : "" }, ext ? "external" : "local"), h("td", {}, ago(l.first_seen))); }))) : h("div", { class: "empty" }, "No listeners.")];
  } else if (S.tab === "conns") {
    const rows = d.conns.filter(c => match(c.proto, c.state, c.local, c.remote, c.process, c.pid));
    body = [h("div", { class: "bar" }, search, h("span", { class: "note" }, `${rows.length} of ${d.conns_total}`)), rows.length ? h("table", {}, h("thead", {}, h("tr", {}, ["Proto", "State", "Local", "Remote", "PID", "Process"].map(t => h("th", {}, t)))),
      h("tbody", {}, rows.slice(0, 1500).map(c => h("tr", {}, h("td", {}, c.proto), h("td", { class: "st-" + c.state }, c.state), h("td", { class: "mono" }, c.local), h("td", { class: "mono" }, c.remote), h("td", {}, c.pid ?? "-"), h("td", {}, c.process))))) : h("div", { class: "empty" }, "No connections.")];
  } else {
    const rows = d.events.filter(e => match(e.what, e.event));
    body = [h("div", { class: "bar" }, search), rows.length ? h("table", {}, h("thead", {}, h("tr", {}, ["Time", "Event", "Listener"].map(t => h("th", {}, t)))),
      h("tbody", {}, rows.map(e => h("tr", {}, h("td", {}, when(e.ts)), h("td", { class: "ev-" + e.event }, e.event.toUpperCase()), h("td", { class: "mono" }, e.what))))) : h("div", { class: "empty" }, "No listener changes recorded yet."),
      h("div", { class: "note" }, "Ports that opened or closed after the agent's first report: the first thing to check in an investigation.")];
  }
  return [
    h("div", { class: "title" }, h("span", { class: "dot " + x.status }), h("h2", {}, x.name), h("span", { class: "pill" }, x.status), h("span", { class: "pill" }, "seen " + ago(x.last_seen)), h("span", { class: "pill" }, x.addr)),
    tagEditor(x), h("div", { class: "note" }, `${x.os} · agent ${x.version} · id ${x.id}`),
    !x.is_root && h("div", { class: "warnbar" }, "Agent is not running as root: process names are missing for other users' sockets."),
    h("div", { class: "cards" }, card("Listening", x.listeners), card("Established", x.established), card("SYN_RECV", x.syn_recv, x.syn_recv > 10), card("TIME_WAIT", x.time_wait), card("Total sockets", x.total), card("Open alerts", x.open_alerts, x.open_alerts > 0)),
    h("div", { class: "tabs", role: "tablist" }, TABS.map(([k, label]) => h("div", { class: "tab" + (S.tab === k ? " sel" : ""), role: "tab", tabindex: "0", onclick: () => { S.tab = k; S.filter = ""; refresh(); }, onkeydown: e => { if (e.key === "Enter") { S.tab = k; S.filter = ""; refresh(); } } }, label))),
    ...body];
}

/* ----- trends: real axes, per-metric scales, hover read-out ----- */
function niceMax(v) { if (v <= 4) return 4; const p = Math.pow(10, Math.floor(Math.log10(v))); for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p; return 10 * p; }
function fmtTick(ts, span) { const d = new Date(ts * 1000); return span <= 86400 * 1.5 ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : d.toLocaleDateString([], { month: "short", day: "numeric" }) + " " + d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); }
function lineChart(title, color, t, vals, since, until, unit) {
  const W = 900, H = 150, L = 46, R = 12, T = 10, B = 24, box = h("div", { class: "chart" }), span = Math.max(until - since, 1);
  box.append(h("div", { class: "ctitle" }, h("span", {}, title), h("span", { class: "dim" }, vals.length ? `now ${vals[vals.length - 1]} · peak ${Math.max(...vals)}` : "")));
  if (vals.length < 2) { box.append(h("div", { class: "note" }, "Not enough data in this window yet (reports arrive every few seconds).")); return box; }
  const ymax = niceMax(Math.max(...vals, 1)), X = ts => L + (ts - since) / span * (W - L - R), Y = v => T + (1 - v / ymax) * (H - T - B);
  const svgEl = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": title + " over time" });
  for (let i = 0; i <= 4; i++) {
    const v = ymax * i / 4, y = Y(v);
    svgEl.append(svg("line", { x1: L, x2: W - R, y1: y, y2: y, stroke: "#2a323d", "stroke-width": "1" }));
    const tx = svg("text", { x: L - 6, y: y + 4, "text-anchor": "end", fill: "#8b96a3", "font-size": "11" }); tx.textContent = Number.isInteger(v) ? v : v.toFixed(1); svgEl.append(tx);
  }
  for (let i = 0; i <= 5; i++) {
    const ts = since + span * i / 5, tx = svg("text", { x: X(ts), y: H - 6, "text-anchor": i === 0 ? "start" : i === 5 ? "end" : "middle", fill: "#8b96a3", "font-size": "11" }); tx.textContent = fmtTick(ts, span); svgEl.append(tx);
  }
  const pts = t.map((ts, i) => X(ts).toFixed(1) + "," + Y(vals[i]).toFixed(1));
  svgEl.append(svg("polygon", { points: `${X(t[0]).toFixed(1)},${Y(0)} ${pts.join(" ")} ${X(t[t.length - 1]).toFixed(1)},${Y(0)}`, fill: color, "fill-opacity": "0.12" }),
    svg("polyline", { points: pts.join(" "), fill: "none", stroke: color, "stroke-width": "2", "stroke-linejoin": "round" }));
  const guide = svg("line", { y1: T, y2: H - B, stroke: "#8b96a3", "stroke-dasharray": "3 3", visibility: "hidden" }), dot = svg("circle", { r: "4", fill: color, visibility: "hidden" });
  svgEl.append(guide, dot);
  const tip = h("div", { class: "tip", hidden: true });
  svgEl.addEventListener("mousemove", ev => {
    const r = svgEl.getBoundingClientRect(), ts = since + ((ev.clientX - r.left) / r.width * W - L) / (W - L - R) * span;
    let best = 0; for (let i = 1; i < t.length; i++) if (Math.abs(t[i] - ts) < Math.abs(t[best] - ts)) best = i;
    const x = X(t[best]); guide.setAttribute("x1", x); guide.setAttribute("x2", x); guide.setAttribute("visibility", "visible");
    dot.setAttribute("cx", x); dot.setAttribute("cy", Y(vals[best])); dot.setAttribute("visibility", "visible");
    tip.hidden = false; tip.textContent = `${new Date(t[best] * 1000).toLocaleString()}  ·  ${vals[best]} ${unit}`;
    tip.style.left = Math.min(Math.max(x / W * r.width - 10, 0), r.width - 230) + "px";
  });
  svgEl.addEventListener("mouseleave", () => { tip.hidden = true; guide.setAttribute("visibility", "hidden"); dot.setAttribute("visibility", "hidden"); });
  box.append(svgEl, tip); return box;
}
function trendsView() {
  const m = S.metrics;
  const bar = h("div", { class: "bar" }, h("div", { class: "seg" }, ["1h", "6h", "24h", "7d"].map(r => h("button", { class: S.cRange === r ? "on" : "", onclick: () => { S.cRange = r; S.metrics = null; refresh(); } }, r))),
    h("span", { class: "note" }, "Each point is the highest value in its time bucket, so short spikes are never averaged away."));
  if (!m) return [bar, h("div", { class: "empty" }, "Loading…")];
  return [bar, lineChart("Established connections", "#4cc2ff", m.t, m.established, m.since, m.until, "connections"),
    lineChart("Half-open connections (SYN_RECV): a flood shows up here", "#f85149", m.t, m.syn_recv, m.since, m.until, "half-open"),
    lineChart("TIME_WAIT", "#e3b341", m.t, m.time_wait, m.since, m.until, "sockets"), lineChart("Listening sockets: a step up means a port was opened", "#3fb950", m.t, m.listeners, m.since, m.until, "listeners")];
}

/* ----- timeline ----- */
function timelineView() {
  const ev = S.timeline; if (!ev) return [h("div", { class: "empty" }, "Loading…")];
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
    S.mutes.length ? h("table", {}, h("thead", {}, h("tr", {}, ["Status", "Scope", "Alert type", "Until", "Reason", "By", ""].map(t => h("th", {}, t)))),
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
    h("table", {}, h("thead", {}, h("tr", {}, head.map(t => h("th", {}, t)))), h("tbody", {}, rows.map(x => h("tr", { class: "click", tabindex: "0", onclick: () => target(x), onkeydown: e => { if (e.key === "Enter") target(x); } }, cells(x)))))] : [];
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
    S.sessions.length ? h("table", {}, h("thead", {}, h("tr", {}, ["User", "From", "Signed in", "Last active", ""].map(t => h("th", {}, t)))),
      h("tbody", {}, S.sessions.map(x => h("tr", {}, h("td", {}, x.user, x.current && h("span", { class: "cur" }, "  (this session)")), h("td", { class: "mono" }, x.ip), h("td", { title: when(x.created) }, ago(x.created)), h("td", {}, ago(x.last)),
        h("td", {}, x.current ? "" : h("button", { class: "danger", onclick: async () => { await api("/api/sessions/revoke", { id: x.id }); refresh(); } }, "Revoke")))))) : h("div", { class: "empty" }, "No sessions."),
    h("div", { class: "note" }, "Sessions end after inactivity or at the absolute lifetime. Changing your password ends your other sessions.")];
}

function auditView() {
  const d = S.audit; if (!d) return [h("div", { class: "empty" }, "Loading…")];
  const q = S.filter.toLowerCase();
  const rows = d.entries.filter(e => !q || [e.actor, e.action, e.target, e.detail, e.ip].some(v => String(v).toLowerCase().includes(q)));
  const search = h("input", { type: "search", id: "filter", placeholder: "Filter…", value: S.filter, "aria-label": "Filter", oninput: e => { S.filter = e.target.value; const p = e.target.selectionStart; render(); const n = document.getElementById("filter"); n.focus(); n.setSelectionRange(p, p); } });
  return [h("div", { class: "title" }, h("h2", {}, "Audit log")),
    h("div", { class: "integrity " + (d.integrity.ok ? "ok" : "bad") }, d.integrity.ok ? `✔ Integrity verified: ${d.integrity.entries} entries, hash chain intact` : "✖ INTEGRITY FAILURE: " + d.integrity.error),
    h("div", { class: "bar" }, search, h("div", { class: "grow" }), h("a", { class: "btn", href: "/api/audit?format=csv&limit=20000", download: "netwatch-audit.csv" }, "Export CSV"), h("a", { class: "btn", href: "/api/audit?format=json&limit=20000", download: "netwatch-audit.json" }, "Export JSON")),
    rows.length ? h("table", {}, h("thead", {}, h("tr", {}, ["Time", "Actor", "Action", "Target", "Detail", "From"].map(t => h("th", {}, t)))),
      h("tbody", {}, rows.map(e => h("tr", {}, h("td", { title: String(e.ts) }, when(e.ts)), h("td", {}, e.actor), h("td", { class: "mono" }, e.action), h("td", {}, e.target), h("td", {}, e.detail), h("td", { class: "mono" }, e.ip))))) : h("div", { class: "empty" }, "No matching entries."),
    h("div", { class: "note" }, "Each entry commits to the hash of the one before it. Verify from the server with `netwatch server audit --verify`.")];
}

/* ---------- boot ---------- */
function start() {
  clearInterval(S.timer); S.me = null; S.view = "hosts";
  refresh();
  S.timer = setInterval(() => {
    const id = document.activeElement?.id;
    // Don't rebuild the page under the user's hands: typing in a filter/search box, or reading a chart tooltip.
    if (!document.hidden && id !== "filter" && id !== "gsearch" && S.view !== "search" && !document.querySelector(".chart:hover")) refresh();
  }, 3000);
}
api("/api/me").then(m => { S.me = m; start(); }).catch(() => { if (!document.getElementById("shell") && !S.me) showLogin(); });
