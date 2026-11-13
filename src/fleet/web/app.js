"use strict";
// All dynamic content goes through textContent (never innerHTML), so agent-supplied data cannot inject markup.
const $app = document.getElementById("app");
const S = { me: null, view: "hosts", hosts: [], openAlerts: 0, sel: null, tab: "alerts", showAcked: false, filter: "", data: null, alerts: [], online: true, timer: null, sessions: [], audit: null };
const canAck = () => S.me && (S.me.role === "operator" || S.me.role === "admin");
const TABS = [["alerts", "Alerts"], ["ports", "Listening ports"], ["conns", "Connections"], ["changes", "Changes"]];

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
async function refresh() {
  try {
    if (!S.me || S.me.must_change === undefined) S.me = await api("/api/me");
    if (S.me.must_change) return showChangePassword();
    const sum = await api("/api/summary");
    S.hosts = sum.hosts; S.openAlerts = sum.open_alerts; S.online = true;
    if (S.view === "sessions") S.sessions = (await api("/api/sessions")).sessions;
    else if (S.view === "audit") S.audit = await api("/api/audit?limit=500");
    else {
      if (S.sel && !S.hosts.some(x => x.id === S.sel)) S.sel = null;
      if (!S.sel) {
        S.data = null;
        S.alerts = (await api("/api/alerts?limit=500" + (S.showAcked ? "&all=1" : ""))).alerts;
      } else {
        S.data = await api("/api/host/" + S.sel);
        if (S.tab === "alerts") S.alerts = (await api("/api/alerts?host=" + S.sel + "&limit=500" + (S.showAcked ? "&all=1" : ""))).alerts;
      }
    }
  } catch (e) { if (e.message === "login") return; S.online = false; }
  render();
}

/* ---------- rendering ---------- */
function shell() {
  if (document.getElementById("shell")) return;
  $app.replaceChildren(h("div", { id: "shell", class: "shell" },
    h("header", { id: "hdr" }),
    h("main", {}, h("aside", { id: "side" }), h("section", { id: "content", class: "content" }))));
}
function render() {
  shell();
  const up = S.hosts.filter(x => x.status === "up").length, down = S.hosts.filter(x => x.status === "down").length;
  document.getElementById("hdr").replaceChildren(
    h("div", { class: "brand" }, "net", h("span", {}, "watch")),
    h("div", { class: "stat" }, h("b", {}, S.hosts.length), "hosts"),
    h("div", { class: "stat ok" }, h("b", {}, up), "up"),
    h("div", { class: "stat" + (down ? " bad" : "") }, h("b", {}, down), "down"),
    h("div", { class: "stat" + (S.openAlerts ? " warn" : "") }, h("b", {}, S.openAlerts), "open alerts"),
    h("div", { class: "grow" }),
    h("div", { class: "conn" + (S.online ? "" : " dead") }, S.online ? "● live" : "● server unreachable"),
    h("div", { class: "userbox" }, h("span", {}, S.me.username), h("span", { class: "role " + S.me.role }, S.me.role),
      h("button", { onclick: async () => { await api("/api/logout", {}).catch(() => {}); showLogin(); } }, "Sign out")));

  const side = document.getElementById("side");
  const go = (view, sel) => { S.view = view; S.sel = sel ?? null; S.tab = "alerts"; S.filter = ""; S.data = null; refresh(); };
  const item = (id, dot, name, sub, badge) => h("div", { class: "host" + (S.view === "hosts" && S.sel === id ? " sel" : ""), onclick: () => go("hosts", id) },
    dot, h("div", { class: "n" }, h("div", {}, name), sub && h("div", { class: "sub" }, sub)), badge ? h("span", { class: "badge" }, badge) : null);
  const nav = (view, label) => h("div", { class: "navitem" + (S.view === view ? " sel" : ""), onclick: () => go(view) }, label);
  side.replaceChildren(item(null, h("span", {}, "★"), "All hosts", null, S.openAlerts),
    ...S.hosts.map(x => item(x.id, h("span", { class: "dot " + x.status }), x.name, x.status === "up" ? x.addr : x.status + " · " + ago(x.last_seen), x.open_alerts)),
    h("div", { class: "side-nav" }, nav("sessions", "Sessions"), S.me.role === "admin" && nav("audit", "Audit log")));

  const c = document.getElementById("content"), keep = c.scrollTop;
  let kids;
  if (S.view === "sessions") kids = sessionsView();
  else if (S.view === "audit" && S.me.role === "admin") kids = auditView();
  else if (!S.hosts.length) kids = [h("div", { class: "empty" }, "No agents enrolled yet. Run ", h("code", {}, "netwatch server token"), " on the server and follow the printed command on a host to monitor.")];
  else kids = S.sel && S.data ? hostView() : [h("div", { class: "title" }, h("h2", {}, "Alert feed · all hosts")), alertsBar(), alertsTable(true)];
  c.replaceChildren(...kids);
  c.scrollTop = keep;
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
  const search = h("input", { type: "search", id: "filter", placeholder: "Filter…", value: S.filter, oninput: e => { S.filter = e.target.value; const p = e.target.selectionStart; render(); const n = document.getElementById("filter"); n.focus(); n.setSelectionRange(p, p); } });
  return [h("div", { class: "title" }, h("h2", {}, "Audit log")),
    h("div", { class: "integrity " + (d.integrity.ok ? "ok" : "bad") }, d.integrity.ok ? `✔ Integrity verified: ${d.integrity.entries} entries, hash chain intact` : "✖ INTEGRITY FAILURE: " + d.integrity.error),
    h("div", { class: "bar" }, search, h("div", { class: "grow" }), h("a", { class: "btn", href: "/api/audit?format=csv&limit=20000", download: "netwatch-audit.csv" }, "Export CSV"), h("a", { class: "btn", href: "/api/audit?format=json&limit=20000", download: "netwatch-audit.json" }, "Export JSON")),
    rows.length ? h("table", {}, h("thead", {}, h("tr", {}, ["Time", "Actor", "Action", "Target", "Detail", "From"].map(t => h("th", {}, t)))),
      h("tbody", {}, rows.map(e => h("tr", {}, h("td", { title: String(e.ts) }, when(e.ts)), h("td", {}, e.actor), h("td", { class: "mono" }, e.action), h("td", {}, e.target), h("td", {}, e.detail), h("td", { class: "mono" }, e.ip))))) : h("div", { class: "empty" }, "No matching entries."),
    h("div", { class: "note" }, "Each entry commits to the hash of the one before it. Verify from the server with `netwatch server audit --verify`.")];
}

function alertsBar() {
  return h("div", { class: "bar" },
    h("label", {}, h("input", { type: "checkbox", checked: S.showAcked, onchange: e => { S.showAcked = e.target.checked; refresh(); } }), "show acknowledged"),
    h("div", { class: "grow" }),
    canAck() && h("button", { onclick: async () => { await api("/api/ack", { all: true, host: S.sel }); refresh(); } }, "Acknowledge all"));
}
function alertsTable(withHost) {
  if (!S.alerts.length) return h("div", { class: "empty" }, "No alerts. ✔");
  return h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Time"), withHost && h("th", {}, "Host"), h("th", {}, "Severity"), h("th", {}, "Type"), h("th", {}, "Message"), h("th", {}, ""))),
    h("tbody", {}, S.alerts.map(a => h("tr", { class: a.acked ? "acked" : "" },
      h("td", { title: when(a.ts) }, ago(a.ts)), withHost && h("td", {}, a.host), h("td", {}, h("span", { class: "sev " + a.severity }, a.severity)),
      h("td", { class: "mono" }, a.kind), h("td", {}, a.message),
      h("td", {}, a.acked || !canAck() ? "" : h("button", { onclick: async () => { await api("/api/ack", { id: a.id }); refresh(); } }, "Ack"))))));
}

function sparkline(vals) {
  const w = 600, hh = 54, box = h("div", { class: "spark" }, h("div", { class: "k" }, "Established connections (recent)"));
  if (vals.length < 2) { box.append(h("div", { class: "note" }, "collecting data…")); return box; }
  const max = Math.max(...vals, 1), pts = vals.map((v, i) => (i / (vals.length - 1) * w).toFixed(1) + "," + (hh - 4 - v / max * (hh - 8)).toFixed(1));
  const s = svg("svg", { viewBox: `0 0 ${w} ${hh}`, preserveAspectRatio: "none" });
  s.append(svg("polyline", { points: pts.join(" "), fill: "none", stroke: "#4cc2ff", "stroke-width": "2", "vector-effect": "non-scaling-stroke" }));
  box.append(s, h("div", { class: "note" }, "peak " + max));
  return box;
}
const card = (k, v, bad) => h("div", { class: "card" + (bad ? " bad" : "") }, h("div", { class: "k" }, k), h("div", { class: "v" }, v));

function hostView() {
  const d = S.data, x = d.host, q = S.filter.toLowerCase();
  const match = (...f) => !q || f.some(v => String(v ?? "").toLowerCase().includes(q));
  const search = h("input", { type: "search", id: "filter", placeholder: "Filter…", value: S.filter, oninput: e => { S.filter = e.target.value; const p = e.target.selectionStart; render(); const n = document.getElementById("filter"); n.focus(); n.setSelectionRange(p, p); } });
  let body;
  if (S.tab === "alerts") body = [alertsBar(), alertsTable(false)];
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
    h("div", { class: "note" }, `${x.os} · agent ${x.version} · id ${x.id}`),
    !x.is_root && h("div", { class: "warnbar" }, "Agent is not running as root: process names are missing for other users' sockets."),
    h("div", { class: "cards" }, card("Listening", x.listeners), card("Established", x.established), card("SYN_RECV", x.syn_recv, x.syn_recv > 10), card("TIME_WAIT", x.time_wait), card("Total sockets", x.total), card("Open alerts", x.open_alerts, x.open_alerts > 0)),
    sparkline(d.history),
    h("div", { class: "tabs" }, TABS.map(([k, label]) => h("div", { class: "tab" + (S.tab === k ? " sel" : ""), onclick: () => { S.tab = k; S.filter = ""; refresh(); } }, label))),
    ...body];
}

/* ---------- boot ---------- */
function start() {
  clearInterval(S.timer); S.me = null; S.view = "hosts";
  refresh();
  S.timer = setInterval(() => { if (!document.hidden && document.activeElement?.id !== "filter") refresh(); }, 3000);
}
api("/api/me").then(m => { S.me = m; start(); }).catch(() => { if (!document.getElementById("shell") && !S.me) showLogin(); });
