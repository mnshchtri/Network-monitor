"use strict";
// All dynamic content goes through textContent (never innerHTML), so agent-supplied data cannot inject markup.
const $app = document.getElementById("app");
const S = { hosts: [], openAlerts: 0, sel: null, tab: "alerts", showAcked: false, filter: "", data: null, alerts: [], online: true, timer: null };
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
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}
const ago = ts => { const d = Math.max(0, Math.floor(Date.now() / 1000 - ts)); return d < 60 ? d + "s ago" : d < 3600 ? Math.floor(d / 60) + "m ago" : d < 86400 ? Math.floor(d / 3600) + "h ago" : Math.floor(d / 86400) + "d ago"; };
const when = ts => new Date(ts * 1000).toLocaleString();

/* ---------- login ---------- */
function showLogin() {
  clearInterval(S.timer);
  const err = h("div", { class: "err" });
  const pw = h("input", { type: "password", placeholder: "Password", autocomplete: "current-password", required: true });
  const form = h("form", {}, h("h1", {}, "net", h("span", {}, "watch")), pw, h("button", { class: "primary", type: "submit" }, "Sign in"), err);
  form.addEventListener("submit", async e => {
    e.preventDefault();
    try { await api("/api/login", { password: pw.value }); start(); }
    catch (x) { err.textContent = x.message; pw.select(); }
  });
  $app.replaceChildren(h("div", { class: "login" }, form));
  pw.focus();
}

/* ---------- data ---------- */
async function refresh() {
  try {
    const sum = await api("/api/summary");
    S.hosts = sum.hosts; S.openAlerts = sum.open_alerts; S.online = true;
    if (S.sel && !S.hosts.some(x => x.id === S.sel)) S.sel = null;
    if (!S.sel) {
      S.data = null;
      S.alerts = (await api("/api/alerts?limit=500" + (S.showAcked ? "&all=1" : ""))).alerts;
    } else {
      S.data = await api("/api/host/" + S.sel);
      if (S.tab === "alerts") S.alerts = (await api("/api/alerts?host=" + S.sel + "&limit=500" + (S.showAcked ? "&all=1" : ""))).alerts;
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
    h("button", { onclick: async () => { await api("/api/logout", {}).catch(() => {}); showLogin(); } }, "Sign out"));

  const side = document.getElementById("side");
  const item = (id, dot, name, sub, badge) => h("div", { class: "host" + (S.sel === id ? " sel" : ""), onclick: () => { S.sel = id; S.tab = "alerts"; S.filter = ""; S.data = null; refresh(); } },
    dot, h("div", { class: "n" }, h("div", {}, name), sub && h("div", { class: "sub" }, sub)), badge ? h("span", { class: "badge" }, badge) : null);
  side.replaceChildren(item(null, h("span", {}, "★"), "All hosts", null, S.openAlerts),
    ...S.hosts.map(x => item(x.id, h("span", { class: "dot " + x.status }), x.name, x.status === "up" ? x.addr : x.status + " · " + ago(x.last_seen), x.open_alerts)));

  const c = document.getElementById("content"), keep = c.scrollTop;
  const kids = !S.hosts.length
    ? [h("div", { class: "empty" }, "No agents enrolled yet. Run ", h("code", {}, "netwatch server token"), " on the server and follow the printed command on a host to monitor.")]
    : S.sel && S.data ? hostView() : [h("div", { class: "title" }, h("h2", {}, "Alert feed · all hosts")), alertsBar(), alertsTable(true)];
  c.replaceChildren(...kids);
  c.scrollTop = keep;
}

function alertsBar() {
  return h("div", { class: "bar" },
    h("label", {}, h("input", { type: "checkbox", checked: S.showAcked, onchange: e => { S.showAcked = e.target.checked; refresh(); } }), "show acknowledged"),
    h("div", { class: "grow" }),
    h("button", { onclick: async () => { await api("/api/ack", { all: true, host: S.sel }); refresh(); } }, "Acknowledge all"));
}
function alertsTable(withHost) {
  if (!S.alerts.length) return h("div", { class: "empty" }, "No alerts. ✔");
  return h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Time"), withHost && h("th", {}, "Host"), h("th", {}, "Severity"), h("th", {}, "Type"), h("th", {}, "Message"), h("th", {}, ""))),
    h("tbody", {}, S.alerts.map(a => h("tr", { class: a.acked ? "acked" : "" },
      h("td", { title: when(a.ts) }, ago(a.ts)), withHost && h("td", {}, a.host), h("td", {}, h("span", { class: "sev " + a.severity }, a.severity)),
      h("td", { class: "mono" }, a.kind), h("td", {}, a.message),
      h("td", {}, a.acked ? "" : h("button", { onclick: async () => { await api("/api/ack", { id: a.id }); refresh(); } }, "Ack"))))));
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
  clearInterval(S.timer);
  refresh();
  S.timer = setInterval(() => { if (!document.hidden && document.activeElement?.id !== "filter") refresh(); }, 3000);
}
api("/api/me").then(start).catch(() => { if (!document.getElementById("shell")) showLogin(); });
