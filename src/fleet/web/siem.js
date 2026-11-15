"use strict";
/* SIEM pages: event explorer, incidents, MITRE ATT&CK, detection rules, compliance, SOC overview. */

/* ---------- shared helpers ---------- */
/* Chart severity in three classes, validated for colourblind separation: routine (two gray steps) vs needs a person (red). */
const sevSeries = hist => [{ name: "Low", cls: "sev-low", vals: hist.low }, { name: "Medium", cls: "sev-med", vals: hist.medium }, { name: "High and critical", cls: "sev-high", vals: hist.high.map((v, i) => v + hist.critical[i]) }];
async function loadRules() {
  if (S.ruleMap) return;
  try { const d = await api("/api/rules?range=24h"); S.ruleList = d.rules; S.ruleMap = Object.fromEntries(d.rules.map(r => [r.kind, r])); } catch (e) { if (e.message === "login") throw e; }
}
function goEvents(q, range) { S.evq = q || ""; if (range) applyRange(range); S.events = null; go("events"); }
function downloadCsv(name, header, rows) {
  const esc = v => { let t = String(v ?? "").replace(/"/g, '""'); if (/^[=+\-@\t\r]/.test(t)) t = "'" + t; return '"' + t + '"'; };   // neutralise spreadsheet formula injection
  const text = [header, ...rows].map(r => r.map(esc).join(",")).join("\n");
  const a = h("a", { href: URL.createObjectURL(new Blob([text], { type: "text/csv" })), download: name });
  document.body.append(a); a.click(); a.remove();
}
const mitreLink = m => m ? h("a", { class: "mitre-chip", href: "https://attack.mitre.org/techniques/" + m.id.replace(".", "/") + "/", target: "_blank", rel: "noopener noreferrer", title: m.name + " (opens attack.mitre.org)", onclick: e => e.stopPropagation() }, m.id) : null;
const heatClass = n => n <= 0 ? "" : n < 3 ? "h1" : n < 10 ? "h2" : n < 50 ? "h3" : "h4";
function riskBar(score, rating) {
  const f = h("div", { class: "barfill " + ({ low: "ok", elevated: "warn", high: "orange", critical: "bad" }[rating] || "") }); f.style.width = Math.max(2, score) + "%";
  return h("div", { class: "riskbar", title: rating + " risk" }, h("div", { class: "bartrack" }, f), h("b", {}, score));
}
function hostRiskBox(id) {
  const r = ((S.riskScores || {}).hosts || []).find(x => x.id === id); if (!r) return null;
  return h("div", { class: "riskgrid" }, h("div", { class: "rpanel" }, h("h4", {}, "Host risk score"), gauge(r.score, r.rating, "Host risk"),
    h("div", { class: "note", style: null }, "0–100, from open alerts (weighted by level and recency), risky exposed services and agent health.")),
    h("div", { class: "rpanel" }, h("h4", {}, "Why this score"), r.factors.length ? r.factors.map(f => h("div", { class: "kv2" }, h("span", {}, f.label), h("b", {}, "+" + f.points))) : h("div", { class: "dim" }, "Nothing is raising this host's risk right now. ✔")));
}

/* ---------- overview ---------- */
function attentionPanel() {
  const r = S.risk;
  const item = (lead, text, onclick, sub) => h("div", { class: "ritem", tabindex: "0", role: "button", onclick, onkeydown: e => { if (e.key === "Enter") onclick(); } }, lead, h("div", { class: "grow" }, text, sub && h("div", { class: "dim" }, sub)));
  const rows = [
    ...r.down.map(x => item(h("span", { class: "sev HIGH" }, "DOWN"), x.name, () => go("hosts", x.id), "silent since " + ago(x.last_seen))),
    ...r.exposed.map(a => item(h("span", { class: "sev HIGH" }, "NEW PORT"), a.message, () => openAlert(a.id), a.host + " · " + ago(a.ts))),
    ...r.cert_expiring.map(x => item(h("span", { class: "sev MEDIUM" }, "CERT"), x.name + (x.days < 0 ? ": agent certificate expired" : ": agent certificate expires in " + x.days + " days"), () => go("hosts", x.id), "re-enroll with: netwatch agent enroll --force")),
    ...r.non_root.map(x => item(h("span", { class: "sev INFO" }, "NO ROOT"), x.name, () => go("hosts", x.id), "process names are missing for other users' sockets"))];
  return h("div", { class: "rpanel" }, h("h4", {}, "Needs attention"), rows.length ? rows : h("div", { class: "dim" }, "Nothing needs attention ✔"));
}
function overviewView() {
  const ov = S.ov, ev = S.ovEvents, rk = S.riskScores, r = S.risk;
  const head = pageHeader("Security overview", "What happened, what matters, and where to look next");
  if (!ov || !ev || !rk || !r) return [head, skeleton()];
  const hi = ev.facets.level.filter(f => f.label === "high" || f.label === "critical").reduce((n, f) => n + f.count, 0);
  const open = (S.incidentsOv ? S.incidentsOv.incidents : []).filter(i => i.open);
  const kpi = (k, v, sub, cls, to) => h("div", { class: "rcard click " + (v > 0 && cls ? cls : ""), tabindex: "0", role: "button", onclick: to, onkeydown: e => { if (e.key === "Enter") to(); } }, h("div", { class: "k" }, k), h("div", { class: "v" }, v), h("div", { class: "s" }, sub));
  const exp = ov.exposure;
  const strip = h("div", { class: "strip" },
    h("div", { class: "rpanel", style: null }, h("h4", {}, "Fleet risk"), gauge(rk.fleet_score, rating(rk.fleet_score), "Fleet risk"), h("div", { class: "note", style: null }, "Average of per-host scores")),
    h("div", { class: "riskcards" },
      kpi("Open incidents", open.length, "correlated attack chains", "bad", () => go("incidents")),
      kpi("High & critical events", hi, "level ≥ 10, " + S.ovRange, "bad", () => goEvents("level>=10", S.ovRange)),
      kpi("Open alerts", S.openAlerts, "waiting for acknowledgement", "warn", () => go("alerts")),
      kpi("Hosts down", r.down.length, "agents not reporting", "bad", () => go("hostlist")),
      kpi("Risky exposed services", exp.risky, exp.exposed + " reachable listeners", "bad", () => go("exposure")),
      kpi("Threat sources", S.threatSources, "addresses in alerts, 24 h", "warn", () => go("threats"))));
  const lvlSeries = sevSeries(ev.histogram);
  const topRules = ev.facets.rule.length ? ev.facets.rule.map(f => h("div", { class: "barrow click", tabindex: "0", onclick: () => goEvents(f.q, S.ovRange), onkeydown: e => { if (e.key === "Enter") goEvents(f.q, S.ovRange); } }, h("span", { class: "lab", title: f.label }, f.label), h("div", { class: "bartrack" }, (() => { const x = h("div", { class: "barfill" }); x.style.width = Math.max(4, f.count / ev.facets.rule[0].count * 100) + "%"; return x; })()), h("span", {}, f.count))) : h("div", { class: "dim" }, "No events in this period.");
  return [head, strip,
    h("div", { class: "twocol" }, stackedBars("Security events by rule level", ev.histogram.t, lvlSeries, ev.histogram.since, ov.until, ev.histogram.bucket),
      h("div", { class: "rpanel" }, h("h4", {}, "Top detection rules", h("button", { class: "link more", onclick: () => go("rules") }, "all rules →")), topRules)),
    h("div", { class: "riskgrid" },
      h("div", { class: "rpanel" }, h("h4", {}, "Open incidents", h("button", { class: "link more", onclick: () => go("incidents") }, "view all →")),
        open.length ? open.slice(0, 5).map(i => h("div", { class: "ritem", tabindex: "0", role: "button", onclick: () => { S.expandedInc[i.id] = true; go("incidents"); } }, levelBadge(i.level), h("div", { class: "grow" }, i.title, h("div", { class: "dim" }, i.alert_count + " alerts · " + ago(i.last))))) : h("div", { class: "dim" }, "No open incidents ✔")),
      h("div", { class: "rpanel" }, h("h4", {}, "Highest-risk hosts", h("button", { class: "link more", onclick: () => go("hostlist") }, "all hosts →")),
        rk.hosts.slice(0, 5).map(x => h("div", { class: "ritem", tabindex: "0", role: "button", onclick: () => go("hosts", x.id) }, h("div", { class: "grow" }, x.name), riskBar(x.score, x.rating)))),
      h("div", { class: "rpanel" }, h("h4", {}, "MITRE ATT&CK activity", h("button", { class: "link more", onclick: () => go("mitre") }, "matrix →")),
        ev.facets.mitre.length ? ev.facets.mitre.slice(0, 6).map(f => h("div", { class: "barrow click", tabindex: "0", onclick: () => goEvents(f.q, S.ovRange), onkeydown: e => { if (e.key === "Enter") goEvents(f.q, S.ovRange); } }, h("span", { class: "lab", title: f.label }, f.label), h("div", { class: "bartrack" }, (() => { const x = h("div", { class: "barfill orange" }); x.style.width = Math.max(4, f.count / ev.facets.mitre[0].count * 100) + "%"; return x; })()), h("span", {}, f.count))) : h("div", { class: "dim" }, "No technique activity."))),
    h("div", { class: "twocol" },
      lineChart("Established connections, whole fleet", "c-accent", ov.fleet.t, ov.fleet.established, ov.fleet.since, ov.until, "connections"),
      lineChart("Half-open (SYN_RECV), whole fleet: a flood shows up here", "c-bad", ov.fleet.t, ov.fleet.syn_recv, ov.fleet.since, ov.until, "half-open")),
    h("div", { class: "riskgrid" }, attentionPanel(),
      h("div", { class: "rpanel" }, h("h4", {}, "Top sources, last 24 h", h("button", { class: "link more", onclick: () => go("threats") }, "all sources →")),
        r.sources.length ? r.sources.map(x => h("div", { class: "ritem", tabindex: "0", role: "button", onclick: () => goSource(x.ip) }, h("b", {}, x.count + "×"), h("div", { class: "grow" }, h("span", { class: "mono" }, x.ip), h("div", { class: "dim" }, x.kinds.join(", ") + " · last " + ago(x.last))))) : h("div", { class: "dim" }, "No attributed activity.")),
      h("div", { class: "rpanel" }, h("h4", {}, "Attack surface", h("button", { class: "link more", onclick: () => go("exposure") }, "review →")),
        h("div", { class: "kvgrid" }, h("div", {}, h("div", { class: "v" }, exp.exposed), h("div", { class: "dim" }, "reachable listeners")), h("div", {}, h("div", { class: "v " + (exp.risky ? "bad" : "") }, exp.risky), h("div", { class: "dim" }, "risky services")), h("div", {}, h("div", { class: "v" }, exp.new24h), h("div", { class: "dim" }, "opened in 24 h")))))];
}
const rating = s => s < 25 ? "low" : s < 50 ? "elevated" : s < 75 ? "high" : "critical";

/* ---------- event explorer ---------- */
function evTokens(q) {
  const out = []; let cur = "", inq = false;
  for (const ch of q) { if (ch === '"') { inq = !inq; cur += ch; } else if (/\s/.test(ch) && !inq) { if (cur) out.push(cur); cur = ""; } else cur += ch; }
  if (cur) out.push(cur); return out;
}
/* Saved searches live in this browser only (localStorage): name, query, time range. */
const savedSearches = () => { try { return JSON.parse(localStorage.getItem("nw_saved") || "[]").filter(x => x && typeof x.name === "string" && typeof x.q === "string").slice(0, 12); } catch (e) { return []; } };
function storeSaved(list) { try { localStorage.setItem("nw_saved", JSON.stringify(list.slice(0, 12))); } catch (e) { toast("This browser would not store the search", "err"); } }
function savedBar() {
  const list = savedSearches();
  const name = h("input", { id: "svname", type: "text", placeholder: "Name this search", maxlength: "40", "aria-label": "Name for the saved search", onkeydown: e => { if (e.key === "Enter") doSave(); if (e.key === "Escape") { S.saveOpen = false; render(); } } });
  const doSave = () => {
    const n = name.value.trim(); if (!n) { toast("Give the search a name first", "err"); return; }
    storeSaved([{ name: n, q: S.evq, range: S.range }, ...savedSearches().filter(x => x.name !== n)]); S.saveOpen = false; toast("Saved “" + n + "”"); render();
  };
  return h("div", { class: "saved" }, h("span", { class: "helpbar" }, "Saved:"),
    list.length ? list.map(x => h("span", { class: "chip" }, h("button", { title: x.q + " · " + RANGE_NAMES[x.range], onclick: () => evRun(x.q, x.range) }, x.name),
      h("button", { "aria-label": "Delete saved search " + x.name, title: "Delete", onclick: () => { storeSaved(savedSearches().filter(y => y.name !== x.name)); render(); } }, "×"))) : h("span", { class: "dim" }, "none yet"),
    S.saveOpen ? [name, h("button", { class: "primary", onclick: doSave }, "Save"), h("button", { onclick: () => { S.saveOpen = false; render(); } }, "Cancel")]
      : h("button", { class: "link", disabled: !S.evq, title: S.evq ? "Save the current query" : "Type a query first", onclick: () => { S.saveOpen = true; render(); setTimeout(() => { const n = document.getElementById("svname"); if (n) n.focus(); }, 0); } }, icon("save", "sm"), " Save this search"));
}
/* Event document view (what Wazuh calls a document): every field with one-click include/exclude. */
function quoteV(v) { return /[\s,"]/.test(String(v)) ? '"' + String(v).replace(/"/g, "") + '"' : String(v); }
function docRow(r) {
  const add = (term) => { if (!S.evq.split(/\s+/).includes(term)) evRun((S.evq + " " + term).trim()); };
  const field = (k, v, q) => v === "" || v == null ? null : h("div", { class: "f" }, h("span", { class: "k" }, k), h("span", { class: "v" }, v),
    q ? h("span", { class: "acts" }, h("button", { title: "Only events with this " + k, "aria-label": "Include " + k + " " + v, onclick: e => { e.stopPropagation(); add(q); } }, "+"),
      h("button", { title: "Exclude events with this " + k, "aria-label": "Exclude " + k + " " + v, onclick: e => { e.stopPropagation(); add("-" + q); } }, "−")) : h("span"));
  const json = JSON.stringify(r, null, 2);
  return h("tr", { class: "docrow" }, h("td", { colspan: "8" }, h("div", { class: "doc" },
    h("div", { class: "fields" },
      field("Time (UTC)", new Date(r.ts * 1000).toISOString().replace("T", " ").slice(0, 19)), field("Alert id", r.id),
      field("Host", r.host, "host:" + quoteV(r.host)), field("Source", r.source, r.source && "src:" + r.source), field("Kind", r.kind, "kind:" + r.kind), field("Severity", r.severity, "severity:" + r.severity),
      field("Rule level", r.level, "level:" + r.level), field("Rule", r.rule ? r.rule.id + " " + r.rule.name : "", r.rule && "rule:" + r.rule.id),
      field("ATT&CK technique", r.mitre ? r.mitre.id + " " + r.mitre.name : "", r.mitre && "mitre:" + r.mitre.id), field("ATT&CK tactic", r.tactic, r.tactic && "tactic:" + quoteV(r.tactic)),
      field("Groups", r.groups.join(", ")), field("State", [r.acked ? "acknowledged" : "open", r.muted ? "muted" : "", r.assignee ? "assigned to " + r.assignee : ""].filter(Boolean).join(", "), "ack:" + r.acked),
      field("Message", r.message, "msg:" + quoteV(r.message.slice(0, 40))),
      h("div", { class: "bar" }, h("button", { onclick: () => openAlert(r.id) }, "Open alert"), r.source ? h("button", { onclick: () => goSource(r.source) }, icon("target", "sm"), "Investigate source") : null)),
    h("pre", { tabindex: "0", "aria-label": "Event as JSON" }, json))));
}
function evRun(q, range) { S.evq = (q ?? S.evq).trim(); if (range) applyRange(range); setHash(); reload(); }
const EV_EXAMPLES = [["High and critical", "level>=10"], ["Scans (T1046)", "mitre:T1046"], ["Denial of service", "group:dos"], ["Credential attacks", "tactic:\"credential access\""], ["Unacknowledged", "ack:false level>=7"], ["Assigned to me", "assigned:me"], ["Everything but new listeners", "-kind:NEW_LISTENER"]];
function eventsView() {
  const d = S.events;
  const input = h("input", { id: "evq", type: "text", value: S.evq, placeholder: "level>=10 src:203.0.113. -mitre:T1046 host:web*  \"connection flood\"", "aria-label": "Event query", autocomplete: "off", spellcheck: "false",
    onkeydown: e => { if (e.key === "Enter") evRun(e.target.value); } });
  const head = pageHeader("Event explorer", "Hunt through every alert with rule, level, MITRE and compliance context", [
    h("button", { onclick: async () => { try { await navigator.clipboard.writeText(location.href); toast("Link copied: it reopens this exact search"); } catch (e) { toast("Copy the address bar instead", "err"); } } }, icon("link", "sm"), "Copy link"),
    d && d.rows && d.rows.length ? h("button", { onclick: () => { downloadCsv("netwatch-events.csv", ["time_utc", "level", "rule", "rule_name", "host", "source", "severity", "mitre", "message"], d.rows.map(r => [new Date(r.ts * 1000).toISOString(), r.level, r.rule ? r.rule.id : "", r.rule ? r.rule.name : r.kind, r.host, r.source, r.severity, r.mitre ? r.mitre.id : "", r.message])); toast("Exported " + d.rows.length + " events"); } }, icon("download", "sm"), "Export CSV") : null]);
  const toks = evTokens(S.evq);
  const bar = [h("div", { class: "qbar" }, input, h("button", { class: "primary", onclick: () => evRun(document.getElementById("evq").value) }, icon("search", "sm"), "Search"), S.evq ? h("button", { onclick: () => evRun("") }, "Clear") : null),
    toks.length ? h("div", { class: "qchips" }, toks.map((t, i) => h("span", { class: "qchip" }, t, h("button", { "aria-label": "Remove " + t, onclick: () => evRun(toks.filter((_, j) => j !== i).join(" ")) }, "×")))) : null,
    h("div", { class: "examples" }, h("span", { class: "helpbar" }, "Try:"), EV_EXAMPLES.map(([l, q]) => h("button", { class: "chip", onclick: () => evRun(q) }, l))), savedBar()];
  if (!d) return [head, ...bar, skeleton()];
  const err = d.error ? h("div", { class: "callout" }, h("b", {}, "Query problem: "), d.error, h("div", { class: "dim" }, "Fields: host kind severity source rule level mitre tactic group ack muted assignee msg. Operators: field:value, level>=10, a,b = OR, -field = NOT, \"quoted text\", wildcard *")) : null;
  const warn = (d.warnings || []).map(w => h("div", { class: "warnbar" }, w));
  const facet = (title, list) => h("div", { class: "facet" }, h("h4", {}, title), list && list.length ? list.map(f => h("div", { class: "fitem", tabindex: "0", role: "button", title: "Add to query: " + f.q, onclick: () => { if (!S.evq.includes(f.q)) evRun((S.evq + " " + f.q).trim()); }, onkeydown: e => { if (e.key === "Enter") evRun((S.evq + " " + f.q).trim()); } }, h("span", {}, f.label), h("b", {}, f.count))) : h("div", { class: "dim" }, "–"));
  const lv = d.histogram;
  const chart = stackedBars("Events over time" + (d.total ? " · " + d.total.toLocaleString() + " match" : ""), lv.t, sevSeries(lv), lv.since, Math.floor(Date.now() / 1000), lv.bucket);
  const rowsOut = [];
  for (const r of d.rows) {
    const open = !!S.expandedEv[r.id], toggle = e => { e.stopPropagation(); S.expandedEv[r.id] = !open; render(); };
    rowsOut.push(h("tr", { class: "click" + (r.acked || r.muted ? " acked" : ""), tabindex: "0", onclick: () => openAlert(r.id), onkeydown: e => { if (e.key === "Enter") openAlert(r.id); } },
      h("td", { class: "expcol" }, h("button", { "aria-expanded": String(open), "aria-label": (open ? "Hide" : "Show") + " event details", title: "Event details", onclick: toggle }, icon(open ? "chevD" : "chevR", "sm"))),
      h("td", { title: when(r.ts) }, ago(r.ts)), h("td", {}, levelBadge(r.level)), h("td", {}, r.rule ? [h("span", { class: "mono" }, r.rule.id), " ", r.rule.name] : r.kind),
      h("td", {}, r.host), h("td", {}, r.source ? h("button", { class: "link mono", onclick: e => { e.stopPropagation(); goSource(r.source); } }, r.source) : ""), h("td", {}, mitreLink(r.mitre)),
      h("td", {}, r.message, r.muted ? pill("muted") : null)));
    if (open) rowsOut.push(docRow(r));
  }
  const table = d.rows.length ? tbl(h("thead", {}, h("tr", {}, ["", "Time", "Level", "Rule", "Host", "Source", "ATT&CK", "Message"].map(t => h("th", {}, t)))), h("tbody", {}, rowsOut)) : h("div", { class: "empty" }, h("div", { class: "big" }, d.error ? "Fix the query to see events" : "No events match"), d.error ? "" : "Loosen the query or widen the time range.");
  return [head, ...bar, err, ...warn, h("div", { class: "evlayout" },
    h("div", { class: "facets" }, facet("Rule level", d.facets.level), facet("Rules", d.facets.rule), facet("Hosts", d.facets.host), facet("Sources", d.facets.source), facet("ATT&CK techniques", d.facets.mitre)),
    h("div", {}, chart, table, d.total > d.shown ? h("div", { class: "note" }, "Showing the newest " + d.shown + " of " + d.total.toLocaleString() + " matching events. Narrow the query to see the rest.") : null,
      d.truncated ? h("div", { class: "warnbar" }, "Very large result set: only the newest 20,000 events in this window were searched.") : null))];
}

/* ---------- incidents ---------- */
function incidentsView() {
  const d = S.incidents;
  const head = pageHeader("Incidents", "Alerts correlated into attack chains: one source, one campaign, in the order it happened", );
  if (!d) return [head, skeleton(4)];
  if (!d.incidents.length) return [head, h("div", { class: "empty" }, h("div", { class: "big" }, "No incidents in this period ✔"), "Isolated low-level alerts do not form incidents. Two or more alerts from one source, or any single high-level alert, do.")];
  const cards = d.incidents.map(i => {
    const open = !!S.expandedInc[i.id], toggle = () => { S.expandedInc[i.id] = !open; render(); };
    const chain = h("div", { class: "chain" }, i.stages.map((st, k) => [k ? icon("chevR") : null, h("span", { class: "stage" }, st.tactic, h("small", {}, st.techniques.join(" · ") + (st.techniques.length ? " · " : "") + "×" + st.count))]));
    const unacked = i.alerts.filter(a => !a.acked);
    return h("div", { class: "inc " + i.class },
      h("div", { class: "inchead", tabindex: "0", role: "button", "aria-expanded": String(open), onclick: toggle, onkeydown: e => { if (e.key === "Enter") toggle(); } },
        levelBadge(i.level), h("div", { class: "t" }, h("b", {}, i.title), h("div", { class: "dim" }, i.hosts.join(", ") + " · " + i.alert_count + " alerts · " + ago(i.first) + " → " + ago(i.last))),
        h("span", { class: "stchip " + (i.open ? "open" : "pass") }, i.open ? "Open" : "Closed"), icon(open ? "chevD" : "chevR")),
      open ? h("div", { class: "incbody" }, chain, i.notes.map(n => h("div", { class: "callout" }, icon("alert", "sm"), " ", n)),
        h("div", { class: "bar" }, i.source ? h("button", { onclick: () => goSource(i.source) }, icon("target", "sm"), "Investigate " + i.source) : null,
          h("button", { onclick: () => goEvents(i.source ? "src:" + i.source : "host:" + quoteQ(i.hosts[0] || ""), "7d") }, icon("search", "sm"), "View events"),
          h("div", { class: "grow" }), canAck() && unacked.length ? h("button", { onclick: async () => { await Promise.all(unacked.map(a => api("/api/ack", { id: a.id }))); toast("Acknowledged " + unacked.length + " alerts"); S.incidents = null; refresh(); } }, icon("check", "sm"), "Acknowledge " + unacked.length + " alert" + (unacked.length > 1 ? "s" : "")) : null),
        tbl(h("thead", {}, h("tr", {}, ["Time", "Level", "Rule", "Host", "Message"].map(t => h("th", {}, t)))),
          h("tbody", {}, i.alerts.map(a => h("tr", { class: "click" + (a.acked ? " acked" : ""), tabindex: "0", onclick: () => openAlert(a.id), onkeydown: e => { if (e.key === "Enter") openAlert(a.id); } },
            h("td", { title: when(a.ts) }, ago(a.ts)), h("td", {}, levelBadge(a.level)), h("td", {}, a.rule ? [h("span", { class: "mono" }, a.rule.id), " ", a.rule.name] : a.kind), h("td", {}, a.host), h("td", {}, a.message)))))) : null);
  });
  return [head, h("div", { class: "cards" }, card("Open incidents", d.open, d.open > 0), card("Total in period", d.incidents.length)), ...cards];
}
const quoteQ = v => /[\s,]/.test(v) ? '"' + v + '"' : v;

/* ---------- MITRE ATT&CK ---------- */
function mitreView() {
  const d = S.mitre;
  const head = pageHeader("MITRE ATT&CK", "Techniques netwatch detects, and how often each fired", );
  if (!d) return [head, skeleton()];
  const covered = d.tactics.filter(t => t.covered), hits = covered.flatMap(t => t.techniques).filter(x => x.count > 0).length;
  const key = h("div", { class: "heatkey" }, "Activity:", ["", "h1", "h2", "h3", "h4"].map((c, i) => [h("i", { class: "tech " + c, style: null }), ["none", "1–2", "3–9", "10–49", "50+"][i]]));
  const cols = d.tactics.map(t => h("div", { class: "tcol" + (t.covered ? "" : " off") },
    h("div", { class: "thead" }, t.name, h("small", {}, t.id + (t.covered ? " · " + t.techniques.reduce((n, x) => n + x.count, 0) + " hits" : ""))),
    t.covered ? t.techniques.map(x => h("div", { class: "tech " + heatClass(x.count), tabindex: "0", role: "button", title: x.name + ": " + x.count + " alerts on " + x.hosts + " host(s); rules " + x.rules.join(", "), onclick: () => goEvents("mitre:" + x.id, S.mitreRange), onkeydown: e => { if (e.key === "Enter") goEvents("mitre:" + x.id, S.mitreRange); } },
      h("span", { class: "n" }, x.id), h("span", {}, x.name), h("span", { class: "dim" }, x.count ? x.count + " alerts · " + x.hosts + " host" + (x.hosts === 1 ? "" : "s") : "no activity")))
      : h("div", { class: "none" }, "No network-layer detection")));
  return [head, h("div", { class: "cards" }, card("Tactics covered", covered.length + " / " + d.tactics.length), card("Techniques seen", hits, hits > 0), card("Detection rules", covered.flatMap(t => t.techniques).reduce((n, x) => n + x.rules.length, 0))),
    key, h("div", { class: "mitre" }, cols), h("div", { class: "note" }, d.note), h("div", { class: "note" }, "Click a technique to hunt its events. The mapping is a suggested reference for triage and reporting; adapt it to your own threat model.")];
}

/* ---------- detection rules ---------- */
function rulesView() {
  const d = S.rules;
  const head = pageHeader("Detection rules", "Every alert netwatch can raise: rule id, level, ATT&CK mapping and the compliance requirements it supports", );
  if (!d) return [head, skeleton()];
  const q = S.filter.toLowerCase();
  const rows = d.rules.filter(r => !q || [r.id, r.name, r.kind, r.desc, r.groups.join(" "), r.technique ? r.technique.id + " " + r.technique.name : "", r.tactic ? r.tactic.name : ""].some(v => String(v).toLowerCase().includes(q)));
  const search = h("input", { type: "search", id: "filter", placeholder: "Filter rules…", value: S.filter, "aria-label": "Filter rules", oninput: e => { S.filter = e.target.value; const p = e.target.selectionStart; render(); const n = document.getElementById("filter"); n.focus(); n.setSelectionRange(p, p); } });
  const body = [];
  for (const r of rows) {
    const open = !!S.expandedRule[r.id], toggle = () => { S.expandedRule[r.id] = !open; render(); };
    body.push(h("tr", { class: "click", tabindex: "0", "aria-expanded": String(open), onclick: toggle, onkeydown: e => { if (e.key === "Enter") toggle(); } },
      h("td", { class: "mono" }, (open ? "▾ " : "▸ ") + r.id), h("td", {}, h("b", {}, r.name), h("div", { class: "dim" }, r.kind)), h("td", {}, levelBadge(r.level)), h("td", {}, r.groups.map(g => pill(g))),
      h("td", {}, r.technique ? [mitreLink(r.technique), " ", h("span", { class: "dim" }, r.tactic.name)] : h("span", { class: "dim" }, "–")), h("td", {}, r.count ? h("b", {}, r.count) : "0", r.hosts ? h("span", { class: "dim" }, " on " + r.hosts + " host" + (r.hosts === 1 ? "" : "s")) : null)));
    if (open) body.push(h("tr", { class: "subrow" }, h("td", {}), h("td", { colspan: "5" }, h("div", {}, r.desc), h("div", { class: "note" }, "Level " + r.level + " when HIGH severity (MEDIUM −2, INFO capped at 3)."),
      r.compliance.length ? h("div", {}, h("span", { class: "dim" }, "Supports: "), r.compliance.map(c => pill(c.framework + " " + c.id))) : h("div", { class: "dim" }, "No compliance mapping."),
      h("div", { class: "bar", style: null }, h("button", { onclick: () => goEvents("rule:" + r.id, S.rulesRange) }, icon("search", "sm"), "Hunt this rule's events")))));
  }
  return [head, h("div", { class: "bar" }, search, h("span", { class: "dim" }, rows.length + " rules")),
    tbl(h("thead", {}, h("tr", {}, ["Rule", "Detection", "Level", "Groups", "ATT&CK", "Hits"].map(t => h("th", {}, t)))), h("tbody", {}, body)),
    h("div", { class: "note" }, "Rule ids are stable (100110–100171). Alerts carry their rule's level, MITRE technique and groups in the event explorer, webhooks and exports.")];
}

/* ---------- compliance ---------- */
function complianceView() {
  const d = S.compliance;
  const head = pageHeader("Compliance evidence", "Network-layer detections and security controls mapped to common frameworks", );
  if (S.me.role !== "admin") return [head, h("div", { class: "empty" }, "Compliance evidence is available to admins.")];
  if (!d) return [head, skeleton()];
  const f = d.frameworks.find(x => x.key === S.fw) || d.frameworks[0];
  const ctl = f.requirements.flatMap(r => r.controls), cnt = s => ctl.filter(c => c.status === s).length;
  const evidence = f.requirements.filter(r => r.alerts > 0).length;
  const tabs = h("div", { class: "tabs", role: "tablist" }, d.frameworks.map(x => h("div", { class: "tab" + (x.key === f.key ? " sel" : ""), role: "tab", "aria-selected": String(x.key === f.key), tabindex: "0", onclick: () => { S.fw = x.key; render(); }, onkeydown: e => { if (e.key === "Enter") { S.fw = x.key; render(); } } }, x.name)));
  const stat = s => h("span", { class: "stchip " + s }, s === "pass" ? "Met" : s === "warn" ? "Partial" : "Gap");
  const rows = f.requirements.map(r => h("tr", {}, h("td", { class: "mono" }, r.id), h("td", {}, r.title),
    h("td", {}, r.alerts ? h("button", { class: "link", onclick: () => goEvents("rule:" + r.rules.join(","), S.compRange) }, r.alerts + " event" + (r.alerts === 1 ? "" : "s") + " · rule" + (r.rules.length > 1 ? "s " : " ") + r.rules.join(", ")) : h("span", { class: "dim" }, r.controls.length ? "–" : "monitored, no events")),
    h("td", {}, r.controls.length ? r.controls.map(c => h("div", { class: "kv", style: null }, stat(c.status), h("span", { class: "dim" }, c.detail))) : h("span", { class: "dim" }, "detection evidence only"))));
  return [head, h("div", { class: "warnbar" }, d.disclaimer), tabs,
    h("div", { class: "cards" }, card("Requirements with event evidence", evidence + " / " + f.requirements.length), card("Controls met", cnt("pass")), card("Controls partial", cnt("warn"), cnt("warn") > 0), card("Control gaps", cnt("fail"), cnt("fail") > 0)),
    tbl(h("thead", {}, h("tr", {}, ["Requirement", "Description", "Event evidence", "netwatch controls"].map(t => h("th", {}, t)))), h("tbody", {}, rows)),
    h("div", { class: "note" }, "“Gap” items are honest: for example alerts and audit entries are kept for 90 days. Export them (CSV/JSON, webhook) to your long-term archive to meet 12-month retention requirements.")];
}

/* ---------- rule context for the alert drawer ---------- */
function ruleBlock(a) {
  const r = (S.ruleMap || {})[a.kind]; if (!r) return null;
  return h("div", { class: "ruleinfo" },
    h("div", {}, h("b", {}, "Rule " + r.id + " · " + r.name), "  ", levelBadge(a.level ?? r.level)), h("div", { class: "dim" }, r.desc),
    r.technique ? h("div", {}, h("span", { class: "dim" }, "ATT&CK: "), mitreLink(r.technique), " ", r.technique.name, " ", h("span", { class: "dim" }, "(" + r.tactic.name + ")")) : null,
    h("div", {}, r.groups.map(g => pill(g))), r.compliance.length ? h("div", {}, h("span", { class: "dim" }, "Supports: "), r.compliance.slice(0, 8).map(c => pill(c.framework + " " + c.id))) : null,
    h("div", { class: "bar" }, h("button", { onclick: () => { closeDrawer(); goEvents("rule:" + r.id); } }, icon("search", "sm"), "Hunt this rule's events")));
}
