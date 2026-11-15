//! Web dashboard: hand-written HTTP/1.1 server (std + optional rustls) serving a static
//! single-page app and a JSON API over the server's SQLite database.
//!
//! Security model: per-user accounts with roles (viewer < operator < admin) enforced on every
//! request against the database; PBKDF2 passwords; optional TOTP; idle and absolute session
//! timeouts; login lockout per IP and per user; every sensitive action recorded in a
//! hash-chained audit log; Host allowlist (DNS rebinding), CSRF header + Origin checks, strict
//! CSP, text-only rendering. Account administration is CLI-only by design.

use super::auth::{self, role_rank};
use super::db::{self, User};
use super::{correlate, insights, query, rules};
use super::pki;
use super::server::default_server_dir;
use super::util::*;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_HEADERS: usize = 16 * 1024;
const MAX_BODY: usize = 4 * 1024;
const MAX_CONNECTIONS: usize = 64;
const LOCK_FOR: Duration = Duration::from_secs(300);
const IP_FAILS: u32 = 5;
const USER_FAILS: u32 = 10;

const INDEX: &str = include_str!("web/index.html");
const CSS: &str = include_str!("web/app.css");
const JS: &str = include_str!("web/app.js");
const THEME_JS: &str = include_str!("web/theme.js");
const UI_JS: &str = include_str!("web/ui.js");
const SIEM_JS: &str = include_str!("web/siem.js");
const BOOT_JS: &str = include_str!("web/boot.js");

static HSTS: AtomicBool = AtomicBool::new(false);

// ---------- state ----------

struct Session {
    user_id: i64,
    username: String,
    ip: IpAddr,
    created: Instant,
    last: Instant,
    created_at: u64,
    last_at: u64,
}

#[derive(Default)]
struct Fails {
    ips: HashMap<IpAddr, (u32, Option<Instant>)>,
    users: HashMap<String, (u32, Option<Instant>)>,
}

struct State {
    dir: PathBuf,
    secure_cookie: bool,
    allowed_hosts: Vec<String>,
    idle: Duration,
    absolute: Duration,
    sessions: Mutex<HashMap<String, Session>>,
    fails: Mutex<Fails>,
    active: AtomicUsize,
    started: u64,
}

fn sid(token: &str) -> String {
    sha256_hex(token.as_bytes())[..12].to_string()
}

fn locked<K: std::hash::Hash + Eq>(m: &mut HashMap<K, (u32, Option<Instant>)>, k: &K) -> bool {
    match m.get(k) {
        Some((_, Some(until))) if *until > Instant::now() => true,
        Some((_, Some(_))) => {
            m.remove(k);
            false
        }
        _ => false,
    }
}

fn bump<K: std::hash::Hash + Eq>(m: &mut HashMap<K, (u32, Option<Instant>)>, k: K, limit: u32) {
    if m.len() > 4000 {
        m.retain(|_, (_, u)| u.map_or(false, |u| u > Instant::now()));
    }
    let e = m.entry(k).or_insert((0, None));
    e.0 += 1;
    if e.0 >= limit {
        e.1 = Some(Instant::now() + LOCK_FOR);
    }
}

impl State {
    fn host_ok(&self, h: &str) -> bool {
        self.allowed_hosts.iter().any(|a| a.eq_ignore_ascii_case(h))
    }

    fn new_session(&self, u: &User, ip: IpAddr) -> String {
        let t = random_hex(32);
        let now = Instant::now();
        let mut s = self.sessions.lock().unwrap();
        s.retain(|_, x| now.duration_since(x.last) < self.idle && now.duration_since(x.created) < self.absolute);
        s.insert(t.clone(), Session { user_id: u.id, username: u.username.clone(), ip, created: now, last: now, created_at: now_secs(), last_at: now_secs() });
        t
    }

    /// Validate and refresh a session; returns the user id if the cookie is live.
    fn touch(&self, token: &str) -> Option<i64> {
        let mut s = self.sessions.lock().unwrap();
        let now = Instant::now();
        let ok = s.get(token).map(|x| now.duration_since(x.last) < self.idle && now.duration_since(x.created) < self.absolute);
        match ok {
            Some(true) => {
                let x = s.get_mut(token).unwrap();
                x.last = now;
                x.last_at = now_secs();
                Some(x.user_id)
            }
            Some(false) => {
                s.remove(token);
                None
            }
            None => None,
        }
    }
}

// ---------- HTTP plumbing ----------

struct Req {
    method: String,
    path: String,
    query: HashMap<String, String>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl Req {
    fn h(&self, n: &str) -> Option<&str> {
        self.headers.get(n).map(String::as_str)
    }
    fn cookie(&self, name: &str) -> Option<String> {
        self.h("cookie")?.split(';').filter_map(|c| c.trim().split_once('=')).find(|(k, _)| *k == name).map(|(_, v)| v.to_string())
    }
}

fn read_req(s: &mut impl Read) -> Result<Req, &'static str> {
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > MAX_HEADERS {
            return Err("headers too large");
        }
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => return Err("incomplete request"),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = std::str::from_utf8(&buf[..end]).map_err(|_| "bad encoding")?;
    let mut lines = head.split("\r\n");
    let mut rl = lines.next().ok_or("bad request")?.split(' ');
    let (method, target, ver) = (rl.next().unwrap_or(""), rl.next().unwrap_or(""), rl.next().unwrap_or(""));
    if !ver.starts_with("HTTP/1.") || !target.starts_with('/') {
        return Err("bad request");
    }
    let mut headers = HashMap::new();
    for l in lines {
        let (k, v) = l.split_once(':').ok_or("bad header")?;
        headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
    }
    if headers.contains_key("transfer-encoding") {
        return Err("chunked requests not supported");
    }
    let clen: usize = headers.get("content-length").map(|v| v.parse().map_err(|_| "bad content-length")).transpose()?.unwrap_or(0);
    if clen > MAX_BODY {
        return Err("body too large");
    }
    let mut body = buf[end + 4..].to_vec();
    while body.len() < clen {
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => return Err("incomplete body"),
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    body.truncate(clen);
    let (path, qs) = target.split_once('?').unwrap_or((target, ""));
    let query = qs.split('&').filter_map(|p| p.split_once('=')).map(|(k, v)| (k.to_string(), url_decode(v))).collect();
    Ok(Req { method: method.to_string(), path: path.to_string(), query, headers, body })
}

fn status_text(c: u16) -> &'static str {
    match c {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        429 => "Too Many Requests",
        _ => "Internal Server Error",
    }
}

fn send(s: &mut impl Write, code: u16, ctype: &str, cache: &str, extra: &[String], body: &[u8]) {
    let mut h = format!(
        "HTTP/1.1 {code} {}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: {cache}\r\nConnection: close\r\n\
         X-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nCross-Origin-Opener-Policy: same-origin\r\n\
         Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'\r\n",
        status_text(code),
        body.len()
    );
    if HSTS.load(Ordering::Relaxed) {
        h.push_str("Strict-Transport-Security: max-age=31536000\r\n");
    }
    for e in extra {
        h.push_str(e);
        h.push_str("\r\n");
    }
    h.push_str("\r\n");
    let _ = s.write_all(h.as_bytes());
    let _ = s.write_all(body);
    let _ = s.flush();
}

fn json_resp(s: &mut impl Write, code: u16, v: Value) {
    send(s, code, "application/json; charset=utf-8", "no-store", &[], v.to_string().as_bytes());
}

fn err(s: &mut impl Write, code: u16, msg: &str) {
    json_resp(s, code, json!({ "error": msg }));
}

fn valid_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn csv_cell(s: &str) -> String {
    let mut t = s.replace('"', "\"\"");
    // Neutralise spreadsheet formula injection in exported data.
    if matches!(t.chars().next(), Some('=' | '+' | '-' | '@' | '\t' | '\r')) {
        t.insert(0, '\'');
    }
    format!("\"{t}\"")
}

fn hex_val(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|d| d as u8)
}

/// Percent-decoding that works on bytes only: malformed or non-ASCII input can never panic
/// (the release build aborts on panic, so one bad request must not be able to reach one).
fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let (mut out, mut i) = (Vec::with_capacity(b.len()), 0);
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' => match (b.get(i + 1).and_then(|c| hex_val(*c)), b.get(i + 2).and_then(|c| hex_val(*c))) {
                (Some(h), Some(l)) => {
                    out.push(h * 16 + l);
                    i += 2;
                }
                _ => out.push(b'%'),
            },
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn valid_kind(k: &str) -> bool {
    !k.is_empty() && k.len() <= 32 && k.chars().all(|c| c.is_ascii_uppercase() || c == '_')
}

fn parse_filter<'a>(req: &'a Req, me: &'a User) -> Result<db::AlertFilter<'a>, &'static str> {
    let q = |k: &str| req.query.get(k).map(String::as_str).filter(|v| !v.is_empty());
    let host = q("host");
    if host.map_or(false, |h| !valid_id(h)) {
        return Err("bad host id");
    }
    let tag = q("tag");
    if tag.map_or(false, |t| !db::valid_tag(t)) {
        return Err("bad tag");
    }
    let severity = q("severity");
    if severity.map_or(false, |v| !["INFO", "MEDIUM", "HIGH"].contains(&v)) {
        return Err("bad severity");
    }
    let kind = q("kind");
    if kind.map_or(false, |k| !valid_kind(k)) {
        return Err("bad kind");
    }
    let assignee = match q("assignee") {
        Some("me") => Some(me.username.as_str()),
        Some(n) if auth::valid_username(n) => Some(n),
        Some(_) => return Err("bad assignee"),
        None => None,
    };
    let source = q("source");
    if source.map_or(false, |v| !insights::valid_ip(v)) {
        return Err("bad source");
    }
    Ok(db::AlertFilter {
        host,
        tag,
        source,
        include_acked: q("all") == Some("1"),
        since: q("since").and_then(|v| v.parse().ok()).unwrap_or(0),
        severity,
        kind,
        assignee,
        limit: q("limit").and_then(|v| v.parse().ok()).unwrap_or(300usize).clamp(1, 20000),
    })
}

fn prom_label(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

fn metrics(st: &State, c: &rusqlite::Connection, s: &mut impl Write, req: &Req) {
    let stored = db::get_setting(c, "metrics_token_hash").ok().flatten().unwrap_or_default();
    if stored.is_empty() {
        return err(s, 404, "metrics endpoint is not enabled (netwatch server metrics-token)");
    }
    let presented = req.h("authorization").and_then(|v| v.strip_prefix("Bearer ")).unwrap_or("");
    if !auth::ct_eq(sha256_hex(presented.as_bytes()).as_bytes(), stored.as_bytes()) {
        return send(s, 401, "text/plain", "no-store", &["WWW-Authenticate: Bearer".into()], b"unauthorized\n");
    }
    let _ = st;
    let hosts = match db::hosts(c) {
        Ok(h) => h,
        Err(e) => return err(s, 500, &format!("database: {e}")),
    };
    let mut o = String::new();
    let mut gauge = |name: &str, help: &str, f: &dyn Fn(&db::HostRow) -> f64| {
        o.push_str(&format!("# HELP {name} {help}\n# TYPE {name} gauge\n"));
        for h in &hosts {
            o.push_str(&format!("{name}{{host=\"{}\",id=\"{}\"}} {}\n", prom_label(&h.name), h.id, f(h)));
        }
    };
    gauge("netwatch_host_up", "1 if the agent is reporting, 0 if it has gone silent", &|h| (h.status == "up") as u8 as f64);
    gauge("netwatch_host_last_seen_timestamp_seconds", "Unix time of the last report", &|h| h.last_seen as f64);
    gauge("netwatch_established_connections", "TCP connections in ESTABLISHED", &|h| h.established as f64);
    gauge("netwatch_syn_recv_connections", "Half-open TCP connections (SYN_RECV)", &|h| h.syn_recv as f64);
    gauge("netwatch_time_wait_connections", "TCP connections in TIME_WAIT", &|h| h.time_wait as f64);
    gauge("netwatch_listening_sockets", "Listening sockets", &|h| h.listeners as f64);
    gauge("netwatch_open_alerts", "Unacknowledged, un-muted MEDIUM/HIGH alerts", &|h| h.open_alerts as f64);
    send(s, 200, "text/plain; version=0.0.4; charset=utf-8", "no-store", &[], o.as_bytes());
}

fn alert_json_full(a: &db::AlertRow) -> Value {
    let e = query::enrich(a);
    json!({"id": a.id, "host": a.host, "ts": a.ts, "kind": a.kind, "severity": a.severity, "message": a.message,
           "acked": a.acked, "assignee": a.assignee, "muted": a.muted, "source": a.source, "level": e.level, "rule": e.rule.map(|r| r.id)})
}


fn range_secs(v: Option<&String>, default: u64) -> u64 {
    match v.map(String::as_str) {
        Some("1h") => 3600,
        Some("24h") => 86400,
        Some("7d") => 7 * 86400,
        Some("30d") => 30 * 86400,
        Some("90d") => 90 * 86400,
        _ => default,
    }
}

fn owner_json(o: Option<&db::Owner>) -> Value {
    o.map_or(Value::Null, |o| json!({"host": o.host, "first_seen": o.first_seen, "last_seen": o.last_seen}))
}

fn technique_url(id: &str) -> String {
    format!("https://attack.mitre.org/techniques/{}/", id.replace('.', "/"))
}

fn event_json(e: &query::Enriched) -> Value {
    let a = e.a;
    json!({
        "id": a.id, "ts": a.ts, "host": a.host, "source": a.source, "kind": a.kind, "severity": a.severity, "level": e.level, "class": rules::level_class(e.level),
        "message": a.message, "acked": a.acked, "muted": a.muted, "assignee": a.assignee,
        "rule": e.rule.map(|r| json!({"id": r.id, "name": r.name})),
        "tactic": e.rule.filter(|r| !r.tactic.is_empty()).map(|r| rules::tactic_name(r.tactic)),
        "mitre": e.rule.filter(|r| !r.technique.is_empty()).map(|r| json!({"id": r.technique, "name": r.technique_name})),
        "groups": e.rule.map(|r| r.groups.to_vec()).unwrap_or_default(),
    })
}

fn quote_if_needed(v: &str) -> String {
    if v.chars().any(|c| c.is_whitespace() || c == ',') { format!("\"{v}\"") } else { v.to_string() }
}

fn facet(map: std::collections::HashMap<String, (String, String, u32)>, n: usize) -> Vec<Value> {
    let mut v: Vec<(String, String, u32)> = map.into_values().collect();
    v.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
    v.into_iter().take(n).map(|(label, q, count)| json!({"label": label, "q": q, "count": count})).collect()
}

// ---------- request handling ----------

struct Authed {
    token: String,
    user: User,
}

fn audit(st: &State, c: &rusqlite::Connection, actor: &str, action: &str, target: &str, detail: &str, ip: IpAddr) {
    let _ = st; // reserved for future per-server audit sinks
    if let Err(e) = db::audit(c, actor, action, target, detail, &ip.to_string()) {
        eprintln!("audit write failed: {e}");
    }
}

fn handle<S: Read + Write>(st: &State, s: &mut S, peer: IpAddr) {
    let req = match read_req(s) {
        Ok(r) => r,
        Err(m) => return err(s, 400, m),
    };
    match req.h("host") {
        Some(h) if st.host_ok(h) => {}
        _ => return err(s, 400, "unrecognised Host header (use --allow-host to permit this name)"),
    }
    let post = req.method == "POST";
    if req.method != "GET" && !post {
        return err(s, 405, "method not allowed");
    }
    if post {
        if req.h("x-requested-with") != Some("netwatch") {
            return err(s, 403, "missing X-Requested-With");
        }
        if let Some(o) = req.h("origin") {
            let host = o.split_once("://").map(|(_, h)| h).unwrap_or(o);
            if !st.host_ok(host) {
                return err(s, 403, "cross-origin request refused");
            }
        }
    }

    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") => return send(s, 200, "text/html; charset=utf-8", "no-cache", &[], INDEX.as_bytes()),
        ("GET", "/app.css") => return send(s, 200, "text/css; charset=utf-8", "no-cache", &[], CSS.as_bytes()),
        ("GET", "/app.js") => return send(s, 200, "text/javascript; charset=utf-8", "no-cache", &[], JS.as_bytes()),
        ("GET", "/theme.js") => return send(s, 200, "text/javascript; charset=utf-8", "no-cache", &[], THEME_JS.as_bytes()),
        ("GET", "/ui.js") => return send(s, 200, "text/javascript; charset=utf-8", "no-cache", &[], UI_JS.as_bytes()),
        ("GET", "/siem.js") => return send(s, 200, "text/javascript; charset=utf-8", "no-cache", &[], SIEM_JS.as_bytes()),
        ("GET", "/boot.js") => return send(s, 200, "text/javascript; charset=utf-8", "no-cache", &[], BOOT_JS.as_bytes()),
        _ => {}
    }
    if !req.path.starts_with("/api/") && req.path != "/metrics" {
        return err(s, 404, "not found");
    }
    let conn = match db::open(&st.dir.join("netwatch.db")) {
        Ok(c) => c,
        Err(e) => return err(s, 500, &format!("database: {e}")),
    };
    if req.method == "GET" && req.path == "/metrics" {
        return metrics(st, &conn, s, &req);
    }
    if req.method == "POST" && req.path == "/api/login" {
        return login(st, &conn, s, &req, peer);
    }
    // Everything else needs a live session whose user still exists and is enabled.
    let authed = req
        .cookie("nw_session")
        .and_then(|t| st.touch(&t).map(|id| (t, id)))
        .and_then(|(t, id)| db::user_by_id(&conn, id).ok().flatten().filter(|u| !u.disabled).map(|user| Authed { token: t, user }));
    let Some(a) = authed else {
        return err(s, 401, "login required");
    };
    if let Err(e) = route(st, &conn, &req, s, &a, peer) {
        err(s, 500, &format!("database: {e}"));
    }
}

fn session_cookie(st: &State, tok: &str, max_age: u64) -> String {
    format!("Set-Cookie: nw_session={tok}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}{}", if st.secure_cookie { "; Secure" } else { "" })
}

fn login(st: &State, c: &rusqlite::Connection, s: &mut impl Write, req: &Req, peer: IpAddr) {
    let v: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
    let username = v["username"].as_str().unwrap_or("").trim().to_string();
    let password = v["password"].as_str().unwrap_or("").to_string();
    let code = v["code"].as_str().unwrap_or("").to_string();
    let ukey = username.to_lowercase();
    {
        let mut f = st.fails.lock().unwrap();
        if locked(&mut f.ips, &peer) || locked(&mut f.users, &ukey) {
            drop(f);
            audit(st, c, &username, "login.locked", "", "attempt while locked out", peer);
            return err(s, 429, "too many failed attempts; try again in a few minutes");
        }
    }
    let user = db::user_by_name(c, &username).ok().flatten();
    let pw_ok = match &user {
        Some(u) if !u.disabled => auth::verify_password(&password, &u.pw_hash),
        _ => {
            auth::dummy_verify(&password);
            false
        }
    };
    let fail_login = |why: &str| {
        {
            let mut f = st.fails.lock().unwrap();
            bump(&mut f.ips, peer, IP_FAILS);
            bump(&mut f.users, ukey.clone(), USER_FAILS);
        }
        audit(st, c, &username, "login.fail", "", why, peer);
        std::thread::sleep(Duration::from_millis(400));
    };
    let Some(u) = user.filter(|_| pw_ok) else {
        fail_login("bad credentials");
        return err(s, 401, "invalid username or password");
    };
    if let Some(secret) = &u.totp_secret {
        if code.is_empty() {
            return json_resp(s, 401, json!({"error": "two-factor code required", "need_code": true}));
        }
        match auth::totp_check(secret, &code, u.totp_last, now_secs()) {
            Some(step) => {
                let _ = db::set_totp_last(c, u.id, step);
            }
            None => {
                fail_login("bad two-factor code");
                return json_resp(s, 401, json!({"error": "invalid two-factor code", "need_code": true}));
            }
        }
    }
    {
        let mut f = st.fails.lock().unwrap();
        f.ips.remove(&peer);
        f.users.remove(&ukey);
    }
    let _ = db::touch_login(c, u.id);
    let tok = st.new_session(&u, peer);
    audit(st, c, &u.username, "login.ok", "", &format!("role={}", u.role), peer);
    send(s, 200, "application/json", "no-store", &[session_cookie(st, &tok, st.absolute.as_secs())], b"{\"ok\":true}");
}

fn host_json(h: &db::HostRow) -> Value {
    json!({"id": h.id, "name": h.name, "os": h.os, "version": h.version, "addr": h.addr, "status": h.status,
           "last_seen": h.last_seen, "is_root": h.is_root, "total": h.total, "established": h.established,
           "syn_recv": h.syn_recv, "time_wait": h.time_wait, "listeners": h.listeners, "open_alerts": h.open_alerts, "tags": h.tags, "cert_expires": h.cert_expires})
}

fn alert_json(a: &db::AlertRow) -> Value {
    alert_json_full(a)
}

fn route(st: &State, c: &rusqlite::Connection, req: &Req, s: &mut impl Write, a: &Authed, ip: IpAddr) -> rusqlite::Result<()> {
    let me = &a.user;
    let rank = role_rank(&me.role);
    let forbidden = |s: &mut dyn Write| {
        let mut w = s;
        err(&mut w, 403, "your role does not permit this");
    };
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/api/me") => json_resp(s, 200, json!({"username": me.username, "role": me.role, "must_change": me.must_change, "totp": me.totp_secret.is_some()})),
        ("POST", "/api/logout") => {
            st.sessions.lock().unwrap().remove(&a.token);
            audit(st, c, &me.username, "logout", "", "", ip);
            send(s, 200, "application/json", "no-store", &[session_cookie(st, "", 0)], b"{\"ok\":true}");
        }
        ("POST", "/api/password") => {
            let v: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            let (old, new) = (v["old"].as_str().unwrap_or(""), v["new"].as_str().unwrap_or(""));
            if !auth::verify_password(old, &me.pw_hash) {
                audit(st, c, &me.username, "password.fail", "", "wrong current password", ip);
                return Ok(err(s, 400, "current password is incorrect"));
            }
            if new == old {
                return Ok(err(s, 400, "the new password must differ from the current one"));
            }
            if let Err(e) = auth::password_policy(new, &me.username) {
                return Ok(err(s, 400, &e));
            }
            db::set_password(c, me.id, &auth::hash_password(new), false)?;
            // A password change ends every other session of this user.
            st.sessions.lock().unwrap().retain(|t, x| *t == a.token || x.user_id != me.id);
            audit(st, c, &me.username, "password.change", "", "", ip);
            json_resp(s, 200, json!({"ok": true}));
        }
        _ if me.must_change => json_resp(s, 403, json!({"error": "password change required", "must_change": true})),
        ("POST", "/api/logout-all") => {
            let n = {
                let mut m = st.sessions.lock().unwrap();
                let before = m.len();
                m.retain(|_, x| x.user_id != me.id);
                before - m.len()
            };
            audit(st, c, &me.username, "logout.all", "", &format!("{n} sessions ended"), ip);
            send(s, 200, "application/json", "no-store", &[session_cookie(st, "", 0)], b"{\"ok\":true}");
        }
        ("GET", "/api/sessions") => {
            let admin = me.role == "admin";
            let m = st.sessions.lock().unwrap();
            let mut list: Vec<Value> = m
                .iter()
                .filter(|(_, x)| admin || x.user_id == me.id)
                .map(|(t, x)| json!({"id": sid(t), "user": x.username, "ip": x.ip.to_string(), "created": x.created_at, "last": x.last_at, "current": *t == a.token}))
                .collect();
            list.sort_by_key(|v| std::cmp::Reverse(v["last"].as_u64().unwrap_or(0)));
            json_resp(s, 200, json!({"sessions": list}));
        }
        ("POST", "/api/sessions/revoke") => {
            let v: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            let id = v["id"].as_str().unwrap_or("");
            let mut m = st.sessions.lock().unwrap();
            let found = m.iter().find(|(t, x)| sid(t) == id && (me.role == "admin" || x.user_id == me.id)).map(|(t, x)| (t.clone(), x.username.clone()));
            match found {
                Some((t, who)) => {
                    m.remove(&t);
                    drop(m);
                    audit(st, c, &me.username, "session.revoke", &who, &format!("session {id}"), ip);
                    json_resp(s, 200, json!({"ok": true}));
                }
                None => return Ok(err(s, 404, "no such session")),
            }
        }
        ("GET", "/api/summary") => {
            let hosts = db::hosts(c)?;
            let open: u32 = hosts.iter().map(|h| h.open_alerts).sum();
            let (_, ex) = insights::exposure(&db::all_listeners(c)?, now_secs());
            let sources = db::threats(c, now_secs().saturating_sub(86400))?.len();
            let a24 = db::alerts_filtered(c, &db::AlertFilter { since: now_secs().saturating_sub(86400), include_acked: true, limit: 5000, ..Default::default() })?;
            let open_incidents = correlate::correlate(&a24).iter().filter(|i| i.open).count();
            json_resp(s, 200, json!({"hosts": hosts.iter().map(host_json).collect::<Vec<_>>(), "open_alerts": open, "now": now_secs(),
                                     "risky_exposed": ex["risky"], "threat_sources": sources, "open_incidents": open_incidents}));
        }
        ("GET", "/api/alerts") => {
            let f = match parse_filter(req, me) {
                Ok(f) => f,
                Err(m) => return Ok(err(s, 400, m)),
            };
            let rows = db::alerts_filtered(c, &f)?;
            json_resp(s, 200, json!({"alerts": rows.iter().map(alert_json).collect::<Vec<_>>()}));
        }
        ("GET", "/api/alerts/export") => {
            let mut f = match parse_filter(req, me) {
                Ok(f) => f,
                Err(m) => return Ok(err(s, 400, m)),
            };
            f.limit = f.limit.max(5000);
            let rows = db::alerts_filtered(c, &f)?;
            let json_fmt = req.query.get("format").map(String::as_str) == Some("json");
            audit(st, c, &me.username, "alerts.export", if json_fmt { "json" } else { "csv" }, &format!("{} rows", rows.len()), ip);
            if json_fmt {
                send(s, 200, "application/json", "no-store", &["Content-Disposition: attachment; filename=\"netwatch-alerts.json\"".into()], json!({"alerts": rows.iter().map(alert_json).collect::<Vec<_>>()}).to_string().as_bytes());
            } else {
                let mut out = String::from("id,time_utc,host,severity,type,message,acknowledged,assignee,muted\n");
                for r in &rows {
                    out.push_str(&format!("{},{},{},{},{},{},{},{},{}\n", r.id, csv_cell(&fmt_time(r.ts)), csv_cell(&r.host), r.severity, csv_cell(&r.kind), csv_cell(&r.message), r.acked, csv_cell(&r.assignee), r.muted));
                }
                send(s, 200, "text/csv; charset=utf-8", "no-store", &["Content-Disposition: attachment; filename=\"netwatch-alerts.csv\"".into()], out.as_bytes());
            }
        }
        ("GET", p) if p.starts_with("/api/alert/") => {
            let Ok(id) = p["/api/alert/".len()..].parse::<i64>() else { return Ok(err(s, 400, "bad alert id")) };
            let Some(a) = db::alert_by_id(c, id)? else { return Ok(err(s, 404, "no such alert")) };
            let cm = db::comments(c, id)?;
            json_resp(s, 200, json!({"alert": alert_json_full(&a), "comments": cm.iter().map(|(ts, who, body)| json!({"ts": ts, "author": who, "body": body})).collect::<Vec<_>>()}));
        }
        ("POST", "/api/alert/assign") => {
            if rank < role_rank("operator") {
                return Ok(forbidden(s));
            }
            let v: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            let Some(id) = v["id"].as_i64() else { return Ok(err(s, 400, "missing alert id")) };
            let who = v["assignee"].as_str().filter(|x| !x.is_empty());
            if let Some(w) = who {
                match db::user_by_name(c, w)? {
                    Some(u) if !u.disabled => {}
                    _ => return Ok(err(s, 400, "no such active user")),
                }
            }
            if db::set_assignee(c, id, who)? == 0 {
                return Ok(err(s, 404, "no such alert"));
            }
            audit(st, c, &me.username, "alert.assign", &id.to_string(), who.unwrap_or("(unassigned)"), ip);
            json_resp(s, 200, json!({"ok": true}));
        }
        ("POST", "/api/alert/comment") => {
            if rank < role_rank("operator") {
                return Ok(forbidden(s));
            }
            let v: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            let (Some(id), Some(body)) = (v["id"].as_i64(), v["body"].as_str().map(str::trim).filter(|b| !b.is_empty())) else {
                return Ok(err(s, 400, "a comment needs an alert id and text"));
            };
            if db::alert_by_id(c, id)?.is_none() {
                return Ok(err(s, 404, "no such alert"));
            }
            db::add_comment(c, id, &me.username, body)?;
            audit(st, c, &me.username, "alert.comment", &id.to_string(), &format!("{} characters", body.chars().count().min(1000)), ip);
            json_resp(s, 200, json!({"ok": true}));
        }
        ("GET", "/api/users") => {
            if rank < role_rank("operator") {
                return Ok(forbidden(s));
            }
            let list: Vec<Value> = db::users(c)?.iter().filter(|u| !u.disabled).map(|u| json!({"username": u.username, "role": u.role})).collect();
            json_resp(s, 200, json!({"users": list}));
        }
        ("GET", "/api/risk") => {
            let r = db::risk(c)?;
            let hosts = db::hosts(c)?;
            let now = now_secs();
            let expiring: Vec<Value> = hosts
                .iter()
                .filter(|h| h.cert_expires < now + 90 * 86400)
                .map(|h| json!({"id": h.id, "name": h.name, "days": (h.cert_expires as i64 - now as i64).div_euclid(86400)}))
                .collect();
            json_resp(s, 200, json!({
                "down": hosts.iter().filter(|h| h.status == "down").map(|h| json!({"id": h.id, "name": h.name, "last_seen": h.last_seen})).collect::<Vec<_>>(),
                "non_root": hosts.iter().filter(|h| !h.is_root && h.status != "pending").map(|h| json!({"id": h.id, "name": h.name})).collect::<Vec<_>>(),
                "cert_expiring": expiring,
                "exposed": r.exposed.iter().map(alert_json_full).collect::<Vec<_>>(),
                "sources": r.sources.iter().map(|(ip, n, kinds, last)| json!({"ip": ip, "count": n, "kinds": kinds, "last": last})).collect::<Vec<_>>(),
                "kinds": r.kinds.iter().map(|(k, n)| json!({"kind": k, "count": n})).collect::<Vec<_>>(),
                "unacked_high": r.unacked_high,
                "mutes_active": r.active_mutes,
            }));
        }
        ("GET", "/api/insights/overview") => {
            let secs: u64 = if req.query.get("range").map(String::as_str) == Some("7d") { 7 * 86400 } else { 86400 };
            let bucket = if secs > 86400 { 6 * 3600 } else { 3600 };
            let since = now_secs().saturating_sub(secs) / bucket * bucket;
            let tr = db::alert_trend(c, since, bucket)?;
            // Fleet trend buckets adapt to how much history exists, so a young install still gets a curve.
            let now = now_secs();
            let fsince = db::earliest_metric(c)?.map_or(now.saturating_sub(secs), |e| e.max(now.saturating_sub(secs)));
            let fbucket = (now.saturating_sub(fsince).max(60) / 100).max(10);
            let fl = db::fleet_series(c, fsince / fbucket * fbucket, fbucket)?;
            let (_, ex) = insights::exposure(&db::all_listeners(c)?, now_secs());
            json_resp(s, 200, json!({
                "since": since, "until": now_secs(), "bucket": bucket,
                "alerts": {"t": tr.iter().map(|r| r.0).collect::<Vec<_>>(), "high": tr.iter().map(|r| r.1).collect::<Vec<_>>(),
                           "medium": tr.iter().map(|r| r.2).collect::<Vec<_>>(), "info": tr.iter().map(|r| r.3).collect::<Vec<_>>()},
                "fleet": {"since": fsince, "bucket": fbucket, "t": fl.iter().map(|r| r.0).collect::<Vec<_>>(), "established": fl.iter().map(|r| r.1).collect::<Vec<_>>(),
                          "syn_recv": fl.iter().map(|r| r.2).collect::<Vec<_>>(), "listeners": fl.iter().map(|r| r.3).collect::<Vec<_>>()},
                "top_hosts": db::top_hosts_by_alerts(c, now_secs().saturating_sub(secs), 6)?.iter().map(|(id, n, k, h)| json!({"id": id, "name": n, "count": k, "high": h})).collect::<Vec<_>>(),
                "exposure": ex,
            }));
        }
        ("GET", "/api/insights/exposure") => {
            let (groups, summary) = insights::exposure(&db::all_listeners(c)?, now_secs());
            json_resp(s, 200, json!({"groups": groups, "summary": summary}));
        }
        ("GET", "/api/insights/traffic") => {
            let mut lp: std::collections::HashMap<String, std::collections::HashSet<u16>> = std::collections::HashMap::new();
            for l in db::all_listeners(c)? {
                lp.entry(l.host_id).or_default().insert(l.port);
            }
            json_resp(s, 200, insights::traffic(&db::all_conns(c)?, &lp));
        }
        ("GET", "/api/insights/threats") => {
            let secs: u64 = match req.query.get("range").map(String::as_str) {
                Some("1h") => 3600,
                Some("7d") => 7 * 86400,
                Some("30d") => 30 * 86400,
                _ => 86400,
            };
            let rows = db::threats(c, now_secs().saturating_sub(secs))?;
            let live: std::collections::HashMap<String, u32> = {
                let mut m = std::collections::HashMap::new();
                for cn in db::all_conns(c)? {
                    if let Some((ip, _)) = insights::split_hostport(&cn.remote) {
                        *m.entry(ip.to_string()).or_default() += 1;
                    }
                }
                m
            };
            let owners = db::address_owners(c)?;
            json_resp(s, 200, json!({"sources": rows.iter().map(|r| json!({
                "ip": r.ip, "count": r.count, "high": r.high, "kinds": r.kinds, "hosts": r.hosts, "first": r.first, "last": r.last,
                "internal": insights::is_internal(&r.ip), "connections_now": live.get(&r.ip).copied().unwrap_or(0), "owner": owner_json(owners.get(&r.ip))})).collect::<Vec<_>>()}));
        }
        ("GET", "/api/insights/source") => {
            let Some(ip) = req.query.get("ip").map(String::as_str).filter(|v| insights::valid_ip(v)) else {
                return Ok(err(s, 400, "a valid IP address is required"));
            };
            let alerts = db::alerts_filtered(c, &db::AlertFilter { source: Some(ip), include_acked: true, limit: 200, ..Default::default() })?;
            let conns = db::conns_from_ip(c, ip)?;
            let mut kinds: std::collections::BTreeMap<&str, u32> = std::collections::BTreeMap::new();
            let mut hosts: std::collections::BTreeMap<&str, u32> = std::collections::BTreeMap::new();
            for a in &alerts {
                *kinds.entry(a.kind.as_str()).or_default() += 1;
                *hosts.entry(a.host.as_str()).or_default() += 1;
            }
            json_resp(s, 200, json!({
                "ip": ip, "internal": insights::is_internal(ip), "conns_total": db::count_conns_from_ip(c, ip)?, "owner": owner_json(db::address_owners(c)?.get(ip)),
                "alerts": alerts.iter().map(alert_json_full).collect::<Vec<_>>(),
                "kinds": kinds, "hosts": hosts,
                "conns": conns.iter().map(|x| json!({"host_id": x.host_id, "host": x.host, "proto": x.proto, "state": x.state, "local": x.local, "remote": x.remote, "process": x.process})).collect::<Vec<_>>(),
            }));
        }
        ("GET", "/api/insights/health") => {
            if rank < role_rank("admin") {
                return Ok(forbidden(s));
            }
            let hosts = db::hosts(c)?;
            let now = now_secs();
            let users = db::users(c)?;
            let dbp = st.dir.join("netwatch.db");
            let size = |p: std::path::PathBuf| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
            let ver = env!("CARGO_PKG_VERSION");
            let url = db::get_setting(c, "webhook_url")?.filter(|u| !u.is_empty());
            json_resp(s, 200, json!({
                "server": {"version": ver, "started": st.started, "now": now, "db_bytes": size(dbp.clone()) + size(st.dir.join("netwatch.db-wal")), "tls": HSTS.load(Ordering::Relaxed),
                           "report_interval": db::get_setting(c, "report_interval")?, "down_after": db::get_setting(c, "down_after")?},
                "tables": db::table_counts(c)?.into_iter().map(|(t, n)| json!({"table": t, "rows": n})).collect::<Vec<_>>(),
                "retention": {"metrics_days": 7, "alerts_days": 90, "audit_days": 90},
                "agents": hosts.iter().map(|h| json!({"id": h.id, "name": h.name, "version": h.version, "os": h.os, "status": h.status, "last_seen": h.last_seen,
                           "is_root": h.is_root, "cert_days": (h.cert_expires as i64 - now as i64).div_euclid(86400), "version_ok": h.version == ver})).collect::<Vec<_>>(),
                "webhook": {"configured": url.is_some(), "target": url.as_deref().map(super::webhook::mask),
                            "min_severity": db::get_setting(c, "webhook_min_severity")?.unwrap_or_else(|| "MEDIUM".into()),
                            "format": url.as_deref().map(|u| super::webhook::effective_format(c, u))},
                "metrics_endpoint": db::get_setting(c, "metrics_token_hash")?.map_or(false, |h| !h.is_empty()),
                "users": {"admin": users.iter().filter(|u| u.role == "admin" && !u.disabled).count(), "operator": users.iter().filter(|u| u.role == "operator" && !u.disabled).count(),
                          "viewer": users.iter().filter(|u| u.role == "viewer" && !u.disabled).count(), "disabled": users.iter().filter(|u| u.disabled).count(),
                          "with_2fa": users.iter().filter(|u| u.totp_secret.is_some() && !u.disabled).count(), "must_change": users.iter().filter(|u| u.must_change).count()},
                "mutes_active": db::mutes(c)?.iter().filter(|m| m.active).count(),
            }));
        }
        ("GET", "/api/events") => {
            let qs = req.query.get("q").map(String::as_str).unwrap_or("");
            if qs.chars().count() > 300 {
                return Ok(err(s, 400, "query too long"));
            }
            let (query, warnings) = match query::parse(qs, &me.username) {
                Ok(x) => x,
                Err(e) => return Ok(err(s, 400, &e)),
            };
            let range = req.query.get("range");
            let secs = range_secs(range, 86400);
            let since = now_secs().saturating_sub(secs);
            let all = db::alerts_filtered(c, &db::AlertFilter { since, include_acked: true, limit: 20000, ..Default::default() })?;
            let matched: Vec<query::Enriched> = all.iter().map(query::enrich).filter(|e| query.matches(e)).collect();
            use std::collections::HashMap;
            let (mut f_rule, mut f_host, mut f_src, mut f_mitre, mut f_class): (HashMap<String, (String, String, u32)>, HashMap<String, (String, String, u32)>, HashMap<String, (String, String, u32)>, HashMap<String, (String, String, u32)>, HashMap<String, (String, String, u32)>) = Default::default();
            let bucket: u64 = match secs { 0..=3600 => 60, 3601..=86400 => 3600, 86401..=604800 => 6 * 3600, 604801..=2592000 => 86400, _ => 3 * 86400 };
            let hist_since = since / bucket * bucket;
            let nb = ((now_secs() - hist_since) / bucket + 1) as usize;
            let mut hist = vec![[0u32; 4]; nb];
            for e in &matched {
                if let Some(r) = e.rule {
                    f_rule.entry(r.kind.into()).or_insert((format!("{} {}", r.id, r.name), format!("rule:{}", r.id), 0)).2 += 1;
                    if !r.technique.is_empty() {
                        f_mitre.entry(r.technique.into()).or_insert((format!("{} {}", r.technique, r.technique_name), format!("mitre:{}", r.technique), 0)).2 += 1;
                    }
                }
                f_host.entry(e.a.host.clone()).or_insert((e.a.host.clone(), format!("host:{}", quote_if_needed(&e.a.host)), 0)).2 += 1;
                if !e.a.source.is_empty() {
                    f_src.entry(e.a.source.clone()).or_insert((e.a.source.clone(), format!("src:{}", e.a.source), 0)).2 += 1;
                }
                let cls = rules::level_class(e.level);
                let qv = match cls { "low" => "level<=6", "medium" => "level>=7 level<=9", "high" => "level>=10 level<=11", _ => "level>=12" };
                f_class.entry(cls.into()).or_insert((cls.to_string(), qv.to_string(), 0)).2 += 1;
                let idx = ((e.a.ts.max(hist_since) - hist_since) / bucket) as usize;
                if let Some(slot) = hist.get_mut(idx) {
                    slot[match cls { "low" => 0, "medium" => 1, "high" => 2, _ => 3 }] += 1;
                }
            }
            json_resp(s, 200, json!({
                "total": matched.len(), "shown": matched.len().min(500), "range_seconds": secs, "truncated": all.len() >= 20000, "warnings": warnings,
                "rows": matched.iter().take(500).map(event_json).collect::<Vec<_>>(),
                "facets": {"rule": facet(f_rule, 8), "host": facet(f_host, 8), "source": facet(f_src, 8), "mitre": facet(f_mitre, 8), "level": facet(f_class, 4)},
                "histogram": {"since": hist_since, "bucket": bucket, "t": (0..nb as u64).map(|i| hist_since + i * bucket).collect::<Vec<_>>(),
                              "low": hist.iter().map(|x| x[0]).collect::<Vec<_>>(), "medium": hist.iter().map(|x| x[1]).collect::<Vec<_>>(),
                              "high": hist.iter().map(|x| x[2]).collect::<Vec<_>>(), "critical": hist.iter().map(|x| x[3]).collect::<Vec<_>>()},
                "fields": query::FIELDS,
            }));
        }
        ("GET", "/api/rules") => {
            let secs = range_secs(req.query.get("range"), 7 * 86400);
            let all = db::alerts_filtered(c, &db::AlertFilter { since: now_secs().saturating_sub(secs), include_acked: true, limit: 20000, ..Default::default() })?;
            let mut stat: std::collections::HashMap<&str, (u32, u64, std::collections::HashSet<&str>)> = std::collections::HashMap::new();
            for a in all.iter().filter(|a| !a.muted) {
                let e = stat.entry(a.kind.as_str()).or_default();
                e.0 += 1;
                e.1 = e.1.max(a.ts);
                e.2.insert(a.host.as_str());
            }
            let fw_name = |k: &str| -> String { rules::FRAMEWORKS.iter().find(|f| f.0 == k).map_or(k, |f| f.1).to_string() };
            json_resp(s, 200, json!({"range_seconds": secs, "rules": rules::RULES.iter().map(|r| {
                let st = stat.get(r.kind);
                json!({"id": r.id, "kind": r.kind, "name": r.name, "desc": r.desc, "level": r.level, "groups": r.groups,
                       "tactic": if r.tactic.is_empty() { Value::Null } else { json!({"id": r.tactic, "name": rules::tactic_name(r.tactic)}) },
                       "technique": if r.technique.is_empty() { Value::Null } else { json!({"id": r.technique, "name": r.technique_name, "url": technique_url(r.technique)}) },
                       "compliance": r.compliance.iter().map(|(fw, id)| json!({"framework": fw_name(fw), "id": id})).collect::<Vec<_>>(),
                       "count": st.map_or(0, |x| x.0), "last": st.map_or(0, |x| x.1), "hosts": st.map_or(0, |x| x.2.len())})
            }).collect::<Vec<_>>()}));
        }
        ("GET", "/api/insights/mitre") => {
            let secs = range_secs(req.query.get("range"), 7 * 86400);
            let all = db::alerts_filtered(c, &db::AlertFilter { since: now_secs().saturating_sub(secs), include_acked: true, limit: 20000, ..Default::default() })?;
            let tactics: Vec<Value> = rules::TACTICS.iter().map(|(tid, tname)| {
                let mut techs: Vec<Value> = Vec::new();
                let mut seen: Vec<&str> = Vec::new();
                for r in rules::RULES.iter().filter(|r| r.tactic == *tid) {
                    if seen.contains(&r.technique) { continue; }
                    seen.push(r.technique);
                    let rs: Vec<&rules::Rule> = rules::RULES.iter().filter(|x| x.technique == r.technique).collect();
                    let hits: Vec<&db::AlertRow> = all.iter().filter(|a| !a.muted && rs.iter().any(|x| x.kind == a.kind)).collect();
                    let hosts: std::collections::HashSet<&str> = hits.iter().map(|a| a.host.as_str()).collect();
                    techs.push(json!({"id": r.technique, "name": r.technique_name, "url": technique_url(r.technique), "rules": rs.iter().map(|x| x.id).collect::<Vec<_>>(),
                                      "count": hits.len(), "hosts": hosts.len(), "last": hits.iter().map(|a| a.ts).max().unwrap_or(0), "high": hits.iter().filter(|a| a.severity == "HIGH").count()}));
                }
                json!({"id": tid, "name": tname, "covered": !techs.is_empty(), "techniques": techs})
            }).collect();
            json_resp(s, 200, json!({"range_seconds": secs, "tactics": tactics,
                "note": "netwatch observes the network layer. Tactics such as Execution or Privilege Escalation happen on the host and need a host-based agent (for example Wazuh or auditd)."}));
        }
        ("GET", "/api/insights/incidents") => {
            let secs = range_secs(req.query.get("range"), 7 * 86400);
            let all = db::alerts_filtered(c, &db::AlertFilter { since: now_secs().saturating_sub(secs), include_acked: true, limit: 20000, ..Default::default() })?;
            let inc = correlate::correlate(&all);
            let list: Vec<Value> = inc.iter().map(|i| json!({
                "id": i.id, "kind": i.kind, "title": i.title, "level": i.level, "class": rules::level_class(i.level), "open": i.open, "first": i.first, "last": i.last,
                "source": i.source, "hosts": i.hosts, "notes": i.notes, "alert_count": i.alerts.len(),
                "stages": i.stages.iter().map(|st| json!({"id": st.tactic_id, "tactic": st.tactic, "techniques": st.techniques, "count": st.count})).collect::<Vec<_>>(),
                "alerts": i.alerts.iter().take(80).map(|&ix| event_json(&query::enrich(&all[ix]))).collect::<Vec<_>>(),
            })).collect();
            json_resp(s, 200, json!({"incidents": list, "open": inc.iter().filter(|i| i.open).count(), "range_seconds": secs}));
        }
        ("GET", "/api/insights/risk") => {
            let now = now_secs();
            let hosts = db::hosts(c)?;
            let recent = db::alerts_filtered(c, &db::AlertFilter { since: now.saturating_sub(86400), include_acked: false, limit: 20000, ..Default::default() })?;
            let risky = correlate::risky_by_host(&db::all_listeners(c)?);
            let mut out: Vec<Value> = hosts.iter().map(|h| {
                let input = correlate::RiskInput {
                    status: h.status.clone(), is_root: h.is_root, cert_days: (h.cert_expires as i64 - now as i64).div_euclid(86400),
                    risky_exposed: risky.get(&h.id).copied().unwrap_or(0),
                    alerts: recent.iter().filter(|a| a.host == h.name && !a.muted).map(|a| (query::enrich(a).level, now.saturating_sub(a.ts))).collect(),
                };
                let (score, factors) = correlate::host_risk(&input);
                json!({"id": h.id, "name": h.name, "score": score, "rating": correlate::rating(score), "status": h.status,
                       "factors": factors.iter().map(|(l, p)| json!({"label": l, "points": p})).collect::<Vec<_>>()})
            }).collect();
            out.sort_by(|a, b| b["score"].as_u64().cmp(&a["score"].as_u64()));
            let avg = if out.is_empty() { 0 } else { out.iter().filter_map(|x| x["score"].as_u64()).sum::<u64>() / out.len() as u64 };
            json_resp(s, 200, json!({"hosts": out, "fleet_score": avg}));
        }
        ("GET", "/api/insights/compliance") => {
            if rank < role_rank("admin") {
                return Ok(forbidden(s));
            }
            let secs = range_secs(req.query.get("range"), 30 * 86400);
            let all = db::alerts_filtered(c, &db::AlertFilter { since: now_secs().saturating_sub(secs), include_acked: true, limit: 20000, ..Default::default() })?;
            let mut counts: std::collections::HashMap<(&str, &str), (u32, std::collections::BTreeSet<u32>)> = std::collections::HashMap::new();
            for a in all.iter().filter(|a| !a.muted) {
                if let Some(r) = rules::by_kind(&a.kind) {
                    for (fw, id) in r.compliance {
                        let e = counts.entry((fw, id)).or_default();
                        e.0 += 1;
                        e.1.insert(r.id);
                    }
                }
            }
            let users = db::users(c)?;
            let admins: Vec<&db::User> = users.iter().filter(|u| u.role == "admin" && !u.disabled).collect();
            let with2fa = admins.iter().filter(|u| u.totp_secret.is_some()).count();
            let audit_n = db::audit_rows(c, 1)?.len();
            let verify = db::audit_verify(c);
            let hosts = db::hosts(c)?;
            let down = hosts.iter().filter(|h| h.status == "down").count();
            let webhook = db::get_setting(c, "webhook_url")?.map_or(false, |u| !u.is_empty());
            let tls = HSTS.load(Ordering::Relaxed);
            // (status, detail, [(framework, requirement)])
            let controls: Vec<(&str, String, Vec<(&str, &str)>)> = vec![
                (if audit_n > 0 { "pass" } else { "warn" }, "Every login, acknowledgement, assignment, mute, export and account change is recorded with actor, time and source address".into(), vec![("pci_dss", "10.2.1"), ("nist_800_53", "AU-2"), ("hipaa", "164.312.b"), ("cis", "8.2")]),
                (if verify.is_ok() { "pass" } else { "fail" }, match &verify { Ok(n) => format!("Hash-chained audit log verified: {n} entries, no gaps or edits"), Err(e) => format!("Audit log failed verification: {e}") }, vec![("pci_dss", "10.3.4"), ("nist_800_53", "AU-9")]),
                ("fail", "Alerts and audit entries are kept for 90 days (metrics 7 days). PCI DSS asks for 12 months: archive the audit log and alerts (CSV/JSON export, webhook to a SIEM) to meet it".into(), vec![("pci_dss", "10.5.1")]),
                (if !admins.is_empty() && with2fa == admins.len() { "pass" } else if with2fa > 0 { "warn" } else { "fail" }, format!("{with2fa} of {} administrator account(s) use two-factor login", admins.len()), vec![("pci_dss", "8.4.2"), ("nist_800_53", "IA-2"), ("soc2", "CC6.1")]),
                ("pass", "Agent-to-server traffic always uses mutual TLS (TLS 1.2+) with a private CA and pinned enrollment".into(), vec![("pci_dss", "4.2.1"), ("nist_800_53", "SC-8"), ("hipaa", "164.312.e.1")]),
                (if tls { "pass" } else { "warn" }, if tls { "Dashboard is served over HTTPS".into() } else { "Dashboard is served over plain HTTP: use --tls or a TLS proxy outside a loopback/SSH-tunnel setup".into() }, vec![("pci_dss", "4.2.1"), ("hipaa", "164.312.e.1")]),
                (if webhook { "pass" } else { "warn" }, if webhook { "Alerts are forwarded to an external channel".into() } else { "No webhook configured: alerts are only visible in this dashboard".into() }, vec![("cis", "13.1"), ("soc2", "CC7.2"), ("nist_800_53", "SI-4")]),
                (if down == 0 { "pass" } else { "fail" }, if down == 0 { format!("All {} agent(s) are reporting", hosts.len()) } else { format!("{down} agent(s) are not reporting") }, vec![("pci_dss", "10.7.1")]),
            ];
            let frameworks: Vec<Value> = rules::FRAMEWORKS.iter().map(|(fk, fname)| {
                let reqs: Vec<Value> = rules::REQUIREMENTS.iter().filter(|r| r.0 == *fk).map(|(_, id, title)| {
                    let (n, rids) = counts.get(&(*fk, *id)).cloned().unwrap_or_default();
                    let ctl: Vec<Value> = controls.iter().filter(|c| c.2.iter().any(|(f, i)| f == fk && i == id)).map(|c| json!({"status": c.0, "detail": c.1})).collect();
                    json!({"id": id, "title": title, "alerts": n, "rules": rids, "controls": ctl})
                }).collect();
                json!({"key": fk, "name": fname, "requirements": reqs})
            }).collect();
            json_resp(s, 200, json!({"range_seconds": secs, "frameworks": frameworks,
                "disclaimer": "Reference mapping only. netwatch provides network-layer detection and audit evidence; it does not make a system compliant. Confirm the mapping with your auditor."}));
        }
        ("GET", "/api/search") => {
            let q = req.query.get("q").map(|v| v.trim().to_string()).unwrap_or_default();
            if q.chars().count() < 2 || q.chars().count() > 64 {
                return Ok(err(s, 400, "search needs 2 to 64 characters"));
            }
            let r = db::search(c, &q)?;
            json_resp(s, 200, json!({
                "hosts": r.hosts.iter().map(|(id, name, addr, tags)| json!({"id": id, "name": name, "addr": addr, "tags": tags})).collect::<Vec<_>>(),
                "listeners": r.listeners.iter().map(|(hid, h, proto, addr, port, process, user)| json!({"host_id": hid, "host": h, "proto": proto, "addr": addr, "port": port, "process": process, "user": user})).collect::<Vec<_>>(),
                "conns": r.conns.iter().map(|(hid, h, proto, state, local, remote, process)| json!({"host_id": hid, "host": h, "proto": proto, "state": state, "local": local, "remote": remote, "process": process})).collect::<Vec<_>>(),
                "alerts": r.alerts.iter().map(alert_json_full).collect::<Vec<_>>(),
            }));
        }
        ("POST", "/api/host/tags") => {
            if rank < role_rank("operator") {
                return Ok(forbidden(s));
            }
            let v: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            let id = v["id"].as_str().unwrap_or("");
            let mut tags: Vec<String> = v["tags"].as_array().map(|a| a.iter().filter_map(|t| t.as_str()).map(|t| t.trim().to_lowercase()).filter(|t| !t.is_empty()).collect()).unwrap_or_default();
            tags.sort();
            tags.dedup();
            if !valid_id(id) || tags.len() > 10 || tags.iter().any(|t| !db::valid_tag(t)) {
                return Ok(err(s, 400, "tags: up to 10, each 1-24 chars of a-z 0-9 - ."));
            }
            if db::set_tags(c, id, &tags)? == 0 {
                return Ok(err(s, 404, "no such host"));
            }
            audit(st, c, &me.username, "host.tags", id, &tags.join(","), ip);
            json_resp(s, 200, json!({"ok": true, "tags": tags}));
        }
        ("GET", p) if p.starts_with("/api/host/") => {
            let rest = &p["/api/host/".len()..];
            let (id, sub) = rest.split_once('/').unwrap_or((rest, ""));
            if !valid_id(id) {
                return Ok(err(s, 400, "bad host id"));
            }
            let Some(h) = db::hosts(c)?.into_iter().find(|h| h.id == id) else { return Ok(err(s, 404, "no such host")) };
            match sub {
                "" => {
                    let ls = db::listeners(c, id)?;
                    let cs = db::conns(c, id)?;
                    let ev = db::events(c, id, 300)?;
                    let hist = db::established_history(c, id, 120)?;
                    json_resp(s, 200, json!({
                        "host": host_json(&h),
                        "listeners": ls.iter().map(|l| json!({"proto": l.proto, "addr": l.addr, "port": l.port, "pid": l.pid, "process": l.process, "user": l.user, "first_seen": l.first_seen})).collect::<Vec<_>>(),
                        "conns": cs.iter().take(2000).map(|x| json!({"proto": x.proto, "state": x.state, "local": x.local, "remote": x.remote, "pid": x.pid, "process": x.process})).collect::<Vec<_>>(),
                        "conns_total": cs.len(),
                        "events": ev.iter().map(|e| json!({"ts": e.ts, "event": e.event, "what": e.what})).collect::<Vec<_>>(),
                        "history": hist,
                    }));
                }
                "metrics" => {
                    let secs: u64 = match req.query.get("range").map(String::as_str) {
                        Some("1h") => 3600,
                        Some("24h") => 86400,
                        Some("7d") => 7 * 86400,
                        _ => 6 * 3600,
                    };
                    let bucket = (secs / 150).max(10);
                    let since = now_secs().saturating_sub(secs);
                    let rows = db::metric_series(c, id, since, bucket)?;
                    json_resp(s, 200, json!({
                        "since": since, "until": now_secs(), "bucket": bucket,
                        "t": rows.iter().map(|r| r.0).collect::<Vec<_>>(),
                        "established": rows.iter().map(|r| r.1).collect::<Vec<_>>(),
                        "syn_recv": rows.iter().map(|r| r.2).collect::<Vec<_>>(),
                        "time_wait": rows.iter().map(|r| r.3).collect::<Vec<_>>(),
                        "listeners": rows.iter().map(|r| r.4).collect::<Vec<_>>(),
                    }));
                }
                "timeline" => {
                    let rows = db::timeline(c, id, 400)?;
                    json_resp(s, 200, json!({"events": rows.iter().map(|r| json!({"ts": r.ts, "type": r.kind, "severity": r.severity, "title": r.title, "detail": r.detail})).collect::<Vec<_>>()}));
                }
                _ => return Ok(err(s, 404, "not found")),
            }
        }
        ("GET", "/api/mutes") => {
            let list = db::mutes(c)?;
            json_resp(s, 200, json!({"mutes": list.iter().map(|m| json!({"id": m.id, "host_id": m.host_id, "host": m.host, "kind": m.kind, "until": m.until, "reason": m.reason, "created_by": m.created_by, "created": m.created, "active": m.active})).collect::<Vec<_>>()}));
        }
        ("POST", "/api/mutes/add") => {
            if rank < role_rank("operator") {
                return Ok(forbidden(s));
            }
            let v: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            let host = v["host"].as_str().filter(|h| !h.is_empty());
            let kind = v["kind"].as_str().filter(|k| !k.is_empty());
            let minutes = v["minutes"].as_u64().unwrap_or(0);
            let reason = v["reason"].as_str().map(str::trim).unwrap_or("");
            if host.map_or(false, |h| !valid_id(h)) || kind.map_or(false, |k| !valid_kind(k)) {
                return Ok(err(s, 400, "bad host or alert type"));
            }
            if !(5..=7 * 24 * 60).contains(&minutes) {
                return Ok(err(s, 400, "duration must be between 5 minutes and 7 days"));
            }
            if reason.chars().count() < 3 {
                return Ok(err(s, 400, "a reason is required (it is recorded in the audit log)"));
            }
            db::add_mute(c, host, kind, minutes, reason, &me.username)?;
            audit(st, c, &me.username, "mute.add", host.unwrap_or("all hosts"), &format!("kind={} for {minutes}m: {}", kind.unwrap_or("any"), reason), ip);
            json_resp(s, 200, json!({"ok": true}));
        }
        ("POST", "/api/mutes/end") => {
            if rank < role_rank("operator") {
                return Ok(forbidden(s));
            }
            let v: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            let Some(id) = v["id"].as_i64() else { return Ok(err(s, 400, "missing mute id")) };
            if db::end_mute(c, id)? == 0 {
                return Ok(err(s, 404, "no such active mute"));
            }
            audit(st, c, &me.username, "mute.end", &id.to_string(), "", ip);
            json_resp(s, 200, json!({"ok": true}));
        }
        ("POST", "/api/ack") => {
            if rank < role_rank("operator") {
                return Ok(forbidden(s));
            }
            let v: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            if let Some(id) = v["id"].as_i64() {
                db::ack(c, id)?;
                audit(st, c, &me.username, "alert.ack", &id.to_string(), "", ip);
            } else if v["all"].as_bool() == Some(true) {
                match v["host"].as_str() {
                    Some(h) if !valid_id(h) => return Ok(err(s, 400, "bad host id")),
                    h => {
                        db::ack_all(c, h)?;
                        audit(st, c, &me.username, "alert.ack_all", h.unwrap_or("all hosts"), "", ip);
                    }
                }
            } else {
                return Ok(err(s, 400, "expected {\"id\":N} or {\"all\":true}"));
            }
            json_resp(s, 200, json!({"ok": true}));
        }
        ("GET", "/api/audit") => {
            if rank < role_rank("admin") {
                return Ok(forbidden(s));
            }
            let limit = req.query.get("limit").and_then(|v| v.parse().ok()).unwrap_or(500usize).clamp(1, 20000);
            let rows = db::audit_rows(c, limit)?;
            match req.query.get("format").map(String::as_str) {
                Some("csv") => {
                    audit(st, c, &me.username, "audit.export", "csv", &format!("{} rows", rows.len()), ip);
                    let mut out = String::from("id,time_utc,actor,action,target,detail,ip\n");
                    for r in &rows {
                        out.push_str(&format!("{},{},{},{},{},{},{}\n", r.id, csv_cell(&fmt_time(r.ts)), csv_cell(&r.actor), csv_cell(&r.action), csv_cell(&r.target), csv_cell(&r.detail), csv_cell(&r.ip)));
                    }
                    send(s, 200, "text/csv; charset=utf-8", "no-store", &["Content-Disposition: attachment; filename=\"netwatch-audit.csv\"".into()], out.as_bytes());
                }
                fmt => {
                    if fmt == Some("json") {
                        audit(st, c, &me.username, "audit.export", "json", &format!("{} rows", rows.len()), ip);
                    }
                    let body = json!({"entries": rows.iter().map(|r| json!({"id": r.id, "ts": r.ts, "actor": r.actor, "action": r.action, "target": r.target, "detail": r.detail, "ip": r.ip})).collect::<Vec<_>>(),
                                      "integrity": match db::audit_verify(c) { Ok(n) => json!({"ok": true, "entries": n}), Err(e) => json!({"ok": false, "error": e}) }});
                    if fmt == Some("json") {
                        send(s, 200, "application/json", "no-store", &["Content-Disposition: attachment; filename=\"netwatch-audit.json\"".into()], body.to_string().as_bytes());
                    } else {
                        json_resp(s, 200, body);
                    }
                }
            }
        }
        _ => err(s, 404, "not found"),
    }
    Ok(())
}

// ---------- entry point ----------

pub const HELP: &str = "\
netwatch web - web dashboard (run on the server host; reads its database)

    netwatch server user add <name> --role admin     Create the first account (or: netwatch server set-password)
    netwatch web [--listen 127.0.0.1:8080] [--dir D] [--allow-host NAME]...
                 [--tls | --cert FILE --key FILE] [--secure] [--idle-minutes 30] [--session-hours 8]

Binds to loopback by default; reach it remotely with an SSH tunnel:
    ssh -L 8080:127.0.0.1:8080 you@server   then open http://127.0.0.1:8080

--tls              Serve HTTPS using the server's own certificate (browsers will warn unless you
                   trust ca.pem from the server directory). Enables HSTS and Secure cookies.
--cert/--key       Serve HTTPS with your own certificate (e.g. from your enterprise CA / Let's Encrypt).
--listen ADDR      Address to bind. A non-loopback address without TLS serves plain HTTP: don't.
--allow-host NAME  Extra Host header value accepted (public name / reverse proxy).
--secure           Mark cookies Secure when TLS is terminated by a reverse proxy in front.
--idle-minutes N   Sign out after N idle minutes (default 30).
--session-hours N  Absolute session lifetime (default 8).

Roles: viewer (read), operator (+ acknowledge), admin (+ audit log, all sessions).
Accounts are managed from the CLI only: netwatch server user ...
";

pub fn cmd(args: &[String]) {
    if has(args, "--help") || has(args, "-h") {
        print!("{HELP}");
        return;
    }
    let dir: PathBuf = opt(args, "--dir").map(PathBuf::from).unwrap_or_else(default_server_dir);
    if !dir.join("netwatch.db").exists() {
        fail(&format!("no database in {} (run on the server host, or pass --dir)", dir.display()));
    }
    let c = db::open(&dir.join("netwatch.db")).unwrap_or_else(|e| fail(&format!("cannot open database: {e}")));
    if db::count_users(&c).unwrap_or(0) == 0 {
        fail("no dashboard accounts exist. Create one: netwatch server user add <name> --role admin");
    }
    drop(c);

    let listen = opt(args, "--listen").unwrap_or_else(|| "127.0.0.1:8080".into());
    let addr: SocketAddr = listen.to_socket_addrs().ok().and_then(|mut a| a.next()).unwrap_or_else(|| fail(&format!("bad --listen address '{listen}'")));
    let port = addr.port();

    let tls = if let (Some(cf), Some(kf)) = (opt(args, "--cert"), opt(args, "--key")) {
        let rd = |p: &str| std::fs::read_to_string(p).unwrap_or_else(|e| fail(&format!("cannot read {p}: {e}")));
        Some(pki::web_config(&rd(&cf), &rd(&kf)).unwrap_or_else(|e| fail(&format!("TLS setup failed: {e}"))))
    } else if has(args, "--tls") {
        let rd = |n: &str| std::fs::read_to_string(dir.join(n)).unwrap_or_else(|e| fail(&format!("cannot read {n}: {e}")));
        Some(pki::web_config(&rd("server.pem"), &rd("server.key")).unwrap_or_else(|e| fail(&format!("TLS setup failed: {e}"))))
    } else {
        None
    };
    HSTS.store(tls.is_some(), Ordering::Relaxed);

    let mut allowed = vec![listen.clone(), format!("localhost:{port}"), format!("127.0.0.1:{port}"), format!("[::1]:{port}")];
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--allow-host" {
            if let Some(h) = args.get(i + 1) {
                allowed.push(h.clone());
                allowed.push(format!("{h}:{port}"));
            }
            i += 1;
        }
        i += 1;
    }
    let mins: u64 = opt(args, "--idle-minutes").and_then(|v| v.parse().ok()).unwrap_or(30).clamp(1, 1440);
    let hours: u64 = opt(args, "--session-hours").and_then(|v| v.parse().ok()).unwrap_or(8).clamp(1, 168);

    let listener = TcpListener::bind(addr).unwrap_or_else(|e| fail(&format!("cannot listen on {listen}: {e}")));
    let scheme = if tls.is_some() { "https" } else { "http" };
    println!("netwatch web dashboard: {scheme}://{listen}  (data: {})", dir.display());
    if !addr.ip().is_loopback() && tls.is_none() && !has(args, "--secure") {
        eprintln!("WARNING: {listen} is not loopback and TLS is off: credentials would cross the network in clear text. Use --tls/--cert, or a TLS reverse proxy with --secure.");
    }
    let st = Arc::new(State {
        dir,
        secure_cookie: tls.is_some() || has(args, "--secure"),
        allowed_hosts: allowed,
        idle: Duration::from_secs(mins * 60),
        absolute: Duration::from_secs(hours * 3600),
        sessions: Mutex::new(HashMap::new()),
        fails: Mutex::new(Fails::default()),
        active: AtomicUsize::new(0),
        started: now_secs(),
    });
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        if st.active.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
            continue;
        }
        st.active.fetch_add(1, Ordering::Relaxed);
        let (st, tls) = (st.clone(), tls.clone());
        std::thread::spawn(move || {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
            if let Ok(peer) = stream.peer_addr() {
                match tls {
                    Some(cfg) => {
                        if let Ok(conn) = rustls::ServerConnection::new(cfg) {
                            let mut t = rustls::StreamOwned::new(conn, stream);
                            handle(&st, &mut t, peer.ip());
                            t.conn.send_close_notify();
                            let _ = t.flush();
                        }
                    }
                    None => {
                        let mut s = stream;
                        handle(&st, &mut s, peer.ip());
                    }
                }
            }
            st.active.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_decode_is_total() {
        assert_eq!(url_decode("a%20b+c%2Fd"), "a b c/d");
        assert_eq!(url_decode("%zz%4"), "%zz%4");
        assert_eq!(url_decode("%é"), "%é");
        assert_eq!(url_decode("%C3%A9"), "é");
        assert_eq!(url_decode("%"), "%");
        assert_eq!(url_decode("%FF%FE"), "\u{fffd}\u{fffd}");
    }

    #[test]
    fn csv_and_labels() {
        assert_eq!(csv_cell("=1+1"), "\"'=1+1\"");
        assert_eq!(csv_cell("a\"b"), "\"a\"\"b\"");
        assert_eq!(prom_label("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }
}
