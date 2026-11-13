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
    let query = qs.split('&').filter_map(|p| p.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect();
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
        _ => {}
    }
    if !req.path.starts_with("/api/") {
        return err(s, 404, "not found");
    }
    let conn = match db::open(&st.dir.join("netwatch.db")) {
        Ok(c) => c,
        Err(e) => return err(s, 500, &format!("database: {e}")),
    };
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
           "syn_recv": h.syn_recv, "time_wait": h.time_wait, "listeners": h.listeners, "open_alerts": h.open_alerts})
}

fn alert_json(a: &db::AlertRow) -> Value {
    json!({"id": a.id, "host": a.host, "ts": a.ts, "kind": a.kind, "severity": a.severity, "message": a.message, "acked": a.acked})
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
            json_resp(s, 200, json!({"hosts": hosts.iter().map(host_json).collect::<Vec<_>>(), "open_alerts": open, "now": now_secs()}));
        }
        ("GET", "/api/alerts") => {
            let host = req.query.get("host").filter(|h| !h.is_empty());
            if host.map_or(false, |h| !valid_id(h)) {
                return Ok(err(s, 400, "bad host id"));
            }
            let all = req.query.get("all").map_or(false, |v| v == "1");
            let limit = req.query.get("limit").and_then(|v| v.parse().ok()).unwrap_or(300usize).clamp(1, 1000);
            let rows = db::alerts(c, host.map(String::as_str), all, limit)?;
            json_resp(s, 200, json!({"alerts": rows.iter().map(alert_json).collect::<Vec<_>>()}));
        }
        ("GET", p) if p.starts_with("/api/host/") => {
            let id = &p["/api/host/".len()..];
            if !valid_id(id) {
                return Ok(err(s, 400, "bad host id"));
            }
            let Some(h) = db::hosts(c)?.into_iter().find(|h| h.id == id) else { return Ok(err(s, 404, "no such host")) };
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
