//! Web dashboard: a small hand-written HTTP/1.1 server (std only) serving a static single-page
//! app plus a JSON API over the server's SQLite database.
//!
//! Security posture: password login (PBKDF2), HttpOnly+SameSite=Strict session cookie, login
//! lockout, Host-header allowlist (DNS-rebinding defence), custom-header + Origin checks on every
//! state-changing request (CSRF), strict CSP, no third-party assets. Binds to loopback by default.

use super::db;
use super::server::default_server_dir;
use super::util::*;
use pbkdf2::pbkdf2_hmac;
use serde_json::{json, Value};
use sha2::Sha256;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const ITER: u32 = 200_000;
const SESSION_TTL: Duration = Duration::from_secs(8 * 3600);
const MAX_HEADERS: usize = 16 * 1024;
const MAX_BODY: usize = 4 * 1024;
const MAX_CONNECTIONS: usize = 64;
const LOCK_AFTER: u32 = 5;
const LOCK_FOR: Duration = Duration::from_secs(300);

const INDEX: &str = include_str!("web/index.html");
const CSS: &str = include_str!("web/app.css");
const JS: &str = include_str!("web/app.js");

// ---------- password hashing ----------

pub fn hash_password(pw: &str) -> String {
    let salt = random_hex(16);
    let mut out = [0u8; 32];
    pbkdf2_hmac::<Sha256>(pw.as_bytes(), salt.as_bytes(), ITER, &mut out);
    format!("pbkdf2-sha256${ITER}${salt}${}", hex(&out))
}

fn verify_password(pw: &str, stored: &str) -> bool {
    let p: Vec<&str> = stored.split('$').collect();
    if p.len() != 4 || p[0] != "pbkdf2-sha256" {
        return false;
    }
    let Ok(iters) = p[1].parse::<u32>() else { return false };
    if iters == 0 || iters > 5_000_000 {
        return false;
    }
    let mut out = [0u8; 32];
    pbkdf2_hmac::<Sha256>(pw.as_bytes(), p[2].as_bytes(), iters, &mut out);
    ct_eq(hex(&out).as_bytes(), p[3].as_bytes())
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ---------- state ----------

struct State {
    dir: PathBuf,
    secure_cookie: bool,
    allowed_hosts: Vec<String>,
    sessions: Mutex<HashMap<String, Instant>>,
    fails: Mutex<HashMap<IpAddr, (u32, Option<Instant>)>>,
    active: AtomicUsize,
}

impl State {
    fn host_ok(&self, h: &str) -> bool {
        self.allowed_hosts.iter().any(|a| a.eq_ignore_ascii_case(h))
    }

    fn new_session(&self) -> String {
        let t = random_hex(32);
        let mut s = self.sessions.lock().unwrap();
        let now = Instant::now();
        s.retain(|_, exp| *exp > now);
        s.insert(t.clone(), now + SESSION_TTL);
        t
    }

    fn session_valid(&self, req: &Req) -> bool {
        let Some(tok) = req.cookie("nw_session") else { return false };
        let mut s = self.sessions.lock().unwrap();
        let now = Instant::now();
        match s.get_mut(&tok) {
            Some(exp) if *exp > now => {
                *exp = now + SESSION_TTL;
                true
            }
            Some(_) => {
                s.remove(&tok);
                false
            }
            None => false,
        }
    }

    fn locked(&self, ip: IpAddr) -> bool {
        let mut f = self.fails.lock().unwrap();
        match f.get(&ip) {
            Some((_, Some(until))) if *until > Instant::now() => true,
            Some((_, Some(_))) => {
                f.remove(&ip);
                false
            }
            _ => false,
        }
    }

    fn record_fail(&self, ip: IpAddr) {
        let mut f = self.fails.lock().unwrap();
        if f.len() > 2000 {
            f.retain(|_, (_, u)| u.map_or(false, |u| u > Instant::now()));
        }
        let e = f.entry(ip).or_insert((0, None));
        e.0 += 1;
        if e.0 >= LOCK_AFTER {
            e.1 = Some(Instant::now() + LOCK_FOR);
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

fn read_req(s: &mut TcpStream) -> Result<Req, &'static str> {
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
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        429 => "Too Many Requests",
        _ => "Internal Server Error",
    }
}

fn send(s: &mut TcpStream, code: u16, ctype: &str, cache: &str, extra: &[String], body: &[u8]) {
    let mut h = format!(
        "HTTP/1.1 {code} {}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: {cache}\r\nConnection: close\r\n\
         X-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nCross-Origin-Opener-Policy: same-origin\r\n\
         Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'\r\n",
        status_text(code),
        body.len()
    );
    for e in extra {
        h.push_str(e);
        h.push_str("\r\n");
    }
    h.push_str("\r\n");
    let _ = s.write_all(h.as_bytes());
    let _ = s.write_all(body);
}

fn json_resp(s: &mut TcpStream, code: u16, v: Value) {
    send(s, code, "application/json; charset=utf-8", "no-store", &[], v.to_string().as_bytes());
}

fn err(s: &mut TcpStream, code: u16, msg: &str) {
    json_resp(s, code, json!({ "error": msg }));
}

fn valid_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && s.chars().all(|c| c.is_ascii_hexdigit())
}

// ---------- request handling ----------

fn handle(st: &State, mut s: TcpStream, peer: IpAddr) {
    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(10)));
    let req = match read_req(&mut s) {
        Ok(r) => r,
        Err(m) => return err(&mut s, 400, m),
    };
    // DNS-rebinding defence: only answer for hostnames we are meant to be reached by.
    match req.h("host") {
        Some(h) if st.host_ok(h) => {}
        _ => return err(&mut s, 400, "unrecognised Host header (use --allow-host to permit this name)"),
    }
    let post = req.method == "POST";
    if req.method != "GET" && !post {
        return err(&mut s, 405, "method not allowed");
    }
    if post {
        // CSRF: browsers cannot add this header cross-origin without a CORS preflight, which we never grant.
        if req.h("x-requested-with") != Some("netwatch") {
            return err(&mut s, 403, "missing X-Requested-With");
        }
        if let Some(o) = req.h("origin") {
            let host = o.split_once("://").map(|(_, h)| h).unwrap_or(o);
            if !st.host_ok(host) {
                return err(&mut s, 403, "cross-origin request refused");
            }
        }
    }

    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") => return send(&mut s, 200, "text/html; charset=utf-8", "no-cache", &[], INDEX.as_bytes()),
        ("GET", "/app.css") => return send(&mut s, 200, "text/css; charset=utf-8", "no-cache", &[], CSS.as_bytes()),
        ("GET", "/app.js") => return send(&mut s, 200, "text/javascript; charset=utf-8", "no-cache", &[], JS.as_bytes()),
        ("POST", "/api/login") => return login(st, &mut s, &req, peer),
        _ => {}
    }
    if !req.path.starts_with("/api/") {
        return err(&mut s, 404, "not found");
    }
    if !st.session_valid(&req) {
        return err(&mut s, 401, "login required");
    }
    let conn = match db::open(&st.dir.join("netwatch.db")) {
        Ok(c) => c,
        Err(e) => return err(&mut s, 500, &format!("database: {e}")),
    };
    let r = route(st, &conn, &req, &mut s);
    if let Err(e) = r {
        err(&mut s, 500, &format!("database: {e}"));
    }
}

fn login(st: &State, s: &mut TcpStream, req: &Req, peer: IpAddr) {
    if st.locked(peer) {
        return err(s, 429, "too many failed attempts; try again in a few minutes");
    }
    let pw = serde_json::from_slice::<Value>(&req.body).ok().and_then(|v| v["password"].as_str().map(String::from)).unwrap_or_default();
    let stored = db::open(&st.dir.join("netwatch.db")).ok().and_then(|c| db::get_setting(&c, "web_password").ok().flatten()).unwrap_or_default();
    if !stored.is_empty() && verify_password(&pw, &stored) {
        st.fails.lock().unwrap().remove(&peer);
        let tok = st.new_session();
        let cookie = format!(
            "Set-Cookie: nw_session={tok}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}{}",
            SESSION_TTL.as_secs(),
            if st.secure_cookie { "; Secure" } else { "" }
        );
        send(s, 200, "application/json", "no-store", &[cookie], b"{\"ok\":true}");
    } else {
        st.record_fail(peer);
        std::thread::sleep(Duration::from_millis(500));
        err(s, 401, "wrong password");
    }
}

fn host_json(h: &db::HostRow) -> Value {
    json!({"id": h.id, "name": h.name, "os": h.os, "version": h.version, "addr": h.addr, "status": h.status,
           "last_seen": h.last_seen, "is_root": h.is_root, "total": h.total, "established": h.established,
           "syn_recv": h.syn_recv, "time_wait": h.time_wait, "listeners": h.listeners, "open_alerts": h.open_alerts})
}

fn alert_json(a: &db::AlertRow) -> Value {
    json!({"id": a.id, "host": a.host, "ts": a.ts, "kind": a.kind, "severity": a.severity, "message": a.message, "acked": a.acked})
}

fn route(st: &State, c: &rusqlite::Connection, req: &Req, s: &mut TcpStream) -> rusqlite::Result<()> {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/api/me") => json_resp(s, 200, json!({"ok": true})),
        ("POST", "/api/logout") => {
            if let Some(t) = req.cookie("nw_session") {
                st.sessions.lock().unwrap().remove(&t);
            }
            send(s, 200, "application/json", "no-store", &["Set-Cookie: nw_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0".into()], b"{\"ok\":true}");
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
            let v: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            if let Some(id) = v["id"].as_i64() {
                db::ack(c, id)?;
            } else if v["all"].as_bool() == Some(true) {
                match v["host"].as_str() {
                    Some(h) if !valid_id(h) => return Ok(err(s, 400, "bad host id")),
                    h => db::ack_all(c, h)?,
                }
            } else {
                return Ok(err(s, 400, "expected {\"id\":N} or {\"all\":true}"));
            }
            json_resp(s, 200, json!({"ok": true}));
        }
        _ => err(s, 404, "not found"),
    }
    Ok(())
}

// ---------- entry point ----------

pub const HELP: &str = "\
netwatch web - web dashboard (run on the server host; reads its database)

    netwatch server set-password            Set the login password first (required, min 10 chars)
    netwatch web [--listen 127.0.0.1:8080] [--dir D] [--allow-host NAME]... [--secure]

Binds to loopback by default; reach it remotely with an SSH tunnel:
    ssh -L 8080:127.0.0.1:8080 you@server   then open http://127.0.0.1:8080

--listen ADDR      Address to bind. Anything other than loopback serves PLAIN HTTP: put it behind
                   an HTTPS reverse proxy (nginx/caddy) and never expose it directly.
--allow-host NAME  Extra Host header value accepted (needed behind a proxy / on a public name).
--secure           Mark the session cookie Secure (use when served through an HTTPS proxy).
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
    if db::get_setting(&c, "web_password").ok().flatten().unwrap_or_default().is_empty() {
        fail("no dashboard password set. Run: netwatch server set-password");
    }
    drop(c);

    let listen = opt(args, "--listen").unwrap_or_else(|| "127.0.0.1:8080".into());
    let addr: SocketAddr = listen
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
        .unwrap_or_else(|| fail(&format!("bad --listen address '{listen}'")));
    let port = addr.port();

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

    let listener = TcpListener::bind(addr).unwrap_or_else(|e| fail(&format!("cannot listen on {listen}: {e}")));
    println!("netwatch web dashboard: http://{listen}  (data: {})", dir.display());
    if !addr.ip().is_loopback() {
        eprintln!("WARNING: {listen} is not loopback. This serves plain HTTP; use an HTTPS reverse proxy and --secure.");
    }
    let st = std::sync::Arc::new(State {
        dir,
        secure_cookie: has(args, "--secure"),
        allowed_hosts: allowed,
        sessions: Mutex::new(HashMap::new()),
        fails: Mutex::new(HashMap::new()),
        active: AtomicUsize::new(0),
    });
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        if st.active.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
            continue;
        }
        st.active.fetch_add(1, Ordering::Relaxed);
        let st = st.clone();
        std::thread::spawn(move || {
            if let Ok(peer) = stream.peer_addr() {
                handle(&st, stream, peer.ip());
            }
            st.active.fetch_sub(1, Ordering::Relaxed);
        });
    }
}
