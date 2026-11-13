//! Central server: terminates mTLS, enrolls agents, stores reports, watches for silent hosts.

use super::db;
use super::pki;
use super::proto::{self, Request, Response};
use super::webhook::{self, Notification};
use super::util::*;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const DEFAULT_PORT: u16 = 7443;
const MAX_CONNECTIONS: usize = 256;

pub fn default_server_dir() -> PathBuf {
    default_dir("/var/lib/netwatch-server", ".local/share/netwatch-server")
}

pub const HELP: &str = "\
netwatch server - central collector

    netwatch server init --name <host-or-ip>[,more] [--port 7443] [--dir D]
                          Create the CA, server certificate and database
    netwatch server token [--dir D]
                          Create a one-time enrollment token (valid 24h) and print the agent command
    netwatch server run [--listen 0.0.0.0:7443] [--dir D] [--log alerts.jsonl]
                          Accept agent connections
    netwatch server hosts [--dir D]       List enrolled hosts
    netwatch server revoke <host> [--dir D]
                          Revoke an agent (its certificate stops working immediately)
    netwatch server set <key> <value> [--dir D]
                          Push a setting to all agents. Keys: report_interval window scan_ports
                          rate_limit conn_limit syn_limit rst_rate ignore (comma list of IPs)
                          Server-only: down_after (seconds of silence before HOST_DOWN, default 90)
                          webhook_url (Slack/Discord/any https endpoint), webhook_min_severity
                          (INFO|MEDIUM|HIGH, default MEDIUM), webhook_format (auto|slack|discord|generic)
    netwatch server user add|list|passwd|role|disable|enable|totp|totp-off|delete ...
                          Manage dashboard accounts and roles (see 'netwatch server user')
    netwatch server audit [--limit N] [--json] [--verify]
                          Show the audit log, or verify its integrity chain
    netwatch server metrics-token [--dir D] [--disable]
                          Enable the Prometheus endpoint (GET /metrics on the web dashboard port) and
                          print its bearer token once. Running it again rotates the token.
    netwatch server set-password [--dir D]
                          Set the 'admin' account password (bootstrap)
    netwatch server webhook test [--dir D]
                          Send a test message to the configured webhook
    netwatch server config [--dir D]      Show settings

Default dir: /var/lib/netwatch-server (root) or ~/.local/share/netwatch-server
";

pub fn dir_of(args: &[String]) -> PathBuf {
    opt(args, "--dir").map(PathBuf::from).unwrap_or_else(default_server_dir)
}

fn db_path(dir: &Path) -> PathBuf {
    dir.join("netwatch.db")
}

pub fn cmd(args: &[String]) {
    let rest = if args.len() > 1 { &args[1..] } else { &[][..] };
    match args.first().map(String::as_str) {
        Some("init") => init(rest),
        Some("token") => token(rest),
        Some("run") => run(rest),
        Some("hosts") => hosts(rest),
        Some("revoke") => revoke(rest),
        Some("set") => set(rest),
        Some("config") => config(rest),
        Some("webhook") => webhook_cmd(rest),
        Some("set-password") => set_password(rest),
        Some("metrics-token") => metrics_token(rest),
        Some("user") => super::users::user_cmd(rest),
        Some("audit") => super::users::audit_cmd(rest),
        _ => print!("{HELP}"),
    }
}

pub fn open_db(dir: &Path) -> rusqlite::Connection {
    if !dir.join("server.pem").exists() {
        fail(&format!("{} is not initialised; run 'netwatch server init' first", dir.display()));
    }
    db::open(&db_path(dir)).unwrap_or_else(|e| fail(&format!("cannot open database: {e}")))
}

fn init(args: &[String]) {
    let dir = dir_of(args);
    let names: Vec<String> = opt(args, "--name")
        .unwrap_or_else(|| fail("--name <host-or-ip> is required: it must be the address agents will use to reach this server"))
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let port: u16 = opt(args, "--port").map(|p| p.parse().unwrap_or_else(|_| fail("bad --port"))).unwrap_or(DEFAULT_PORT);
    if dir.join("server.pem").exists() {
        fail(&format!("{} is already initialised (delete it to start over)", dir.display()));
    }
    ensure_dir(&dir).unwrap_or_else(|e| fail(&format!("cannot create {}: {e}", dir.display())));
    let p = pki::init_server(&names).unwrap_or_else(|e| fail(&format!("certificate generation failed: {e}")));
    let w = |n: &str, d: &str, secret: bool| {
        let path = dir.join(n);
        let r = if secret { write_secret(&path, d.as_bytes()) } else { fs::write(&path, d) };
        r.unwrap_or_else(|e| fail(&format!("cannot write {}: {e}", path.display())));
    };
    w("ca.pem", &p.ca_pem, false);
    w("ca.key", &p.ca_key_pem, true);
    w("server.pem", &p.cert_pem, false);
    w("server.key", &p.key_pem, true);
    let c = db::open(&db_path(&dir)).unwrap_or_else(|e| fail(&format!("database error: {e}")));
    db::set_setting(&c, "public_addr", &format!("{}:{port}", names[0])).ok();
    println!("Initialised {}", dir.display());
    println!("Server certificate fingerprint (SHA-256): {}", pki::fingerprint(&p.cert_pem).unwrap_or_default());
    println!("\nNext: netwatch server token    then    netwatch server run");
}

fn token(args: &[String]) {
    let dir = dir_of(args);
    let c = open_db(&dir);
    let pem = fs::read_to_string(dir.join("server.pem")).unwrap_or_else(|e| fail(&format!("{e}")));
    let fp = pki::fingerprint(&pem).unwrap_or_else(|e| fail(&format!("{e}")));
    let t = db::create_token(&c, 86400).unwrap_or_else(|e| fail(&format!("{e}")));
    let addr = db::get_setting(&c, "public_addr").ok().flatten().unwrap_or_else(|| format!("<server>:{DEFAULT_PORT}"));
    println!("One-time token (valid 24h, single use). On the server you want to monitor, run as root:\n");
    println!("  netwatch agent enroll --server {addr} --token {t} --pin {fp}\n");
    println!("Or install and enroll in one line:\n");
    println!("  curl -fsSL https://raw.githubusercontent.com/mnshchtri/Network-monitor/main/install.sh | \\");
    println!("    NETWATCH_AGENT=\"--server {addr} --token {t} --pin {fp}\" sh");
}

fn hosts(args: &[String]) {
    let c = open_db(&dir_of(args));
    let rows = db::hosts(&c).unwrap_or_else(|e| fail(&format!("{e}")));
    println!("{:<18} {:<20} {:<8} {:<12} {:>6} {:>6}  {}", "ID", "NAME", "STATUS", "LAST SEEN", "LISTEN", "ALERTS", "ADDRESS");
    for h in rows {
        println!("{:<18} {:<20} {:<8} {:<12} {:>6} {:>6}  {}", h.id, h.name, h.status, ago(h.last_seen), h.listeners, h.open_alerts, h.addr);
    }
}

fn revoke(args: &[String]) {
    let target = args.first().filter(|a| !a.starts_with("--")).unwrap_or_else(|| fail("usage: netwatch server revoke <host id or name>"));
    let c = open_db(&dir_of(args));
    match db::revoke(&c, target) {
        Ok(0) => fail("no such host"),
        Ok(n) => {
            let _ = db::audit(&c, &super::users::cli_actor(), "host.revoke", target, "agent certificate revoked", "");
            println!("revoked {n} host(s); the agent can no longer report")
        }
        Err(e) => fail(&format!("{e}")),
    }
}

fn set(args: &[String]) {
    let (k, v) = match (args.first(), args.get(1)) {
        (Some(k), Some(v)) if !k.starts_with("--") => (k.as_str(), v.as_str()),
        _ => fail("usage: netwatch server set <key> <value>"),
    };
    if !db::SETTING_KEYS.contains(&k) && !db::SERVER_KEYS.contains(&k) {
        fail(&format!("unknown key '{k}'. Valid: {} {}", db::SETTING_KEYS.join(" "), db::SERVER_KEYS.join(" ")));
    }
    match k {
        "ignore" => {
            for ip in v.split(',').filter(|s| !s.trim().is_empty()) {
                if ip.trim().parse::<std::net::IpAddr>().is_err() {
                    fail(&format!("'{ip}' is not a valid IP address"));
                }
            }
        }
        "webhook_url" => {
            if !v.is_empty() {
                webhook::parse_url(v).unwrap_or_else(|e| fail(&e));
            }
        }
        "webhook_min_severity" if !["INFO", "MEDIUM", "HIGH"].contains(&v) => fail("webhook_min_severity must be INFO, MEDIUM or HIGH"),
        "webhook_format" if !["auto", "slack", "discord", "generic"].contains(&v) => fail("webhook_format must be auto, slack, discord or generic"),
        "webhook_min_severity" | "webhook_format" => {}
        _ => {
            if v.parse::<f64>().is_err() {
                fail(&format!("'{v}' is not a number"));
            }
        }
    }
    let c = open_db(&dir_of(args));
    db::set_setting(&c, k, v).unwrap_or_else(|e| fail(&format!("{e}")));
    let _ = db::audit(&c, &super::users::cli_actor(), "setting.set", k, &if k == "webhook_url" { webhook::mask(v) } else { v.to_string() }, "");
    if k.starts_with("webhook") || k == "down_after" {
        println!("{k} = {} (applies immediately; restart not needed)", if k == "webhook_url" { webhook::mask(v) } else { v.to_string() });
    } else {
        println!("{k} = {v} (agents pick it up on their next report)");
    }
}

fn config(args: &[String]) {
    let c = open_db(&dir_of(args));
    for k in db::SETTING_KEYS.iter().chain(db::SERVER_KEYS.iter()) {
        let v = db::get_setting(&c, k).ok().flatten();
        let shown = match (*k, v) {
            (_, None) => "(default)".to_string(),
            ("webhook_url", Some(u)) if !u.is_empty() => webhook::mask(&u),
            (_, Some(v)) => v,
        };
        println!("{k:<22} {shown}");
    }
}

pub fn read_secret(prompt: &str, tty: bool) -> String {
    use std::io::{BufRead, Write};
    if tty {
        eprint!("{prompt}");
        let _ = std::io::stderr().flush();
        let _ = std::process::Command::new("stty").arg("-echo").status();
    }
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    if tty {
        let _ = std::process::Command::new("stty").arg("echo").status();
        eprintln!();
    }
    line.trim_end_matches(['\n', '\r']).to_string()
}

fn metrics_token(args: &[String]) {
    let c = open_db(&dir_of(args));
    let actor = super::users::cli_actor();
    if has(args, "--disable") {
        db::set_setting(&c, "metrics_token_hash", "").unwrap_or_else(|e| fail(&format!("{e}")));
        let _ = db::audit(&c, &actor, "metrics.disable", "", "", "");
        println!("metrics endpoint disabled");
        return;
    }
    let token = random_hex(24);
    db::set_setting(&c, "metrics_token_hash", &sha256_hex(token.as_bytes())).unwrap_or_else(|e| fail(&format!("{e}")));
    let _ = db::audit(&c, &actor, "metrics.token", "", "token created/rotated", "");
    println!("Prometheus bearer token (shown once, only its hash is stored):\n\n  {token}\n");
    println!("prometheus.yml:\n  scrape_configs:\n    - job_name: netwatch\n      scheme: https            # or http behind an SSH tunnel / on loopback\n      authorization: {{ credentials: {token} }}\n      static_configs: [{{ targets: ['127.0.0.1:8080'] }}]\n      # if the dashboard is served on a public name, also pass --allow-host for it");
}

/// Legacy/bootstrap command: set (or create) the `admin` account's password.
fn set_password(args: &[String]) {
    use std::io::IsTerminal;
    let c = open_db(&dir_of(args));
    let tty = std::io::stdin().is_terminal() && !has(args, "--password-stdin");
    let pw = read_secret("New password for the admin account: ", tty);
    if tty && read_secret("Repeat password: ", true) != pw {
        fail("passwords do not match");
    }
    if let Err(e) = super::auth::password_policy(&pw, "admin") {
        fail(&e);
    }
    let hash = super::auth::hash_password(&pw);
    let actor = super::users::cli_actor();
    match db::user_by_name(&c, "admin").unwrap_or_else(|e| fail(&format!("{e}"))) {
        Some(u) => {
            db::set_password(&c, u.id, &hash, false).unwrap_or_else(|e| fail(&format!("{e}")));
            let _ = db::audit(&c, &actor, "user.passwd", "admin", "password set via server set-password", "");
        }
        None => {
            db::add_user(&c, "admin", &hash, "admin", false).unwrap_or_else(|e| fail(&format!("{e}")));
            let _ = db::audit(&c, &actor, "user.add", "admin", "role=admin (bootstrap)", "");
        }
    }
    println!("admin password set. Start the dashboard with: netwatch web   (user: admin)");
}

fn webhook_cmd(args: &[String]) {
    if args.first().map(String::as_str) != Some("test") {
        fail("usage: netwatch server webhook test");
    }
    let c = open_db(&dir_of(args));
    let url = db::get_setting(&c, "webhook_url").ok().flatten().filter(|u| !u.is_empty())
        .unwrap_or_else(|| fail("no webhook configured: netwatch server set webhook_url <url>"));
    let n = Notification {
        host: hostname(), ts: now_secs(), kind: "TEST".into(), severity: "INFO".into(), source: None,
        message: "netwatch webhook test: delivery works".into(),
    };
    let fmt = webhook::effective_format(&c, &url);
    match webhook::post(&url, &webhook::body(&fmt, &[n])) {
        Ok(()) => println!("delivered to {} ({fmt} format)", webhook::mask(&url)),
        Err(e) => fail(&format!("delivery to {} failed: {e}", webhook::mask(&url))),
    }
}

struct Shared {
    notify: SyncSender<Notification>,
    cfg: Arc<rustls::ServerConfig>,
    dir: PathBuf,
    ca_pem: String,
    ca_key_pem: String,
    active: AtomicUsize,
    log: Mutex<Option<File>>,
}

fn run(args: &[String]) {
    let dir = dir_of(args);
    let _ = open_db(&dir); // validates init + creates schema
    let rd = |n: &str| fs::read_to_string(dir.join(n)).unwrap_or_else(|e| fail(&format!("cannot read {n}: {e}")));
    let (ca_pem, ca_key_pem, cert, key) = (rd("ca.pem"), rd("ca.key"), rd("server.pem"), rd("server.key"));
    let cfg = pki::server_config(&ca_pem, &cert, &key).unwrap_or_else(|e| fail(&format!("TLS setup failed: {e}")));
    let listen = opt(args, "--listen").unwrap_or_else(|| format!("0.0.0.0:{DEFAULT_PORT}"));
    let log = opt(args, "--log").map(|p| {
        OpenOptions::new().create(true).append(true).open(&p).unwrap_or_else(|e| fail(&format!("cannot open log {p}: {e}")))
    });
    let listener = TcpListener::bind(&listen).unwrap_or_else(|e| fail(&format!("cannot listen on {listen}: {e}")));
    println!("netwatch server listening on {listen} (data: {})", dir.display());

    let notify = webhook::spawn(db_path(&dir));
    let shared = Arc::new(Shared { notify: notify.clone(), cfg, dir: dir.clone(), ca_pem, ca_key_pem, active: AtomicUsize::new(0), log: Mutex::new(log) });

    // Watchdog: HOST_DOWN detection + retention.
    let wd_dir = dir.clone();
    let wd_notify = notify;
    std::thread::spawn(move || {
        let Ok(c) = db::open(&db_path(&wd_dir)) else { return };
        let mut ticks = 0u64;
        loop {
            std::thread::sleep(Duration::from_secs(15));
            let down_after = db::get_setting(&c, "down_after").ok().flatten().and_then(|v| v.parse().ok()).unwrap_or(90);
            match db::watchdog(&c, down_after) {
                Ok(v) => v.iter().for_each(|n| {
                    println!("{} HOST_DOWN {n}", fmt_time(now_secs()));
                    let _ = wd_notify.try_send(Notification {
                        host: n.clone(), ts: now_secs(), kind: "HOST_DOWN".into(), severity: "HIGH".into(), source: None,
                        message: format!("no report from {n} for over {down_after}s"),
                    });
                }),
                Err(e) => eprintln!("watchdog: {e}"),
            }
            ticks += 1;
            if ticks % 240 == 0 {
                let _ = db::prune(&c);
            }
        }
    });

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        if shared.active.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
            continue; // shed load instead of exhausting threads
        }
        shared.active.fetch_add(1, Ordering::Relaxed);
        let sh = shared.clone();
        std::thread::spawn(move || {
            let peer = stream.peer_addr().map(|a| a.ip().to_string()).unwrap_or_default();
            if let Err(e) = handle(&sh, stream, &peer) {
                if e.kind() != std::io::ErrorKind::UnexpectedEof {
                    eprintln!("{} {peer}: {e}", fmt_time(now_secs()));
                }
            }
            sh.active.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

fn handle(sh: &Shared, stream: TcpStream, peer: &str) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    let conn = rustls::ServerConnection::new(sh.cfg.clone()).map_err(std::io::Error::other)?;
    let mut tls = rustls::StreamOwned::new(conn, stream);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }
    tls.sock.set_read_timeout(Some(Duration::from_secs(120)))?;

    let mut dbc = db::open(&db_path(&sh.dir)).map_err(std::io::Error::other)?;
    let identity: Option<(String, String)> = match tls.conn.peer_certificates().and_then(|c| c.first()) {
        Some(c) => {
            let fp = sha256_hex(c.as_ref());
            match db::host_by_fp(&dbc, &fp).map_err(std::io::Error::other)? {
                Some(h) => Some(h),
                None => {
                    let _ = proto::send(&mut tls, &Response::Error { message: "unknown or revoked agent".into() });
                    return Ok(());
                }
            }
        }
        None => None,
    };

    let mut reader = BufReader::new(tls);
    while let Some(req) = proto::recv::<_, Request>(&mut reader)? {
        let resp = match (req, &identity) {
            (Request::Enroll { token, hostname, csr_pem }, None) => enroll(sh, &dbc, peer, &token, &hostname, &csr_pem),
            (Request::Report(r), Some((id, name))) => match db::ingest(&mut dbc, id, peer, &r) {
                Ok((changes, recovered)) => {
                    log_alerts(sh, name, &r);
                    for a in &r.alerts {
                        // Muted (maintenance) alerts are still stored and shown, just not pushed out.
                        if db::is_muted(&dbc, id, &clean(&a.kind, 32)).unwrap_or(false) {
                            continue;
                        }
                        let _ = sh.notify.try_send(Notification {
                            host: name.clone(), ts: a.ts, kind: clean(&a.kind, 32), severity: clean(&a.severity, 8),
                            source: a.source.as_deref().map(|s| clean(s, 64)), message: clean(&a.message, 500),
                        });
                    }
                    if recovered && !db::is_muted(&dbc, id, "HOST_UP").unwrap_or(false) {
                        let _ = sh.notify.try_send(Notification {
                            host: name.clone(), ts: now_secs(), kind: "HOST_UP".into(), severity: "INFO".into(),
                            source: None, message: "agent is reporting again".into(),
                        });
                    }
                    for a in &r.alerts {
                        println!("{} {name:<16} {:<6} {:<15} {}", fmt_time(a.ts), a.severity, a.kind, clean(&a.message, 200));
                    }
                    if changes > 0 {
                        println!("{} {name:<16} listener changes: {changes}", fmt_time(now_secs()));
                    }
                    Response::Ack { config: db::remote_config(&dbc).ok() }
                }
                Err(e) => {
                    eprintln!("ingest error for {name}: {e}");
                    Response::Error { message: "server could not store report".into() }
                }
            },
            (Request::Report(_), None) => Response::Error { message: "client certificate required".into() },
            (Request::Enroll { .. }, Some(_)) => Response::Error { message: "already enrolled".into() },
        };
        let done = matches!(resp, Response::Enrolled { .. } | Response::Error { .. });
        proto::send(reader.get_mut(), &resp)?;
        if done {
            break;
        }
    }
    Ok(())
}

fn enroll(sh: &Shared, c: &rusqlite::Connection, peer: &str, token: &str, hostname: &str, csr: &str) -> Response {
    let bad = |m: &str| {
        std::thread::sleep(Duration::from_secs(1)); // slow down token guessing
        Response::Error { message: m.into() }
    };
    match db::consume_token(c, token) {
        Ok(true) => {}
        _ => return bad("invalid or expired token"),
    }
    let id = random_hex(8);
    let cert = match pki::sign_csr(csr, &sh.ca_pem, &sh.ca_key_pem, &id) {
        Ok(c) => c,
        Err(e) => return Response::Error { message: format!("bad CSR: {e}") },
    };
    let fp = match pki::fingerprint(&cert) {
        Ok(f) => f,
        Err(e) => return Response::Error { message: format!("{e}") },
    };
    if let Err(e) = db::add_host(c, &id, hostname, &fp, peer) {
        return Response::Error { message: format!("could not register host: {e}") };
    }
    println!("{} enrolled {} ({id}) from {peer}", fmt_time(now_secs()), clean(hostname, 64));
    Response::Enrolled { host_id: id, cert_pem: cert, ca_pem: sh.ca_pem.clone() }
}

fn log_alerts(sh: &Shared, host: &str, r: &proto::Report) {
    if r.alerts.is_empty() {
        return;
    }
    if let Ok(mut g) = sh.log.lock() {
        if let Some(f) = g.as_mut() {
            for a in &r.alerts {
                let _ = writeln!(
                    f,
                    "{}",
                    serde_json::json!({"time": fmt_time(a.ts), "host": host, "severity": a.severity, "type": a.kind, "source": a.source, "message": a.message})
                );
            }
        }
    }
}
