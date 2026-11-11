//! Agent: runs the local detectors and reports to the server over outbound mTLS.
//! Active mode only: the monitored host never opens a listening port for netwatch.

use super::pki;
use super::proto::{self, AlertMsg, Conn, Listener, RemoteConfig, Report, Request, Response, Stats};
use super::util::*;
use crate::detect::{Config, Detector};
use crate::proc::{self, Proto, Sock};
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::BufReader;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

pub const HELP: &str = "\
netwatch agent - report this host's network state to a netwatch server

    netwatch agent enroll --server host:7443 --token <T> --pin <sha256> [--dir D]
                          One-time registration (get the command from 'netwatch server token')
    netwatch agent run [--dir D]
                          Run the agent (use the systemd service for always-on)

Default dir: /etc/netwatch (root) or ~/.config/netwatch
Run as root so sockets can be mapped to processes.
";

#[derive(Serialize, Deserialize)]
struct AgentFile {
    server: String,
    host_id: String,
}

fn dir_of(args: &[String]) -> PathBuf {
    opt(args, "--dir").map(PathBuf::from).unwrap_or_else(|| default_dir("/etc/netwatch", ".config/netwatch"))
}

pub fn cmd(args: &[String]) {
    let rest = if args.len() > 1 { &args[1..] } else { &[][..] };
    match args.first().map(String::as_str) {
        Some("enroll") => enroll(rest),
        Some("run") => run(rest),
        _ => print!("{HELP}"),
    }
}

fn split_host(server: &str) -> (String, String) {
    let host = server.rsplit_once(':').map(|(h, _)| h).unwrap_or(server).trim_matches(|c| c == '[' || c == ']');
    (host.to_string(), server.to_string())
}

fn connect(server: &str, cfg: std::sync::Arc<rustls::ClientConfig>) -> std::io::Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>> {
    let (host, addr) = split_host(server);
    let sock = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::other("cannot resolve server address"))?;
    let tcp = TcpStream::connect_timeout(&sock, Duration::from_secs(10))?;
    tcp.set_read_timeout(Some(Duration::from_secs(30)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(30)))?;
    tcp.set_nodelay(true).ok();
    let name = ServerName::try_from(host).map_err(|e| std::io::Error::other(format!("bad server name: {e}")))?;
    let conn = rustls::ClientConnection::new(cfg, name).map_err(std::io::Error::other)?;
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }
    Ok(tls)
}

fn enroll(args: &[String]) {
    let dir = dir_of(args);
    let server = opt(args, "--server").unwrap_or_else(|| fail("--server host:port is required"));
    let token = opt(args, "--token").unwrap_or_else(|| fail("--token is required"));
    let pin = opt(args, "--pin").unwrap_or_else(|| fail("--pin <server certificate sha256> is required"));
    if !server.contains(':') {
        fail("--server must include the port, e.g. server.example.com:7443");
    }
    if dir.join("agent.json").exists() && !has(args, "--force") {
        fail(&format!("already enrolled ({}); use --force to re-enroll", dir.display()));
    }
    let host = hostname();
    let (key_pem, csr_pem) = pki::agent_csr(&host).unwrap_or_else(|e| fail(&format!("key generation failed: {e}")));
    let cfg = pki::enroll_config(&pin).unwrap_or_else(|e| fail(&format!("{e}")));
    let tls = connect(&server, cfg).unwrap_or_else(|e| fail(&format!("cannot connect to {server}: {e} (is the --pin correct?)")));
    let mut r = BufReader::new(tls);
    proto::send(r.get_mut(), &Request::Enroll { token, hostname: host, csr_pem }).unwrap_or_else(|e| fail(&format!("{e}")));
    match proto::recv::<_, Response>(&mut r) {
        Ok(Some(Response::Enrolled { host_id, cert_pem, ca_pem })) => {
            ensure_dir(&dir).unwrap_or_else(|e| fail(&format!("cannot create {}: {e}", dir.display())));
            let w = |n: &str, d: &str, secret: bool| {
                let p = dir.join(n);
                let res = if secret { write_secret(&p, d.as_bytes()) } else { fs::write(&p, d) };
                res.unwrap_or_else(|e| fail(&format!("cannot write {}: {e}", p.display())));
            };
            w("ca.pem", &ca_pem, false);
            w("client.pem", &cert_pem, false);
            w("client.key", &key_pem, true);
            w("agent.json", &serde_json::to_string_pretty(&AgentFile { server, host_id: host_id.clone() }).unwrap(), false);
            println!("Enrolled as {host_id}. Credentials stored in {}", dir.display());
            println!("Start reporting with: netwatch agent run   (or enable the systemd service)");
        }
        Ok(Some(Response::Error { message })) => fail(&format!("server refused enrollment: {message}")),
        Ok(_) => fail("unexpected response from server"),
        Err(e) => fail(&format!("enrollment failed: {e}")),
    }
}

type Link = BufReader<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>;

fn build_report(socks: &[Sock], owners: &HashMap<u64, proc::ProcInfo>, alerts: Vec<AlertMsg>, eph: u16) -> Report {
    let who = |s: &Sock| owners.get(&s.inode).map(|p| (p.pid, p.name.clone()));
    let mut st = Stats { total: socks.len() as u32, ..Default::default() };
    let mut listeners = Vec::new();
    let mut conns = Vec::new();
    for s in socks {
        if s.proto == Proto::Tcp {
            match s.state {
                0x01 => st.established += 1,
                0x03 => st.syn_recv += 1,
                0x06 => st.time_wait += 1,
                _ => {}
            }
        }
        if s.is_listening() {
            if s.proto == Proto::Udp && s.lport >= eph {
                continue;
            }
            st.listeners += 1;
            let w = who(s);
            listeners.push(Listener {
                proto: s.proto.name().into(),
                addr: s.local.to_string(),
                port: s.lport,
                pid: w.as_ref().map(|x| x.0),
                process: w.map(|x| x.1),
                user: proc::uid_name(s.uid),
            });
        } else {
            let w = who(s);
            conns.push(Conn {
                proto: s.proto.name().into(),
                state: s.state_name().into(),
                local: format!("{}:{}", s.local, s.lport),
                remote: format!("{}:{}", s.remote, s.rport),
                pid: w.as_ref().map(|x| x.0),
                process: w.map(|x| x.1),
            });
        }
    }
    // Keep the interesting ones if we must truncate: live flows before TIME_WAIT noise.
    conns.sort_by_key(|c| c.state == "TIME_WAIT");
    conns.truncate(2000);
    Report {
        hostname: hostname(),
        os: kernel(),
        version: env!("CARGO_PKG_VERSION").into(),
        ts: now_secs(),
        root: proc::can_see_all_processes(),
        listeners,
        conns,
        stats: st,
        alerts,
    }
}

fn send_report(link: &mut Option<Link>, server: &str, cfg: &std::sync::Arc<rustls::ClientConfig>, r: &Report) -> std::io::Result<Option<RemoteConfig>> {
    if link.is_none() {
        *link = Some(BufReader::new(connect(server, cfg.clone())?));
    }
    let l = link.as_mut().unwrap();
    let res = (|| {
        proto::send(l.get_mut(), &Request::Report(r.clone()))?;
        match proto::recv::<_, Response>(l)? {
            Some(Response::Ack { config }) => Ok(config),
            Some(Response::Error { message }) => Err(std::io::Error::other(message)),
            _ => Err(std::io::Error::other("connection closed by server")),
        }
    })();
    if res.is_err() {
        *link = None;
    }
    res
}

fn apply(base: &Config, interval: &mut u64, rc: &RemoteConfig) -> Config {
    let mut c = base.clone();
    if let Some(v) = rc.report_interval {
        *interval = v.clamp(2, 3600);
    }
    if let Some(v) = rc.window { c.window = Duration::from_secs(v.clamp(5, 3600)); }
    if let Some(v) = rc.scan_ports { c.scan_ports = v.max(1); }
    if let Some(v) = rc.rate_limit { c.rate_limit = v.max(1); }
    if let Some(v) = rc.conn_limit { c.conn_limit = v.max(1); }
    if let Some(v) = rc.syn_limit { c.syn_limit = v.max(1); }
    if let Some(v) = rc.rst_rate { c.rst_rate = v.max(1.0); }
    if let Some(list) = &rc.ignore {
        c.ignore = list.iter().filter_map(|s| s.parse().ok()).collect();
    }
    c
}

fn run(args: &[String]) {
    let dir = dir_of(args);
    let af: AgentFile = fs::read_to_string(dir.join("agent.json"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_else(|| fail(&format!("not enrolled ({}); run 'netwatch agent enroll' first", dir.display())));
    let rd = |n: &str| fs::read_to_string(dir.join(n)).unwrap_or_else(|e| fail(&format!("cannot read {n}: {e}")));
    let cfg = pki::agent_config(&rd("ca.pem"), &rd("client.pem"), &rd("client.key")).unwrap_or_else(|e| fail(&format!("TLS setup failed: {e}")));

    crate::install_signal_handlers();
    let spool = dir.join("spool.json");
    let mut pending: Vec<AlertMsg> = fs::read_to_string(&spool).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
    if !proc::can_see_all_processes() {
        eprintln!("netwatch agent: not root, process attribution will be incomplete");
    }
    eprintln!("netwatch agent {} -> {} (id {})", env!("CARGO_PKG_VERSION"), af.server, af.host_id);

    let base = Config::default();
    let mut det = Detector::new(base.clone());
    let mut applied = RemoteConfig::default();
    let mut interval: u64 = 10;
    let eph = proc::ephemeral_start();
    let mut link: Option<Link> = None;
    let mut last_report = Instant::now() - Duration::from_secs(3600);
    let mut backoff = 0u32;
    let mut next_try = Instant::now();
    let mut was_down = false;

    while !crate::STOP.load(Ordering::Relaxed) {
        let socks = proc::read_sockets();
        let owners = proc::socket_owners();
        for a in det.tick(&socks, &owners) {
            pending.push(AlertMsg {
                ts: now_secs(),
                kind: a.kind.into(),
                severity: a.severity.name().into(),
                source: a.src.map(|s| s.to_string()),
                message: a.msg,
            });
        }
        if pending.len() > 2000 {
            let excess = pending.len() - 2000;
            pending.drain(..excess);
        }

        let due = last_report.elapsed() >= Duration::from_secs(interval) || !pending.is_empty();
        if due && Instant::now() >= next_try {
            let report = build_report(&socks, &owners, pending.clone(), eph);
            match send_report(&mut link, &af.server, &cfg, &report) {
                Ok(rc) => {
                    if was_down {
                        eprintln!("netwatch agent: reconnected to server");
                        was_down = false;
                    }
                    pending.clear();
                    let _ = fs::remove_file(&spool);
                    last_report = Instant::now();
                    backoff = 0;
                    if let Some(rc) = rc {
                        if rc != applied {
                            det.set_config(apply(&base, &mut interval, &rc));
                            applied = rc;
                        }
                    }
                }
                Err(e) => {
                    if !was_down {
                        eprintln!("netwatch agent: cannot reach server ({e}); buffering alerts, will retry");
                        was_down = true;
                    }
                    backoff = (backoff + 1).min(6);
                    next_try = Instant::now() + Duration::from_secs((2u64 << backoff).min(60));
                    if !pending.is_empty() {
                        persist(&spool, &pending);
                    }
                }
            }
        }

        let mut left = 2.0f64;
        while left > 0.0 && !crate::STOP.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(250));
            left -= 0.25;
        }
    }
    if !pending.is_empty() {
        persist(&spool, &pending);
    }
}

fn persist(path: &Path, pending: &[AlertMsg]) {
    if let Ok(s) = serde_json::to_vec(pending) {
        let _ = write_secret(path, &s);
    }
}
