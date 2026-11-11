//! Attack heuristics evaluated on every poll of /proc.

use crate::proc::{self, Counters, Proto, Sock};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct Config {
    pub window: Duration,
    pub scan_ports: usize,
    pub conn_limit: usize,
    pub rate_limit: usize,
    pub syn_limit: usize,
    pub rst_rate: f64,
    pub cooldown: Duration,
    pub ignore: HashSet<IpAddr>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            window: Duration::from_secs(60),
            scan_ports: 5,
            conn_limit: 100,
            rate_limit: 30,
            syn_limit: 50,
            rst_rate: 100.0,
            cooldown: Duration::from_secs(60),
            ignore: HashSet::new(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Severity {
    Info,
    Medium,
    High,
}

impl Severity {
    pub fn name(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
        }
    }
}

pub struct Alert {
    pub kind: &'static str,
    pub severity: Severity,
    pub src: Option<IpAddr>,
    pub msg: String,
}

type Flow = (IpAddr, u16, u16); // remote ip, remote port, local port

pub struct Detector {
    cfg: Config,
    baseline: Option<HashSet<(Proto, u16)>>,
    known_flows: HashSet<Flow>,
    events: HashMap<IpAddr, VecDeque<(Instant, u16)>>, // new inbound flows: (time, local port)
    last_alert: HashMap<String, Instant>,
    prev: Option<(Instant, Counters)>,
    ephemeral_start: u16,
}

fn service(port: u16) -> Option<&'static str> {
    Some(match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 | 465 | 587 => "SMTP",
        110 | 143 | 993 | 995 => "mail",
        445 => "SMB",
        1433 => "MSSQL",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        5900 => "VNC",
        6379 => "Redis",
        27017 => "MongoDB",
        _ => return None,
    })
}

fn external(ip: &IpAddr) -> bool {
    !(ip.is_unspecified() || ip.is_loopback())
}

impl Detector {
    pub fn new(cfg: Config) -> Self {
        Detector {
            cfg,
            baseline: None,
            known_flows: HashSet::new(),
            events: HashMap::new(),
            last_alert: HashMap::new(),
            prev: None,
            ephemeral_start: proc::ephemeral_start(),
        }
    }

    fn emit(&mut self, out: &mut Vec<Alert>, now: Instant, key: String, a: Alert) {
        if let Some(t) = self.last_alert.get(&key) {
            if now.duration_since(*t) < self.cfg.cooldown {
                return;
            }
        }
        self.last_alert.insert(key, now);
        out.push(a);
    }

    pub fn tick(&mut self, socks: &[Sock], owners: &HashMap<u64, proc::ProcInfo>) -> Vec<Alert> {
        let now = Instant::now();
        let mut alerts = Vec::new();

        // --- new listening ports (after the first snapshot establishes a baseline) ---
        // UDP sockets bound to ephemeral ports are normal client behaviour (QUIC, DNS), not services.
        let eph = self.ephemeral_start;
        let listeners: HashSet<(Proto, u16)> = socks
            .iter()
            .filter(|s| s.is_listening() && !(s.proto == Proto::Udp && s.lport >= eph))
            .map(|s| (s.proto, s.lport))
            .collect();
        match &self.baseline {
            None => {}
            Some(base) => {
                let mut fresh: Vec<_> = listeners.difference(base).copied().collect();
                fresh.sort_by_key(|(_, p)| *p);
                for (proto, port) in fresh {
                    let who = socks
                        .iter()
                        .find(|s| s.is_listening() && s.proto == proto && s.lport == port)
                        .and_then(|s| owners.get(&s.inode))
                        .map(|p| format!("{} (pid {})", p.name, p.pid))
                        .unwrap_or_else(|| "unknown process".into());
                    let exposed = socks.iter().any(|s| {
                        s.is_listening() && s.lport == port && !s.local.is_loopback()
                    });
                    self.emit(
                        &mut alerts,
                        now,
                        format!("newlisten:{}:{port}", proto.name()),
                        Alert {
                            kind: "NEW_LISTENER",
                            severity: if exposed { Severity::High } else { Severity::Info },
                            src: None,
                            msg: format!(
                                "new {} listener on port {port} opened by {who}{}",
                                proto.name(),
                                if exposed { " (reachable externally)" } else { "" }
                            ),
                        },
                    );
                }
            }
        }
        if let Some(base) = &mut self.baseline {
            // Track closures so a re-opened port is reported again, but never shrink silently.
            base.extend(listeners.iter().copied());
        } else {
            self.baseline = Some(listeners.clone());
        }

        // --- inbound TCP flow bookkeeping ---
        let tcp_listen_ports: HashSet<u16> = socks
            .iter()
            .filter(|s| s.proto == Proto::Tcp && s.state == proc::LISTEN)
            .map(|s| s.lport)
            .collect();

        let mut current: HashSet<Flow> = HashSet::new();
        let mut per_ip_now: HashMap<IpAddr, usize> = HashMap::new();
        let mut syn_recv = 0usize;
        for s in socks.iter().filter(|s| s.proto == Proto::Tcp) {
            if s.state == proc::SYN_RECV {
                syn_recv += 1;
            }
            let inbound = tcp_listen_ports.contains(&s.lport) || s.state == proc::SYN_RECV;
            if !inbound || s.state == proc::LISTEN || !external(&s.remote) {
                continue;
            }
            if self.cfg.ignore.contains(&s.remote) {
                continue;
            }
            let flow = (s.remote, s.rport, s.lport);
            current.insert(flow);
            *per_ip_now.entry(s.remote).or_default() += 1;
            if !self.known_flows.contains(&flow) {
                self.events.entry(s.remote).or_default().push_back((now, s.lport));
            }
        }
        self.known_flows = current;

        let window = self.cfg.window;
        self.events.retain(|_, q| {
            while q.front().map_or(false, |(t, _)| now.duration_since(*t) > window) {
                q.pop_front();
            }
            !q.is_empty()
        });

        let mut ips: Vec<IpAddr> = self.events.keys().copied().collect();
        ips.sort();
        for ip in ips {
            let q = self.events[&ip].clone();
            let ports: HashSet<u16> = q.iter().map(|(_, p)| *p).collect();
            let n = q.len();
            let secs = self.cfg.window.as_secs();
            if ports.len() >= self.cfg.scan_ports {
                let mut p: Vec<_> = ports.iter().copied().collect();
                p.sort();
                self.emit(
                    &mut alerts,
                    now,
                    format!("scan:{ip}"),
                    Alert {
                        kind: "PORT_SCAN",
                        severity: Severity::High,
                        src: Some(ip),
                        msg: format!(
                            "{ip} touched {} distinct local ports in {secs}s: {}",
                            p.len(),
                            p.iter().take(15).map(|x| x.to_string()).collect::<Vec<_>>().join(",")
                        ),
                    },
                );
            }
            if n >= self.cfg.rate_limit {
                // Most-hit local port decides the label.
                let mut counts: HashMap<u16, usize> = HashMap::new();
                for (_, p) in &q {
                    *counts.entry(*p).or_default() += 1;
                }
                let (&top, &hits) = counts.iter().max_by_key(|(p, c)| (**c, **p)).unwrap();
                let (kind, msg) = match service(top) {
                    Some(svc) => (
                        "BRUTE_FORCE",
                        format!("{ip} opened {hits} connections to {svc} (port {top}) in {secs}s: possible password guessing"),
                    ),
                    None => (
                        "CONN_BURST",
                        format!("{ip} opened {n} new connections in {secs}s (most to port {top})"),
                    ),
                };
                self.emit(
                    &mut alerts,
                    now,
                    format!("rate:{ip}"),
                    Alert { kind, severity: Severity::High, src: Some(ip), msg },
                );
            }
        }

        let mut floods: Vec<_> = per_ip_now
            .iter()
            .filter(|(_, c)| **c >= self.cfg.conn_limit)
            .map(|(ip, c)| (*ip, *c))
            .collect();
        floods.sort();
        for (ip, c) in floods {
            self.emit(
                &mut alerts,
                now,
                format!("flood:{ip}"),
                Alert {
                    kind: "CONN_FLOOD",
                    severity: Severity::High,
                    src: Some(ip),
                    msg: format!("{ip} currently holds {c} inbound connections"),
                },
            );
        }

        if syn_recv >= self.cfg.syn_limit {
            self.emit(
                &mut alerts,
                now,
                "synflood".into(),
                Alert {
                    kind: "SYN_FLOOD",
                    severity: Severity::High,
                    src: None,
                    msg: format!("{syn_recv} half-open connections (SYN_RECV): possible SYN flood"),
                },
            );
        }

        // --- kernel counter deltas ---
        let c = proc::read_counters();
        if let Some((pt, p)) = self.prev.take() {
            let dt = now.duration_since(pt).as_secs_f64().max(0.001);
            let rst = c.out_rsts.saturating_sub(p.out_rsts) as f64 / dt;
            if rst >= self.cfg.rst_rate {
                self.emit(
                    &mut alerts,
                    now,
                    "rst".into(),
                    Alert {
                        kind: "RST_STORM",
                        severity: Severity::Medium,
                        src: None,
                        msg: format!("{rst:.0} TCP resets/s sent: likely scan of closed ports (packets that never create a socket)"),
                    },
                );
            }
            let drops = c.listen_drops.saturating_sub(p.listen_drops)
                + c.listen_overflows.saturating_sub(p.listen_overflows);
            if drops > 0 {
                self.emit(
                    &mut alerts,
                    now,
                    "listendrop".into(),
                    Alert {
                        kind: "LISTEN_OVERFLOW",
                        severity: Severity::Medium,
                        src: None,
                        msg: format!("{drops} connection attempts dropped: accept queue full (flood or overloaded service)"),
                    },
                );
            }
            let cookies = c.syncookies_sent.saturating_sub(p.syncookies_sent);
            if cookies > 0 {
                self.emit(
                    &mut alerts,
                    now,
                    "syncookies".into(),
                    Alert {
                        kind: "SYN_COOKIES",
                        severity: Severity::High,
                        src: None,
                        msg: format!("kernel sent {cookies} SYN cookies: SYN backlog overflowed (SYN flood)"),
                    },
                );
            }
        }
        self.prev = Some((now, c));

        alerts
    }
}
