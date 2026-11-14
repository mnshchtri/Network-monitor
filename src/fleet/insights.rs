//! Analysis that turns raw socket snapshots into answers: what is exposed, who is talking to us,
//! and how risky is each service. Pure functions over database rows so they are easy to test.

use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// "ip:port" as the agent formats it (IPv6 is not bracketed, so split at the LAST colon).
pub fn split_hostport(s: &str) -> Option<(&str, u16)> {
    let (h, p) = s.rsplit_once(':')?;
    Some((h.trim_matches(|c| c == '[' || c == ']'), p.parse().ok()?))
}

/// Loopback, private (RFC 1918), link-local, CGNAT and unique-local addresses: "not the internet".
pub fn is_internal(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => {
            let o = a.octets();
            a.is_loopback() || a.is_private() || a.is_link_local() || (o[0] == 100 && (64..128).contains(&o[1])) || a.is_unspecified()
        }
        Ok(IpAddr::V6(a)) => {
            let s = a.segments();
            a.is_loopback() || a.is_unspecified() || (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80
        }
        Err(_) => false,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Risk {
    Info = 0,
    Medium = 1,
    High = 2,
}

pub struct Svc {
    pub name: &'static str,
    pub risk: Risk,
    pub why: &'static str,
}

/// Well-known services and how worrying it is to find them reachable from the network.
pub fn service(port: u16) -> Option<Svc> {
    use Risk::*;
    let (name, risk, why) = match port {
        21 => ("FTP", High, "sends credentials and data in clear text"),
        22 => ("SSH", Info, "expected for administration; keep it key-only and rate-limited"),
        23 => ("Telnet", High, "clear-text remote login; replace with SSH"),
        25 => ("SMTP", Info, "mail transfer"),
        53 => ("DNS", Info, "name resolution"),
        80 => ("HTTP", Info, "web, unencrypted"),
        110 => ("POP3", Medium, "mail retrieval, usually clear text"),
        111 => ("rpcbind", Medium, "RPC portmapper, often abused for amplification"),
        135 | 139 => ("NetBIOS/RPC", High, "Windows file sharing and RPC; frequent attack target"),
        143 => ("IMAP", Medium, "mail retrieval, often clear text"),
        161 => ("SNMP", Medium, "device management; weak community strings are common"),
        389 => ("LDAP", Medium, "directory service, clear text unless TLS"),
        443 => ("HTTPS", Info, "web over TLS"),
        445 => ("SMB", High, "Windows file sharing; frequent ransomware entry point"),
        512..=514 => ("r-services", High, "legacy remote shell with weak authentication"),
        631 => ("CUPS", Medium, "print service; rarely needs to be reachable"),
        873 => ("rsync", Medium, "file sync, often unauthenticated"),
        1433 => ("MS SQL", High, "database should not be directly reachable"),
        1521 => ("Oracle DB", High, "database should not be directly reachable"),
        2049 => ("NFS", Medium, "network file system"),
        2375 => ("Docker API", High, "unauthenticated Docker API means full host takeover"),
        3306 => ("MySQL", High, "database should not be directly reachable"),
        3389 => ("RDP", High, "remote desktop; heavily brute-forced"),
        5432 => ("PostgreSQL", High, "database should not be directly reachable"),
        5900..=5902 => ("VNC", High, "remote desktop with weak authentication"),
        5984 => ("CouchDB", High, "database should not be directly reachable"),
        6379 => ("Redis", High, "usually unauthenticated; remote code execution is well known"),
        8080 | 8000 | 8888 => ("HTTP alt", Info, "web service on an alternative port"),
        8443 => ("HTTPS alt", Info, "web over TLS on an alternative port"),
        9200 | 9300 => ("Elasticsearch", High, "often unauthenticated; frequent data-leak source"),
        11211 => ("Memcached", High, "unauthenticated; used for DDoS amplification"),
        27017 => ("MongoDB", High, "database should not be directly reachable"),
        _ => return None,
    };
    Some(Svc { name, risk, why })
}

pub struct Listener {
    pub host_id: String,
    pub host: String,
    pub proto: String,
    pub addr: String,
    pub port: u16,
    pub process: String,
    pub user: String,
    pub first_seen: u64,
}

/// "loopback" (only this machine), "any" (all interfaces) or "specific" (one address).
pub fn scope(addr: &str) -> &'static str {
    match addr.parse::<IpAddr>() {
        Ok(a) if a.is_loopback() => "loopback",
        Ok(a) if a.is_unspecified() => "any",
        _ => "specific",
    }
}

fn scope_rank(s: &str) -> u8 {
    match s {
        "any" => 2,
        "specific" => 1,
        _ => 0,
    }
}

/// Group listeners by port across the fleet. Returns (groups, summary).
pub fn exposure(rows: &[Listener], now: u64) -> (Vec<Value>, Value) {
    // One entry per (host, proto, port): the same port bound on 0.0.0.0 and :: is one exposure.
    let mut per_host: HashMap<(String, String, u16), &Listener> = HashMap::new();
    for l in rows {
        let key = (l.host_id.clone(), l.proto.clone(), l.port);
        match per_host.get(&key) {
            Some(prev) if scope_rank(scope(&prev.addr)) >= scope_rank(scope(&l.addr)) => {}
            _ => {
                per_host.insert(key, l);
            }
        }
    }
    let mut groups: HashMap<(String, u16), Vec<&Listener>> = HashMap::new();
    for l in per_host.values() {
        groups.entry((l.proto.clone(), l.port)).or_default().push(l);
    }
    let (mut total, mut exposed, mut risky, mut new24) = (0u32, 0u32, 0u32, 0u32);
    let mut out: Vec<(Risk, u32, Value)> = Vec::new();
    for ((proto, port), mut hosts) in groups {
        hosts.sort_by(|a, b| a.host.cmp(&b.host));
        let svc = service(port);
        let mut hv = Vec::new();
        let mut exp_here = 0u32;
        for l in &hosts {
            total += 1;
            let sc = scope(&l.addr);
            let is_exposed = sc != "loopback";
            let is_new = is_exposed && l.first_seen + 86400 > now;
            if is_exposed {
                exposed += 1;
                exp_here += 1;
                if svc.as_ref().map_or(false, |s| s.risk == Risk::High) {
                    risky += 1;
                }
            }
            if is_new {
                new24 += 1;
            }
            hv.push(json!({"host_id": l.host_id, "host": l.host, "addr": l.addr, "scope": sc, "internal_addr": sc == "specific" && is_internal(&l.addr),
                           "process": l.process, "user": l.user, "first_seen": l.first_seen, "new": is_new}));
        }
        let risk = if exp_here > 0 { svc.as_ref().map(|s| s.risk).unwrap_or(Risk::Info) } else { Risk::Info };
        out.push((risk, exp_here, json!({
            "port": port, "proto": proto, "service": svc.as_ref().map(|s| s.name), "why": svc.as_ref().map(|s| s.why),
            "risk": risk as u8, "exposed_hosts": exp_here, "hosts": hv,
        })));
    }
    // Riskiest first, then widest exposure, then port number.
    out.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)).then_with(|| a.2["port"].as_u64().cmp(&b.2["port"].as_u64())));
    (out.into_iter().map(|x| x.2).collect(), json!({"listeners": total, "exposed": exposed, "risky": risky, "new24h": new24}))
}

pub struct ConnRow {
    pub host_id: String,
    pub host: String,
    pub proto: String,
    pub state: String,
    pub local: String,
    pub remote: String,
    pub process: String,
}

#[derive(Default)]
struct Peer {
    inbound: u32,
    outbound: u32,
    hosts: HashSet<String>,
    local_ports: HashSet<u16>,
    remote_ports: HashSet<u16>,
}

/// Aggregate the latest connection snapshots into "who is talking to what".
pub fn traffic(conns: &[ConnRow], listen_ports: &HashMap<String, HashSet<u16>>) -> Value {
    let mut peers: HashMap<String, Peer> = HashMap::new();
    let mut ports_in: HashMap<u16, u32> = HashMap::new();
    let mut procs: HashMap<String, u32> = HashMap::new();
    let mut states: HashMap<String, u32> = HashMap::new();
    let mut per_host: HashMap<String, (String, u32, u32)> = HashMap::new();
    for c in conns {
        let (Some((rip, rport)), Some((_, lport))) = (split_hostport(&c.remote), split_hostport(&c.local)) else { continue };
        *states.entry(c.state.clone()).or_default() += 1;
        if c.process != "-" && !c.process.is_empty() {
            *procs.entry(c.process.clone()).or_default() += 1;
        }
        let inbound = listen_ports.get(&c.host_id).map_or(false, |p| p.contains(&lport));
        let ph = per_host.entry(c.host_id.clone()).or_insert((c.host.clone(), 0, 0));
        if inbound { ph.1 += 1 } else { ph.2 += 1 }
        // Wildcard remotes and loopback peers (a host talking to itself) are not network traffic.
        if rip == "0.0.0.0" || rip == "::" || rip.is_empty() || rport == 0 || rip.parse::<IpAddr>().map_or(false, |a| a.is_loopback()) {
            continue;
        }
        let p = peers.entry(rip.to_string()).or_default();
        p.hosts.insert(c.host.clone());
        if inbound {
            p.inbound += 1;
            p.local_ports.insert(lport);
            *ports_in.entry(lport).or_default() += 1;
        } else {
            p.outbound += 1;
            p.remote_ports.insert(rport);
        }
    }
    let top = |inbound: bool, n: usize| -> Vec<Value> {
        let mut v: Vec<(&String, &Peer)> = peers.iter().filter(|(_, p)| if inbound { p.inbound > 0 } else { p.outbound > 0 }).collect();
        v.sort_by(|a, b| {
            let (ka, kb) = if inbound { (a.1.inbound, b.1.inbound) } else { (a.1.outbound, b.1.outbound) };
            kb.cmp(&ka).then_with(|| a.0.cmp(b.0))
        });
        v.into_iter().take(n).map(|(ip, p)| {
            let mut ports: Vec<u16> = if inbound { p.local_ports.iter().copied().collect() } else { p.remote_ports.iter().copied().collect() };
            ports.sort();
            let mut hosts: Vec<&String> = p.hosts.iter().collect();
            hosts.sort();
            json!({"ip": ip, "count": if inbound { p.inbound } else { p.outbound }, "internal": is_internal(ip),
                   "ports": ports.iter().take(8).collect::<Vec<_>>(), "port_count": ports.len(), "hosts": hosts})
        }).collect()
    };
    let mut pin: Vec<(u16, u32)> = ports_in.into_iter().collect();
    pin.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let mut pr: Vec<(String, u32)> = procs.into_iter().collect();
    pr.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let mut st: Vec<(String, u32)> = states.into_iter().collect();
    st.sort_by(|a, b| b.1.cmp(&a.1));
    let mut hosts: Vec<(String, u32, u32)> = per_host.into_values().collect();
    hosts.sort_by(|a, b| (b.1 + b.2).cmp(&(a.1 + a.2)));
    json!({
        "total": conns.len(),
        "top_inbound": top(true, 15),
        "top_outbound": top(false, 12),
        "inbound_ports": pin.iter().take(10).map(|(p, n)| json!({"port": p, "count": n, "service": service(*p).map(|s| s.name)})).collect::<Vec<_>>(),
        "processes": pr.iter().take(10).map(|(p, n)| json!({"process": p, "count": n})).collect::<Vec<_>>(),
        "states": st.iter().map(|(s, n)| json!({"state": s, "count": n})).collect::<Vec<_>>(),
        "hosts": hosts.iter().map(|(h, i, o)| json!({"host": h, "inbound": i, "outbound": o})).collect::<Vec<_>>(),
    })
}

/// Only IP-literal characters: safe to embed in a LIKE pattern and to show in suggested commands.
pub fn valid_ip(s: &str) -> bool {
    !s.is_empty() && s.len() <= 45 && s.parse::<IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostport_and_internal() {
        assert_eq!(split_hostport("192.168.1.5:443"), Some(("192.168.1.5", 443)));
        assert_eq!(split_hostport("2400:1a00:6b41:c5dd::11:34418"), Some(("2400:1a00:6b41:c5dd::11", 34418)));
        assert_eq!(split_hostport("[::1]:80"), Some(("::1", 80)));
        assert_eq!(split_hostport("nonsense"), None);
        for ip in ["10.1.2.3", "172.16.0.1", "172.31.255.1", "192.168.0.9", "127.0.0.1", "169.254.1.1", "100.64.0.1", "::1", "fd00::1", "fe80::1"] {
            assert!(is_internal(ip), "{ip} should be internal");
        }
        for ip in ["8.8.8.8", "172.32.0.1", "100.128.0.1", "2607:6bc0::10", "203.0.113.9"] {
            assert!(!is_internal(ip), "{ip} should be external");
        }
        assert!(valid_ip("203.0.113.9") && valid_ip("2001:db8::1") && !valid_ip("1.2.3.4' OR 1=1") && !valid_ip("%") && !valid_ip(""));
    }

    #[test]
    fn scopes_and_services() {
        assert_eq!(scope("127.0.0.53"), "loopback");
        assert_eq!(scope("::1"), "loopback");
        assert_eq!(scope("0.0.0.0"), "any");
        assert_eq!(scope("::"), "any");
        assert_eq!(scope("192.168.1.10"), "specific");
        assert_eq!(service(3306).unwrap().risk, Risk::High);
        assert_eq!(service(22).unwrap().risk, Risk::Info);
        assert!(service(54321).is_none());
    }

    fn l(host: &str, addr: &str, port: u16, seen: u64) -> Listener {
        Listener { host_id: host.into(), host: host.into(), proto: "tcp".into(), addr: addr.into(), port, process: "p".into(), user: "u".into(), first_seen: seen }
    }

    #[test]
    fn exposure_groups_dedupes_and_ranks() {
        let now = 1_000_000;
        let rows = vec![
            l("web1", "0.0.0.0", 3306, 10), l("web1", "::", 3306, 10), // same exposure on v4 + v6
            l("db1", "127.0.0.1", 3306, 10),                            // loopback only: not exposed
            l("web1", "0.0.0.0", 22, 10), l("db1", "0.0.0.0", 22, now - 100), // ssh, one of them new
            l("web1", "0.0.0.0", 40000, 10),                            // unknown service
        ];
        let (groups, sum) = exposure(&rows, now);
        assert_eq!(sum["listeners"], 5, "v4+v6 of the same port is one listener");
        assert_eq!(sum["exposed"], 4);
        assert_eq!(sum["risky"], 1, "only web1's mysql is exposed AND high-risk");
        assert_eq!(sum["new24h"], 1);
        assert_eq!(groups[0]["port"], 3306, "riskiest first");
        assert_eq!(groups[0]["exposed_hosts"], 1);
        assert_eq!(groups[0]["hosts"].as_array().unwrap().len(), 2);
        let mysql_loop = groups[0]["hosts"].as_array().unwrap().iter().find(|h| h["host"] == "db1").unwrap();
        assert_eq!(mysql_loop["scope"], "loopback");
    }

    #[test]
    fn traffic_direction_and_ranking() {
        let mut lp: HashMap<String, HashSet<u16>> = HashMap::new();
        lp.insert("h1".into(), [22u16, 443].into_iter().collect());
        let c = |state: &str, local: &str, remote: &str, p: &str| ConnRow { host_id: "h1".into(), host: "h1".into(), proto: "tcp".into(), state: state.into(), local: local.into(), remote: remote.into(), process: p.into() };
        let rows = vec![
            c("ESTABLISHED", "10.0.0.5:22", "203.0.113.9:50001", "sshd"), c("ESTABLISHED", "10.0.0.5:22", "203.0.113.9:50002", "sshd"),
            c("SYN_RECV", "10.0.0.5:443", "203.0.113.9:50003", "-"), c("ESTABLISHED", "10.0.0.5:443", "198.51.100.1:4000", "nginx"),
            c("ESTABLISHED", "10.0.0.5:40000", "93.184.216.34:443", "curl"),
            c("ESTABLISHED", "127.0.0.1:443", "127.0.0.1:50999", "nginx"), c("ESTABLISHED", "::1:22", "::1:50998", "sshd"),
        ];
        let t = traffic(&rows, &lp);
        assert_eq!(t["top_inbound"][0]["ip"], "203.0.113.9");
        assert_eq!(t["top_inbound"][0]["count"], 3);
        assert_eq!(t["top_inbound"][0]["port_count"], 2, "touched both 22 and 443");
        assert_eq!(t["top_outbound"][0]["ip"], "93.184.216.34");
        assert_eq!(t["inbound_ports"][0]["port"], 22);
        assert_eq!(t["inbound_ports"][0]["service"], "SSH");
        assert_eq!(t["hosts"][0]["inbound"], 6, "4 external + 2 loopback still count as host load");
        assert_eq!(t["hosts"][0]["outbound"], 1);
        assert_eq!(t["processes"][0]["process"], "sshd");
        let ips: Vec<&str> = t["top_inbound"].as_array().unwrap().iter().chain(t["top_outbound"].as_array().unwrap()).map(|x| x["ip"].as_str().unwrap()).collect();
        assert!(!ips.iter().any(|i| i.starts_with("127.") || *i == "::1"), "loopback peers must not be listed: {ips:?}");
        assert_eq!(t["total"], 7, "loopback connections still count towards totals");
    }
}
