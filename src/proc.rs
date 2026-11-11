//! Reads socket and process information straight from /proc (no external deps).

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn name(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

pub const LISTEN: u8 = 0x0A;
pub const SYN_RECV: u8 = 0x03;

#[derive(Clone, Debug)]
pub struct Sock {
    pub proto: Proto,
    pub local: IpAddr,
    pub lport: u16,
    pub remote: IpAddr,
    pub rport: u16,
    pub state: u8,
    pub uid: u32,
    pub inode: u64,
}

impl Sock {
    pub fn state_name(&self) -> &'static str {
        if self.proto == Proto::Udp {
            return if self.state == 0x07 { "UNCONN" } else { "ESTAB" };
        }
        match self.state {
            0x01 => "ESTABLISHED",
            0x02 => "SYN_SENT",
            0x03 => "SYN_RECV",
            0x04 => "FIN_WAIT1",
            0x05 => "FIN_WAIT2",
            0x06 => "TIME_WAIT",
            0x07 => "CLOSE",
            0x08 => "CLOSE_WAIT",
            0x09 => "LAST_ACK",
            0x0A => "LISTEN",
            0x0B => "CLOSING",
            _ => "UNKNOWN",
        }
    }

    pub fn is_listening(&self) -> bool {
        match self.proto {
            Proto::Tcp => self.state == LISTEN,
            Proto::Udp => self.state == 0x07 && self.rport == 0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProcInfo {
    pub pid: u32,
    pub name: String,
}

fn parse_addr(s: &str) -> Option<(IpAddr, u16)> {
    let (ip, port) = s.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let addr = match ip.len() {
        8 => {
            let v = u32::from_str_radix(ip, 16).ok()?;
            IpAddr::V4(Ipv4Addr::from(v.to_le_bytes()))
        }
        32 => {
            let mut b = [0u8; 16];
            for i in 0..4 {
                let w = u32::from_str_radix(&ip[i * 8..i * 8 + 8], 16).ok()?;
                b[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
            }
            let v6 = Ipv6Addr::from(b);
            match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(v6),
            }
        }
        _ => return None,
    };
    Some((addr, port))
}

fn read_table(path: &str, proto: Proto, out: &mut Vec<Sock>) {
    let Ok(text) = fs::read_to_string(path) else { return };
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let (Some((local, lport)), Some((remote, rport))) = (parse_addr(f[1]), parse_addr(f[2]))
        else {
            continue;
        };
        let Ok(state) = u8::from_str_radix(f[3], 16) else { continue };
        out.push(Sock {
            proto,
            local,
            lport,
            remote,
            rport,
            state,
            uid: f[7].parse().unwrap_or(0),
            inode: f[9].parse().unwrap_or(0),
        });
    }
}

pub fn read_sockets() -> Vec<Sock> {
    let mut v = Vec::new();
    read_table("/proc/net/tcp", Proto::Tcp, &mut v);
    read_table("/proc/net/tcp6", Proto::Tcp, &mut v);
    read_table("/proc/net/udp", Proto::Udp, &mut v);
    read_table("/proc/net/udp6", Proto::Udp, &mut v);
    v
}

/// Map socket inode -> owning process (what lsof does). Needs root to see all processes.
pub fn socket_owners() -> HashMap<u64, ProcInfo> {
    let mut map = HashMap::new();
    let Ok(dir) = fs::read_dir("/proc") else { return map };
    for e in dir.flatten() {
        let fname = e.file_name();
        let Some(pid) = fname.to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
        let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else { continue };
        let mut name: Option<String> = None;
        for fd in fds.flatten() {
            let Ok(link) = fs::read_link(fd.path()) else { continue };
            let Some(l) = link.to_str() else { continue };
            let Some(inode) = l.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) else {
                continue;
            };
            let Ok(inode) = inode.parse::<u64>() else { continue };
            let n = name.get_or_insert_with(|| {
                fs::read_to_string(format!("/proc/{pid}/comm"))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|_| "?".into())
            });
            map.insert(inode, ProcInfo { pid, name: n.clone() });
        }
    }
    map
}

pub fn can_see_all_processes() -> bool {
    fs::read_dir("/proc/1/fd").is_ok()
}

/// Parse a pair of "Name: field field..." / "Name: value value..." lines.
fn kernel_counters(path: &str, section: &str) -> HashMap<String, u64> {
    let mut m = HashMap::new();
    let Ok(text) = fs::read_to_string(path) else { return m };
    let prefix = format!("{section}:");
    let lines: Vec<&str> = text.lines().filter(|l| l.starts_with(&prefix)).collect();
    if lines.len() >= 2 {
        for (k, v) in lines[0].split_whitespace().skip(1).zip(lines[1].split_whitespace().skip(1)) {
            if let Ok(n) = v.parse::<i64>() {
                m.insert(k.to_string(), n.max(0) as u64);
            }
        }
    }
    m
}

pub struct Counters {
    pub out_rsts: u64,
    pub listen_drops: u64,
    pub listen_overflows: u64,
    pub syncookies_sent: u64,
}

pub fn read_counters() -> Counters {
    let tcp = kernel_counters("/proc/net/snmp", "Tcp");
    let ext = kernel_counters("/proc/net/netstat", "TcpExt");
    let g = |m: &HashMap<String, u64>, k: &str| m.get(k).copied().unwrap_or(0);
    Counters {
        out_rsts: g(&tcp, "OutRsts"),
        listen_drops: g(&ext, "ListenDrops"),
        listen_overflows: g(&ext, "ListenOverflows"),
        syncookies_sent: g(&ext, "SyncookiesSent"),
    }
}

pub fn uid_name(uid: u32) -> String {
    if let Ok(t) = fs::read_to_string("/etc/passwd") {
        for l in t.lines() {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() > 2 && f[2].parse::<u32>().ok() == Some(uid) {
                return f[0].to_string();
            }
        }
    }
    uid.to_string()
}

/// First port of the kernel's ephemeral range (default 32768).
pub fn ephemeral_start() -> u16 {
    fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .ok()
        .and_then(|t| t.split_whitespace().next().and_then(|n| n.parse().ok()))
        .unwrap_or(32768)
}
