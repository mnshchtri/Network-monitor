//! Wire protocol: newline-delimited JSON over mutually authenticated TLS.

use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, Write};

/// Hard cap on a single message (a full report is far smaller).
pub const MAX_MSG: usize = 4 * 1024 * 1024;

#[derive(Serialize, Deserialize, Debug)]
pub enum Request {
    /// First contact: exchange a one-time token + CSR for a client certificate.
    Enroll { token: String, hostname: String, csr_pem: String },
    Report(Report),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Response {
    Enrolled { host_id: String, cert_pem: String, ca_pem: String },
    Ack { config: Option<RemoteConfig> },
    Error { message: String },
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Report {
    pub hostname: String,
    pub os: String,
    pub version: String,
    pub ts: u64,
    pub root: bool,
    pub listeners: Vec<Listener>,
    pub conns: Vec<Conn>,
    pub stats: Stats,
    pub alerts: Vec<AlertMsg>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Listener {
    pub proto: String,
    pub addr: String,
    pub port: u16,
    pub pid: Option<u32>,
    pub process: Option<String>,
    pub user: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Conn {
    pub proto: String,
    pub state: String,
    pub local: String,
    pub remote: String,
    pub pid: Option<u32>,
    pub process: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Stats {
    pub total: u32,
    pub established: u32,
    pub syn_recv: u32,
    pub time_wait: u32,
    pub listeners: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AlertMsg {
    pub ts: u64,
    pub kind: String,
    pub severity: String,
    pub source: Option<String>,
    pub message: String,
}

/// Settings the server pushes to agents (all optional; absent = keep current).
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct RemoteConfig {
    pub report_interval: Option<u64>,
    pub window: Option<u64>,
    pub scan_ports: Option<usize>,
    pub rate_limit: Option<usize>,
    pub conn_limit: Option<usize>,
    pub syn_limit: Option<usize>,
    pub rst_rate: Option<f64>,
    pub ignore: Option<Vec<String>>,
}

pub fn send<W: Write, T: Serialize>(w: &mut W, msg: &T) -> io::Result<()> {
    let mut line = serde_json::to_vec(msg).map_err(io::Error::other)?;
    if line.len() > MAX_MSG {
        return Err(io::Error::other("message too large"));
    }
    line.push(b'\n');
    w.write_all(&line)?;
    w.flush()
}

/// Read one message. Returns Ok(None) on clean EOF. Enforces MAX_MSG while reading so a
/// malicious peer cannot make us buffer unbounded data.
pub fn recv<R: BufRead, T: for<'a> Deserialize<'a>>(r: &mut R) -> io::Result<Option<T>> {
    let mut buf = Vec::new();
    loop {
        let chunk = r.fill_buf()?;
        if chunk.is_empty() {
            return if buf.is_empty() { Ok(None) } else { Err(io::ErrorKind::UnexpectedEof.into()) };
        }
        match chunk.iter().position(|b| *b == b'\n') {
            Some(i) => {
                buf.extend_from_slice(&chunk[..i]);
                r.consume(i + 1);
                break;
            }
            None => {
                let n = chunk.len();
                buf.extend_from_slice(chunk);
                r.consume(n);
            }
        }
        if buf.len() > MAX_MSG {
            return Err(io::Error::other("message too large"));
        }
    }
    if buf.len() > MAX_MSG {
        return Err(io::Error::other("message too large"));
    }
    serde_json::from_slice(&buf).map(Some).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}
