//! Alert delivery to a webhook (Slack, Discord or generic JSON) over http/https.
//! Minimal HTTP/1.1 client on std + rustls; bundled root CAs so it works on any server.

use super::db;
use super::util::*;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct Notification {
    pub host: String,
    pub ts: u64,
    pub kind: String,
    pub severity: String,
    pub source: Option<String>,
    pub message: String,
}

fn rank(sev: &str) -> u8 {
    match sev {
        "HIGH" => 3,
        "MEDIUM" => 2,
        _ => 1,
    }
}

pub struct Url {
    pub https: bool,
    pub host: String,
    pub port: u16,
    pub path: String,
}

pub fn parse_url(u: &str) -> Result<Url, String> {
    let (https, rest) = if let Some(r) = u.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = u.strip_prefix("http://") {
        (false, r)
    } else {
        return Err("webhook URL must start with http:// or https://".into());
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains('@') || u.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("invalid webhook URL".into());
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            (h.trim_matches(|c| c == '[' || c == ']').to_string(), p.parse().map_err(|_| "bad port")?)
        }
        _ => (authority.to_string(), if https { 443 } else { 80 }),
    };
    Ok(Url { https, host, port, path: path.to_string() })
}

/// Safe-to-display form (the path usually contains the secret token).
pub fn mask(u: &str) -> String {
    match parse_url(u) {
        Ok(p) => format!("{}://{}/…", if p.https { "https" } else { "http" }, p.host),
        Err(_) => "(invalid)".into(),
    }
}

fn tls_config() -> Arc<ClientConfig> {
    let roots = RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    Arc::new(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// POST a JSON body. Ok if the endpoint answers 2xx.
pub fn post(url: &str, body: &str) -> Result<(), String> {
    let u = parse_url(url)?;
    let addr = (u.host.as_str(), u.port)
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {}: {e}", u.host))?
        .next()
        .ok_or("no address")?;
    let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(10)).map_err(|e| format!("connect: {e}"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(15))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(15))).ok();
    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: netwatch/{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        u.path, u.host, env!("CARGO_PKG_VERSION"), body.len(), body
    );
    let mut resp = Vec::new();
    let mut read_some = |r: &mut dyn Read| {
        let mut buf = [0u8; 4096];
        while resp.len() < 16384 {
            match r.read(&mut buf) {
                Ok(0) | Err(_) => break, // close_notify omissions are harmless here
                Ok(n) => resp.extend_from_slice(&buf[..n]),
            }
        }
    };
    if u.https {
        let name = ServerName::try_from(u.host.clone()).map_err(|e| format!("bad host: {e}"))?;
        let conn = rustls::ClientConnection::new(tls_config(), name).map_err(|e| e.to_string())?;
        let mut tls = rustls::StreamOwned::new(conn, tcp);
        tls.write_all(req.as_bytes()).map_err(|e| format!("send: {e}"))?;
        read_some(&mut tls);
    } else {
        let mut tcp = tcp;
        tcp.write_all(req.as_bytes()).map_err(|e| format!("send: {e}"))?;
        read_some(&mut tcp);
    }
    let text = String::from_utf8_lossy(&resp);
    let status: u16 = text.split_whitespace().nth(1).and_then(|s| s.parse().ok()).ok_or("no HTTP response")?;
    if (200..300).contains(&status) { Ok(()) } else { Err(format!("endpoint returned HTTP {status}")) }
}

fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

fn line(n: &Notification) -> String {
    let src = n.source.as_deref().map(|s| format!(" [{s}]")).unwrap_or_default();
    format!("[{}] {} on {}: {}{}", n.severity, n.kind, n.host, n.message, src)
}

/// Build the request body for a batch. `format`: slack | discord | generic.
pub fn body(format: &str, batch: &[Notification]) -> String {
    match format {
        "slack" | "discord" => {
            let mut text = batch.iter().map(line).collect::<Vec<_>>().join("\n");
            let (key, limit) = if format == "slack" { ("text", 35000) } else { ("content", 1900) };
            if text.chars().count() > limit {
                text = text.chars().take(limit - 20).collect::<String>() + "\n…(truncated)";
            }
            format!("{{\"{key}\":{}}}", json_str(&text))
        }
        _ => {
            let alerts: Vec<serde_json::Value> = batch
                .iter()
                .map(|n| {
                    serde_json::json!({"time": fmt_time(n.ts), "host": n.host, "severity": n.severity,
                        "type": n.kind, "source": n.source, "message": n.message})
                })
                .collect();
            serde_json::json!({"source": "netwatch", "alerts": alerts}).to_string()
        }
    }
}

pub fn detect_format(url: &str) -> &'static str {
    if url.contains("hooks.slack.com") {
        "slack"
    } else if url.contains("discord.com/api/webhooks") || url.contains("discordapp.com/api/webhooks") {
        "discord"
    } else {
        "generic"
    }
}

pub fn effective_format(c: &rusqlite::Connection, url: &str) -> String {
    db::get_setting(c, "webhook_format").ok().flatten().filter(|f| f != "auto").unwrap_or_else(|| detect_format(url).into())
}

/// Start the delivery worker. Alerts are queued (bounded) so a slow or dead endpoint can never
/// stall agent ingestion.
pub fn spawn(db_path: PathBuf) -> SyncSender<Notification> {
    let (tx, rx) = mpsc::sync_channel::<Notification>(1000);
    std::thread::spawn(move || {
        let Ok(c) = db::open(&db_path) else { return };
        loop {
            let Ok(first) = rx.recv() else { return };
            let mut batch = vec![first];
            // Coalesce bursts (a scan can raise several alerts at once) into a single message.
            let deadline = Instant::now() + Duration::from_secs(2);
            while batch.len() < 25 {
                let left = deadline.saturating_duration_since(Instant::now());
                match rx.recv_timeout(left) {
                    Ok(n) => batch.push(n),
                    Err(RecvTimeoutError::Timeout) => break,
                    Err(RecvTimeoutError::Disconnected) => return,
                }
            }
            let Some(url) = db::get_setting(&c, "webhook_url").ok().flatten().filter(|u| !u.is_empty()) else { continue };
            let min = rank(&db::get_setting(&c, "webhook_min_severity").ok().flatten().unwrap_or_else(|| "MEDIUM".into()));
            batch.retain(|n| rank(&n.severity) >= min);
            if batch.is_empty() {
                continue;
            }
            let payload = body(&effective_format(&c, &url), &batch);
            let mut last = String::new();
            for (i, wait) in [0u64, 3, 10].iter().enumerate() {
                if *wait > 0 {
                    std::thread::sleep(Duration::from_secs(*wait));
                }
                match post(&url, &payload) {
                    Ok(()) => {
                        last.clear();
                        break;
                    }
                    Err(e) => last = format!("attempt {}: {e}", i + 1),
                }
            }
            if !last.is_empty() {
                eprintln!("{} webhook delivery failed ({} alerts dropped): {last}", fmt_time(now_secs()), batch.len());
            }
        }
    });
    tx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_parsing() {
        let u = parse_url("https://hooks.slack.com/services/T0/B0/xyz").unwrap();
        assert!(u.https && u.port == 443 && u.host == "hooks.slack.com" && u.path == "/services/T0/B0/xyz");
        let u = parse_url("http://10.0.0.5:8080").unwrap();
        assert!(!u.https && u.port == 8080 && u.path == "/");
        assert!(parse_url("ftp://x").is_err() && parse_url("http://user@host/").is_err());
        assert_eq!(mask("https://hooks.slack.com/services/SECRET"), "https://hooks.slack.com/…");
    }

    #[test]
    fn bodies() {
        let n = Notification { host: "h".into(), ts: 0, kind: "PORT_SCAN".into(), severity: "HIGH".into(), source: Some("1.2.3.4".into()), message: "m \"q\"".into() };
        let s = body("slack", &[n.clone()]);
        assert!(s.starts_with("{\"text\":") && serde_json::from_str::<serde_json::Value>(&s).is_ok());
        assert!(body("discord", &[n.clone()]).starts_with("{\"content\":"));
        let g: serde_json::Value = serde_json::from_str(&body("generic", &[n])).unwrap();
        assert_eq!(g["alerts"][0]["type"], "PORT_SCAN");
    }

    /// Needs internet: proves TLS + bundled roots work (any HTTP status, even 4xx, means the handshake succeeded).
    #[test]
    #[ignore]
    fn https_handshake() {
        match post("https://example.com/", "{}") {
            Ok(()) => {}
            Err(e) => assert!(e.starts_with("endpoint returned HTTP"), "TLS/transport failure: {e}"),
        }
    }
}
