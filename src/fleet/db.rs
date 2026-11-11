//! SQLite storage shared by the server (writer) and the console UI (reader/acker).

use super::proto::{RemoteConfig, Report};
use super::util::{clean, now_secs, random_hex};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashSet;
use std::path::Path;

pub type Res<T> = rusqlite::Result<T>;

pub fn open(path: &Path) -> Res<Connection> {
    let c = Connection::open(path)?;
    c.busy_timeout(std::time::Duration::from_secs(5))?;
    c.pragma_update(None, "journal_mode", "WAL")?;
    c.pragma_update(None, "synchronous", "NORMAL")?;
    c.execute_batch(SCHEMA)?;
    Ok(c)
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS hosts(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, os TEXT DEFAULT '', version TEXT DEFAULT '',
  cert_fp TEXT UNIQUE NOT NULL, remote_addr TEXT DEFAULT '', first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'pending',
  is_root INTEGER DEFAULT 0, baselined INTEGER DEFAULT 0, revoked INTEGER DEFAULT 0,
  total INTEGER DEFAULT 0, established INTEGER DEFAULT 0, syn_recv INTEGER DEFAULT 0,
  time_wait INTEGER DEFAULT 0, listeners INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS tokens(token TEXT PRIMARY KEY, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, host_id TEXT NOT NULL, ts INTEGER NOT NULL, kind TEXT NOT NULL,
  severity TEXT NOT NULL, source TEXT, message TEXT NOT NULL, acked INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS alerts_ts ON alerts(ts DESC);
CREATE INDEX IF NOT EXISTS alerts_host ON alerts(host_id, ts DESC);
CREATE TABLE IF NOT EXISTS listeners(
  host_id TEXT NOT NULL, proto TEXT NOT NULL, addr TEXT NOT NULL, port INTEGER NOT NULL,
  pid INTEGER, process TEXT, user TEXT, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
  PRIMARY KEY(host_id, proto, addr, port));
CREATE TABLE IF NOT EXISTS listener_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, host_id TEXT NOT NULL, ts INTEGER NOT NULL, event TEXT NOT NULL,
  proto TEXT, addr TEXT, port INTEGER, process TEXT, pid INTEGER);
CREATE INDEX IF NOT EXISTS lev_host ON listener_events(host_id, ts DESC);
CREATE TABLE IF NOT EXISTS conns(
  host_id TEXT NOT NULL, proto TEXT, state TEXT, local TEXT, remote TEXT, pid INTEGER, process TEXT);
CREATE INDEX IF NOT EXISTS conns_host ON conns(host_id);
CREATE TABLE IF NOT EXISTS metrics(
  host_id TEXT NOT NULL, ts INTEGER NOT NULL, established INTEGER, syn_recv INTEGER,
  time_wait INTEGER, listeners INTEGER, total INTEGER);
CREATE INDEX IF NOT EXISTS metrics_host ON metrics(host_id, ts DESC);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
";

// ---------- enrollment ----------

pub fn create_token(c: &Connection, ttl_secs: u64) -> Res<String> {
    let t = random_hex(16);
    c.execute("DELETE FROM tokens WHERE expires < ?1", [now_secs() as i64])?;
    c.execute("INSERT INTO tokens(token, expires) VALUES(?1, ?2)", params![t, (now_secs() + ttl_secs) as i64])?;
    Ok(t)
}

/// Atomically consume a token. True if it existed and was unexpired.
pub fn consume_token(c: &Connection, token: &str) -> Res<bool> {
    let n = c.execute("DELETE FROM tokens WHERE token = ?1 AND expires >= ?2", params![token, now_secs() as i64])?;
    Ok(n == 1)
}

pub fn add_host(c: &Connection, id: &str, name: &str, fp: &str, addr: &str) -> Res<()> {
    c.execute(
        "INSERT INTO hosts(id, name, cert_fp, remote_addr, first_seen, last_seen, status) VALUES(?1,?2,?3,?4,?5,?5,'pending')",
        params![id, clean(name, 64), fp, addr, now_secs() as i64],
    )?;
    Ok(())
}

/// Authenticate by client-certificate fingerprint.
pub fn host_by_fp(c: &Connection, fp: &str) -> Res<Option<(String, String)>> {
    c.query_row("SELECT id, name FROM hosts WHERE cert_fp = ?1 AND revoked = 0", [fp], |r| {
        Ok((r.get(0)?, r.get(1)?))
    })
    .optional()
}

pub fn revoke(c: &Connection, id_or_name: &str) -> Res<usize> {
    c.execute("UPDATE hosts SET revoked = 1, status = 'revoked' WHERE id = ?1 OR name = ?1", [id_or_name])
}

// ---------- ingestion ----------

pub fn insert_alert(c: &Connection, host: &str, ts: u64, kind: &str, sev: &str, src: Option<&str>, msg: &str) -> Res<()> {
    c.execute(
        "INSERT INTO alerts(host_id, ts, kind, severity, source, message) VALUES(?1,?2,?3,?4,?5,?6)",
        params![host, ts as i64, clean(kind, 32), clean(sev, 8), src.map(|s| clean(s, 64)), clean(msg, 500)],
    )?;
    Ok(())
}

const MAX_LISTENERS: usize = 5000;
const MAX_CONNS: usize = 3000;
const MAX_ALERTS: usize = 200;

/// Store one report. Returns the number of listener changes detected.
pub fn ingest(c: &mut Connection, host: &str, addr: &str, r: &Report) -> Res<usize> {
    let now = now_secs() as i64;
    let tx = c.transaction()?;

    let (was_baselined, prev_status): (i64, String) =
        tx.query_row("SELECT baselined, status FROM hosts WHERE id = ?1", [host], |r| Ok((r.get(0)?, r.get(1)?)))?;
    if prev_status == "down" {
        tx.execute(
            "INSERT INTO alerts(host_id, ts, kind, severity, message) VALUES(?1,?2,'HOST_UP','INFO','agent is reporting again')",
            params![host, now],
        )?;
    }

    tx.execute(
        "UPDATE hosts SET name=?2, os=?3, version=?4, remote_addr=?5, last_seen=?6, status='up', is_root=?7,
         total=?8, established=?9, syn_recv=?10, time_wait=?11, listeners=?12 WHERE id=?1",
        params![
            host, clean(&r.hostname, 64), clean(&r.os, 64), clean(&r.version, 16), addr, now, r.root as i64,
            r.stats.total, r.stats.established, r.stats.syn_recv, r.stats.time_wait, r.stats.listeners
        ],
    )?;

    // Listener diff -> opened/closed events (the "what changed" trail for investigations).
    let mut changes = 0;
    let mut existing: HashSet<(String, String, u16)> = HashSet::new();
    {
        let mut st = tx.prepare("SELECT proto, addr, port FROM listeners WHERE host_id = ?1")?;
        let rows = st.query_map([host], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, u16>(2)?)))?;
        for row in rows {
            existing.insert(row?);
        }
    }
    let mut seen: HashSet<(String, String, u16)> = HashSet::new();
    for l in r.listeners.iter().take(MAX_LISTENERS) {
        let key = (clean(&l.proto, 8), clean(&l.addr, 64), l.port);
        seen.insert(key.clone());
        if !existing.contains(&key) {
            if was_baselined == 1 {
                tx.execute(
                    "INSERT INTO listener_events(host_id, ts, event, proto, addr, port, process, pid) VALUES(?1,?2,'opened',?3,?4,?5,?6,?7)",
                    params![host, now, key.0, key.1, key.2, l.process.as_deref().map(|s| clean(s, 64)), l.pid],
                )?;
                changes += 1;
            }
            tx.execute(
                "INSERT OR REPLACE INTO listeners(host_id, proto, addr, port, pid, process, user, first_seen, last_seen) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?8)",
                params![host, key.0, key.1, key.2, l.pid, l.process.as_deref().map(|s| clean(s, 64)), clean(&l.user, 32), now],
            )?;
        } else {
            tx.execute(
                "UPDATE listeners SET pid=?5, process=?6, user=?7, last_seen=?8 WHERE host_id=?1 AND proto=?2 AND addr=?3 AND port=?4",
                params![host, key.0, key.1, key.2, l.pid, l.process.as_deref().map(|s| clean(s, 64)), clean(&l.user, 32), now],
            )?;
        }
    }
    for gone in existing.difference(&seen) {
        tx.execute(
            "INSERT INTO listener_events(host_id, ts, event, proto, addr, port) VALUES(?1,?2,'closed',?3,?4,?5)",
            params![host, now, gone.0, gone.1, gone.2],
        )?;
        tx.execute(
            "DELETE FROM listeners WHERE host_id=?1 AND proto=?2 AND addr=?3 AND port=?4",
            params![host, gone.0, gone.1, gone.2],
        )?;
        changes += 1;
    }
    tx.execute("UPDATE hosts SET baselined = 1 WHERE id = ?1", [host])?;

    tx.execute("DELETE FROM conns WHERE host_id = ?1", [host])?;
    for cn in r.conns.iter().take(MAX_CONNS) {
        tx.execute(
            "INSERT INTO conns(host_id, proto, state, local, remote, pid, process) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![host, clean(&cn.proto, 8), clean(&cn.state, 16), clean(&cn.local, 64), clean(&cn.remote, 64), cn.pid, cn.process.as_deref().map(|s| clean(s, 64))],
        )?;
    }

    for a in r.alerts.iter().take(MAX_ALERTS) {
        // Never accept timestamps from the future or absurdly old; fall back to receive time.
        let ts = if a.ts > now_secs() + 60 || a.ts + 7 * 86400 < now_secs() { now_secs() } else { a.ts };
        tx.execute(
            "INSERT INTO alerts(host_id, ts, kind, severity, source, message) VALUES(?1,?2,?3,?4,?5,?6)",
            params![host, ts as i64, clean(&a.kind, 32), clean(&a.severity, 8), a.source.as_deref().map(|s| clean(s, 64)), clean(&a.message, 500)],
        )?;
    }

    tx.execute(
        "INSERT INTO metrics(host_id, ts, established, syn_recv, time_wait, listeners, total) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![host, now, r.stats.established, r.stats.syn_recv, r.stats.time_wait, r.stats.listeners, r.stats.total],
    )?;
    tx.commit()?;
    Ok(changes)
}

/// Mark silent hosts down (and raise HOST_DOWN once). Returns hosts newly marked down.
pub fn watchdog(c: &Connection, down_after: u64) -> Res<Vec<String>> {
    let cutoff = now_secs().saturating_sub(down_after) as i64;
    let mut st = c.prepare("SELECT id, name FROM hosts WHERE status = 'up' AND last_seen < ?1 AND revoked = 0")?;
    let stale: Vec<(String, String)> =
        st.query_map([cutoff], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Res<_>>()?;
    for (id, name) in &stale {
        c.execute("UPDATE hosts SET status = 'down' WHERE id = ?1", [id])?;
        insert_alert(c, id, now_secs(), "HOST_DOWN", "HIGH", None, &format!("no report from {name} for over {down_after}s"))?;
    }
    Ok(stale.into_iter().map(|(_, n)| n).collect())
}

pub fn prune(c: &Connection) -> Res<()> {
    let n = now_secs() as i64;
    c.execute("DELETE FROM metrics WHERE ts < ?1", [n - 7 * 86400])?;
    c.execute("DELETE FROM alerts WHERE ts < ?1", [n - 90 * 86400])?;
    c.execute("DELETE FROM listener_events WHERE ts < ?1", [n - 90 * 86400])?;
    Ok(())
}

// ---------- settings / config push ----------

pub const SETTING_KEYS: &[&str] =
    &["report_interval", "window", "scan_ports", "rate_limit", "conn_limit", "syn_limit", "rst_rate", "ignore"];

pub fn set_setting(c: &Connection, k: &str, v: &str) -> Res<()> {
    c.execute("INSERT INTO settings(key, value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=?2", params![k, v])?;
    Ok(())
}

pub fn get_setting(c: &Connection, k: &str) -> Res<Option<String>> {
    c.query_row("SELECT value FROM settings WHERE key = ?1", [k], |r| r.get(0)).optional()
}

pub fn remote_config(c: &Connection) -> Res<RemoteConfig> {
    let g = |k: &str| get_setting(c, k).ok().flatten();
    Ok(RemoteConfig {
        report_interval: g("report_interval").and_then(|v| v.parse().ok()),
        window: g("window").and_then(|v| v.parse().ok()),
        scan_ports: g("scan_ports").and_then(|v| v.parse().ok()),
        rate_limit: g("rate_limit").and_then(|v| v.parse().ok()),
        conn_limit: g("conn_limit").and_then(|v| v.parse().ok()),
        syn_limit: g("syn_limit").and_then(|v| v.parse().ok()),
        rst_rate: g("rst_rate").and_then(|v| v.parse().ok()),
        ignore: g("ignore").map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()),
    })
}

// ---------- queries for the UI / CLI ----------

#[derive(Clone, Debug)]
pub struct HostRow {
    pub id: String,
    pub name: String,
    pub os: String,
    pub version: String,
    pub addr: String,
    pub status: String,
    pub last_seen: u64,
    pub is_root: bool,
    pub total: u32,
    pub established: u32,
    pub syn_recv: u32,
    pub time_wait: u32,
    pub listeners: u32,
    pub open_alerts: u32,
}

pub fn hosts(c: &Connection) -> Res<Vec<HostRow>> {
    let mut st = c.prepare(
        "SELECT h.id, h.name, h.os, h.version, h.remote_addr, h.status, h.last_seen, h.is_root, h.total,
                h.established, h.syn_recv, h.time_wait, h.listeners,
                (SELECT COUNT(*) FROM alerts a WHERE a.host_id = h.id AND a.acked = 0 AND a.severity != 'INFO')
         FROM hosts h WHERE h.revoked = 0 ORDER BY (h.status = 'down') DESC, 14 DESC, h.name",
    )?;
    let rows = st.query_map([], |r| {
        Ok(HostRow {
            id: r.get(0)?, name: r.get(1)?, os: r.get(2)?, version: r.get(3)?, addr: r.get(4)?,
            status: r.get(5)?, last_seen: r.get::<_, i64>(6)? as u64, is_root: r.get::<_, i64>(7)? != 0,
            total: r.get(8)?, established: r.get(9)?, syn_recv: r.get(10)?, time_wait: r.get(11)?,
            listeners: r.get(12)?, open_alerts: r.get(13)?,
        })
    })?;
    rows.collect()
}

#[derive(Clone, Debug)]
pub struct AlertRow {
    pub id: i64,
    pub host: String,
    pub ts: u64,
    pub kind: String,
    pub severity: String,
    pub source: String,
    pub message: String,
    pub acked: bool,
}

pub fn alerts(c: &Connection, host: Option<&str>, include_acked: bool, limit: usize) -> Res<Vec<AlertRow>> {
    let mut st = c.prepare(
        "SELECT a.id, COALESCE(h.name, a.host_id), a.ts, a.kind, a.severity, COALESCE(a.source,''), a.message, a.acked
         FROM alerts a LEFT JOIN hosts h ON h.id = a.host_id
         WHERE (?1 IS NULL OR a.host_id = ?1) AND (?2 = 1 OR a.acked = 0)
         ORDER BY a.ts DESC, a.id DESC LIMIT ?3",
    )?;
    let rows = st.query_map(params![host, include_acked as i64, limit as i64], |r| {
        Ok(AlertRow {
            id: r.get(0)?, host: r.get(1)?, ts: r.get::<_, i64>(2)? as u64, kind: r.get(3)?, severity: r.get(4)?,
            source: r.get(5)?, message: r.get(6)?, acked: r.get::<_, i64>(7)? != 0,
        })
    })?;
    rows.collect()
}

pub fn ack(c: &Connection, id: i64) -> Res<()> {
    c.execute("UPDATE alerts SET acked = 1 WHERE id = ?1", [id])?;
    Ok(())
}

pub fn ack_all(c: &Connection, host: Option<&str>) -> Res<()> {
    c.execute("UPDATE alerts SET acked = 1 WHERE ?1 IS NULL OR host_id = ?1", [host])?;
    Ok(())
}

#[derive(Clone, Debug)]
pub struct ListenerRow {
    pub proto: String,
    pub addr: String,
    pub port: u16,
    pub pid: Option<u32>,
    pub process: String,
    pub user: String,
    pub first_seen: u64,
}

pub fn listeners(c: &Connection, host: &str) -> Res<Vec<ListenerRow>> {
    let mut st = c.prepare(
        "SELECT proto, addr, port, pid, COALESCE(process,'-'), COALESCE(user,''), first_seen FROM listeners
         WHERE host_id = ?1 ORDER BY port, proto, addr",
    )?;
    let rows = st.query_map([host], |r| {
        Ok(ListenerRow {
            proto: r.get(0)?, addr: r.get(1)?, port: r.get(2)?, pid: r.get(3)?, process: r.get(4)?,
            user: r.get(5)?, first_seen: r.get::<_, i64>(6)? as u64,
        })
    })?;
    rows.collect()
}

#[derive(Clone, Debug)]
pub struct ConnRow {
    pub proto: String,
    pub state: String,
    pub local: String,
    pub remote: String,
    pub pid: Option<u32>,
    pub process: String,
}

pub fn conns(c: &Connection, host: &str) -> Res<Vec<ConnRow>> {
    let mut st = c.prepare(
        "SELECT proto, state, local, remote, pid, COALESCE(process,'-') FROM conns WHERE host_id = ?1
         ORDER BY (state = 'ESTABLISHED') DESC, state, remote",
    )?;
    let rows = st.query_map([host], |r| {
        Ok(ConnRow { proto: r.get(0)?, state: r.get(1)?, local: r.get(2)?, remote: r.get(3)?, pid: r.get(4)?, process: r.get(5)? })
    })?;
    rows.collect()
}

#[derive(Clone, Debug)]
pub struct EventRow {
    pub ts: u64,
    pub event: String,
    pub what: String,
}

pub fn events(c: &Connection, host: &str, limit: usize) -> Res<Vec<EventRow>> {
    let mut st = c.prepare(
        "SELECT ts, event, COALESCE(proto,''), COALESCE(addr,''), COALESCE(port,0), COALESCE(process,'') FROM listener_events
         WHERE host_id = ?1 ORDER BY ts DESC, id DESC LIMIT ?2",
    )?;
    let rows = st.query_map(params![host, limit as i64], |r| {
        let (proto, addr, port, proc_): (String, String, u32, String) = (r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?);
        Ok(EventRow {
            ts: r.get::<_, i64>(0)? as u64,
            event: r.get(1)?,
            what: format!("{proto} {addr}:{port} {proc_}").trim().to_string(),
        })
    })?;
    rows.collect()
}

/// Recent established-connection counts, oldest first, for sparklines.
pub fn established_history(c: &Connection, host: &str, points: usize) -> Res<Vec<u64>> {
    let mut st = c.prepare("SELECT established FROM metrics WHERE host_id = ?1 ORDER BY ts DESC LIMIT ?2")?;
    let mut v: Vec<u64> = st.query_map(params![host, points as i64], |r| Ok(r.get::<_, i64>(0)?.max(0) as u64))?.collect::<Res<_>>()?;
    v.reverse();
    Ok(v)
}
