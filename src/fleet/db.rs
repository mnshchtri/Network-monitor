//! SQLite storage shared by the server (writer) and the console UI (reader/acker).

use super::proto::{RemoteConfig, Report};
use super::util::{clean, now_secs, random_hex, sha256_hex};
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
    // Columns added after the first release. Errors are ignored on purpose: a concurrent process
    // may have added the column between our check and the ALTER.
    add_column(&c, "hosts", "tags", "TEXT NOT NULL DEFAULT ''");
    add_column(&c, "alerts", "assignee", "TEXT");
    add_column(&c, "alerts", "muted", "INTEGER NOT NULL DEFAULT 0");
    migrate_users(&c)?;
    Ok(c)
}

fn add_column(c: &Connection, table: &str, col: &str, decl: &str) {
    let have: i64 = c
        .query_row("SELECT COUNT(*) FROM pragma_table_info(?1) WHERE name = ?2", params![table, col], |r| r.get(0))
        .unwrap_or(1);
    if have == 0 {
        let _ = c.execute(&format!("ALTER TABLE {table} ADD COLUMN {col} {decl}"), []);
    }
}

/// Older versions had a single shared dashboard password. Turn it into the first admin account
/// and force a password change at first login.
fn migrate_users(c: &Connection) -> Res<()> {
    if count_users(c)? == 0 {
        if let Some(h) = get_setting(c, "web_password")?.filter(|h| !h.is_empty()) {
            c.execute(
                "INSERT INTO users(username, pw_hash, role, must_change, created) VALUES('admin', ?1, 'admin', 1, ?2)",
                params![h, now_secs() as i64],
            )?;
            c.execute("DELETE FROM settings WHERE key = 'web_password'", [])?;
            audit(c, "system", "user.migrate", "admin", "converted the legacy shared dashboard password into the admin account", "")?;
        }
    }
    Ok(())
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
CREATE TABLE IF NOT EXISTS alert_comments(
  id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id INTEGER NOT NULL, ts INTEGER NOT NULL, author TEXT NOT NULL, body TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS comments_alert ON alert_comments(alert_id);
CREATE TABLE IF NOT EXISTS mutes(
  id INTEGER PRIMARY KEY AUTOINCREMENT, host_id TEXT, kind TEXT, until INTEGER NOT NULL, reason TEXT NOT NULL,
  created_by TEXT NOT NULL, created INTEGER NOT NULL, ended INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL COLLATE NOCASE, pw_hash TEXT NOT NULL,
  role TEXT NOT NULL, disabled INTEGER NOT NULL DEFAULT 0, must_change INTEGER NOT NULL DEFAULT 0,
  totp_secret TEXT, totp_last INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL, last_login INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '', ip TEXT NOT NULL DEFAULT '',
  prev TEXT NOT NULL, hash TEXT NOT NULL);
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
    let kind = clean(kind, 32);
    let muted = is_muted(c, host, &kind)? as i64;
    c.execute(
        "INSERT INTO alerts(host_id, ts, kind, severity, source, message, muted) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![host, ts as i64, kind, clean(sev, 8), src.map(|s| clean(s, 64)), clean(msg, 500), muted],
    )?;
    Ok(())
}

const MAX_LISTENERS: usize = 5000;
const MAX_CONNS: usize = 3000;
const MAX_ALERTS: usize = 200;

/// Store one report. Returns (listener changes detected, host just recovered from down).
pub fn ingest(c: &mut Connection, host: &str, addr: &str, r: &Report) -> Res<(usize, bool)> {
    let now = now_secs() as i64;
    let tx = c.transaction()?;

    let (was_baselined, prev_status): (i64, String) =
        tx.query_row("SELECT baselined, status FROM hosts WHERE id = ?1", [host], |r| Ok((r.get(0)?, r.get(1)?)))?;
    if prev_status == "down" {
        let muted = is_muted(&tx, host, "HOST_UP")? as i64;
        tx.execute(
            "INSERT INTO alerts(host_id, ts, kind, severity, message, muted) VALUES(?1,?2,'HOST_UP','INFO','agent is reporting again',?3)",
            params![host, now, muted],
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
        let kind = clean(&a.kind, 32);
        let muted = is_muted(&tx, host, &kind)? as i64;
        tx.execute(
            "INSERT INTO alerts(host_id, ts, kind, severity, source, message, muted) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![host, ts as i64, kind, clean(&a.severity, 8), a.source.as_deref().map(|s| clean(s, 64)), clean(&a.message, 500), muted],
        )?;
    }

    tx.execute(
        "INSERT INTO metrics(host_id, ts, established, syn_recv, time_wait, listeners, total) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![host, now, r.stats.established, r.stats.syn_recv, r.stats.time_wait, r.stats.listeners, r.stats.total],
    )?;
    tx.commit()?;
    Ok((changes, prev_status == "down"))
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

/// Settings pushed to agents.
pub const SETTING_KEYS: &[&str] =
    &["report_interval", "window", "scan_ports", "rate_limit", "conn_limit", "syn_limit", "rst_rate", "ignore"];
/// Settings used by the server itself.
pub const SERVER_KEYS: &[&str] = &["down_after", "webhook_url", "webhook_min_severity", "webhook_format"];

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
    pub tags: Vec<String>,
}

pub fn hosts(c: &Connection) -> Res<Vec<HostRow>> {
    let mut st = c.prepare(
        "SELECT h.id, h.name, h.os, h.version, h.remote_addr, h.status, h.last_seen, h.is_root, h.total,
                h.established, h.syn_recv, h.time_wait, h.listeners,
                (SELECT COUNT(*) FROM alerts a WHERE a.host_id = h.id AND a.acked = 0 AND a.severity != 'INFO' AND a.muted = 0), h.tags
         FROM hosts h WHERE h.revoked = 0 ORDER BY (h.status = 'down') DESC, 14 DESC, h.name",
    )?;
    let rows = st.query_map([], |r| {
        Ok(HostRow {
            id: r.get(0)?, name: r.get(1)?, os: r.get(2)?, version: r.get(3)?, addr: r.get(4)?,
            status: r.get(5)?, last_seen: r.get::<_, i64>(6)? as u64, is_root: r.get::<_, i64>(7)? != 0,
            total: r.get(8)?, established: r.get(9)?, syn_recv: r.get(10)?, time_wait: r.get(11)?,
            listeners: r.get(12)?, open_alerts: r.get(13)?,
            tags: r.get::<_, String>(14)?.split(',').filter(|t| !t.is_empty()).map(String::from).collect(),
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
    pub message: String,
    pub acked: bool,
    pub assignee: String,
    pub muted: bool,
}

pub fn alerts(c: &Connection, host: Option<&str>, include_acked: bool, limit: usize) -> Res<Vec<AlertRow>> {
    alerts_filtered(c, &AlertFilter { host, include_acked, limit, ..Default::default() })
}

#[derive(Default)]
pub struct AlertFilter<'a> {
    pub host: Option<&'a str>,
    pub tag: Option<&'a str>,
    pub include_acked: bool,
    pub since: u64,
    pub severity: Option<&'a str>,
    pub kind: Option<&'a str>,
    pub assignee: Option<&'a str>,
    pub limit: usize,
}

const ALERT_COLS: &str = "a.id, COALESCE(h.name, a.host_id), a.ts, a.kind, a.severity, a.message, a.acked, COALESCE(a.assignee,''), a.muted";

fn alert_row(r: &rusqlite::Row) -> Res<AlertRow> {
    Ok(AlertRow {
        id: r.get(0)?, host: r.get(1)?, ts: r.get::<_, i64>(2)? as u64, kind: r.get(3)?, severity: r.get(4)?,
        message: r.get(5)?, acked: r.get::<_, i64>(6)? != 0, assignee: r.get(7)?, muted: r.get::<_, i64>(8)? != 0,
    })
}

pub fn alerts_filtered(c: &Connection, f: &AlertFilter) -> Res<Vec<AlertRow>> {
    let mut st = c.prepare(&format!(
        "SELECT {ALERT_COLS} FROM alerts a LEFT JOIN hosts h ON h.id = a.host_id
         WHERE (?1 IS NULL OR a.host_id = ?1)
           AND (?2 IS NULL OR (',' || COALESCE(h.tags,'') || ',') LIKE '%,' || ?2 || ',%')
           AND (?3 = 1 OR a.acked = 0) AND a.ts >= ?4
           AND (?5 IS NULL OR a.severity = ?5) AND (?6 IS NULL OR a.kind = ?6) AND (?7 IS NULL OR a.assignee = ?7)
         ORDER BY a.ts DESC, a.id DESC LIMIT ?8"
    ))?;
    let rows = st.query_map(
        params![f.host, f.tag, f.include_acked as i64, f.since as i64, f.severity, f.kind, f.assignee, f.limit.max(1) as i64],
        alert_row,
    )?;
    rows.collect()
}

pub fn alert_by_id(c: &Connection, id: i64) -> Res<Option<AlertRow>> {
    c.query_row(&format!("SELECT {ALERT_COLS} FROM alerts a LEFT JOIN hosts h ON h.id = a.host_id WHERE a.id = ?1"), [id], alert_row).optional()
}

pub fn set_assignee(c: &Connection, id: i64, who: Option<&str>) -> Res<usize> {
    c.execute("UPDATE alerts SET assignee = ?2 WHERE id = ?1", params![id, who])
}

pub fn add_comment(c: &Connection, alert_id: i64, author: &str, body: &str) -> Res<()> {
    c.execute(
        "INSERT INTO alert_comments(alert_id, ts, author, body) VALUES(?1,?2,?3,?4)",
        params![alert_id, now_secs() as i64, clean(author, 32), body.chars().filter(|ch| !ch.is_control() || *ch == '\n').take(1000).collect::<String>()],
    )?;
    Ok(())
}

pub fn comments(c: &Connection, alert_id: i64) -> Res<Vec<(u64, String, String)>> {
    let mut st = c.prepare("SELECT ts, author, body FROM alert_comments WHERE alert_id = ?1 ORDER BY id")?;
    let rows = st.query_map([alert_id], |r| Ok((r.get::<_, i64>(0)? as u64, r.get(1)?, r.get(2)?)))?;
    rows.collect()
}

// ---------- host tags ----------

pub fn valid_tag(t: &str) -> bool {
    !t.is_empty() && t.len() <= 24 && t.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.')
}

pub fn set_tags(c: &Connection, host: &str, tags: &[String]) -> Res<usize> {
    c.execute("UPDATE hosts SET tags = ?2 WHERE id = ?1", params![host, tags.join(",")])
}

// ---------- maintenance mutes ----------

#[derive(Clone, Debug)]
pub struct MuteRow {
    pub id: i64,
    pub host_id: Option<String>,
    pub host: String,
    pub kind: Option<String>,
    pub until: u64,
    pub reason: String,
    pub created_by: String,
    pub created: u64,
    pub active: bool,
}

/// True when an unexpired, un-ended mute covers this host and alert kind.
pub fn is_muted(c: &Connection, host: &str, kind: &str) -> Res<bool> {
    let n: i64 = c.query_row(
        "SELECT COUNT(*) FROM mutes WHERE ended = 0 AND until > ?1 AND (host_id IS NULL OR host_id = ?2) AND (kind IS NULL OR kind = ?3)",
        params![now_secs() as i64, host, kind],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

pub fn add_mute(c: &Connection, host: Option<&str>, kind: Option<&str>, minutes: u64, reason: &str, by: &str) -> Res<()> {
    let now = now_secs() as i64;
    c.execute(
        "INSERT INTO mutes(host_id, kind, until, reason, created_by, created) VALUES(?1,?2,?3,?4,?5,?6)",
        params![host, kind, now + (minutes * 60) as i64, clean(reason, 200), clean(by, 32), now],
    )?;
    Ok(())
}

pub fn end_mute(c: &Connection, id: i64) -> Res<usize> {
    c.execute("UPDATE mutes SET ended = 1 WHERE id = ?1 AND ended = 0", [id])
}

pub fn mutes(c: &Connection) -> Res<Vec<MuteRow>> {
    let now = now_secs();
    let mut st = c.prepare(
        "SELECT m.id, m.host_id, COALESCE(h.name, ''), m.kind, m.until, m.reason, m.created_by, m.created, m.ended
         FROM mutes m LEFT JOIN hosts h ON h.id = m.host_id ORDER BY m.id DESC LIMIT 200",
    )?;
    let rows = st.query_map([], |r| {
        let (until, ended): (i64, i64) = (r.get(4)?, r.get(8)?);
        Ok(MuteRow {
            id: r.get(0)?, host_id: r.get(1)?, host: r.get(2)?, kind: r.get(3)?, until: until as u64, reason: r.get(5)?,
            created_by: r.get(6)?, created: r.get::<_, i64>(7)? as u64, active: ended == 0 && until as u64 > now,
        })
    })?;
    rows.collect()
}

// ---------- trends, timeline, search ----------

/// Time-bucketed MAX per metric (max, not average, so short spikes such as a SYN burst survive).
/// Returns (bucket start, established, syn_recv, time_wait, listeners) oldest first.
pub fn metric_series(c: &Connection, host: &str, since: u64, bucket: u64) -> Res<Vec<(u64, u32, u32, u32, u32)>> {
    let bucket = bucket.max(1) as i64;
    let mut st = c.prepare(
        "SELECT (ts / ?3) * ?3, MAX(established), MAX(syn_recv), MAX(time_wait), MAX(listeners) FROM metrics
         WHERE host_id = ?1 AND ts >= ?2 GROUP BY 1 ORDER BY 1",
    )?;
    let rows = st.query_map(params![host, since as i64, bucket], |r| {
        Ok((r.get::<_, i64>(0)? as u64, r.get::<_, Option<u32>>(1)?.unwrap_or(0), r.get::<_, Option<u32>>(2)?.unwrap_or(0), r.get::<_, Option<u32>>(3)?.unwrap_or(0), r.get::<_, Option<u32>>(4)?.unwrap_or(0)))
    })?;
    rows.collect()
}

#[derive(Clone, Debug)]
pub struct TimelineRow {
    pub ts: u64,
    pub kind: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
}

/// Everything that happened on a host, newest first: alerts (including HOST_DOWN/UP) and listener changes.
pub fn timeline(c: &Connection, host: &str, limit: usize) -> Res<Vec<TimelineRow>> {
    let mut st = c.prepare(
        "SELECT ts, 'alert', severity, kind, message || CASE WHEN muted = 1 THEN '  [muted]' ELSE '' END FROM alerts WHERE host_id = ?1
         UNION ALL
         SELECT ts, 'listener', CASE event WHEN 'opened' THEN 'MEDIUM' ELSE 'INFO' END, 'PORT ' || upper(event),
                trim(COALESCE(proto,'') || ' ' || COALESCE(addr,'') || ':' || COALESCE(port,0) || ' ' || COALESCE(process,''))
         FROM listener_events WHERE host_id = ?1
         ORDER BY 1 DESC LIMIT ?2",
    )?;
    let rows = st.query_map(params![host, limit as i64], |r| {
        Ok(TimelineRow { ts: r.get::<_, i64>(0)? as u64, kind: r.get(1)?, severity: r.get(2)?, title: r.get(3)?, detail: r.get(4)? })
    })?;
    rows.collect()
}

#[derive(Default)]
pub struct SearchResults {
    pub hosts: Vec<(String, String, String, Vec<String>)>,
    pub listeners: Vec<(String, String, String, String, u16, String, String)>,
    pub conns: Vec<(String, String, String, String, String, String, String)>,
    pub alerts: Vec<AlertRow>,
}

fn like(q: &str) -> String {
    format!("%{}%", q.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_"))
}

pub fn search(c: &Connection, q: &str) -> Res<SearchResults> {
    let (pat, exact) = (like(q), q.to_string());
    let mut out = SearchResults::default();
    let mut st = c.prepare(
        "SELECT id, name, remote_addr, tags FROM hosts WHERE revoked = 0 AND (name LIKE ?1 ESCAPE '\\' OR remote_addr LIKE ?1 ESCAPE '\\' OR (',' || tags || ',') LIKE ?1 ESCAPE '\\' OR os LIKE ?1 ESCAPE '\\') LIMIT 50",
    )?;
    out.hosts = st
        .query_map([&pat], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get::<_, String>(3)?.split(',').filter(|t| !t.is_empty()).map(String::from).collect())))?
        .collect::<Res<_>>()?;
    let mut st = c.prepare(
        "SELECT l.host_id, COALESCE(h.name,''), l.proto, l.addr, l.port, COALESCE(l.process,''), COALESCE(l.user,'') FROM listeners l
         LEFT JOIN hosts h ON h.id = l.host_id
         WHERE h.revoked = 0 AND (CAST(l.port AS TEXT) = ?2 OR l.addr LIKE ?1 ESCAPE '\\' OR l.process LIKE ?1 ESCAPE '\\' OR l.user LIKE ?1 ESCAPE '\\')
         ORDER BY l.port LIMIT 100",
    )?;
    out.listeners = st.query_map(params![pat, exact], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)))?.collect::<Res<_>>()?;
    let mut st = c.prepare(
        "SELECT n.host_id, COALESCE(h.name,''), n.proto, n.state, n.local, n.remote, COALESCE(n.process,'') FROM conns n
         LEFT JOIN hosts h ON h.id = n.host_id
         WHERE h.revoked = 0 AND (n.local LIKE ?1 ESCAPE '\\' OR n.remote LIKE ?1 ESCAPE '\\' OR n.process LIKE ?1 ESCAPE '\\') LIMIT 100",
    )?;
    out.conns = st.query_map([&pat], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)))?.collect::<Res<_>>()?;
    let mut st = c.prepare(&format!(
        "SELECT {ALERT_COLS} FROM alerts a LEFT JOIN hosts h ON h.id = a.host_id
         WHERE a.message LIKE ?1 ESCAPE '\\' OR a.kind LIKE ?1 ESCAPE '\\' OR a.source LIKE ?1 ESCAPE '\\' ORDER BY a.ts DESC LIMIT 50"
    ))?;
    out.alerts = st.query_map([&pat], alert_row)?.collect::<Res<_>>()?;
    Ok(out)
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


// ---------- users ----------

#[derive(Clone, Debug)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub pw_hash: String,
    pub role: String,
    pub disabled: bool,
    pub must_change: bool,
    pub totp_secret: Option<String>,
    pub totp_last: i64,
    pub created: u64,
    pub last_login: u64,
}

const USER_COLS: &str = "id, username, pw_hash, role, disabled, must_change, totp_secret, totp_last, created, last_login";

fn user_row(r: &rusqlite::Row) -> Res<User> {
    Ok(User {
        id: r.get(0)?, username: r.get(1)?, pw_hash: r.get(2)?, role: r.get(3)?, disabled: r.get::<_, i64>(4)? != 0,
        must_change: r.get::<_, i64>(5)? != 0, totp_secret: r.get(6)?, totp_last: r.get(7)?,
        created: r.get::<_, i64>(8)? as u64, last_login: r.get::<_, i64>(9)? as u64,
    })
}

pub fn count_users(c: &Connection) -> Res<i64> {
    c.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
}

pub fn user_by_name(c: &Connection, name: &str) -> Res<Option<User>> {
    c.query_row(&format!("SELECT {USER_COLS} FROM users WHERE username = ?1"), [name], user_row).optional()
}

pub fn user_by_id(c: &Connection, id: i64) -> Res<Option<User>> {
    c.query_row(&format!("SELECT {USER_COLS} FROM users WHERE id = ?1"), [id], user_row).optional()
}

pub fn users(c: &Connection) -> Res<Vec<User>> {
    let mut st = c.prepare(&format!("SELECT {USER_COLS} FROM users ORDER BY username"))?;
    let rows = st.query_map([], user_row)?;
    rows.collect()
}

pub fn add_user(c: &Connection, name: &str, hash: &str, role: &str, must_change: bool) -> Res<()> {
    c.execute(
        "INSERT INTO users(username, pw_hash, role, must_change, created) VALUES(?1,?2,?3,?4,?5)",
        params![name, hash, role, must_change as i64, now_secs() as i64],
    )?;
    Ok(())
}

pub fn set_password(c: &Connection, id: i64, hash: &str, must_change: bool) -> Res<()> {
    c.execute("UPDATE users SET pw_hash = ?2, must_change = ?3 WHERE id = ?1", params![id, hash, must_change as i64])?;
    Ok(())
}

pub fn set_role(c: &Connection, id: i64, role: &str) -> Res<()> {
    c.execute("UPDATE users SET role = ?2 WHERE id = ?1", params![id, role])?;
    Ok(())
}

pub fn set_disabled(c: &Connection, id: i64, d: bool) -> Res<()> {
    c.execute("UPDATE users SET disabled = ?2 WHERE id = ?1", params![id, d as i64])?;
    Ok(())
}

pub fn set_totp(c: &Connection, id: i64, secret: Option<&str>) -> Res<()> {
    c.execute("UPDATE users SET totp_secret = ?2, totp_last = 0 WHERE id = ?1", params![id, secret])?;
    Ok(())
}

pub fn set_totp_last(c: &Connection, id: i64, step: i64) -> Res<()> {
    c.execute("UPDATE users SET totp_last = ?2 WHERE id = ?1", params![id, step])?;
    Ok(())
}

pub fn touch_login(c: &Connection, id: i64) -> Res<()> {
    c.execute("UPDATE users SET last_login = ?2 WHERE id = ?1", params![id, now_secs() as i64])?;
    Ok(())
}

pub fn delete_user(c: &Connection, id: i64) -> Res<()> {
    c.execute("DELETE FROM users WHERE id = ?1", [id])?;
    Ok(())
}

pub fn enabled_admins(c: &Connection) -> Res<i64> {
    c.query_row("SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0", [], |r| r.get(0))
}

// ---------- audit log (hash chained) ----------

fn audit_hash(prev: &str, ts: i64, actor: &str, action: &str, target: &str, detail: &str, ip: &str) -> String {
    sha256_hex(serde_json::json!([prev, ts, actor, action, target, detail, ip]).to_string().as_bytes())
}

/// Append an entry. Each entry commits to the previous one's hash, so editing or deleting a row in
/// the middle of the log is detectable with `netwatch audit --verify`.
pub fn audit(c: &Connection, actor: &str, action: &str, target: &str, detail: &str, ip: &str) -> Res<()> {
    let tx = rusqlite::Transaction::new_unchecked(c, rusqlite::TransactionBehavior::Immediate)?;
    let prev: String = tx
        .query_row("SELECT hash FROM audit ORDER BY id DESC LIMIT 1", [], |r| r.get(0))
        .optional()?
        .unwrap_or_else(|| "0".repeat(64));
    let (actor, action, target, detail, ip) = (clean(actor, 64), clean(action, 48), clean(target, 96), clean(detail, 400), clean(ip, 64));
    let ts = now_secs() as i64;
    let h = audit_hash(&prev, ts, &actor, &action, &target, &detail, &ip);
    tx.execute(
        "INSERT INTO audit(ts, actor, action, target, detail, ip, prev, hash) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![ts, actor, action, target, detail, ip, prev, h],
    )?;
    tx.commit()
}

#[derive(Clone, Debug)]
pub struct AuditRow {
    pub id: i64,
    pub ts: u64,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub detail: String,
    pub ip: String,
}

pub fn audit_rows(c: &Connection, limit: usize) -> Res<Vec<AuditRow>> {
    let mut st = c.prepare("SELECT id, ts, actor, action, target, detail, ip FROM audit ORDER BY id DESC LIMIT ?1")?;
    let rows = st.query_map([limit as i64], |r| {
        Ok(AuditRow { id: r.get(0)?, ts: r.get::<_, i64>(1)? as u64, actor: r.get(2)?, action: r.get(3)?, target: r.get(4)?, detail: r.get(5)?, ip: r.get(6)? })
    })?;
    rows.collect()
}

pub fn audit_head(c: &Connection) -> Res<Option<(i64, String)>> {
    c.query_row("SELECT id, hash FROM audit ORDER BY id DESC LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?))).optional()
}

/// Recompute the whole chain. Ok(n entries) or Err(description of the first inconsistency).
pub fn audit_verify(c: &Connection) -> Result<usize, String> {
    let mut st = c
        .prepare("SELECT id, ts, actor, action, target, detail, ip, prev, hash FROM audit ORDER BY id")
        .map_err(|e| e.to_string())?;
    let mut rows = st.query([]).map_err(|e| e.to_string())?;
    let mut prev = "0".repeat(64);
    let mut n = 0;
    while let Some(r) = rows.next().map_err(|e| e.to_string())? {
        let g = |i| r.get::<_, String>(i).map_err(|e| e.to_string());
        let id: i64 = r.get(0).map_err(|e| e.to_string())?;
        let ts: i64 = r.get(1).map_err(|e| e.to_string())?;
        let (stored_prev, hash) = (g(7)?, g(8)?);
        if stored_prev != prev {
            return Err(format!("entry {id}: chain broken (a previous entry was removed or altered)"));
        }
        if audit_hash(&stored_prev, ts, &g(2)?, &g(3)?, &g(4)?, &g(5)?, &g(6)?) != hash {
            return Err(format!("entry {id}: contents do not match their hash (entry was modified)"));
        }
        prev = hash;
        n += 1;
    }
    Ok(n)
}
