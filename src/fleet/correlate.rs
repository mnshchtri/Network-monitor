//! Correlation: turn a flat stream of alerts into incidents (attack chains) and score host risk.

use super::db::AlertRow;
use super::query;
use super::rules;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

const SOURCE_GAP: u64 = 30 * 60; // a quiet half hour ends a source's campaign
const HOST_GAP: u64 = 15 * 60;

pub struct Stage {
    pub tactic_id: String,
    pub tactic: String,
    pub techniques: Vec<String>,
    pub count: u32,
}

pub struct Incident {
    pub id: String,
    pub kind: &'static str, // "source" or "host"
    pub title: String,
    pub level: u8,
    pub open: bool,
    pub first: u64,
    pub last: u64,
    pub source: Option<String>,
    pub hosts: Vec<String>,
    pub stages: Vec<Stage>,
    pub alerts: Vec<usize>, // indexes into the slice passed to `correlate`, oldest first
    pub notes: Vec<String>,
}

fn port_tokens(msg: &str) -> HashSet<&str> {
    msg.split(|c: char| !c.is_ascii_digit()).filter(|t| !t.is_empty()).collect()
}

/// "new tcp listener on port 8089 opened by ..." -> "8089"
fn listener_port(msg: &str) -> Option<&str> {
    let rest = msg.split("on port ").nth(1)?;
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    (end > 0).then(|| &rest[..end])
}

fn build(alerts: &[AlertRow], idxs: &[usize], kind: &'static str, key: &str, source: Option<&str>, notes: Vec<String>, bonus: u8) -> Incident {
    let mut order: Vec<usize> = idxs.to_vec();
    order.sort_by_key(|&i| (alerts[i].ts, alerts[i].id));
    let mut stages: Vec<Stage> = Vec::new();
    let mut hosts: BTreeSet<String> = BTreeSet::new();
    let (mut level, mut open) = (0u8, false);
    for &i in &order {
        let a = &alerts[i];
        let e = query::enrich(a);
        level = level.max(e.level);
        open |= !a.acked;
        hosts.insert(a.host.clone());
        let (tid, tname, tech) = e.rule.map_or(("", "", ""), |r| (r.tactic, rules::tactic_name(r.tactic), r.technique));
        let label = if tid.is_empty() { ("other", "Other activity") } else { (tid, tname) };
        match stages.iter_mut().find(|s| s.tactic_id == label.0) {
            Some(s) => {
                s.count += 1;
                if !tech.is_empty() && !s.techniques.iter().any(|t| t == tech) {
                    s.techniques.push(tech.to_string());
                }
            }
            None => stages.push(Stage { tactic_id: label.0.to_string(), tactic: label.1.to_string(), techniques: if tech.is_empty() { vec![] } else { vec![tech.to_string()] }, count: 1 }),
        }
    }
    let real_stages = stages.iter().filter(|s| s.tactic_id != "other").count();
    let chain = if real_stages == 0 { "Suspicious activity".to_string() } else { stages.iter().filter(|s| s.tactic_id != "other").map(|s| s.tactic.as_str()).collect::<Vec<_>>().join(" → ") };
    let level = (level + bonus + u8::from(real_stages >= 2) + u8::from(hosts.len() >= 2)).min(15);
    Incident {
        id: format!("{kind}:{key}:{}", alerts[order[0]].ts),
        kind,
        title: match source {
            Some(s) => format!("{chain} from {s}"),
            None => format!("{chain} on {}", hosts.iter().next().cloned().unwrap_or_default()),
        },
        level,
        open,
        first: alerts[order[0]].ts,
        last: alerts[*order.last().unwrap()].ts,
        source: source.map(String::from),
        hosts: hosts.into_iter().collect(),
        stages,
        alerts: order,
        notes,
    }
}

/// Group alerts into incidents. Muted alerts are ignored.
///  * Per source address: alerts from one source form a campaign until it goes quiet for 30 min.
///  * A NEW_LISTENER shortly before a source touched that port on that host is attached to the
///    campaign (a new service that was immediately accessed from outside is a strong signal).
///  * Alerts without a source cluster per host (15 min gap): floods, resets, agent loss, new ports.
pub fn correlate(alerts: &[AlertRow]) -> Vec<Incident> {
    let mut order: Vec<usize> = (0..alerts.len()).filter(|&i| !alerts[i].muted && alerts[i].kind != "HOST_UP").collect();
    order.sort_by_key(|&i| (alerts[i].ts, alerts[i].id));
    let mut by_src: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for &i in &order {
        if !alerts[i].source.is_empty() {
            by_src.entry(alerts[i].source.as_str()).or_default().push(i);
        }
    }
    let mut incidents: Vec<(Incident, String)> = Vec::new(); // (incident, source)
    for (src, idxs) in &by_src {
        let mut session: Vec<usize> = Vec::new();
        let mut flush = |session: &mut Vec<usize>| {
            if session.is_empty() {
                return;
            }
            let max_level = session.iter().map(|&i| query::enrich(&alerts[i]).level).max().unwrap_or(0);
            // Low-level chatter (INFO alerts) never makes an incident: at least one medium-or-worse alert is needed.
            if (session.len() >= 2 && max_level >= 7) || max_level >= 10 {
                incidents.push((build(alerts, session, "source", src, Some(src), vec![], 0), src.to_string()));
            }
            session.clear();
        };
        for &i in idxs {
            if let Some(&prev) = session.last() {
                if alerts[i].ts.saturating_sub(alerts[prev].ts) > SOURCE_GAP {
                    flush(&mut session);
                }
            }
            session.push(i);
        }
        flush(&mut session);
    }

    // New-listener -> accessed-from-outside correlation.
    let mut used: HashSet<usize> = HashSet::new();
    let mut attached: Vec<Vec<(String, String)>> = vec![Vec::new(); incidents.len()]; // (host, port) per incident
    for &li in order.iter().filter(|&&i| alerts[i].kind == "NEW_LISTENER") {
        let Some(port) = listener_port(&alerts[li].message) else { continue };
        for (n, (inc, _)) in incidents.iter_mut().enumerate().filter(|(_, (inc, _))| inc.kind == "source") {
            let host_hit = inc.alerts.iter().any(|&i| alerts[i].host == alerts[li].host);
            let touched = inc.alerts.iter().any(|&i| alerts[i].host == alerts[li].host && port_tokens(&alerts[i].message).contains(port));
            let timely = alerts[li].ts + SOURCE_GAP >= inc.first && alerts[li].ts <= inc.last;
            if host_hit && touched && timely && !inc.alerts.contains(&li) {
                inc.alerts.push(li);
                inc.alerts.sort_by_key(|&i| (alerts[i].ts, alerts[i].id));
                attached[n].push((alerts[li].host.clone(), port.to_string()));
                used.insert(li);
            }
        }
    }
    // Rebuild attached incidents so stages/hosts/open reflect the added alerts, with ONE note per host.
    let incidents: Vec<Incident> = incidents
        .into_iter()
        .zip(attached)
        .map(|((inc, src), att)| {
            if att.is_empty() {
                return inc;
            }
            let mut by_host: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for (h, p) in att {
                by_host.entry(h).or_default().push(p);
            }
            let notes: Vec<String> = by_host
                .into_iter()
                .map(|(h, mut ports)| {
                    ports.sort_by_key(|p| p.parse::<u32>().unwrap_or(0));
                    ports.dedup();
                    format!("{} new listener{} on port{} {} ({h}) {} accessed from {src} right after opening", ports.len(), if ports.len() == 1 { "" } else { "s" }, if ports.len() == 1 { "" } else { "s" }, ports.join(", "), if ports.len() == 1 { "was" } else { "were" })
                })
                .collect();
            build(alerts, &inc.alerts, "source", &src, Some(&src), notes, 2)
        })
        .collect();
    let mut incidents = incidents;

    // Host clusters for everything without a source.
    let mut by_host: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for &i in &order {
        if alerts[i].source.is_empty() && !used.contains(&i) {
            by_host.entry(alerts[i].host.as_str()).or_default().push(i);
        }
    }
    for (host, idxs) in by_host {
        let mut session: Vec<usize> = Vec::new();
        let mut done: Vec<Vec<usize>> = Vec::new();
        for &i in &idxs {
            if let Some(&prev) = session.last() {
                if alerts[i].ts.saturating_sub(alerts[prev].ts) > HOST_GAP {
                    done.push(std::mem::take(&mut session));
                }
            }
            session.push(i);
        }
        if !session.is_empty() {
            done.push(session);
        }
        for s in done {
            let max_level = s.iter().map(|&i| query::enrich(&alerts[i]).level).max().unwrap_or(0);
            if (s.len() >= 2 && max_level >= 7) || max_level >= 10 {
                incidents.push(build(alerts, &s, "host", host, None, vec![], 0));
            }
        }
    }
    incidents.sort_by(|a, b| b.open.cmp(&a.open).then(b.level.cmp(&a.level)).then(b.last.cmp(&a.last)));
    incidents.truncate(200);
    incidents
}

// ---------------- host risk ----------------

pub struct RiskInput {
    pub status: String,
    pub is_root: bool,
    pub cert_days: i64,
    pub risky_exposed: u32,
    /// (level, age in seconds) of each unacknowledged, un-muted alert in the last 24 h
    pub alerts: Vec<(u8, u64)>,
}

pub fn rating(score: u32) -> &'static str {
    match score {
        0..=24 => "low",
        25..=49 => "elevated",
        50..=74 => "high",
        _ => "critical",
    }
}

/// A transparent 0-100 score: every contribution is returned so the UI can explain it.
pub fn host_risk(i: &RiskInput) -> (u32, Vec<(String, u32)>) {
    let mut factors: Vec<(String, u32)> = Vec::new();
    let mut alert_pts = 0.0f64;
    for (level, age) in &i.alerts {
        let w = match level {
            12..=15 => 12.0,
            10..=11 => 8.0,
            7..=9 => 4.0,
            4..=6 => 2.0,
            _ => 0.0,
        };
        let decay = if *age < 3600 { 1.0 } else if *age < 6 * 3600 { 0.7 } else { 0.4 };
        alert_pts += w * decay;
    }
    let alert_pts = (alert_pts.round() as u32).min(60);
    if alert_pts > 0 {
        factors.push((format!("{} open alert(s) in the last 24 h, weighted by level and recency", i.alerts.len()), alert_pts));
    }
    let exp = (i.risky_exposed * 15).min(30);
    if exp > 0 {
        factors.push((format!("{} risky service(s) reachable from the network", i.risky_exposed), exp));
    }
    if i.status == "down" {
        factors.push(("agent is not reporting".into(), 20));
    }
    if !i.is_root && i.status != "pending" {
        factors.push(("agent without root: reduced visibility".into(), 5));
    }
    if i.cert_days < 0 {
        factors.push(("agent certificate has expired".into(), 10));
    } else if i.cert_days < 90 {
        factors.push(("agent certificate expires within 90 days".into(), 5));
    }
    let total = factors.iter().map(|f| f.1).sum::<u32>().min(100);
    (total, factors)
}

pub fn risky_by_host(rows: &[super::insights::Listener]) -> HashMap<String, u32> {
    let mut seen: HashSet<(String, String, u16)> = HashSet::new();
    let mut out: HashMap<String, u32> = HashMap::new();
    for l in rows {
        if super::insights::scope(&l.addr) == "loopback" {
            continue;
        }
        if super::insights::service(l.port).map_or(false, |s| s.risk == super::insights::Risk::High) && seen.insert((l.host_id.clone(), l.proto.clone(), l.port)) {
            *out.entry(l.host_id.clone()).or_default() += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(id: i64, ts: u64, host: &str, kind: &str, sev: &str, src: &str, msg: &str) -> AlertRow {
        AlertRow { id, host: host.into(), ts, kind: kind.into(), severity: sev.into(), message: msg.into(), acked: false, assignee: String::new(), muted: false, source: src.into() }
    }

    #[test]
    fn campaign_chain_and_listener_correlation() {
        let alerts = vec![
            a(1, 1000, "web", "NEW_LISTENER", "HIGH", "", "new tcp listener on port 3306 opened by mysqld (reachable externally)"),
            a(2, 1100, "web", "PORT_SCAN", "HIGH", "203.0.113.9", "203.0.113.9 touched 5 distinct local ports in 60s: 22,80,443,3306,8080"),
            a(3, 1300, "web", "BRUTE_FORCE", "HIGH", "203.0.113.9", "203.0.113.9 opened 40 connections to SSH (port 22) in 60s"),
            a(4, 1400, "web", "CONN_FLOOD", "HIGH", "203.0.113.9", "203.0.113.9 currently holds 150 inbound connections"),
            a(5, 90_000, "web", "PORT_SCAN", "HIGH", "198.51.100.1", "198.51.100.1 touched 6 distinct local ports in 60s: 1,2,3,4,5,6"),
        ];
        let inc = correlate(&alerts);
        let main = inc.iter().find(|i| i.source.as_deref() == Some("203.0.113.9")).expect("campaign incident");
        assert_eq!(main.alerts.len(), 4, "3 from the source + the listener it then hit: {:?}", main.alerts);
        let tactics: Vec<&str> = main.stages.iter().map(|s| s.tactic.as_str()).collect();
        assert_eq!(tactics, vec!["Command and Control", "Discovery", "Credential Access", "Impact"], "stages in the order they happened");
        assert!(main.title.contains("→") && main.title.ends_with("from 203.0.113.9"), "{}", main.title);
        assert!(main.notes.len() == 1 && main.notes[0].contains("3306") && main.notes[0].contains("accessed from 203.0.113.9"), "{:?}", main.notes);
        assert!(main.level >= 14, "multi-stage + listener correlation raises the level: {}", main.level);
        assert!(main.open && main.first == 1000 && main.last == 1400);
        let late = inc.iter().find(|i| i.source.as_deref() == Some("198.51.100.1")).expect("separate day => separate incident");
        assert_eq!(late.alerts.len(), 1, "a single HIGH alert is still an incident");
        assert_eq!(inc.len(), 2, "no stray host incident for the attached listener");
    }

    #[test]
    fn source_gap_splits_campaigns_and_muted_and_acked() {
        let alerts = vec![
            a(1, 1000, "h", "PORT_SCAN", "HIGH", "1.1.1.1", "x"), a(2, 1100, "h", "CONN_BURST", "MEDIUM", "1.1.1.1", "y"),
            a(3, 1100 + 3600, "h", "PORT_SCAN", "HIGH", "1.1.1.1", "z"),
        ];
        assert_eq!(correlate(&alerts).len(), 2, "an hour of quiet splits one source into two campaigns");
        let mut m = alerts.clone();
        m.iter_mut().for_each(|x| x.muted = true);
        assert!(correlate(&m).is_empty(), "muted alerts never form incidents");
        let mut k = vec![a(1, 1000, "h", "PORT_SCAN", "HIGH", "1.1.1.1", "x"), a(2, 1010, "h", "CONN_BURST", "MEDIUM", "1.1.1.1", "y")];
        k.iter_mut().for_each(|x| x.acked = true);
        assert!(!correlate(&k)[0].open, "all acknowledged => closed");
    }

    #[test]
    fn host_clusters_for_sourceless_alerts() {
        let alerts = vec![
            a(1, 1000, "db", "SYN_FLOOD", "HIGH", "", "50 half-open"), a(2, 1100, "db", "LISTEN_OVERFLOW", "MEDIUM", "", "drops"),
            a(3, 1200, "db", "HOST_UP", "INFO", "", "back"), a(4, 50_000, "db", "HOST_DOWN", "HIGH", "", "silent"),
            a(5, 1300, "web", "RST_STORM", "MEDIUM", "", "resets"),
        ];
        let inc = correlate(&alerts);
        let db = inc.iter().find(|i| i.hosts == vec!["db".to_string()] && i.alerts.len() == 2).expect("db cluster");
        assert!(db.title.ends_with("on db") && db.source.is_none() && db.kind == "host");
        assert!(!inc.iter().any(|i| i.alerts.contains(&2)), "HOST_UP (index 2) never creates or joins incidents");
        assert!(!inc.iter().any(|i| i.alerts.contains(&3)), "a lone HOST_DOWN is level 9, below the single-alert bar");
        assert!(!inc.iter().any(|i| i.hosts == vec!["web".to_string()]), "one MEDIUM reset storm alone is below the bar");
    }

    #[test]
    fn info_chatter_is_not_an_incident() {
        let alerts = vec![
            a(1, 1000, "h", "NEW_LISTENER", "INFO", "", "new tcp listener on port 18870 opened by netwatch (pid 1)"),
            a(2, 1010, "h", "NEW_LISTENER", "INFO", "", "new tcp listener on port 18871 opened by netwatch (pid 1)"),
            a(3, 1020, "h", "CONN_BURST", "INFO", "9.9.9.9", "a"), a(4, 1030, "h", "CONN_BURST", "INFO", "9.9.9.9", "b"),
        ];
        assert!(correlate(&alerts).is_empty(), "INFO-level alerts alone are never an incident");
    }

    #[test]
    fn risk_scoring_is_explainable() {
        let calm = RiskInput { status: "up".into(), is_root: true, cert_days: 900, risky_exposed: 0, alerts: vec![] };
        assert_eq!(host_risk(&calm).0, 0);
        let bad = RiskInput { status: "down".into(), is_root: false, cert_days: 30, risky_exposed: 4, alerts: vec![(12, 60), (12, 90), (10, 7200), (3, 10)] };
        let (score, f) = host_risk(&bad);
        assert_eq!(f.iter().map(|x| x.1).sum::<u32>(), score);
        assert!(f.iter().any(|x| x.0.contains("risky service") && x.1 == 30), "exposure is capped at 30: {f:?}");
        assert!(f.iter().any(|x| x.0.contains("not reporting") && x.1 == 20));
        assert_eq!(rating(score), "critical");
        assert_eq!((rating(0), rating(25), rating(50), rating(75)), ("low", "elevated", "high", "critical"));
        let cap = RiskInput { status: "down".into(), is_root: false, cert_days: -5, risky_exposed: 9, alerts: vec![(14, 1); 50] };
        assert_eq!(host_risk(&cap).0, 100, "score never exceeds 100");
    }
}
