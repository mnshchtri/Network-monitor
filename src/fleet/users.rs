//! `netwatch server user ...` and `netwatch server audit ...`. Account administration is
//! deliberately CLI-only (needs shell access to the server), so a compromised dashboard
//! session can never create admins or change roles.

use super::auth::{self, ROLES};
use super::db::{self, User};
use super::server::{dir_of, open_db, read_secret};
use super::util::*;
use super::db::AlertRow;
use std::io::IsTerminal;

pub fn cli_actor() -> String {
    format!("cli:{}", std::env::var("SUDO_USER").or_else(|_| std::env::var("USER")).unwrap_or_else(|_| "unknown".into()))
}

const USER_HELP: &str = "\
Dashboard accounts (roles: viewer = read only, operator = + acknowledge alerts, admin = + audit log & sessions)

    netwatch server user add <name> [--role viewer|operator|admin] [--password-stdin] [--no-force-change]
    netwatch server user list
    netwatch server user passwd <name> [--password-stdin]     (user must change it at next login)
    netwatch server user role <name> <role>
    netwatch server user disable <name> | enable <name> | delete <name>
    netwatch server user totp <name>         Enable two-factor login (prints the secret to enrol)
    netwatch server user totp-off <name>
";

fn need_user(c: &rusqlite::Connection, name: &str) -> User {
    db::user_by_name(c, name).ok().flatten().unwrap_or_else(|| fail(&format!("no such user '{name}'")))
}

fn read_new_password(args: &[String], name: &str) -> String {
    let tty = std::io::stdin().is_terminal() && !has(args, "--password-stdin");
    let pw = read_secret(&format!("Password for {name}: "), tty);
    if tty && read_secret("Repeat password: ", true) != pw {
        fail("passwords do not match");
    }
    if let Err(e) = auth::password_policy(&pw, name) {
        fail(&e);
    }
    pw
}

/// Refuse changes that would leave the system with no enabled admin.
fn guard_last_admin(c: &rusqlite::Connection, u: &User, what: &str) {
    if u.role == "admin" && !u.disabled && db::enabled_admins(c).unwrap_or(0) <= 1 {
        fail(&format!("refusing to {what} the last enabled admin"));
    }
}

pub fn user_cmd(args: &[String]) {
    let (sub, rest) = match args.split_first() {
        Some((s, r)) => (s.as_str(), r),
        None => {
            print!("{USER_HELP}");
            return;
        }
    };
    let c = open_db(&dir_of(rest));
    let actor = cli_actor();
    let name = rest.first().filter(|a| !a.starts_with("--")).cloned();
    let need_name = || name.clone().unwrap_or_else(|| fail("a user name is required"));
    let log = |action: &str, target: &str, detail: &str| {
        let _ = db::audit(&c, &actor, action, target, detail, "");
    };
    match sub {
        "add" => {
            let n = need_name();
            if !auth::valid_username(&n) {
                fail("user names may use letters, digits, '.', '_' and '-' (max 32)");
            }
            let role = opt(rest, "--role").unwrap_or_else(|| "viewer".into());
            if !ROLES.contains(&role.as_str()) {
                fail("role must be viewer, operator or admin");
            }
            if db::user_by_name(&c, &n).ok().flatten().is_some() {
                fail("that user already exists");
            }
            let hash = auth::hash_password(&read_new_password(rest, &n));
            db::add_user(&c, &n, &hash, &role, !has(rest, "--no-force-change")).unwrap_or_else(|e| fail(&format!("{e}")));
            log("user.add", &n, &format!("role={role}"));
            println!("created {n} ({role}){}", if has(rest, "--no-force-change") { "" } else { "; must change the password at first login" });
        }
        "list" => {
            println!("{:<20} {:<9} {:<9} {:<4} {:<5} {:<20} {}", "USER", "ROLE", "STATUS", "2FA", "MUST", "LAST LOGIN", "CREATED");
            for u in db::users(&c).unwrap_or_else(|e| fail(&format!("{e}"))) {
                println!(
                    "{:<20} {:<9} {:<9} {:<4} {:<5} {:<20} {}",
                    u.username, u.role, if u.disabled { "disabled" } else { "active" },
                    if u.totp_secret.is_some() { "yes" } else { "no" }, if u.must_change { "yes" } else { "" },
                    if u.last_login == 0 { "never".into() } else { fmt_time(u.last_login) },
                    fmt_time(u.created)
                );
            }
        }
        "passwd" => {
            let u = need_user(&c, &need_name());
            let hash = auth::hash_password(&read_new_password(rest, &u.username));
            db::set_password(&c, u.id, &hash, true).unwrap_or_else(|e| fail(&format!("{e}")));
            log("user.passwd", &u.username, "password reset; change forced at next login");
            println!("password updated for {}; they must change it at next login (existing sessions end within the idle timeout)", u.username);
        }
        "role" => {
            let u = need_user(&c, &need_name());
            let role = rest.get(1).cloned().unwrap_or_else(|| fail("usage: user role <name> <role>"));
            if !ROLES.contains(&role.as_str()) {
                fail("role must be viewer, operator or admin");
            }
            if role != "admin" {
                guard_last_admin(&c, &u, "demote");
            }
            db::set_role(&c, u.id, &role).unwrap_or_else(|e| fail(&format!("{e}")));
            log("user.role", &u.username, &format!("{} -> {role}", u.role));
            println!("{} is now {role} (effective immediately)", u.username);
        }
        "disable" | "enable" => {
            let u = need_user(&c, &need_name());
            if sub == "disable" {
                guard_last_admin(&c, &u, "disable");
            }
            db::set_disabled(&c, u.id, sub == "disable").unwrap_or_else(|e| fail(&format!("{e}")));
            log(&format!("user.{sub}"), &u.username, "");
            println!("{} {}d (effective immediately, including open sessions)", u.username, sub);
        }
        "delete" => {
            let u = need_user(&c, &need_name());
            guard_last_admin(&c, &u, "delete");
            db::delete_user(&c, u.id).unwrap_or_else(|e| fail(&format!("{e}")));
            log("user.delete", &u.username, "");
            println!("deleted {}", u.username);
        }
        "totp" => {
            let u = need_user(&c, &need_name());
            let secret = auth::new_totp_secret();
            db::set_totp(&c, u.id, Some(&secret)).unwrap_or_else(|e| fail(&format!("{e}")));
            log("user.totp", &u.username, "two-factor enabled");
            println!("Two-factor enabled for {}.\n\nSecret (enter in your authenticator app): {secret}\nURI: {}\n\nTreat this like a password; it is shown only now.", u.username, auth::otpauth_uri(&u.username, &secret));
        }
        "totp-off" => {
            let u = need_user(&c, &need_name());
            db::set_totp(&c, u.id, None).unwrap_or_else(|e| fail(&format!("{e}")));
            log("user.totp-off", &u.username, "two-factor disabled");
            println!("two-factor disabled for {}", u.username);
        }
        _ => print!("{USER_HELP}"),
    }
}

pub fn audit_cmd(args: &[String]) {
    let c = open_db(&dir_of(args));
    if has(args, "--verify") {
        match db::audit_verify(&c) {
            Ok(n) => {
                let head = db::audit_head(&c).ok().flatten().map(|(_, h)| h).unwrap_or_default();
                println!("OK: {n} entries, chain intact.\nHead hash: {head}\n(Record the head hash somewhere the server cannot write to, to detect truncation or full rewrites.)");
            }
            Err(e) => fail(&format!("AUDIT LOG FAILED VERIFICATION: {e}")),
        }
        return;
    }
    let limit = opt(args, "--limit").and_then(|v| v.parse().ok()).unwrap_or(50usize);
    let rows = db::audit_rows(&c, limit).unwrap_or_else(|e| fail(&format!("{e}")));
    for r in rows.iter().rev() {
        if has(args, "--json") {
            println!("{}", serde_json::json!({"id": r.id, "time": fmt_time(r.ts), "actor": r.actor, "action": r.action, "target": r.target, "detail": r.detail, "ip": r.ip}));
        } else {
            println!("{}  {:<16} {:<16} {:<16} {} {}", fmt_time(r.ts), r.actor, r.action, r.target, r.detail, if r.ip.is_empty() { String::new() } else { format!("[{}]", r.ip) });
        }
    }
}


// ---------- bulk acknowledge ----------

pub const ACK_HELP: &str = "\
netwatch server ack - acknowledge many alerts at once (audited). Previews unless --yes is given.

    netwatch server ack [--source IP[,IP]] [--kind KIND[,KIND]] [--host NAME] [--contains TEXT]...
                        [--from 'YYYY-MM-DD HH:MM'] [--to 'YYYY-MM-DD HH:MM'] [--yes] [--dir D]

At least one filter is required (there is deliberately no 'acknowledge everything'). All filters must
match; --contains may be repeated and every occurrence must match. Times are UTC, like the audit log.
";

pub struct AckFilter {
    pub sources: Vec<String>,
    pub kinds: Vec<String>,
    pub host: Option<String>,
    pub contains: Vec<String>,
    pub from: Option<u64>,
    pub to: Option<u64>,
}

impl AckFilter {
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty() && self.kinds.is_empty() && self.host.is_none() && self.contains.is_empty() && self.from.is_none() && self.to.is_none()
    }
    pub fn matches(&self, a: &AlertRow) -> bool {
        !a.acked
            && (self.sources.is_empty() || self.sources.iter().any(|x| *x == a.source))
            && (self.kinds.is_empty() || self.kinds.iter().any(|k| k.eq_ignore_ascii_case(&a.kind)))
            && self.host.as_ref().map_or(true, |h| h.eq_ignore_ascii_case(&a.host))
            && self.contains.iter().all(|t| a.message.to_lowercase().contains(&t.to_lowercase()))
            && self.from.map_or(true, |t| a.ts >= t)
            && self.to.map_or(true, |t| a.ts <= t)
    }
}

/// "2026-11-14 22:50" or "2026-11-14 22:50:30" (UTC) -> unix seconds.
pub fn parse_utc(s: &str) -> Option<u64> {
    let (d, t) = s.trim().split_once(' ')?;
    let mut dp = d.split('-').map(|x| x.parse::<u32>().ok());
    let (y, m, day) = (dp.next()??, dp.next()??, dp.next()??);
    let mut tp = t.split(':').map(|x| x.parse::<u64>().ok());
    let (hh, mm, ss) = (tp.next()??, tp.next()??, tp.next().flatten().unwrap_or(0));
    if !(1..=12).contains(&m) || !(1..=31).contains(&day) || hh > 23 || mm > 59 || ss > 59 || y < 1970 {
        return None;
    }
    Some(ymd_to_unix(y as i32, m, day) + hh * 3600 + mm * 60 + ss)
}

pub fn ack_cmd(args: &[String]) {
    if has(args, "--help") || has(args, "-h") {
        print!("{ACK_HELP}");
        return;
    }
    let list = |name: &str| opt(args, name).map(|v| v.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect::<Vec<_>>()).unwrap_or_default();
    let time = |name: &str| opt(args, name).map(|v| parse_utc(&v).unwrap_or_else(|| fail(&format!("{name}: expected 'YYYY-MM-DD HH:MM' (UTC)"))));
    let mut contains = Vec::new();
    for (i, a) in args.iter().enumerate() {
        if a == "--contains" {
            contains.push(args.get(i + 1).cloned().unwrap_or_else(|| fail("--contains needs a value")));
        }
    }
    let f = AckFilter { sources: list("--source"), kinds: list("--kind"), host: opt(args, "--host"), contains, from: time("--from"), to: time("--to") };
    if f.is_empty() {
        fail("give at least one filter (--source, --kind, --host, --contains, --from, --to); see 'netwatch server ack --help'");
    }
    if f.sources.iter().any(|s| s.parse::<std::net::IpAddr>().is_err()) {
        fail("--source must be IP addresses");
    }
    let c = open_db(&dir_of(args));
    let all = db::alerts_filtered(&c, &db::AlertFilter { include_acked: false, limit: 100_000, ..Default::default() }).unwrap_or_else(|e| fail(&format!("{e}")));
    let hit: Vec<&AlertRow> = all.iter().filter(|a| f.matches(a)).collect();
    let mut by_kind: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for a in &hit {
        *by_kind.entry(a.kind.as_str()).or_default() += 1;
    }
    println!("{} of {} unacknowledged alert(s) match:", hit.len(), all.len());
    for (k, n) in &by_kind {
        println!("  {n:>4}  {k}");
    }
    if hit.is_empty() {
        return;
    }
    if !has(args, "--yes") {
        println!("\nPreview only. Add --yes to acknowledge them (recorded in the audit log).");
        return;
    }
    let tx = rusqlite::Transaction::new_unchecked(&c, rusqlite::TransactionBehavior::Immediate).unwrap_or_else(|e| fail(&format!("{e}")));
    for a in &hit {
        tx.execute("UPDATE alerts SET acked = 1 WHERE id = ?1", [a.id]).unwrap_or_else(|e| fail(&format!("{e}")));
    }
    tx.commit().unwrap_or_else(|e| fail(&format!("{e}")));
    // Record the filters, not housekeeping flags or data-directory paths.
    let mut desc_parts: Vec<String> = Vec::new();
    let mut it = std::env::args().skip(1).skip_while(|a| a != "ack").skip(1);
    while let Some(a) = it.next() {
        if a == "--dir" {
            it.next();
        } else if a != "--yes" {
            desc_parts.push(if a.contains(' ') { format!("'{a}'") } else { a });
        }
    }
    let desc = desc_parts.join(" ");
    let _ = db::audit(&c, &cli_actor(), "alert.ack_bulk", &format!("{} alerts", hit.len()), &clean(&desc, 300), "");
    println!("\nacknowledged {} alert(s).", hit.len());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(id: i64, ts: u64, kind: &str, source: &str, msg: &str, acked: bool) -> AlertRow {
        AlertRow { id, host: "h".into(), ts, kind: kind.into(), severity: "HIGH".into(), message: msg.into(), acked, assignee: String::new(), muted: false, source: source.into() }
    }

    #[test]
    fn utc_parsing() {
        assert_eq!(parse_utc("1970-01-01 00:00"), Some(0));
        assert_eq!(parse_utc("2026-11-14 17:05"), Some(ymd_to_unix(2026, 11, 14) + 17 * 3600 + 5 * 60));
        assert_eq!(parse_utc("2026-11-14 17:05:30"), Some(ymd_to_unix(2026, 11, 14) + 17 * 3600 + 5 * 60 + 30));
        for bad in ["", "2026-13-01 00:00", "2026-11-14", "2026-11-14 25:00", "x y"] {
            assert!(parse_utc(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn filters_are_anded_and_skip_acked() {
        let rows = vec![
            a(1, 100, "NEW_LISTENER", "", "new tcp listener on port 3306 opened by python3 (pid 1)", false),
            a(2, 100, "NEW_LISTENER", "", "new tcp listener on port 8080 opened by netwatch (pid 2)", false),
            a(3, 200, "PORT_SCAN", "10.0.0.1", "x", false),
            a(4, 300, "PORT_SCAN", "10.0.0.1", "x", true),
        ];
        let f = |kinds: &[&str], contains: &[&str], from: Option<u64>| AckFilter { sources: vec![], kinds: kinds.iter().map(|s| s.to_string()).collect(), host: None, contains: contains.iter().map(|s| s.to_string()).collect(), from, to: None };
        let ids = |f: &AckFilter| rows.iter().filter(|r| f.matches(r)).map(|r| r.id).collect::<Vec<_>>();
        assert_eq!(ids(&f(&["new_listener"], &["opened by python3"], None)), vec![1], "kind is case-insensitive; python3 listener only");
        assert_eq!(ids(&f(&["NEW_LISTENER"], &["on port 8080", "opened by netwatch"], None)), vec![2], "every --contains must match");
        assert_eq!(ids(&f(&["PORT_SCAN"], &[], None)), vec![3], "already-acknowledged alerts are never matched");
        assert_eq!(ids(&f(&[], &[], Some(150))), vec![3], "time filter");
        let src = AckFilter { sources: vec!["10.0.0.1".into()], kinds: vec![], host: None, contains: vec![], from: None, to: None };
        assert_eq!(ids(&src), vec![3]);
        assert!(AckFilter { sources: vec![], kinds: vec![], host: None, contains: vec![], from: None, to: None }.is_empty());
    }
}
