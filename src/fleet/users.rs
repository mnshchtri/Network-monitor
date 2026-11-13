//! `netwatch server user ...` and `netwatch server audit ...`. Account administration is
//! deliberately CLI-only (needs shell access to the server), so a compromised dashboard
//! session can never create admins or change roles.

use super::auth::{self, ROLES};
use super::db::{self, User};
use super::server::{dir_of, open_db, read_secret};
use super::util::*;
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
