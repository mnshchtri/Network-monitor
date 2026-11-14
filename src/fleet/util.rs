use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn is_root() -> bool {
    fs::metadata("/proc/self").map(|m| m.uid() == 0).unwrap_or(false)
}

/// System directory when root, otherwise a per-user directory.
pub fn default_dir(system: &str, user_rel: &str) -> PathBuf {
    if is_root() {
        PathBuf::from(system)
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        Path::new(&home).join(user_rel)
    }
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

pub fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .expect("cannot read /dev/urandom");
    hex(&buf)
}

/// Write a file readable only by its owner (private keys, tokens).
pub fn write_secret(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut f = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
    f.write_all(data)
}

pub fn ensure_dir(path: &Path) -> std::io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Strip control characters and cap length. Everything an agent sends is untrusted and ends up
/// on an operator's terminal, so escape sequences must never survive ingestion.
pub fn clean(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}

pub fn hostname() -> String {
    fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

pub fn kernel() -> String {
    let rel = fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    format!("Linux {}", rel.trim())
}

/// Current year from the unix clock (UTC).
pub fn current_year() -> i32 {
    year_at(now_secs())
}

/// Calendar year (UTC) of a unix timestamp.
pub fn year_at(ts: u64) -> i32 {
    let days = (ts / 86400) as i64 + 719468;
    let era = days.div_euclid(146097);
    let doe = days.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + if m <= 2 { 1 } else { 0 }) as i32
}

pub fn fmt_time(ts: u64) -> String {
    let secs = ts as i64;
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}", rem / 3600, rem % 3600 / 60, rem % 60)
}

pub fn ago(ts: u64) -> String {
    let d = now_secs().saturating_sub(ts);
    match d {
        0..=59 => format!("{d}s ago"),
        60..=3599 => format!("{}m ago", d / 60),
        3600..=86399 => format!("{}h ago", d / 3600),
        _ => format!("{}d ago", d / 86400),
    }
}

/// Value of `--name value` in an argument list.
pub fn opt(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

pub fn has(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

pub fn fail(msg: &str) -> ! {
    eprintln!("netwatch: {msg}");
    std::process::exit(1);
}

/// Unix time of 00:00:00 UTC on the given civil date (Howard Hinnant's days_from_civil).
pub fn ymd_to_unix(y: i32, m: u32, d: u32) -> u64 {
    let y = y as i64 - if m <= 2 { 1 } else { 0 };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    ((era * 146097 + doe - 719468) * 86400).max(0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates() {
        assert_eq!(ymd_to_unix(1970, 1, 1), 0);
        assert_eq!(ymd_to_unix(2000, 3, 1), 951868800);
        assert_eq!(ymd_to_unix(2031, 1, 1), 1924992000);
        assert_eq!(year_at(1924992000), 2031);
        assert_eq!(year_at(1924991999), 2030);
        assert_eq!(fmt_time(ymd_to_unix(2026, 11, 14)), "2026-11-14 00:00:00");
    }
}
