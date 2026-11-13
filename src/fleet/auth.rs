//! Password hashing, TOTP two-factor codes and account validation.

use super::util::*;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use sha2::Sha256;

pub const MIN_PW: usize = 12;
const ITER: u32 = 200_000;
const DUMMY: &str = "pbkdf2-sha256$200000$0000000000000000$0000000000000000000000000000000000000000000000000000000000000000";

pub fn hash_password(pw: &str) -> String {
    let salt = random_hex(16);
    let mut out = [0u8; 32];
    pbkdf2_hmac::<Sha256>(pw.as_bytes(), salt.as_bytes(), ITER, &mut out);
    format!("pbkdf2-sha256${ITER}${salt}${}", hex(&out))
}

pub fn verify_password(pw: &str, stored: &str) -> bool {
    let p: Vec<&str> = stored.split('$').collect();
    if p.len() != 4 || p[0] != "pbkdf2-sha256" {
        return false;
    }
    let Ok(iters) = p[1].parse::<u32>() else { return false };
    if iters == 0 || iters > 5_000_000 {
        return false;
    }
    let mut out = [0u8; 32];
    pbkdf2_hmac::<Sha256>(pw.as_bytes(), p[2].as_bytes(), iters, &mut out);
    ct_eq(hex(&out).as_bytes(), p[3].as_bytes())
}

/// Spend the same time as a real verification so unknown usernames are not distinguishable by timing.
pub fn dummy_verify(pw: &str) {
    let _ = verify_password(pw, DUMMY);
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn password_policy(pw: &str, username: &str) -> Result<(), String> {
    if pw.chars().count() < MIN_PW {
        return Err(format!("password must be at least {MIN_PW} characters"));
    }
    if pw.to_lowercase().contains(&username.to_lowercase()) {
        return Err("password must not contain the username".into());
    }
    Ok(())
}

pub fn valid_username(u: &str) -> bool {
    !u.is_empty() && u.len() <= 32 && u.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

pub const ROLES: [&str; 3] = ["viewer", "operator", "admin"];

pub fn role_rank(r: &str) -> u8 {
    ROLES.iter().position(|x| *x == r).map(|i| i as u8 + 1).unwrap_or(0)
}

// ---------- TOTP (RFC 6238, SHA-1, 6 digits, 30s) ----------

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn base32_encode(data: &[u8]) -> String {
    let (mut out, mut buf, mut bits) = (String::new(), 0u32, 0);
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            out.push(B32[((buf >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let (mut out, mut buf, mut bits) = (Vec::new(), 0u32, 0);
    for c in s.chars().filter(|c| !c.is_whitespace() && *c != '=') {
        let v = B32.iter().position(|x| *x as char == c.to_ascii_uppercase())? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            out.push((buf >> (bits - 8)) as u8);
            bits -= 8;
        }
    }
    Some(out)
}

pub fn new_totp_secret() -> String {
    let h = random_hex(20);
    let bytes: Vec<u8> = (0..20).map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap()).collect();
    base32_encode(&bytes)
}

fn hotp(key: &[u8], counter: u64, digits: u32) -> u32 {
    let mut m = Hmac::<Sha1>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(&counter.to_be_bytes());
    let h = m.finalize().into_bytes();
    let o = (h[19] & 0xf) as usize;
    let n = u32::from_be_bytes([h[o] & 0x7f, h[o + 1], h[o + 2], h[o + 3]]);
    n % 10u32.pow(digits)
}

/// Accept the current step and one either side (clock skew). Returns the matched step, and only
/// if it is newer than `last_step` so a code cannot be replayed.
pub fn totp_check(secret_b32: &str, code: &str, last_step: i64, now: u64) -> Option<i64> {
    let key = base32_decode(secret_b32)?;
    let code = code.trim();
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let cur = (now / 30) as i64;
    for step in cur - 1..=cur + 1 {
        if step > last_step && ct_eq(format!("{:06}", hotp(&key, step as u64, 6)).as_bytes(), code.as_bytes()) {
            return Some(step);
        }
    }
    None
}

pub fn otpauth_uri(user: &str, secret: &str) -> String {
    format!("otpauth://totp/netwatch:{user}?secret={secret}&issuer=netwatch&digits=6&period=30")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_vector() {
        // RFC 6238 appendix B, SHA-1, T=59 -> 94287082 (8 digits); last 6 digits are 287082.
        assert_eq!(hotp(b"12345678901234567890", 59 / 30, 8), 94287082);
        assert_eq!(hotp(b"12345678901234567890", 59 / 30, 6), 287082);
    }

    #[test]
    fn totp_replay_and_window() {
        let secret = base32_encode(b"12345678901234567890");
        let step = totp_check(&secret, "287082", 0, 59).unwrap();
        assert_eq!(step, 1);
        assert!(totp_check(&secret, "287082", step, 59).is_none(), "replay must be rejected");
        assert!(totp_check(&secret, "000000", 0, 59).is_none());
        assert!(totp_check(&secret, "28708", 0, 59).is_none());
    }

    #[test]
    fn base32_roundtrip() {
        let d = b"hello world, netwatch!";
        assert_eq!(base32_decode(&base32_encode(d)).unwrap(), d);
        assert_eq!(base32_encode(b"12345678901234567890"), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    }

    #[test]
    fn passwords() {
        let h = hash_password("a-long-test-password");
        assert!(verify_password("a-long-test-password", &h) && !verify_password("wrong", &h));
        assert!(password_policy("short", "bob").is_err() && password_policy("bob-is-in-this-pass", "bob").is_err());
        assert!(password_policy("a-long-test-password", "bob").is_ok());
    }
}
