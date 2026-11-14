//! A small, safe query language for the event explorer (in the spirit of Wazuh/Kibana discover).
//!
//!   src:203.0.113. level>=10 -mitre:T1046 host:web*  "connection flood"  ack:false  assigned:me
//!
//! Terms are ANDed; `a,b` inside a value is OR; a leading `-` negates; quotes keep spaces.
//! Everything is evaluated in Rust over already-fetched rows, so a query can never reach SQL.

use super::db::AlertRow;
use super::rules::{self, Rule};

#[derive(Debug, Clone, Copy, PartialEq)]
enum Op {
    Eq,
    Ge,
    Le,
    Gt,
    Lt,
}

#[derive(Debug)]
struct Clause {
    neg: bool,
    field: &'static str, // "" = free text
    op: Op,
    vals: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Query {
    clauses: Vec<Clause>,
    me: String,
}

pub struct Enriched<'a> {
    pub a: &'a AlertRow,
    pub rule: Option<&'static Rule>,
    pub level: u8,
}

pub fn enrich(a: &AlertRow) -> Enriched<'_> {
    let rule = rules::by_kind(&a.kind);
    Enriched { a, rule, level: rules::level_for(rule, &a.severity) }
}

pub const FIELDS: &str = "host kind severity source rule level mitre tactic group ack muted assignee msg";

fn canon(f: &str) -> Option<&'static str> {
    Some(match f {
        "host" | "agent" => "host",
        "kind" | "type" | "alert" => "kind",
        "severity" | "sev" => "severity",
        "source" | "src" | "ip" => "source",
        "rule" | "rule.id" => "rule",
        "level" | "rule.level" => "level",
        "mitre" | "technique" | "rule.mitre" => "mitre",
        "tactic" => "tactic",
        "group" | "rule.groups" => "group",
        "ack" | "acked" => "ack",
        "muted" => "muted",
        "assignee" | "assigned" => "assignee",
        "msg" | "message" | "text" => "msg",
        _ => return None,
    })
}

fn tokens(q: &str) -> Result<Vec<String>, String> {
    let (mut out, mut cur, mut quoted) = (Vec::new(), String::new(), false);
    for ch in q.chars() {
        match ch {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if quoted {
        return Err("unclosed quote in query".into());
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    Ok(out)
}

fn truthy(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "true" | "yes" | "1" => Some(true),
        "false" | "no" | "0" => Some(false),
        _ => None,
    }
}

/// Returns the query plus warnings (e.g. an unknown field name that was treated as plain text).
pub fn parse(q: &str, me: &str) -> Result<(Query, Vec<String>), String> {
    let mut query = Query { clauses: Vec::new(), me: me.to_string() };
    let mut warnings = Vec::new();
    for tok in tokens(q)? {
        let (neg, body) = match tok.strip_prefix('-') {
            Some(rest) if !rest.is_empty() => (true, rest.to_string()),
            _ => (false, tok.clone()),
        };
        let name_len = body.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '_').count();
        let (name, rest) = body.split_at(name_len);
        let op = [(">=", Op::Ge), ("<=", Op::Le), (">", Op::Gt), ("<", Op::Lt), (":", Op::Eq)].iter().find(|(s, _)| rest.starts_with(s)).copied();
        match (op, canon(&name.to_ascii_lowercase())) {
            (Some((sym, op)), Some(field)) if !name.is_empty() => {
                let value = &rest[sym.len()..];
                if value.is_empty() {
                    return Err(format!("'{name}{sym}' needs a value"));
                }
                if field != "level" && op != Op::Eq {
                    return Err(format!("only 'level' supports {sym}; use {name}:value"));
                }
                let vals: Vec<String> = value.split(',').map(|v| v.trim().to_string()).filter(|v| !v.is_empty()).collect();
                if vals.is_empty() {
                    return Err(format!("'{name}' needs a value"));
                }
                match field {
                    "level" => {
                        if vals.iter().any(|v| v.parse::<u8>().map_or(true, |n| n > 15)) {
                            return Err("level must be a number from 0 to 15".into());
                        }
                    }
                    "rule" => {
                        if vals.iter().any(|v| v.parse::<u32>().is_err()) {
                            return Err("rule must be a numeric rule id, e.g. rule:100110".into());
                        }
                    }
                    "ack" | "muted" => {
                        if vals.iter().any(|v| truthy(v).is_none()) {
                            return Err(format!("{name} must be true or false"));
                        }
                    }
                    _ => {}
                }
                query.clauses.push(Clause { neg, field, op, vals });
            }
            (Some((_, _)), None) if !name.is_empty() && rest.starts_with(':') && rest.len() > 1 && !rest.starts_with("::") && !rest.starts_with("://") && name.chars().all(|c| c.is_ascii_alphabetic() || c == '.' || c == '_') => {
                warnings.push(format!("unknown field '{name}' was searched as plain text (fields: {FIELDS})"));
                query.clauses.push(Clause { neg, field: "", op: Op::Eq, vals: vec![tok.trim_start_matches('-').to_string()] });
            }
            _ => query.clauses.push(Clause { neg, field: "", op: Op::Eq, vals: vec![body] }),
        }
    }
    Ok((query, warnings))
}

fn has(hay: &str, needle: &str) -> bool {
    hay.to_ascii_lowercase().contains(&needle.to_ascii_lowercase())
}

/// Simple `*` wildcard support on top of substring matching ("web*" = starts with "web").
fn text_match(hay: &str, pat: &str) -> bool {
    let (h, p) = (hay.to_ascii_lowercase(), pat.to_ascii_lowercase());
    if !p.contains('*') {
        return h.contains(&p);
    }
    let parts: Vec<&str> = p.split('*').collect();
    let mut pos = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        match h[pos..].find(part) {
            Some(at) => {
                if i == 0 && !p.starts_with('*') && at != 0 {
                    return false;
                }
                pos += at + part.len();
            }
            None => return false,
        }
    }
    !(!p.ends_with('*') && pos != h.len() && !parts.last().map_or(true, |l| l.is_empty()))
}

impl Query {
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.clauses.is_empty()
    }

    fn eval(&self, c: &Clause, e: &Enriched) -> bool {
        let a = e.a;
        c.vals.iter().any(|v| match c.field {
            "host" => text_match(&a.host, v),
            "kind" => a.kind.eq_ignore_ascii_case(v),
            "severity" => a.severity.eq_ignore_ascii_case(v),
            "source" => text_match(&a.source, v),
            "rule" => e.rule.map_or(false, |r| v.parse::<u32>().ok() == Some(r.id)),
            "level" => {
                let n: u8 = v.parse().unwrap_or(0);
                match c.op {
                    Op::Eq => e.level == n,
                    Op::Ge => e.level >= n,
                    Op::Le => e.level <= n,
                    Op::Gt => e.level > n,
                    Op::Lt => e.level < n,
                }
            }
            "mitre" => e.rule.map_or(false, |r| {
                let (want, have) = (v.to_ascii_uppercase(), r.technique);
                !have.is_empty() && (have == want || have.starts_with(&format!("{want}.")))
            }),
            "tactic" => e.rule.map_or(false, |r| !r.tactic.is_empty() && (r.tactic.eq_ignore_ascii_case(v) || has(rules::tactic_name(r.tactic), v))),
            "group" => e.rule.map_or(false, |r| r.groups.iter().any(|g| g.eq_ignore_ascii_case(v))),
            "ack" => a.acked == truthy(v).unwrap_or(false),
            "muted" => a.muted == truthy(v).unwrap_or(false),
            "assignee" => match v.to_ascii_lowercase().as_str() {
                "me" => !self.me.is_empty() && a.assignee.eq_ignore_ascii_case(&self.me),
                "none" | "nobody" => a.assignee.is_empty(),
                _ => a.assignee.eq_ignore_ascii_case(v),
            },
            "msg" => text_match(&a.message, v),
            _ => text_match(&a.message, v) || has(&a.kind, v) || text_match(&a.host, v) || text_match(&a.source, v) || e.rule.map_or(false, |r| has(r.name, v) || has(r.technique, v)),
        })
    }

    pub fn matches(&self, e: &Enriched) -> bool {
        self.clauses.iter().all(|c| self.eval(c, e) != c.neg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(kind: &str, sev: &str, host: &str, source: &str, msg: &str) -> AlertRow {
        AlertRow { id: 1, host: host.into(), ts: 0, kind: kind.into(), severity: sev.into(), message: msg.into(), acked: false, assignee: String::new(), muted: false, source: source.into() }
    }
    fn run(q: &str, a: &AlertRow) -> bool {
        let (q, _) = parse(q, "alice").unwrap();
        q.matches(&enrich(a))
    }

    #[test]
    fn fields_and_ops() {
        let a = alert("PORT_SCAN", "HIGH", "web-1", "203.0.113.9", "203.0.113.9 touched 5 ports");
        assert!(run("", &a) && run("kind:port_scan", &a) && run("sev:high", &a) && run("host:web*", &a) && run("src:203.0.113.", &a));
        assert!(run("level>=10", &a) && run("level:10", &a) && !run("level>10", &a) && run("level<=10", &a));
        assert!(run("rule:100110", &a) && run("mitre:T1046", &a) && run("tactic:discovery", &a) && run("tactic:TA0007", &a) && run("group:recon", &a));
        assert!(run("kind:port_scan,brute_force", &a) && !run("kind:brute_force,syn_flood", &a), "comma = OR");
        assert!(run("-kind:brute_force", &a) && !run("-kind:port_scan", &a), "dash = NOT");
        assert!(run("ack:false muted:false assigned:none", &a) && !run("ack:true", &a));
        assert!(run("touched", &a) && run("\"touched 5\"", &a) && !run("\"touched 6\"", &a), "free text and quotes");
        assert!(run("level>=10 -mitre:T1110 src:203.* host:web-1", &a), "terms are ANDed");
    }

    #[test]
    fn subtechniques_and_assignee() {
        let a = alert("SYN_FLOOD", "HIGH", "h", "", "x");
        assert!(run("mitre:T1498", &a) && run("mitre:T1498.001", &a) && !run("mitre:T1499", &a));
        let mut b = alert("HOST_UP", "INFO", "h", "", "x");
        b.assignee = "alice".into();
        assert!(run("assigned:me", &b) && run("assigned:alice", &b) && !run("assigned:bob", &b));
        assert!(!run("mitre:T1046", &b), "rules without a technique never match mitre");
    }

    #[test]
    fn wildcards() {
        assert!(text_match("web-prod-1", "web*") && text_match("web-prod-1", "*1") && text_match("web-prod-1", "w*d-1") && !text_match("web-prod-1", "*db*"));
        assert!(text_match("a.b.c", "a.b") && !text_match("web-prod-1", "prod*"));
    }

    #[test]
    fn errors_and_warnings() {
        for bad in ["level>=x", "level>=99", "rule:abc", "ack:maybe", "kind>5", "host:", "\"open"] {
            assert!(parse(bad, "me").is_err(), "{bad} should be rejected");
        }
        let (_, w) = parse("severty:high", "me").unwrap();
        assert_eq!(w.len(), 1, "unknown field warns");
        let (q, w) = parse("2001:db8::1 http://x.test", "me").unwrap();
        assert!(w.is_empty() && !q.is_empty(), "IPv6 and URLs are plain text, not unknown fields");
        assert!(run("2001:db8::1", &alert("PORT_SCAN", "HIGH", "h", "2001:db8::1", "m")));
    }
}
