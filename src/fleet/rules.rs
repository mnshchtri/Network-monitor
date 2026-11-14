//! Detection rule catalog (Wazuh-style): every alert kind netwatch can raise gets a stable rule ID,
//! a 0-15 severity level, groups, a MITRE ATT&CK mapping and reference compliance tags.
//!
//! The ATT&CK and compliance mappings are *suggested references* to help analysts triage and
//! report. They are not a certification: confirm them with your auditor.

pub struct Rule {
    pub id: u32,
    pub kind: &'static str,
    pub name: &'static str,
    pub desc: &'static str,
    /// Level when the alert is HIGH severity (MEDIUM is 2 lower, INFO is capped at 3).
    pub level: u8,
    pub groups: &'static [&'static str],
    pub tactic: &'static str,
    pub technique: &'static str,
    pub technique_name: &'static str,
    /// (framework key, requirement id)
    pub compliance: &'static [(&'static str, &'static str)],
}

const IDS: &[(&str, &str)] = &[("pci_dss", "11.5.1"), ("nist_800_53", "SI-4"), ("gdpr", "IV_35.7.d"), ("hipaa", "164.312.b"), ("cis", "13.3"), ("soc2", "CC7.2")];
const DOS: &[(&str, &str)] = &[("pci_dss", "11.5.1"), ("nist_800_53", "SI-4"), ("nist_800_53", "SC-5"), ("gdpr", "IV_35.7.d"), ("cis", "13.3"), ("soc2", "A1.2")];

pub const RULES: &[Rule] = &[
    Rule { id: 100110, kind: "PORT_SCAN", name: "Port scan", desc: "One source touched many distinct local ports in a short time", level: 10,
        groups: &["network", "recon", "scan"], tactic: "TA0007", technique: "T1046", technique_name: "Network Service Discovery", compliance: IDS },
    Rule { id: 100111, kind: "RST_STORM", name: "Reset storm", desc: "High rate of TCP resets sent: probes of closed ports that never create a socket", level: 8,
        groups: &["network", "recon", "scan"], tactic: "TA0007", technique: "T1046", technique_name: "Network Service Discovery", compliance: IDS },
    Rule { id: 100120, kind: "BRUTE_FORCE", name: "Brute force", desc: "Many new connections from one source to an authentication service", level: 12,
        groups: &["network", "authentication_failures", "brute_force"], tactic: "TA0006", technique: "T1110", technique_name: "Brute Force",
        compliance: &[("pci_dss", "8.3.4"), ("pci_dss", "11.5.1"), ("nist_800_53", "AC-7"), ("nist_800_53", "SI-4"), ("gdpr", "IV_32.2"), ("hipaa", "164.312.b"), ("soc2", "CC6.1")] },
    Rule { id: 100130, kind: "CONN_BURST", name: "Connection burst", desc: "A single source opened an unusual number of new connections", level: 8,
        groups: &["network", "dos"], tactic: "TA0040", technique: "T1499", technique_name: "Endpoint Denial of Service", compliance: DOS },
    Rule { id: 100131, kind: "CONN_FLOOD", name: "Connection flood", desc: "A single source holds an excessive number of simultaneous connections", level: 10,
        groups: &["network", "dos"], tactic: "TA0040", technique: "T1499", technique_name: "Endpoint Denial of Service", compliance: DOS },
    Rule { id: 100140, kind: "SYN_FLOOD", name: "SYN flood", desc: "Many half-open (SYN_RECV) connections: a SYN flood", level: 12,
        groups: &["network", "dos", "syn_flood"], tactic: "TA0040", technique: "T1498.001", technique_name: "Direct Network Flood", compliance: DOS },
    Rule { id: 100141, kind: "SYN_COOKIES", name: "SYN cookies engaged", desc: "The kernel had to send SYN cookies because the SYN backlog overflowed", level: 12,
        groups: &["network", "dos", "syn_flood"], tactic: "TA0040", technique: "T1498.001", technique_name: "Direct Network Flood", compliance: DOS },
    Rule { id: 100142, kind: "LISTEN_OVERFLOW", name: "Accept queue overflow", desc: "Connection attempts were dropped because a service's accept queue was full", level: 9,
        groups: &["network", "dos"], tactic: "TA0040", technique: "T1499.002", technique_name: "Service Exhaustion Flood", compliance: DOS },
    Rule { id: 100160, kind: "NEW_LISTENER", name: "New listening service", desc: "A port started listening after monitoring began (possible backdoor or unapproved service)", level: 10,
        groups: &["network", "new_service", "backdoor"], tactic: "TA0011", technique: "T1571", technique_name: "Non-Standard Port",
        compliance: &[("pci_dss", "1.2.5"), ("nist_800_53", "CM-7"), ("nist_800_53", "CM-6"), ("gdpr", "IV_32.2"), ("cis", "4.8"), ("soc2", "CC6.6")] },
    Rule { id: 100170, kind: "HOST_DOWN", name: "Agent stopped reporting", desc: "A monitored host stopped reporting: crashed, unreachable, or its agent was silenced", level: 9,
        groups: &["availability", "agent"], tactic: "TA0005", technique: "T1562", technique_name: "Impair Defenses",
        compliance: &[("pci_dss", "10.7.1"), ("nist_800_53", "SI-4"), ("hipaa", "164.312.b"), ("soc2", "CC7.2")] },
    Rule { id: 100171, kind: "HOST_UP", name: "Agent reporting again", desc: "A host that had gone silent is reporting again", level: 3,
        groups: &["availability", "agent"], tactic: "", technique: "", technique_name: "", compliance: &[] },
];

pub fn by_kind(kind: &str) -> Option<&'static Rule> {
    RULES.iter().find(|r| r.kind == kind)
}

/// Wazuh-style 0-15 level for one alert.
pub fn level_for(rule: Option<&Rule>, severity: &str) -> u8 {
    let base = rule.map_or(10, |r| r.level);
    match severity {
        "HIGH" => base,
        "MEDIUM" => base.saturating_sub(2).max(4),
        _ => base.min(3),
    }
}

/// low (0-6), medium (7-9), high (10-11), critical (12-15)
pub fn level_class(level: u8) -> &'static str {
    match level {
        0..=6 => "low",
        7..=9 => "medium",
        10..=11 => "high",
        _ => "critical",
    }
}

/// MITRE ATT&CK enterprise tactics in kill-chain order.
pub const TACTICS: &[(&str, &str)] = &[
    ("TA0043", "Reconnaissance"), ("TA0042", "Resource Development"), ("TA0001", "Initial Access"), ("TA0002", "Execution"), ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"), ("TA0005", "Defense Evasion"), ("TA0006", "Credential Access"), ("TA0007", "Discovery"), ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"), ("TA0011", "Command and Control"), ("TA0010", "Exfiltration"), ("TA0040", "Impact"),
];

pub fn tactic_name(id: &str) -> &'static str {
    TACTICS.iter().find(|t| t.0 == id).map_or("", |t| t.1)
}

pub const FRAMEWORKS: &[(&str, &str)] = &[
    ("pci_dss", "PCI DSS v4.0"), ("nist_800_53", "NIST SP 800-53 r5"), ("gdpr", "GDPR"), ("hipaa", "HIPAA Security Rule"), ("cis", "CIS Controls v8"), ("soc2", "SOC 2 (Trust Services)"),
];

/// (framework, requirement id, title)
pub const REQUIREMENTS: &[(&str, &str, &str)] = &[
    ("pci_dss", "1.2.5", "Allowed services, protocols and ports are identified and approved"),
    ("pci_dss", "4.2.1", "Strong cryptography protects data in transit"),
    ("pci_dss", "8.3.4", "Invalid authentication attempts are limited"),
    ("pci_dss", "8.4.2", "Multi-factor authentication is required for administrative access"),
    ("pci_dss", "10.2.1", "Audit logs capture user and security events"),
    ("pci_dss", "10.3.4", "Audit logs are protected from modification"),
    ("pci_dss", "10.5.1", "Audit log history is retained for at least 12 months"),
    ("pci_dss", "10.7.1", "Failures of critical security control systems are detected and reported"),
    ("pci_dss", "11.5.1", "Intrusion-detection techniques detect and alert on intrusions"),
    ("nist_800_53", "AC-7", "Unsuccessful logon attempts"),
    ("nist_800_53", "AU-2", "Event logging"),
    ("nist_800_53", "AU-9", "Protection of audit information"),
    ("nist_800_53", "CM-6", "Configuration settings"),
    ("nist_800_53", "CM-7", "Least functionality"),
    ("nist_800_53", "IA-2", "Identification and authentication (multi-factor)"),
    ("nist_800_53", "SC-5", "Denial-of-service protection"),
    ("nist_800_53", "SC-8", "Transmission confidentiality and integrity"),
    ("nist_800_53", "SI-4", "System monitoring"),
    ("gdpr", "IV_32.2", "Security of processing: assess the risk of unauthorised access"),
    ("gdpr", "IV_35.7.d", "Measures to address risks to personal data"),
    ("hipaa", "164.312.b", "Audit controls"),
    ("hipaa", "164.312.e.1", "Transmission security"),
    ("cis", "4.8", "Uninstall or disable unnecessary services"),
    ("cis", "8.2", "Collect audit logs"),
    ("cis", "13.1", "Centralize security event alerting"),
    ("cis", "13.3", "Deploy a network intrusion detection solution"),
    ("soc2", "CC6.1", "Logical access security"),
    ("soc2", "CC6.6", "Boundary protection"),
    ("soc2", "CC7.2", "Monitor system components for anomalies"),
    ("soc2", "A1.2", "Availability protections"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_consistent() {
        let mut ids: Vec<u32> = RULES.iter().map(|r| r.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), RULES.len(), "rule ids must be unique");
        let mut kinds: Vec<&str> = RULES.iter().map(|r| r.kind).collect();
        kinds.sort();
        kinds.dedup();
        assert_eq!(kinds.len(), RULES.len(), "one rule per alert kind");
        for r in RULES {
            assert!(r.level <= 15);
            if !r.tactic.is_empty() {
                assert!(TACTICS.iter().any(|t| t.0 == r.tactic), "{} has unknown tactic {}", r.kind, r.tactic);
                assert!(!r.technique.is_empty() && !r.technique_name.is_empty());
            }
            for (fw, req) in r.compliance {
                assert!(FRAMEWORKS.iter().any(|f| f.0 == *fw), "{} references unknown framework {fw}", r.kind);
                assert!(REQUIREMENTS.iter().any(|q| q.0 == *fw && q.1 == *req), "{} references undefined requirement {fw} {req}", r.kind);
            }
        }
        // Every alert kind the detectors can emit has a rule.
        for k in ["PORT_SCAN", "BRUTE_FORCE", "CONN_BURST", "CONN_FLOOD", "SYN_FLOOD", "SYN_COOKIES", "LISTEN_OVERFLOW", "RST_STORM", "NEW_LISTENER", "HOST_DOWN", "HOST_UP"] {
            assert!(by_kind(k).is_some(), "missing rule for {k}");
        }
    }

    #[test]
    fn levels() {
        let r = by_kind("BRUTE_FORCE");
        assert_eq!(level_for(r, "HIGH"), 12);
        assert_eq!(level_for(r, "MEDIUM"), 10);
        assert_eq!(level_for(r, "INFO"), 3);
        assert_eq!(level_for(None, "HIGH"), 10);
        assert_eq!(level_class(3), "low");
        assert_eq!(level_class(8), "medium");
        assert_eq!(level_class(10), "high");
        assert_eq!(level_class(12), "critical");
    }
}
