mod detect;
#[cfg(feature = "fleet")]
mod fleet;
mod proc;

use detect::{Alert, Config, Detector, Severity};
use proc::{ProcInfo, Sock};
use std::fs::OpenOptions;
use std::io::{IsTerminal, Write};
use std::net::IpAddr;
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const VERSION: &str = env!("CARGO_PKG_VERSION");

const HELP: &str = "\
netwatch - defensive network monitor for Linux servers

USAGE:
    netwatch <command> [options]

COMMANDS:
    ports                 Listening ports with owning process (like lsof -i / ss -ltnup)
    conns                 All sockets with owning process and state
    watch                 Continuously monitor and alert on suspected attacks
    up                    Run server + agent + web dashboard together   [fleet]
    agent                 Report to a central server (enroll / run)      [fleet]
    server                Central collector (init / token / run / hosts) [fleet]
    tui                   Console dashboard for the server's data        [fleet]
    web                   Web dashboard for the server's data            [fleet]
    help | version

FILTERS (ports, conns):
    --port <n>            Only sockets using local or remote port n
    --state <NAME>        Only this state (ESTABLISHED, SYN_RECV, TIME_WAIT, ...)
    --tcp | --udp         Only that protocol
    --json                JSON lines output

WATCH OPTIONS:
    -i, --interval <s>    Poll interval in seconds            [default: 2]
    --log <file>          Append alerts as JSON lines to file
    --json                Print alerts as JSON lines on stdout
    --ignore <ip>         Never alert on this IP (repeatable; e.g. your office/monitoring IPs)
    --window <s>          Sliding window for rate/scan rules  [default: 60]
    --scan-ports <n>      Distinct local ports from one IP => PORT_SCAN        [default: 5]
    --rate-limit <n>      New connections from one IP in window => burst/brute [default: 30]
    --conn-limit <n>      Simultaneous connections from one IP => flood        [default: 100]
    --syn-limit <n>       Total half-open (SYN_RECV) sockets => SYN flood      [default: 50]
    --rst-rate <n>        TCP RSTs sent per second => closed-port scan         [default: 100]
    --cooldown <s>        Suppress repeat alerts for the same key              [default: 60]

Run as root to see which process owns each socket.
";

static STOP: AtomicBool = AtomicBool::new(false);

fn die(msg: &str) -> ! {
    eprintln!("netwatch: {msg}\nTry 'netwatch help'.");
    exit(2);
}

fn now_iso() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) as i64;
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    // civil-from-days (Howard Hinnant)
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

fn jesc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

fn endpoint(ip: &IpAddr, port: u16) -> String {
    let p = if port == 0 { "*".to_string() } else { port.to_string() };
    match ip {
        IpAddr::V6(_) => format!("[{ip}]:{p}"),
        _ if ip.is_unspecified() => format!("*:{p}"),
        _ => format!("{ip}:{p}"),
    }
}

#[derive(Default)]
struct Filter {
    port: Option<u16>,
    state: Option<String>,
    proto: Option<proc::Proto>,
    json: bool,
}

fn next_val(args: &[String], i: &mut usize, flag: &str) -> String {
    *i += 1;
    args.get(*i).cloned().unwrap_or_else(|| die(&format!("{flag} needs a value")))
}

fn num<T: std::str::FromStr>(s: &str, flag: &str) -> T {
    s.parse().unwrap_or_else(|_| die(&format!("invalid value '{s}' for {flag}")))
}

fn list(args: &[String], listening_only: bool) {
    let mut f = Filter::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => f.port = Some(num(&next_val(args, &mut i, "--port"), "--port")),
            "--state" => f.state = Some(next_val(args, &mut i, "--state").to_uppercase()),
            "--tcp" => f.proto = Some(proc::Proto::Tcp),
            "--udp" => f.proto = Some(proc::Proto::Udp),
            "--json" => f.json = true,
            o => die(&format!("unknown option '{o}'")),
        }
        i += 1;
    }
    if !proc::can_see_all_processes() {
        eprintln!("netwatch: not root, process names may be missing for other users' sockets");
    }
    let owners = proc::socket_owners();
    let mut socks: Vec<Sock> = proc::read_sockets()
        .into_iter()
        .filter(|s| !listening_only || s.is_listening())
        .filter(|s| f.proto.map_or(true, |p| p == s.proto))
        .filter(|s| f.port.map_or(true, |p| s.lport == p || s.rport == p))
        .filter(|s| f.state.as_ref().map_or(true, |st| s.state_name() == st))
        .collect();
    socks.sort_by_key(|s| (s.proto.name(), s.lport, s.rport));

    if !f.json {
        println!(
            "{:<5} {:<12} {:<28} {:<28} {:>7}  {:<16} {}",
            "PROTO", "STATE", "LOCAL", "REMOTE", "PID", "PROCESS", "USER"
        );
    }
    for s in &socks {
        let (pid, name) = match owners.get(&s.inode) {
            Some(ProcInfo { pid, name }) => (pid.to_string(), name.clone()),
            None => ("-".into(), "-".into()),
        };
        let user = proc::uid_name(s.uid);
        if f.json {
            println!(
                "{{\"proto\":\"{}\",\"state\":\"{}\",\"local\":\"{}\",\"remote\":\"{}\",\"pid\":{},\"process\":\"{}\",\"user\":\"{}\"}}",
                s.proto.name(),
                s.state_name(),
                jesc(&endpoint(&s.local, s.lport)),
                jesc(&endpoint(&s.remote, s.rport)),
                if pid == "-" { "null".into() } else { pid },
                jesc(&name),
                jesc(&user)
            );
        } else {
            println!(
                "{:<5} {:<12} {:<28} {:<28} {:>7}  {:<16} {}",
                s.proto.name(),
                s.state_name(),
                endpoint(&s.local, s.lport),
                endpoint(&s.remote, s.rport),
                pid,
                name,
                user
            );
        }
    }
}

fn watch(args: &[String]) {
    let mut cfg = Config::default();
    let mut interval = 2.0f64;
    let mut log: Option<String> = None;
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].clone();
        match a.as_str() {
            "-i" | "--interval" => interval = num(&next_val(args, &mut i, &a), &a),
            "--log" => log = Some(next_val(args, &mut i, &a)),
            "--json" => json = true,
            "--ignore" => {
                let v = next_val(args, &mut i, &a);
                cfg.ignore.insert(v.parse().unwrap_or_else(|_| die(&format!("invalid IP '{v}'"))));
            }
            "--window" => cfg.window = Duration::from_secs(num(&next_val(args, &mut i, &a), &a)),
            "--cooldown" => cfg.cooldown = Duration::from_secs(num(&next_val(args, &mut i, &a), &a)),
            "--scan-ports" => cfg.scan_ports = num(&next_val(args, &mut i, &a), &a),
            "--rate-limit" => cfg.rate_limit = num(&next_val(args, &mut i, &a), &a),
            "--conn-limit" => cfg.conn_limit = num(&next_val(args, &mut i, &a), &a),
            "--syn-limit" => cfg.syn_limit = num(&next_val(args, &mut i, &a), &a),
            "--rst-rate" => cfg.rst_rate = num(&next_val(args, &mut i, &a), &a),
            o => die(&format!("unknown option '{o}'")),
        }
        i += 1;
    }
    if !(0.1..=3600.0).contains(&interval) {
        die("--interval must be between 0.1 and 3600 seconds");
    }
    let mut logfile = log.as_ref().map(|p| {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .unwrap_or_else(|e| die(&format!("cannot open log '{p}': {e}")))
    });

    install_signal_handlers();
    let color = std::io::stdout().is_terminal() && !json;
    if !json {
        eprintln!(
            "netwatch {VERSION}: watching every {interval}s (window {}s). Ctrl-C to stop.",
            cfg.window.as_secs()
        );
        if !proc::can_see_all_processes() {
            eprintln!("netwatch: not root, process attribution will be incomplete");
        }
    }

    let mut det = Detector::new(cfg);
    while !STOP.load(Ordering::Relaxed) {
        let socks = proc::read_sockets();
        let owners = proc::socket_owners();
        for a in det.tick(&socks, &owners) {
            report(&a, json, color, logfile.as_mut());
        }
        // Sleep in small steps so Ctrl-C is responsive.
        let mut left = interval;
        while left > 0.0 && !STOP.load(Ordering::Relaxed) {
            let step = left.min(0.25);
            std::thread::sleep(Duration::from_secs_f64(step));
            left -= step;
        }
    }
}

fn report(a: &Alert, json: bool, color: bool, log: Option<&mut std::fs::File>) {
    let ts = now_iso();
    let src = a.src.map(|s| s.to_string());
    let line = format!(
        "{{\"time\":\"{ts}\",\"severity\":\"{}\",\"type\":\"{}\",\"source\":{},\"message\":\"{}\"}}",
        a.severity.name(),
        a.kind,
        src.as_ref().map_or("null".to_string(), |s| format!("\"{s}\"")),
        jesc(&a.msg)
    );
    if let Some(f) = log {
        let _ = writeln!(f, "{line}");
    }
    if json {
        println!("{line}");
    } else {
        let (on, off) = if color {
            (
                match a.severity {
                    Severity::High => "\x1b[1;31m",
                    Severity::Medium => "\x1b[33m",
                    Severity::Info => "\x1b[36m",
                },
                "\x1b[0m",
            )
        } else {
            ("", "")
        };
        println!("{ts} {on}{:<6} {:<15}{off} {}", a.severity.name(), a.kind, a.msg);
    }
    let _ = std::io::stdout().flush();
}

// std has no signal API; a tiny binding to signal(2) avoids a libc crate dependency.
extern "C" {
    fn signal(signum: i32, handler: usize) -> usize;
}

fn install_signal_handlers() {
    extern "C" fn handler(_: i32) {
        STOP.store(true, Ordering::Relaxed);
    }
    unsafe {
        signal(2, handler as extern "C" fn(i32) as usize); // SIGINT
        signal(15, handler as extern "C" fn(i32) as usize); // SIGTERM
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Short-lived commands should die quietly when piped into head/less (SIGPIPE default).
    // Long-running ones (servers, agents, watchers) must NOT: a client that disconnects mid-write
    // would otherwise kill the whole process. Rust ignores SIGPIPE by default, so leave those alone.
    let long_running = match args.first().map(String::as_str) {
        Some("watch" | "agent" | "web" | "up" | "tui") => true,
        Some("server") => args.get(1).map(String::as_str) == Some("run"),
        _ => false,
    };
    if !long_running {
        unsafe {
            signal(13, 0); // SIGPIPE -> SIG_DFL
        }
    }
    match args.first().map(String::as_str) {
        Some("ports") => list(&args[1..], true),
        Some("conns") => list(&args[1..], false),
        Some("watch") => watch(&args[1..]),
        #[cfg(feature = "fleet")]
        Some("agent") => fleet::agent::cmd(&args[1..]),
        #[cfg(feature = "fleet")]
        Some("server") => fleet::server::cmd(&args[1..]),
        #[cfg(feature = "fleet")]
        Some("up") => fleet::up::cmd(&args[1..]),
        #[cfg(feature = "fleet")]
        Some("web") => fleet::web::cmd(&args[1..]),
        #[cfg(feature = "fleet")]
        Some("tui") => fleet::tui::cmd(&args[1..]),
        Some("version") | Some("--version") | Some("-V") => println!("netwatch {VERSION}"),
        Some("help") | Some("--help") | Some("-h") | None => print!("{HELP}"),
        Some(o) => die(&format!("unknown command '{o}'")),
    }
}
