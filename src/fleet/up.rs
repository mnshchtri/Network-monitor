//! `netwatch up`: one command that sets up (first run) and supervises server + agent + web
//! dashboard on this machine. Each runs as a child process of this same binary.

use super::agent::default_agent_dir;
use super::server::default_server_dir;
use super::util::*;
use super::{db, pki};
use std::io::{BufRead, BufReader, IsTerminal};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

pub const HELP: &str = "\
netwatch up - run the server, a local agent and the web dashboard with one command

    netwatch up [--port 7443] [--web-listen 127.0.0.1:8080] [--dir SERVER_DIR] [--agent-dir DIR]
                [--no-agent] [--no-web]

First run sets everything up: creates the server CA, enrolls this machine as a host, and (when
run in a terminal) asks you to choose the dashboard password. Later runs just start everything.
Crashed components are restarted. Ctrl-C stops them all.

--no-agent   Don't monitor this machine (use when the server host itself isn't monitored)
--no-web     Skip the web dashboard
";

const SIGTERM: i32 = 15;
extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

struct Svc {
    name: &'static str,
    args: Vec<String>,
    child: Option<Child>,
    next_start: Instant,
    crashes: Vec<Instant>,
    dead: bool,
}

fn spawn(exe: &Path, svc: &mut Svc) {
    let mut cmd = Command::new(exe);
    cmd.args(&svc.args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    match cmd.spawn() {
        Ok(mut c) => {
            let name = svc.name;
            if let Some(o) = c.stdout.take() {
                std::thread::spawn(move || pump(name, BufReader::new(o)));
            }
            if let Some(e) = c.stderr.take() {
                std::thread::spawn(move || pump(name, BufReader::new(e)));
            }
            svc.child = Some(c);
        }
        Err(e) => {
            eprintln!("[up] cannot start {}: {e}", svc.name);
            svc.dead = true;
        }
    }
}

fn pump<R: BufRead>(name: &str, r: R) {
    for line in r.lines().map_while(Result::ok) {
        println!("[{name:<6}] {line}");
    }
}

fn run_step(exe: &Path, args: &[&str], what: &str) {
    match Command::new(exe).args(args).status() {
        Ok(s) if s.success() => {}
        Ok(_) => fail(&format!("{what} failed")),
        Err(e) => fail(&format!("{what}: {e}")),
    }
}

fn port_free(addr: &str) -> bool {
    TcpListener::bind(addr).is_ok()
}

pub fn cmd(args: &[String]) {
    if has(args, "--help") || has(args, "-h") {
        print!("{HELP}");
        return;
    }
    let exe = std::env::current_exe().unwrap_or_else(|e| fail(&format!("cannot locate own binary: {e}")));
    let dir: PathBuf = opt(args, "--dir").map(PathBuf::from).unwrap_or_else(default_server_dir);
    let agent_dir: PathBuf = opt(args, "--agent-dir").map(PathBuf::from).unwrap_or_else(default_agent_dir);
    let port: u16 = opt(args, "--port").map(|p| p.parse().unwrap_or_else(|_| fail("bad --port"))).unwrap_or(7443);
    let web_listen = opt(args, "--web-listen").unwrap_or_else(|| "127.0.0.1:8080".into());
    let (want_agent, mut want_web) = (!has(args, "--no-agent"), !has(args, "--no-web"));
    let (dir_s, agent_dir_s) = (dir.to_string_lossy().to_string(), agent_dir.to_string_lossy().to_string());
    let server_addr = format!("127.0.0.1:{port}");

    if !port_free(&server_addr) {
        fail(&format!("{server_addr} is already in use (is netwatch already running?)"));
    }
    if want_web && !port_free(&web_listen) {
        fail(&format!("{web_listen} is already in use (pick another with --web-listen)"));
    }

    // ---- first-run setup ----
    if !dir.join("server.pem").exists() {
        println!("[up] first run: creating the server certificate authority in {}", dir.display());
        run_step(&exe, &["server", "init", "--name", "127.0.0.1", "--port", &port.to_string(), "--dir", &dir_s], "server init");
    }
    let dbc = db::open(&dir.join("netwatch.db")).unwrap_or_else(|e| fail(&format!("cannot open database: {e}")));
    if want_web && db::count_users(&dbc).unwrap_or(0) == 0 {
        if std::io::stdin().is_terminal() {
            println!("[up] create the dashboard login (user: admin):");
            run_step(&exe, &["server", "set-password", "--dir", &dir_s], "set-password");
        } else {
            eprintln!("[up] no dashboard account exists and there is no terminal to ask: skipping the web dashboard.\n     Run 'netwatch server set-password' once, then start again.");
            want_web = false;
        }
    }

    let mut svcs = vec![Svc {
        name: "server",
        args: vec!["server".into(), "run".into(), "--listen".into(), server_addr.clone(), "--dir".into(), dir_s.clone(), "--log".into(), dir.join("alerts.jsonl").to_string_lossy().into()],
        child: None,
        next_start: Instant::now(),
        crashes: vec![],
        dead: false,
    }];
    spawn(&exe, &mut svcs[0]);

    // Wait for the server to accept connections (needed before the agent can enroll).
    let ready = (0..80).any(|_| {
        std::thread::sleep(Duration::from_millis(100));
        TcpStream::connect_timeout(&server_addr.parse().unwrap(), Duration::from_millis(200)).is_ok()
    });
    if !ready {
        shutdown(&mut svcs);
        fail("the server did not start; see the [server] messages above");
    }

    if want_agent {
        if !agent_dir.join("agent.json").exists() {
            println!("[up] enrolling this machine as a monitored host");
            let pem = std::fs::read_to_string(dir.join("server.pem")).unwrap_or_else(|e| fail(&format!("{e}")));
            let pin = pki::fingerprint(&pem).unwrap_or_else(|e| fail(&format!("{e}")));
            let token = db::create_token(&dbc, 600).unwrap_or_else(|e| fail(&format!("{e}")));
            run_step(&exe, &["agent", "enroll", "--server", &server_addr, "--token", &token, "--pin", &pin, "--dir", &agent_dir_s], "agent enroll");
        }
        svcs.push(Svc { name: "agent", args: vec!["agent".into(), "run".into(), "--dir".into(), agent_dir_s.clone()], child: None, next_start: Instant::now(), crashes: vec![], dead: false });
    }
    if want_web {
        svcs.push(Svc { name: "web", args: vec!["web".into(), "--dir".into(), dir_s.clone(), "--listen".into(), web_listen.clone()], child: None, next_start: Instant::now(), crashes: vec![], dead: false });
    }
    drop(dbc);
    for s in svcs.iter_mut().skip(1) {
        spawn(&exe, s);
    }

    crate::install_signal_handlers();
    println!("\n[up] running. Ctrl-C to stop everything.");
    if want_web {
        println!("[up] web dashboard:  http://{web_listen}");
    }
    println!("[up] console UI:     netwatch tui{}", if dir == default_server_dir() { String::new() } else { format!(" --dir {dir_s}") });
    if !is_root() && want_agent {
        println!("[up] note: not root, so process names are missing for other users' sockets (run with sudo for full detail)");
    }

    while !crate::STOP.load(Ordering::Relaxed) {
        for s in svcs.iter_mut() {
            if let Some(c) = s.child.as_mut() {
                if let Ok(Some(status)) = c.try_wait() {
                    s.child = None;
                    let now = Instant::now();
                    s.crashes.retain(|t| now.duration_since(*t) < Duration::from_secs(60));
                    s.crashes.push(now);
                    if s.crashes.len() >= 5 {
                        s.dead = true;
                        eprintln!("[up] {} exited ({status}) too many times; giving up on it", s.name);
                    } else {
                        eprintln!("[up] {} exited ({status}); restarting in 3s", s.name);
                        s.next_start = now + Duration::from_secs(3);
                    }
                }
            } else if !s.dead && Instant::now() >= s.next_start {
                spawn(&exe, s);
            }
        }
        if svcs[0].dead {
            eprintln!("[up] the server is not recoverable; shutting down");
            break;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    println!("[up] stopping…");
    shutdown(&mut svcs);
}

fn shutdown(svcs: &mut [Svc]) {
    for s in svcs.iter() {
        if let Some(c) = &s.child {
            unsafe { kill(c.id() as i32, SIGTERM) };
        }
    }
    let deadline = Instant::now() + Duration::from_secs(4);
    for s in svcs.iter_mut() {
        if let Some(c) = s.child.as_mut() {
            while Instant::now() < deadline && matches!(c.try_wait(), Ok(None)) {
                std::thread::sleep(Duration::from_millis(50));
            }
            if matches!(c.try_wait(), Ok(None)) {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }
}
