//! Console dashboard. Reads the server's SQLite database directly (run it on the server host,
//! e.g. over SSH), so there is no extra network surface to protect.

use super::db::{self, AlertRow, ConnRow, EventRow, HostRow, ListenerRow};
use super::server::default_server_dir;
use super::util::*;
use ratatui::backend::TestBackend;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, List, ListItem, ListState, Paragraph, Row, Sparkline, Table, TableState, Tabs};
use ratatui::{Frame, Terminal};
use rusqlite::Connection;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const TABS: [&str; 4] = ["1 Alerts", "2 Listening ports", "3 Connections", "4 Changes"];

struct App {
    db: Connection,
    hosts: Vec<HostRow>,
    sel: usize, // 0 = all hosts, i = hosts[i-1]
    tab: usize,
    focus_right: bool,
    show_acked: bool,
    hstate: ListState,
    tstate: TableState,
    alerts: Vec<AlertRow>,
    listeners: Vec<ListenerRow>,
    conns: Vec<ConnRow>,
    events: Vec<EventRow>,
    hist: Vec<u64>,
    msg: String,
}

impl App {
    fn new(db: Connection) -> Self {
        let mut a = App {
            db, hosts: vec![], sel: 0, tab: 0, focus_right: false, show_acked: false,
            hstate: ListState::default(), tstate: TableState::default(),
            alerts: vec![], listeners: vec![], conns: vec![], events: vec![], hist: vec![], msg: String::new(),
        };
        a.refresh();
        a
    }

    fn host(&self) -> Option<&HostRow> {
        if self.sel == 0 { None } else { self.hosts.get(self.sel - 1) }
    }

    fn rows(&self) -> usize {
        if self.sel == 0 {
            return self.alerts.len();
        }
        match self.tab {
            0 => self.alerts.len(),
            1 => self.listeners.len(),
            2 => self.conns.len(),
            _ => self.events.len(),
        }
    }

    fn refresh(&mut self) {
        match db::hosts(&self.db) {
            Ok(h) => self.hosts = h,
            Err(e) => self.msg = format!("db error: {e}"),
        }
        if self.sel > self.hosts.len() {
            self.sel = self.hosts.len();
        }
        self.alerts.clear();
        self.listeners.clear();
        self.conns.clear();
        self.events.clear();
        self.hist.clear();
        let id = self.host().map(|h| h.id.clone());
        let r: Result<(), rusqlite::Error> = (|| {
            match &id {
                None => self.alerts = db::alerts(&self.db, None, self.show_acked, 500)?,
                Some(id) => {
                    self.hist = db::established_history(&self.db, id, 120)?;
                    match self.tab {
                        0 => self.alerts = db::alerts(&self.db, Some(id), self.show_acked, 500)?,
                        1 => self.listeners = db::listeners(&self.db, id)?,
                        2 => self.conns = db::conns(&self.db, id)?,
                        _ => self.events = db::events(&self.db, id, 300)?,
                    }
                }
            }
            Ok(())
        })();
        if let Err(e) = r {
            self.msg = format!("db error: {e}");
        }
        self.hstate.select(Some(self.sel));
        let n = self.rows();
        match self.tstate.selected() {
            _ if n == 0 => self.tstate.select(None),
            Some(i) if i >= n => self.tstate.select(Some(n - 1)),
            None => self.tstate.select(Some(0)),
            _ => {}
        }
    }

    fn select_host(&mut self, i: usize) {
        self.sel = i.min(self.hosts.len());
        self.tstate.select(None);
        self.refresh();
    }

    fn move_row(&mut self, d: isize) {
        let n = self.rows();
        if n == 0 {
            return;
        }
        let cur = self.tstate.selected().unwrap_or(0) as isize;
        self.tstate.select(Some((cur + d).clamp(0, n as isize - 1) as usize));
    }

    fn ack(&mut self, all: bool) {
        let host_id = self.host().map(|h| h.id.clone());
        let res = if all {
            db::ack_all(&self.db, host_id.as_deref())
        } else if let Some(a) = self.tstate.selected().and_then(|i| self.alerts.get(i)) {
            db::ack(&self.db, a.id)
        } else {
            Ok(())
        };
        self.msg = match res {
            Ok(()) => if all { "acknowledged all shown alerts".into() } else { "acknowledged".into() },
            Err(e) => format!("ack failed: {e}"),
        };
        self.refresh();
    }

    /// Returns true to quit.
    fn key(&mut self, code: KeyCode, mods: KeyModifiers) -> bool {
        self.msg.clear();
        let alerts_view = self.sel == 0 || self.tab == 0;
        match code {
            KeyCode::Char('q') | KeyCode::Esc => return true,
            KeyCode::Char('c') if mods.contains(KeyModifiers::CONTROL) => return true,
            KeyCode::Tab => self.focus_right = !self.focus_right,
            KeyCode::Up | KeyCode::Char('k') => {
                if self.focus_right { self.move_row(-1) } else { self.select_host(self.sel.saturating_sub(1)) }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.focus_right { self.move_row(1) } else { self.select_host(self.sel + 1) }
            }
            KeyCode::PageUp => self.move_row(-15),
            KeyCode::PageDown => self.move_row(15),
            KeyCode::Home | KeyCode::Char('g') => {
                if self.focus_right { self.tstate.select(Some(0)) } else { self.select_host(0) }
            }
            KeyCode::Left | KeyCode::Char('h') => self.set_tab(self.tab.saturating_sub(1)),
            KeyCode::Right | KeyCode::Char('l') => self.set_tab((self.tab + 1).min(3)),
            KeyCode::Char(c @ '1'..='4') => self.set_tab(c as usize - '1' as usize),
            KeyCode::Char('a') if alerts_view => self.ack(false),
            KeyCode::Char('A') if alerts_view => self.ack(true),
            KeyCode::Char('x') => {
                self.show_acked = !self.show_acked;
                self.refresh();
            }
            KeyCode::Char('r') => self.refresh(),
            _ => {}
        }
        false
    }

    fn set_tab(&mut self, t: usize) {
        if self.sel == 0 {
            return;
        }
        self.tab = t;
        self.tstate.select(None);
        self.refresh();
    }
}

fn sev_style(s: &str) -> Style {
    match s {
        "HIGH" => Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
        "MEDIUM" => Style::new().fg(Color::Yellow),
        _ => Style::new().fg(Color::Cyan),
    }
}

fn status_style(s: &str) -> (Style, &'static str) {
    match s {
        "up" => (Style::new().fg(Color::Green), "●"),
        "down" => (Style::new().fg(Color::Red).add_modifier(Modifier::BOLD), "✖"),
        _ => (Style::new().fg(Color::Yellow), "○"),
    }
}

fn block(title: &str, focused: bool) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .title(format!(" {title} "))
        .border_style(if focused { Style::new().fg(Color::Cyan) } else { Style::new().fg(Color::DarkGray) })
}

fn draw(f: &mut Frame, app: &mut App) {
    let [head, body, foot] = Layout::vertical([Constraint::Length(1), Constraint::Min(0), Constraint::Length(1)]).areas(f.area());
    let [left, right] = Layout::horizontal([Constraint::Length(34), Constraint::Min(0)]).areas(body);

    let up = app.hosts.iter().filter(|h| h.status == "up").count();
    let down = app.hosts.iter().filter(|h| h.status == "down").count();
    let alerts: u32 = app.hosts.iter().map(|h| h.open_alerts).sum();
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" netwatch ", Style::new().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(format!("  {} hosts  ", app.hosts.len())),
            Span::styled(format!("{up} up  "), Style::new().fg(Color::Green)),
            Span::styled(format!("{down} down  "), if down > 0 { Style::new().fg(Color::Red) } else { Style::new() }),
            Span::styled(format!("{alerts} unacknowledged alerts"), if alerts > 0 { Style::new().fg(Color::Yellow) } else { Style::new() }),
        ])),
        head,
    );

    // Host list
    let mut items = vec![ListItem::new(Line::from(vec![
        Span::styled("★ ", Style::new().fg(Color::Yellow)),
        Span::raw(format!("All hosts ({alerts})")),
    ]))];
    for h in &app.hosts {
        let (st, sym) = status_style(&h.status);
        let mut spans = vec![Span::styled(format!("{sym} "), st), Span::raw(format!("{:<18}", truncate(&h.name, 18)))];
        if h.open_alerts > 0 {
            spans.push(Span::styled(format!(" {:>3}!", h.open_alerts), Style::new().fg(Color::Red).add_modifier(Modifier::BOLD)));
        }
        items.push(ListItem::new(Line::from(spans)));
    }
    f.render_stateful_widget(
        List::new(items)
            .block(block("Hosts", !app.focus_right))
            .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
            .highlight_symbol("▶"),
        left,
        &mut app.hstate,
    );

    if app.hosts.is_empty() {
        f.render_widget(
            Paragraph::new("\n  No agents enrolled yet.\n\n  netwatch server token   -> prints the command to run on a server you want to monitor")
                .block(block("Welcome", true)),
            right,
        );
    } else if app.sel == 0 {
        let t = alerts_table(&app.alerts, true);
        f.render_stateful_widget(t.block(block("Alert feed (all hosts)", app.focus_right)), right, &mut app.tstate);
    } else {
        draw_host(f, app, right);
    }

    let help = if app.msg.is_empty() {
        " ↑↓ move  Tab switch pane  ←→/1-4 tabs  a ack  A ack all  x show/hide acked  r refresh  q quit".to_string()
    } else {
        format!(" {}", app.msg)
    };
    f.render_widget(Paragraph::new(help).style(Style::new().fg(Color::DarkGray)), foot);
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n { s.to_string() } else { format!("{}…", s.chars().take(n - 1).collect::<String>()) }
}

fn draw_host(f: &mut Frame, app: &mut App, area: Rect) {
    let h = app.host().cloned().unwrap();
    let [sum, tabs, content] = Layout::vertical([Constraint::Length(6), Constraint::Length(1), Constraint::Min(0)]).areas(area);

    let (st, sym) = status_style(&h.status);
    let mut l2 = vec![Span::raw(format!(
        " listening {}  established {}  ",
        h.listeners, h.established
    ))];
    l2.push(Span::styled(format!("SYN_RECV {}", h.syn_recv), if h.syn_recv > 10 { Style::new().fg(Color::Red) } else { Style::new() }));
    l2.push(Span::raw(format!("  TIME_WAIT {}  total sockets {}", h.time_wait, h.total)));
    let mut lines = vec![
        Line::from(vec![
            Span::styled(format!(" {sym} {} ", h.status.to_uppercase()), st),
            Span::styled(h.name.clone(), Style::new().add_modifier(Modifier::BOLD)),
            Span::raw(format!("   {}   seen {}", h.addr, ago(h.last_seen))),
        ]),
        Line::from(format!(" {}  ·  agent {}  ·  id {}", h.os, h.version, h.id)),
        Line::from(l2),
    ];
    if !h.is_root {
        lines.push(Line::from(Span::styled(" ! agent is not root: process names are missing for other users' sockets", Style::new().fg(Color::Yellow))));
    }
    let b = block("Host", false);
    let inner = b.inner(sum);
    f.render_widget(b, sum);
    let [txt, spark] = Layout::vertical([Constraint::Length(lines.len().min(4) as u16), Constraint::Min(0)]).areas(inner);
    f.render_widget(Paragraph::new(lines), txt);
    f.render_widget(Sparkline::default().data(app.hist.iter().copied()).style(Style::new().fg(Color::Cyan)), spark);

    f.render_widget(Tabs::new(TABS.to_vec()).select(app.tab).highlight_style(Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)), tabs);

    let title = TABS[app.tab];
    let t = match app.tab {
        0 => alerts_table(&app.alerts, false),
        1 => {
            let rows = app.listeners.iter().map(|l| {
                let exposed = !(l.addr.starts_with("127.") || l.addr == "::1");
                let style = if exposed { Style::new().fg(Color::Yellow) } else { Style::new() };
                Row::new(vec![
                    l.proto.clone(), l.addr.clone(), l.port.to_string(), l.pid.map(|p| p.to_string()).unwrap_or("-".into()),
                    l.process.clone(), l.user.clone(), if exposed { "external".into() } else { "local".into() }, ago(l.first_seen),
                ]).style(style)
            });
            Table::new(rows, [Constraint::Length(5), Constraint::Length(30), Constraint::Length(6), Constraint::Length(8), Constraint::Length(18), Constraint::Length(12), Constraint::Length(9), Constraint::Fill(1)])
                .header(header(&["PROTO", "ADDRESS", "PORT", "PID", "PROCESS", "USER", "SCOPE", "OPEN FOR"]))
        }
        2 => {
            let rows = app.conns.iter().map(|c| {
                let style = match c.state.as_str() {
                    "ESTABLISHED" => Style::new().fg(Color::Green),
                    "SYN_RECV" => Style::new().fg(Color::Red),
                    "TIME_WAIT" | "CLOSE_WAIT" => Style::new().fg(Color::DarkGray),
                    _ => Style::new(),
                };
                Row::new(vec![c.proto.clone(), c.state.clone(), c.local.clone(), c.remote.clone(), c.pid.map(|p| p.to_string()).unwrap_or("-".into()), c.process.clone()]).style(style)
            });
            Table::new(rows, [Constraint::Length(5), Constraint::Length(12), Constraint::Length(30), Constraint::Length(30), Constraint::Length(8), Constraint::Fill(1)])
                .header(header(&["PROTO", "STATE", "LOCAL", "REMOTE", "PID", "PROCESS"]))
        }
        _ => {
            let rows = app.events.iter().map(|e| {
                let style = if e.event == "opened" { Style::new().fg(Color::Red) } else { Style::new().fg(Color::DarkGray) };
                Row::new(vec![fmt_time(e.ts), e.event.to_uppercase(), e.what.clone()]).style(style)
            });
            Table::new(rows, [Constraint::Length(20), Constraint::Length(8), Constraint::Fill(1)])
                .header(header(&["TIME", "EVENT", "LISTENER"]))
        }
    };
    f.render_stateful_widget(t.block(block(title, app.focus_right)).row_highlight_style(Style::new().add_modifier(Modifier::REVERSED)), content, &mut app.tstate);
}

fn header(cols: &[&'static str]) -> Row<'static> {
    Row::new(cols.iter().map(|c| Cell::from(*c))).style(Style::new().fg(Color::DarkGray).add_modifier(Modifier::BOLD))
}

fn alerts_table(alerts: &[AlertRow], with_host: bool) -> Table<'static> {
    let rows = alerts.iter().map(|a| {
        let base = if a.acked { Style::new().fg(Color::DarkGray) } else { Style::new() };
        let mut cells = vec![Cell::from(fmt_time(a.ts)).style(base)];
        if with_host {
            cells.push(Cell::from(truncate(&a.host, 16)).style(base));
        }
        cells.push(Cell::from(a.severity.clone()).style(if a.acked { base } else { sev_style(&a.severity) }));
        cells.push(Cell::from(a.kind.clone()).style(base));
        cells.push(Cell::from(a.message.clone()).style(base));
        Row::new(cells)
    });
    if with_host {
        Table::new(rows, [Constraint::Length(20), Constraint::Length(16), Constraint::Length(7), Constraint::Length(16), Constraint::Fill(1)])
            .header(header(&["TIME", "HOST", "SEV", "TYPE", "MESSAGE"]))
    } else {
        Table::new(rows, [Constraint::Length(20), Constraint::Length(7), Constraint::Length(16), Constraint::Fill(1)])
            .header(header(&["TIME", "SEV", "TYPE", "MESSAGE"]))
    }
    .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED))
}

pub const HELP: &str = "\
netwatch tui - console dashboard (run on the server host; reads its database)

    netwatch tui [--dir D]
    netwatch tui --snapshot [--host NAME] [--tab 1-4] [--width 120 --height 35]
                          Print one rendered frame as text and exit (useful over SSH/logs)

Keys: ↑↓ select  Tab switch pane  ←→ or 1-4 tabs  a ack  A ack all  x show acked  q quit
";

pub fn cmd(args: &[String]) {
    if has(args, "--help") || has(args, "-h") {
        print!("{HELP}");
        return;
    }
    let dir: PathBuf = opt(args, "--dir").map(PathBuf::from).unwrap_or_else(default_server_dir);
    if !dir.join("netwatch.db").exists() {
        fail(&format!("no database in {} (run on the server host, or pass --dir)", dir.display()));
    }
    let db = db::open(&dir.join("netwatch.db")).unwrap_or_else(|e| fail(&format!("cannot open database: {e}")));
    let mut app = App::new(db);

    if has(args, "--snapshot") {
        if let Some(name) = opt(args, "--host") {
            if let Some(i) = app.hosts.iter().position(|h| h.name == name || h.id == name) {
                app.select_host(i + 1);
            }
        }
        if let Some(t) = opt(args, "--tab").and_then(|t| t.parse::<usize>().ok()) {
            app.set_tab(t.clamp(1, 4) - 1);
        }
        let w = opt(args, "--width").and_then(|v| v.parse().ok()).unwrap_or(120);
        let h = opt(args, "--height").and_then(|v| v.parse().ok()).unwrap_or(35);
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let buf = term.backend().buffer().clone();
        for y in 0..buf.area.height {
            let line: String = (0..buf.area.width).map(|x| buf[(x, y)].symbol().to_string()).collect();
            println!("{}", line.trim_end());
        }
        return;
    }

    let mut term = ratatui::init();
    let mut last = Instant::now();
    let res: std::io::Result<()> = (|| loop {
        term.draw(|f| draw(f, &mut app))?;
        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(k) = event::read()? {
                if k.kind == KeyEventKind::Press && app.key(k.code, k.modifiers) {
                    return Ok(());
                }
                last = Instant::now();
            }
        }
        if last.elapsed() >= Duration::from_secs(1) {
            app.refresh();
            last = Instant::now();
        }
    })();
    ratatui::restore();
    if let Err(e) = res {
        fail(&format!("terminal error: {e}"));
    }
}
