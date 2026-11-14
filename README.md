# netwatch

A defensive network monitor for Linux servers, written in Rust. It shows what is listening, which process owns each socket (like `lsof -i`), and raises alerts on signs of network attacks, so you have a record to investigate afterwards.

- **Single static binary.** Reads `/proc` directly: no libpcap, no Python, no runtime. Standalone mode is pure Rust std (`--no-default-features` builds just that); fleet mode adds rustls, SQLite and a terminal UI.
- **Works on any Linux** (x86_64 and aarch64, any distro, containers included).
- **Read-only.** It observes and reports; it never blocks traffic or changes the system.

## Install (one line)

```sh
curl -fsSL https://raw.githubusercontent.com/mnshchtri/Network-monitor/main/install.sh | sh
```

Installs a prebuilt, checksum-verified binary to `/usr/local/bin` (or `~/.local/bin` without sudo). If no prebuilt binary exists for your platform it builds from source with cargo.

Install and run it as an always-on service (alerts logged to `/var/log/netwatch/alerts.jsonl`):

```sh
curl -fsSL https://raw.githubusercontent.com/mnshchtri/Network-monitor/main/install.sh | NETWATCH_SERVICE=1 sh
```

Or build manually: `cargo build --release`.

## Usage: standalone

Run with `sudo` so process names can be resolved for every socket.

```sh
sudo netwatch ports                       # listening ports + process, user
sudo netwatch conns                       # all sockets
sudo netwatch conns --state SYN_RECV      # filter by state
sudo netwatch conns --port 22 --json      # filter by port, JSON lines
sudo netwatch watch                       # live attack detection
sudo netwatch watch --log alerts.jsonl --ignore 203.0.113.7
```

## Quick start: everything on one machine

```sh
netwatch up
```

First run creates the server CA, enrolls this machine as a monitored host and asks you to choose the web dashboard password. After that it starts the server, the agent and the dashboard (`http://127.0.0.1:8080`) together, prefixes each component's log lines, restarts anything that crashes and stops them all on Ctrl-C. Options: `--port`, `--web-listen`, `--no-agent`, `--no-web`, `--dir`, `--agent-dir`. Use `sudo netwatch up` to see process names for every socket. For always-on use, install the systemd services below instead.

**Run it in the background** with the control script (no terminal needs to stay open):

```sh
scripts/netwatch.sh start        # starts `netwatch up` detached; prints the dashboard URL
scripts/netwatch.sh status       # pid, uptime, components, URL
scripts/netwatch.sh logs         # follow the log
scripts/netwatch.sh restart
scripts/netwatch.sh stop         # graceful (like Ctrl-C), escalates to SIGTERM/SIGKILL only if it hangs
```

Anything after `start` is passed to `netwatch up` (`scripts/netwatch.sh start --web-listen 127.0.0.1:9090 --no-agent`). The script records its own pid and log under `~/.local/state/netwatch` (override with `NETWATCH_RUN_DIR`) and uses `NETWATCH_BIN` or `target/release/netwatch` or `netwatch` from `PATH`. It only ever signals the process in its own pid file, and only if that process really is netwatch, so a stale or recycled pid can't make it kill something else. `netwatch up` itself refuses unknown options instead of silently ignoring them.

## Usage: fleet mode (agent / server / dashboard)

Monitor many servers from one place, the way Zabbix does.

```
 monitored servers                         central host
┌───────────────────┐   mTLS (outbound)  ┌──────────────────────────┐
│ netwatch agent    │ ─────────────────► │ netwatch server          │
│ detectors + ports │   reports, alerts  │ auth, SQLite, history    │
│ + connections     │ ◄───────────────── │ pushes detector settings │
└───────────────────┘                    └────────────┬─────────────┘
                                                      │ reads DB
                                         ┌────────────▼─────────────┐
                                         │ netwatch tui (console)   │
                                         └──────────────────────────┘
```

**1. Central server** (one host reachable by your servers on TCP 7443):

```sh
curl -fsSL https://raw.githubusercontent.com/mnshchtri/Network-monitor/main/install.sh | \
  NETWATCH_SERVER="--name server.example.com" sh
```

This creates a private CA and server certificate, starts the `netwatch-server` service and prints an enrollment command.

**2. Each monitored host**: run the command printed by `sudo netwatch server token` (a new single-use token per host, valid 24h):

```sh
curl -fsSL https://raw.githubusercontent.com/mnshchtri/Network-monitor/main/install.sh | \
  NETWATCH_AGENT="--server server.example.com:7443 --token <T> --pin <fingerprint>" sh
```

**3. Dashboard** on the server host (over SSH is fine):

```sh
sudo netwatch tui
```

Hosts on the left, then per-host tabs: **Alerts**, **Listening ports** (with owning process), **Connections**, and **Changes** (a log of ports that opened or closed, the first thing to check in an investigation). Keys: `↑↓` select, `Tab` switch pane, `←→`/`1-4` tabs, `a` acknowledge, `A` acknowledge all, `x` show acknowledged, `q` quit. `netwatch tui --snapshot` prints one frame as plain text.

### Web dashboard

The same views as the console UI in a browser, plus the access controls a team needs: host list with live status, alert feed, per-host Alerts / Listening ports / Connections / Changes tabs with filtering, active sessions, and an audit log.

```sh
sudo netwatch server user add alice --role admin   # first account (prompts for a password, min 12 chars)
sudo netwatch web                                  # http://127.0.0.1:8080
```

It binds to loopback by default. From your laptop, tunnel over SSH and browse to `http://127.0.0.1:8080`:

```sh
ssh -L 8080:127.0.0.1:8080 you@server
```

**HTTPS** is built in, no reverse proxy needed:

```sh
sudo netwatch web --listen 0.0.0.0:8443 --cert /etc/ssl/netwatch.crt --key /etc/ssl/netwatch.key --allow-host netwatch.example.com
sudo netwatch web --listen 127.0.0.1:8443 --tls      # the server's own CA-signed certificate (trust ca.pem in your browser)
```

HTTPS turns on HSTS and `Secure` cookies. Behind your own TLS proxy instead, use `--allow-host <name> --secure`. A non-loopback address without TLS prints a warning: don't do it.

#### Accounts and roles

| Role | Can |
|---|---|
| `viewer` | See hosts, alerts, ports, connections, changes |
| `operator` | + acknowledge, assign and comment on alerts; edit host tags; start/end maintenance windows |
| `admin` | + audit log (view/export), see and revoke everyone's sessions |

Roles are checked on the server for every request and take effect immediately, including for sessions that are already open. **Accounts are managed only from the server's command line**, so a hijacked dashboard session can never create admins or change roles:

```sh
sudo netwatch server user add bob --role operator    # bob must change the password at first login
sudo netwatch server user list
sudo netwatch server user role bob viewer
sudo netwatch server user disable bob                # ends bob's open sessions immediately
sudo netwatch server user passwd bob                 # reset; change is forced at next login
sudo netwatch server user totp bob                   # enable two-factor (authenticator app)
sudo netwatch server user totp-off bob
```

The last enabled admin cannot be disabled, demoted or deleted. Upgrading from a version with the single shared dashboard password converts it into an `admin` account (forced password change at first login).

#### Security controls

- Passwords: PBKDF2-SHA256, 12+ characters, must not contain the username. Login timing does not reveal whether a user exists.
- Optional TOTP two-factor (RFC 6238, verified against the RFC test vector); a code cannot be used twice.
- Sessions: `HttpOnly` + `SameSite=Strict` cookie, 30-minute idle timeout and 8-hour lifetime (`--idle-minutes`, `--session-hours`), "sign out everywhere", changing a password ends your other sessions.
- Lockout: 5 failed logins from one IP or 10 for one account locks it for 5 minutes. (Per-account lockout means someone who knows a username can lock that user out for 5 minutes; that is the usual trade-off against guessing.)
- Host-header allowlist (DNS rebinding), CSRF header and Origin checks, strict Content-Security-Policy with no third-party assets, agent-supplied text rendered as text, never HTML.

#### Analysis pages

The sidebar is grouped into **Monitor** (Overview, Alerts, Hosts), **Analyze** (Threat sources, Exposure, Traffic), **Manage** (Maintenance, System health) and **Account** (Sessions, Audit log), with live badges for open alerts and risky exposures.

- **Overview** leads with eight risk cards, then *Alerts over time* (stacked by severity), whole-fleet established and half-open connection trends, the busiest hosts, an attack-surface summary and the items that need attention. 24 h / 7 d switch.
- **Threat sources.** Every address named in alerts (scans, brute force, floods), ranked by high-severity alerts, with the alert types it used, how many hosts it hit, how many connections it holds right now and when it was first and last seen. Click one to investigate: what it did, which hosts it touched, its alerts and its current connections. For external addresses the page suggests copy-paste blocking commands (`ufw`, `iptables`/`ip6tables`, `nftables`) to run on the affected host; for internal addresses it warns against blocking blindly. netwatch itself never changes your firewall.
- **Exposure.** Everything listening across the fleet, grouped by port, with a plain-language reason when a service is risky to expose (databases, remote desktop, Docker API, Redis, Memcached, SMB, clear-text protocols...). Loopback-only listeners are never counted as exposed, and IPv4+IPv6 binds of the same port count once. Shows what opened in the last 24 hours.
- **Traffic.** Top inbound sources (with how many distinct ports each touched, which is what a scan looks like), top outbound destinations, most-hit local ports, busiest processes, connection states and per-host load. Based on the latest agent reports (up to 2000 connections per host); loopback peers are ignored.
- **System health** (admins). Checks with a verdict: agents reporting, version skew, agents without root, certificates about to expire, webhook and Prometheus configured, admins without two-factor, TLS. Plus account counts, stored-data sizes against retention, and per-agent details.
- **Hosts** is a sortable, filterable table of the whole fleet.

#### Fleet overview, themes, keyboard and accessibility

- **Fleet overview.** The landing page leads with what needs attention: hosts down, unacknowledged HIGH alerts, new externally reachable listeners, agent certificates expiring within 90 days, agents running without root, active maintenance windows, the top attacking sources of the last 24 hours and an activity-by-type breakdown. Click any item to jump to it. Muted alerts are excluded.
- **Agent certificate expiry.** Agent certificates last until 1 January of (issue year + 5). The server tracks this per host and flags certificates within 90 days of expiry (re-enroll with `netwatch agent enroll --force`). Hosts enrolled before this tracking existed are derived from their enrollment date.
- **Light and dark themes.** Follows your system setting by default; the header button or `t` switches and remembers the choice. The theme is applied before the first paint, so there is no flash.
- **Keyboard.** `/` search, `g o` overview, `g a` alerts, `g h` hosts, `g t` threat sources, `g e` exposure, `g n` traffic, `g m` maintenance, `g y` system health, `g s` sessions, `g u` audit log, `j`/`k` move between table rows, `Enter` opens, `t` theme, `?` help, `Esc` closes panels.
- **Accessibility.** Skip link, labelled landmarks and controls, a live region for connection changes, focus-trapped dialogs that return focus when closed, keyboard focus preserved across the 3-second refresh, status shown as text as well as colour, and respect for reduced-motion. Text/background contrast meets WCAG AA (4.5:1) in both themes; all 52 colour pairs were computed from the stylesheet.
- **Phones and tablets.** Below 820 px the host list becomes a slide-in menu and wide tables scroll sideways.

#### Working with many hosts

- **Tags and groups.** Operators tag hosts (`prod`, `db`, `eu-west`; up to 10 per host, `a-z 0-9 - .`) from the host page. Tag chips at the top of the sidebar filter the host list and the alert feed.
- **Search.** The box in the header searches hosts, tags, listening ports (exact port numbers match: type `3306` to see every host listening on MySQL), processes, IP addresses, connections and alerts. Click a result to jump to it.
- **Alert workflow.** Click an alert to open it: assign it to a user, add notes (kept with the alert, shown as plain text), acknowledge it. Filter the feed by time range, severity and "assigned to me"; export the filtered view as CSV or JSON.
- **Trends.** Per-host charts for 1h / 6h / 24h / 7d with real axes and a hover read-out: established connections, half-open `SYN_RECV` (a flood is obvious here), `TIME_WAIT` and listening sockets. Each point is the *maximum* in its bucket, so a short spike is never averaged away. History is kept for 7 days.
- **Timeline.** One chronological stream per host: alerts, host up/down, ports opened and closed.
- **Maintenance windows.** Mute a host and/or an alert type for 5 minutes to 7 days (a reason is required and goes to the audit log). Muted alerts are **still recorded and shown** (marked `muted`) but don't count as open alerts and aren't sent to the webhook, so nothing is lost for later investigation. Operators and admins can start and end windows.

#### Prometheus metrics

```sh
sudo netwatch server metrics-token     # prints a bearer token once; only its hash is stored
```

Then scrape `GET /metrics` on the dashboard port with `Authorization: Bearer <token>` (the command prints a ready-made `prometheus.yml` snippet). Per-host gauges: `netwatch_host_up`, `netwatch_established_connections`, `netwatch_syn_recv_connections`, `netwatch_time_wait_connections`, `netwatch_listening_sockets`, `netwatch_open_alerts`, `netwatch_host_last_seen_timestamp_seconds`. The endpoint is off until you create a token; running the command again rotates it and `--disable` turns it off. If the dashboard is on a public name, pass `--allow-host` for it.

#### Audit log

Logins (and failures, lockouts), logouts, password changes, alert acknowledgements, session revocations, exports, every account change, setting change and agent revocation made from the CLI. Shown in the dashboard (admin) and from the server:

```sh
sudo netwatch server audit --limit 100       # or --json
sudo netwatch server audit --verify          # recompute the integrity chain
```

Each entry includes the hash of the one before it, so editing an entry or deleting one from the middle is detected (by `--verify` and by a red banner in the dashboard). **Limit:** someone with write access to the database can rewrite the whole chain consistently, or truncate the end. To catch that, periodically record the `Head hash` that `--verify` prints somewhere the server cannot write to. Exports (CSV/JSON) neutralise spreadsheet formula injection.

Server administration:

```sh
sudo netwatch server hosts                 # enrolled hosts and status
sudo netwatch server revoke <host>         # cut an agent off immediately
sudo netwatch server set scan_ports 8      # push a detector setting to every agent
sudo netwatch server set ignore 10.0.0.5,10.0.0.6
sudo netwatch server set down_after 120    # seconds of silence before HOST_DOWN
sudo netwatch server config
```

### Webhook notifications

The server can push alerts to Slack, Discord or any HTTP(S) endpoint:

```sh
sudo netwatch server set webhook_url https://hooks.slack.com/services/T000/B000/XXXX
sudo netwatch server set webhook_min_severity HIGH     # INFO | MEDIUM (default) | HIGH
sudo netwatch server set webhook_format auto           # auto | slack | discord | generic
sudo netwatch server webhook test                      # send a test message
```

Applies immediately, no restart. Slack and Discord are auto-detected from the URL. The `generic` format POSTs JSON you can feed to anything:

```json
{"source":"netwatch","alerts":[{"time":"2026-11-11 18:22:25","host":"web-1","severity":"HIGH","type":"PORT_SCAN","source":"198.51.100.4","message":"…"}]}
```

Bursts are batched into one message, failed deliveries are retried (3 attempts), and a slow or dead endpoint never delays agent reports. `HOST_DOWN` and `HOST_UP` are sent too. The URL is treated as a secret: `server config` only shows its host. HTTPS works on any server (root certificates are bundled); redirects are not followed.

Server-side alerts: `HOST_DOWN` (agent stopped reporting) and `HOST_UP`. The server also appends every alert to `/var/lib/netwatch-server/alerts.jsonl`, ready to ship to a SIEM.

### Security model

- **Agents connect out.** Monitored hosts open no listening port for netwatch; the only inbound port is the server's 7443.
- **Mutual TLS** (rustls) with a private CA. Agents generate their own key and send a CSR, so private keys never leave the host.
- **Enrollment is pinned.** The `--pin` is the SHA-256 of the server certificate, so a man-in-the-middle cannot capture the one-time token. Tokens are single-use and expire after 24h.
- **Revocation** is immediate: `server revoke` invalidates the agent's certificate fingerprint.
- Everything an agent reports is treated as untrusted: size limits, control characters stripped before it reaches the database or your terminal.
- The agent is read-only on the host. Its service runs with only `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH` (to see other users' sockets) and a read-only filesystem.
- Agent certificates are valid for 5 years and there is no automatic renewal yet; re-enroll with `agent enroll --force` before expiry.
- If the server is unreachable the agent buffers alerts to disk and replays them on reconnect. Reports that cannot be sent are not buffered.

## What `watch` detects

| Alert | Meaning | Default trigger |
|---|---|---|
| `NEW_LISTENER` | A port started listening after monitoring began (backdoor / bind shell indicator), with the process that opened it | any |
| `PORT_SCAN` | One IP touched many distinct local ports | 5 ports / 60s |
| `BRUTE_FORCE` | Many new connections from one IP to SSH/FTP/RDP/DB/etc. | 30 conns / 60s |
| `CONN_BURST` | Many new connections from one IP to other ports | 30 conns / 60s |
| `CONN_FLOOD` | One IP holding many simultaneous connections | 100 |
| `SYN_FLOOD` | Many half-open (`SYN_RECV`) sockets | 50 |
| `SYN_COOKIES` | Kernel had to send SYN cookies (backlog overflow) | any |
| `LISTEN_OVERFLOW` | Connections dropped, accept queue full | any |
| `RST_STORM` | High rate of TCP resets sent, typical of scans of closed ports | 100/s |

Tune with `--scan-ports`, `--rate-limit`, `--conn-limit`, `--syn-limit`, `--rst-rate`, `--window`, `--cooldown`. Run `netwatch help` for all options. Use `--ignore <ip>` for your own monitoring/office IPs.

Alerts print to the terminal and, with `--log`, are appended as JSON lines:

```json
{"time":"2026-11-11T17:46:41Z","severity":"HIGH","type":"PORT_SCAN","source":"198.51.100.4","message":"198.51.100.4 touched 5 distinct local ports in 60s: 22,80,443,3306,8080"}
```

## Limitations

`netwatch` polls the kernel's socket tables (default every 2s). Be aware of what that means:

- It sees connections that create a socket, not raw packets. Probes to **closed** ports leave no socket; they only show up indirectly through `RST_STORM`.
- Very short connections between polls can be missed. Lower `--interval` (e.g. `0.5`) for finer resolution. Lingering `TIME_WAIT`/`SYN_RECV` entries help catch many of them.
- Without root, process names for other users' sockets are not available.
- It is a triage and investigation aid, not a replacement for a firewall, IDS (Suricata/Zeek) or fail2ban. Thresholds are heuristics; expect to tune them and `--ignore` known-good IPs (load balancers, health checks).

## Releasing

Pushing a tag like `v0.2.0` triggers `.github/workflows/release.yml`, which builds static musl binaries for x86_64 and aarch64 and publishes them with checksums for the installer.

## License

MIT
