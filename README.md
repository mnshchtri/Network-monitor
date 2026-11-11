# netwatch

A defensive network monitor for Linux servers, written in Rust. It shows what is listening, which process owns each socket (like `lsof -i`), and raises alerts on signs of network attacks, so you have a record to investigate afterwards.

- **Single static binary, zero dependencies.** Pure Rust std; reads `/proc` directly. No libpcap, no Python, no runtime.
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

## Usage

Run with `sudo` so process names can be resolved for every socket.

```sh
sudo netwatch ports                       # listening ports + process, user
sudo netwatch conns                       # all sockets
sudo netwatch conns --state SYN_RECV      # filter by state
sudo netwatch conns --port 22 --json      # filter by port, JSON lines
sudo netwatch watch                       # live attack detection
sudo netwatch watch --log alerts.jsonl --ignore 203.0.113.7
```

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

Pushing a tag like `v0.1.0` triggers `.github/workflows/release.yml`, which builds static musl binaries for x86_64 and aarch64 and publishes them with checksums for the installer.

## License

MIT
