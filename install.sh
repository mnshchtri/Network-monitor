#!/bin/sh
# netwatch installer
#   curl -fsSL https://raw.githubusercontent.com/mnshchtri/Network-monitor/main/install.sh | sh
#
# Env options:
#   NETWATCH_SERVER="--name <address>"   set up the central server as a systemd service
#   NETWATCH_AGENT="--server h:7443 --token T --pin FP"   enroll this host and run the agent service
#                        (the exact command is printed by 'netwatch server token')
#   NETWATCH_SERVICE=1   standalone mode: local detection as a systemd service
#   NETWATCH_VERSION=v0.1.0   install a specific release (default: latest)
#   NETWATCH_FROM_SOURCE=1    skip the prebuilt binary and compile with cargo
#   PREFIX=/some/dir     install directory for the binary
set -eu

REPO="mnshchtri/Network-monitor"
BIN="netwatch"

say() { printf '==> %s\n' "$*"; }
fail() { printf 'error: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

[ "$(uname -s)" = "Linux" ] || fail "netwatch reads /proc and only supports Linux"

case "$(uname -m)" in
  x86_64|amd64)  ARCH=x86_64 ;;
  aarch64|arm64) ARCH=aarch64 ;;
  *) ARCH="" ;;
esac

# Privilege helper: use sudo only when needed.
if [ "$(id -u)" -eq 0 ]; then SUDO=""; elif have sudo; then SUDO="sudo"; else SUDO=""; fi

if [ -n "${PREFIX:-}" ]; then DEST="$PREFIX"
elif [ "$(id -u)" -eq 0 ] || [ -n "$SUDO" ]; then DEST=/usr/local/bin
else DEST="$HOME/.local/bin"; fi

fetch() { # url outfile
  if have curl; then curl -fsSL "$1" -o "$2"
  elif have wget; then wget -qO "$2" "$1"
  else fail "need curl or wget"; fi
}

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT INT TERM

install_bin() { # path-to-binary
  if [ -w "$DEST" ] 2>/dev/null || { [ ! -e "$DEST" ] && mkdir -p "$DEST" 2>/dev/null; }; then
    install -m 0755 "$1" "$DEST/$BIN"
  else
    $SUDO mkdir -p "$DEST" && $SUDO install -m 0755 "$1" "$DEST/$BIN"
  fi
}

got=0
if [ -n "$ARCH" ] && [ -z "${NETWATCH_FROM_SOURCE:-}" ]; then
  if [ -n "${NETWATCH_VERSION:-}" ]; then
    BASE="https://github.com/$REPO/releases/download/$NETWATCH_VERSION"
  else
    BASE="https://github.com/$REPO/releases/latest/download"
  fi
  ASSET="$BIN-$ARCH-linux.tar.gz"
  say "Downloading $ASSET"
  if fetch "$BASE/$ASSET" "$TMP/$ASSET" 2>/dev/null; then
    if fetch "$BASE/$ASSET.sha256" "$TMP/$ASSET.sha256" 2>/dev/null; then
      ( cd "$TMP" && if have sha256sum; then sha256sum -c "$ASSET.sha256" >/dev/null; \
        else shasum -a 256 -c "$ASSET.sha256" >/dev/null; fi ) || fail "checksum mismatch, aborting"
      say "Checksum OK"
    else
      say "No checksum published for this release, skipping verification"
    fi
    tar -xzf "$TMP/$ASSET" -C "$TMP" "$BIN"
    got=1
  else
    say "No prebuilt binary available, falling back to building from source"
  fi
fi

if [ "$got" -eq 0 ]; then
  if ! have cargo; then
    have curl || have wget || fail "need curl or wget"
    say "Installing a Rust toolchain via rustup (user-local, no root)"
    fetch https://sh.rustup.rs "$TMP/rustup.sh"
    sh "$TMP/rustup.sh" -y --profile minimal --no-modify-path >/dev/null
    PATH="$HOME/.cargo/bin:$PATH"
  fi
  have cc || have gcc || fail "a C linker (gcc/cc) is required to build; install build-essential / base-devel"
  say "Building from source"
  if have git; then
    git clone --depth 1 "https://github.com/$REPO.git" "$TMP/src" >/dev/null 2>&1 || fail "git clone failed"
  else
    fetch "https://github.com/$REPO/archive/refs/heads/main.tar.gz" "$TMP/src.tgz"
    mkdir "$TMP/src" && tar -xzf "$TMP/src.tgz" -C "$TMP/src" --strip-components=1
  fi
  ( cd "$TMP/src" && cargo build --release --quiet )
  cp "$TMP/src/target/release/$BIN" "$TMP/$BIN"
fi

install_bin "$TMP/$BIN"
say "Installed $DEST/$BIN ($("$DEST/$BIN" version))"

case ":$PATH:" in *":$DEST:"*) ;; *) say "Note: $DEST is not on your PATH" ;; esac

need_systemd() {
  have systemctl || fail "systemd not found; cannot install a service (run the command manually instead)"
  { [ "$(id -u)" -eq 0 ] || [ -n "$SUDO" ]; } || fail "root (or sudo) is required to install a service"
}

install_unit() { # name  (unit text on stdin)
  cat > "$TMP/$1.service"
  $SUDO install -m 0644 "$TMP/$1.service" "/etc/systemd/system/$1.service"
  $SUDO systemctl daemon-reload
  $SUDO systemctl enable --now "$1.service"
}

# Standalone mode: local detection only, alerts to a JSON-lines file.
if [ -n "${NETWATCH_SERVICE:-}" ]; then
  need_systemd
  say "Installing standalone watch service"
  install_unit netwatch <<UNIT
[Unit]
Description=netwatch defensive network monitor
After=network.target

[Service]
ExecStart=$DEST/$BIN watch --log /var/log/netwatch/alerts.jsonl
Restart=on-failure
LogsDirectory=netwatch
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
ReadWritePaths=/var/log/netwatch
CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH

[Install]
WantedBy=multi-user.target
UNIT
  say "Running. Alerts: /var/log/netwatch/alerts.jsonl   Live: journalctl -fu netwatch"
fi

# Central server: NETWATCH_SERVER="--name server.example.com"  (the address agents will use)
if [ -n "${NETWATCH_SERVER:-}" ]; then
  need_systemd
  say "Setting up the netwatch server"
  if [ ! -f /var/lib/netwatch-server/server.pem ]; then
    # shellcheck disable=SC2086
    $SUDO "$DEST/$BIN" server init $NETWATCH_SERVER
  fi
  install_unit netwatch-server <<UNIT
[Unit]
Description=netwatch central server
After=network.target

[Service]
ExecStart=$DEST/$BIN server run --log /var/lib/netwatch-server/alerts.jsonl
Restart=on-failure
StateDirectory=netwatch-server
StateDirectoryMode=0700
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
ReadWritePaths=/var/lib/netwatch-server
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
UNIT
  say "Server running on port 7443 (allow it in your firewall). Add monitored hosts with a token:"
  $SUDO "$DEST/$BIN" server token
  say "Dashboard: sudo netwatch tui"
fi

# Monitored host: NETWATCH_AGENT="--server host:7443 --token T --pin FP" (from 'netwatch server token')
if [ -n "${NETWATCH_AGENT:-}" ]; then
  need_systemd
  say "Enrolling this host"
  # shellcheck disable=SC2086
  $SUDO "$DEST/$BIN" agent enroll $NETWATCH_AGENT
  install_unit netwatch-agent <<UNIT
[Unit]
Description=netwatch agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$DEST/$BIN agent run
Restart=always
RestartSec=5
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
ReadWritePaths=/etc/netwatch
# Needed to map sockets to processes owned by other users; nothing else.
CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH

[Install]
WantedBy=multi-user.target
UNIT
  say "Agent running. Logs: journalctl -fu netwatch-agent"
fi

cat <<MSG

Try it (run with sudo to see process names for every socket):
  sudo netwatch ports          # listening ports + owning process
  sudo netwatch conns          # every connection
  sudo netwatch watch          # live attack detection (standalone)

Fleet mode:  netwatch server | netwatch agent | netwatch tui   (see README)
MSG
