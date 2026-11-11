#!/bin/sh
# netwatch installer
#   curl -fsSL https://raw.githubusercontent.com/mnshchtri/Network-monitor/main/install.sh | sh
#
# Env options:
#   NETWATCH_SERVICE=1   also install + start a systemd service logging to /var/log/netwatch/alerts.jsonl
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

if [ -n "${NETWATCH_SERVICE:-}" ]; then
  have systemctl || fail "systemd not found; cannot install the service"
  say "Installing systemd service"
  UNIT="$TMP/netwatch.service"
  fetch "https://raw.githubusercontent.com/$REPO/main/packaging/netwatch.service" "$UNIT"
  sed -i "s|/usr/local/bin/netwatch|$DEST/$BIN|" "$UNIT"
  $SUDO install -m 0644 "$UNIT" /etc/systemd/system/netwatch.service
  $SUDO systemctl daemon-reload
  $SUDO systemctl enable --now netwatch.service
  say "Service running. Alerts: /var/log/netwatch/alerts.jsonl   Live: journalctl -fu netwatch"
fi

cat <<MSG

Try it (run with sudo to see process names for every socket):
  sudo netwatch ports          # listening ports + owning process
  sudo netwatch conns          # every connection
  sudo netwatch watch          # live attack detection
MSG
