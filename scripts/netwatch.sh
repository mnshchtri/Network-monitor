#!/usr/bin/env bash
# Start / stop / inspect `netwatch up` (server + agent + web dashboard) as a background service.
#
#   scripts/netwatch.sh start [up options]   start in the background (options go to `netwatch up`)
#   scripts/netwatch.sh stop                 stop gracefully (Ctrl-C equivalent), escalate if it hangs
#   scripts/netwatch.sh restart [up options]
#   scripts/netwatch.sh status
#   scripts/netwatch.sh logs [-n LINES]      follow the log
#
# Examples:
#   scripts/netwatch.sh start
#   scripts/netwatch.sh start --web-listen 127.0.0.1:9090 --no-agent
#   sudo scripts/netwatch.sh start           # as root: process names for every socket
#
# Environment:
#   NETWATCH_BIN      path to the netwatch binary (default: ./target/release/netwatch next to this
#                     repo, then `netwatch` from PATH)
#   NETWATCH_RUN_DIR  where the pid file and log live (default: ~/.local/state/netwatch, or
#                     /var/run/netwatch-ctl when root)
#
# It only ever signals the process recorded in its own pid file, and only if that process is
# really netwatch, so a stale or recycled pid can never make it kill something else.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$script_dir/.." && pwd)"

if [[ -n "${NETWATCH_RUN_DIR:-}" ]]; then
  run_dir="$NETWATCH_RUN_DIR"
elif [[ $EUID -eq 0 ]]; then
  run_dir=/var/run/netwatch-ctl
else
  run_dir="${XDG_STATE_HOME:-$HOME/.local/state}/netwatch"
fi
pid_file="$run_dir/netwatch.pid"
log_file="$run_dir/netwatch.log"
args_file="$run_dir/netwatch.args"
url_file="$run_dir/netwatch.url"

if [[ -t 1 ]]; then red=$'\e[31m'; green=$'\e[32m'; dim=$'\e[2m'; off=$'\e[0m'; else red=; green=; dim=; off=; fi
say()  { printf '%s\n' "$*"; }
ok()   { printf '%s%s%s\n' "$green" "$*" "$off"; }
die()  { printf '%serror:%s %s\n' "$red" "$off" "$*" >&2; exit 1; }

find_bin() {
  if [[ -n "${NETWATCH_BIN:-}" ]]; then
    [[ -x "$NETWATCH_BIN" ]] || die "NETWATCH_BIN=$NETWATCH_BIN is not executable"
    printf '%s' "$NETWATCH_BIN"
  elif [[ -x "$repo_dir/target/release/netwatch" ]]; then
    printf '%s' "$repo_dir/target/release/netwatch"
  elif command -v netwatch >/dev/null 2>&1; then
    command -v netwatch
  else
    die "netwatch binary not found. Build it (cargo build --release), install it, or set NETWATCH_BIN."
  fi
}

# Is the pid in the pid file alive AND actually netwatch?
managed_pid() {
  [[ -f "$pid_file" ]] || return 1
  local pid
  pid="$(<"$pid_file")"
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  [[ -r "/proc/$pid/comm" ]] || return 1
  [[ "$(<"/proc/$pid/comm")" == "netwatch" ]] || return 1
  printf '%s' "$pid"
}

wait_gone() { # pid seconds
  local pid=$1 n=$(( $2 * 10 ))
  while (( n-- > 0 )); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.1
  done
  ! kill -0 "$pid" 2>/dev/null
}

cmd_start() {
  local bin pid
  bin="$(find_bin)"
  if pid="$(managed_pid)"; then
    ok "already running (pid $pid). Use '$0 status' or '$0 restart'."
    return 0
  fi
  if [[ -f "$pid_file" ]]; then
    say "${dim}removing stale pid file${off}"
    rm -f "$pid_file"
  fi
  mkdir -p "$run_dir"
  chmod 700 "$run_dir"
  # Keep the log from growing without bound.
  if [[ -f "$log_file" && $(stat -c %s "$log_file" 2>/dev/null || echo 0) -gt 10485760 ]]; then
    mv -f "$log_file" "$log_file.1"
  fi

  printf '%s\n' "$*" > "$args_file"
  rm -f "$url_file"
  say "starting: $bin up $*"
  # Only look at what THIS run writes; older lines in the log must never influence the result.
  local start_off
  start_off="$(stat -c %s "$log_file" 2>/dev/null || echo 0)"
  new_log() { tail -c +$(( start_off + 1 )) "$log_file"; }
  printf '\n=== %s start: %s up %s ===\n' "$(date '+%F %T')" "$bin" "$*" >> "$log_file"
  nohup "$bin" up "$@" >> "$log_file" 2>&1 < /dev/null &
  pid=$!
  disown "$pid" 2>/dev/null || true
  printf '%s\n' "$pid" > "$pid_file"

  # `up` validates its options and ports first; wait until it is clearly running or has died.
  local i ready=0
  for (( i = 0; i < 100; i++ )); do
    if ! kill -0 "$pid" 2>/dev/null; then
      rm -f "$pid_file"
      printf '%s\n' "${red}netwatch exited during startup. Its output:${off}" >&2
      new_log | tail -n 15 >&2
      exit 1
    fi
    if new_log | grep -q '\[up\] running'; then ready=1; break; fi
    sleep 0.1
  done
  if (( ! ready )); then
    say "${dim}still starting after 10 s; check '$0 logs'${off}"
    return 0
  fi

  # The "running" line is printed just before the web component binds; wait for its verdict.
  local url="" skipped=0
  for (( i = 0; i < 30; i++ )); do
    url="$(new_log | grep -o 'http://[^ ]*' | tail -n 1 || true)"
    [[ -n "$url" ]] && break
    new_log | grep -q 'skipping the web dashboard' && { skipped=1; break; }
    [[ " $* " == *" --no-web "* ]] && break
    sleep 0.1
  done
  if [[ -n "$url" ]]; then
    local hp="${url#http://}"; hp="${hp%%/*}"
    for (( i = 0; i < 50; i++ )); do
      if (exec 3<>"/dev/tcp/${hp%:*}/${hp##*:}") 2>/dev/null; then break; fi
      sleep 0.1
    done
    printf '%s\n' "$url" > "$url_file"
  fi
  kill -0 "$pid" 2>/dev/null || { rm -f "$pid_file" "$url_file"; die "netwatch exited right after starting; see $log_file"; }
  ok "started (pid $pid)"
  [[ -n "$url" ]] && say "dashboard: $url"
  (( skipped )) && say "note: no dashboard account exists yet. Create one, then restart:  $bin server user add <name> --role admin"
  say "log:       $log_file"
}

cmd_stop() {
  local pid
  if ! pid="$(managed_pid)"; then
    [[ -f "$pid_file" ]] && { say "${dim}removing stale pid file${off}"; rm -f "$pid_file"; }
    say "not running (nothing started by this script)."
    return 0
  fi
  # Remember the children now: if we have to escalate, they must not be left behind.
  local children
  children="$(pgrep -P "$pid" 2>/dev/null || true)"

  say "stopping netwatch (pid $pid)…"
  kill -INT "$pid" 2>/dev/null || true       # same as Ctrl-C: `up` stops its children cleanly
  if ! wait_gone "$pid" 10; then
    say "${dim}did not exit in 10 s, sending SIGTERM${off}"
    kill -TERM "$pid" 2>/dev/null || true
    if ! wait_gone "$pid" 5; then
      say "${dim}still alive, sending SIGKILL${off}"
      kill -KILL "$pid" 2>/dev/null || true
      wait_gone "$pid" 3 || die "could not stop pid $pid"
    fi
  fi
  local c
  for c in $children; do
    if [[ -r "/proc/$c/comm" && "$(<"/proc/$c/comm")" == "netwatch" ]]; then
      kill -TERM "$c" 2>/dev/null || true
      wait_gone "$c" 3 || kill -KILL "$c" 2>/dev/null || true
    fi
  done
  rm -f "$pid_file" "$url_file"
  printf '=== %s stop ===\n' "$(date '+%F %T')" >> "$log_file" 2>/dev/null || true
  ok "stopped."
}

cmd_status() {
  local pid
  if pid="$(managed_pid)"; then
    ok "running (pid $pid, up $(ps -o etime= -p "$pid" | tr -d ' '))"
    local url
    url="$(cat "$url_file" 2>/dev/null || true)"
    [[ -n "$url" ]] && say "dashboard: $url"
    say "components:"
    pgrep -P "$pid" -a 2>/dev/null | sed -E 's|^([0-9]+) .*/netwatch |  \1  |' | cut -c1-100 || true
    say "log:       $log_file"
  else
    say "stopped."
    # Be helpful if someone started it by hand, but never touch those processes.
    local other
    other="$(pgrep -x netwatch -a 2>/dev/null | grep -E ' up( |$)' || true)"
    [[ -n "$other" ]] && say "${dim}note: a netwatch 'up' started outside this script is running; stop it with Ctrl-C in its terminal.${off}"
    return 3
  fi
}

cmd_logs() {
  [[ -f "$log_file" ]] || die "no log yet ($log_file)"
  local n=50
  [[ "${1:-}" == "-n" && -n "${2:-}" ]] && n="$2"
  exec tail -n "$n" -f "$log_file"
}

usage() { sed -n '2,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

case "${1:-}" in
  start)   shift; cmd_start "$@" ;;
  stop)    cmd_stop ;;
  restart) shift; cmd_stop; cmd_start "$@" ;;
  status)  cmd_status ;;
  logs)    shift; cmd_logs "$@" ;;
  -h|--help|help|"") usage ;;
  *) usage >&2; exit 2 ;;
esac
