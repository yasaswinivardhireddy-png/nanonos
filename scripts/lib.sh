#!/usr/bin/env bash
# Shared helpers for the network-namespace integration tests. Run as root.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BUILD=${BUILD:-$ROOT/build}
NANONOSD=$BUILD/nanonosd
NOSCTL_BIN=$BUILD/nosctl
RUN=${RUN:-/tmp/nanonos-test}
SUMMARY=${GITHUB_STEP_SUMMARY:-/dev/null}
NAMESPACES=()
PIDS=()

rm -rf "$RUN"
mkdir -p "$RUN"

pass() {
  echo "PASS: $*"
  echo "- PASS: $*" >> "$SUMMARY"
}

fail() {
  echo "FAIL: $*"
  echo "- FAIL: $*" >> "$SUMMARY"
  dump_logs
  exit 1
}

dump_logs() {
  for f in "$RUN"/*.log; do
    [ -e "$f" ] || continue
    echo "===== $f (last 60 lines)"
    tail -n 60 "$f"
  done
}

cleanup() {
  set +e
  for pid in "${PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2> /dev/null
  done
  sleep 0.3
  for ns in "${NAMESPACES[@]:-}"; do
    [ -n "$ns" ] && ip netns del "$ns" 2> /dev/null
  done
}
trap cleanup EXIT

make_ns() {
  ip netns add "$1"
  NAMESPACES+=("$1")
  ip -n "$1" link set lo up
  ip netns exec "$1" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
}

# connect NS1 IF1 NS2 IF2: a veth pair. Checksum and segmentation offloads are
# off so frames crossing the userspace switch carry complete checksums.
connect() {
  ip link add "$2" netns "$1" type veth peer name "$4" netns "$3"
  for end in "$1:$2" "$3:$4"; do
    local ns=${end%%:*} dev=${end#*:}
    ip netns exec "$ns" ethtool -K "$dev" rx off tx off tso off gso off gro off > /dev/null 2>&1 || true
    ip -n "$ns" link set "$dev" up
  done
}

host_ip() { # host_ip NS DEV ADDR/LEN GATEWAY
  ip -n "$1" addr add "$3" dev "$2"
  ip -n "$1" route add default via "$4"
}

nosctl() { # nosctl NS command...
  local ns=$1
  shift
  "$NOSCTL_BIN" -s "$RUN/$ns.sock" "$@"
}

wait_for() { # wait_for DESCRIPTION TIMEOUT_S command...
  local what=$1 timeout=$2
  shift 2
  local deadline=$((SECONDS + timeout))
  until "$@" > /dev/null 2>&1; do
    if ((SECONDS >= deadline)); then fail "timed out waiting for $what"; fi
    sleep 0.2
  done
}

start_switch() { # start_switch NS CONFIG
  ip netns exec "$1" "$NANONOSD" -c "$2" -s "$RUN/$1.sock" -t 2 > "$RUN/$1.log" 2>&1 &
  PIDS+=($!)
  wait_for "$1 CLI" 10 nosctl "$1" show version
}

# json EXPR: evaluates a Python expression over the JSON document on stdin (as d).
json() {
  python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"
}

now() { date +%s.%N; }
elapsed() { python3 -c "print(round($(now) - $1, 2))"; }
