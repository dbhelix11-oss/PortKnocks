#!/usr/bin/env bash
# End-to-end test for `default_deny = true` mode: knockd's chain becomes
# the default-deny authority for the whole (simulated) host, not just
# target_port. Two network namespaces connected by a veth pair, so this
# never touches the real host firewall. Must be run as root.
#
# Usage: sudo bash server/tests/e2e_netns_default_deny_test.sh
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "must be run as root (sudo bash $0)" >&2
    exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERVER_DIR="$ROOT_DIR/server"
CLIENT_DIR="$ROOT_DIR/client"
WORK_DIR="$(mktemp -d)"

NS_SERVER=knock_srv_dd
NS_CLIENT=knock_cli_dd
VETH_SRV=veth-srv-dd
VETH_CLI=veth-cli-dd
SRV_IP=10.202.0.1
CLI_IP=10.202.0.2
ALWAYS_PORT=2200   # always reachable, no knock needed -- the "decoy"
TARGET_PORT=2222   # knock-gated
UNLISTED_PORT=2233 # nothing listens here; must be dropped, not just closed
OPEN_DURATION=8

KNOCKD_PID=""
ALWAYS_HTTPD_PID=""
TARGET_HTTPD_PID=""

cleanup() {
    echo "--- cleaning up ---"
    [[ -n "$KNOCKD_PID" ]] && kill "$KNOCKD_PID" 2>/dev/null || true
    [[ -n "$ALWAYS_HTTPD_PID" ]] && ip netns exec "$NS_SERVER" kill "$ALWAYS_HTTPD_PID" 2>/dev/null || true
    [[ -n "$TARGET_HTTPD_PID" ]] && ip netns exec "$NS_SERVER" kill "$TARGET_HTTPD_PID" 2>/dev/null || true
    ip netns del "$NS_SERVER" 2>/dev/null || true
    ip netns del "$NS_CLIENT" 2>/dev/null || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

echo "--- building server if needed ---"
make -C "$SERVER_DIR" >/dev/null

echo "--- setting up namespaces + veth pair ---"
ip netns add "$NS_SERVER"
ip netns add "$NS_CLIENT"
ip link add "$VETH_SRV" type veth peer name "$VETH_CLI"
ip link set "$VETH_SRV" netns "$NS_SERVER"
ip link set "$VETH_CLI" netns "$NS_CLIENT"

ip netns exec "$NS_SERVER" ip addr add "$SRV_IP/24" dev "$VETH_SRV"
ip netns exec "$NS_SERVER" ip link set "$VETH_SRV" up
ip netns exec "$NS_SERVER" ip link set lo up

ip netns exec "$NS_CLIENT" ip addr add "$CLI_IP/24" dev "$VETH_CLI"
ip netns exec "$NS_CLIENT" ip link set "$VETH_CLI" up
ip netns exec "$NS_CLIENT" ip link set lo up

echo "--- generating a fresh shared secret ---"
openssl rand -out "$WORK_DIR/secret.key" 32
chmod 600 "$WORK_DIR/secret.key"

echo "--- starting two plain HTTP servers: one always-allowed, one knock-gated ---"
ip netns exec "$NS_SERVER" python3 -m http.server "$ALWAYS_PORT" --bind "$SRV_IP" \
    >"$WORK_DIR/always_httpd.log" 2>&1 &
ALWAYS_HTTPD_PID=$!
# Bound to all addresses (not just $SRV_IP) so the loopback check below can
# also reach it, from inside the server namespace itself -- proving the new
# `iif "lo" accept` rule holds even under default_deny's drop-everything
# policy, the same way it must for e.g. an SSM-forwarded connection hitting
# a knock-gated port via 127.0.0.1.
ip netns exec "$NS_SERVER" python3 -m http.server "$TARGET_PORT" --bind 0.0.0.0 \
    >"$WORK_DIR/target_httpd.log" 2>&1 &
TARGET_HTTPD_PID=$!
sleep 0.5

cat > "$WORK_DIR/knockd.conf" <<EOF
[knock]
keyfile = $WORK_DIR/secret.key
time_step = 30
n_ports = 6
port_low = 20000
port_high = 60000
inactivity_timeout = 5
replay_ttl = 90

[server]
interface = $VETH_SRV
target_port = $TARGET_PORT
open_duration = $OPEN_DURATION
base_chain_priority = -10
default_deny = true
always_allow_ports = $ALWAYS_PORT
EOF

cat > "$WORK_DIR/knock.conf" <<EOF
[knock]
keyfile = $WORK_DIR/secret.key
time_step = 30
n_ports = 6
port_low = 20000
port_high = 60000
knock_interval_ms = 100
knock_proto = tcp-syn
EOF

echo "--- starting knockd (default_deny=true) in the server namespace ---"
ip netns exec "$NS_SERVER" "$SERVER_DIR/knockd" --config "$WORK_DIR/knockd.conf" \
    >"$WORK_DIR/knockd.log" 2>&1 &
KNOCKD_PID=$!
sleep 1

echo "--- sanity check: knockd process alive? ---"
if ! kill -0 "$KNOCKD_PID" 2>/dev/null; then
    echo "knockd failed to start, log follows:" >&2
    cat "$WORK_DIR/knockd.log" >&2
    exit 1
fi

# Distinguishes a firewall DROP (curl times out, exit 28) from a port
# that's merely closed/refused (curl exit 7) or a real response (exit 0
# plus an HTTP status) -- "not 200" alone can't tell these apart, and
# proving default_deny actually *drops* rather than just "nothing happens
# to be listening" is the whole point of this test.
check_port() {
    local port=$1
    local out rc
    set +e
    out=$(ip netns exec "$NS_CLIENT" curl -s -o /dev/null -w '%{http_code}' --max-time 2 \
        "http://$SRV_IP:$port/" 2>/dev/null)
    rc=$?
    set -e
    case "$rc" in
        28) echo "TIMEOUT" ;;
        7)  echo "REFUSED" ;;
        0)  echo "OK:$out" ;;
        *)  echo "OTHER:$rc" ;;
    esac
}

# Same, but issued from inside NS_SERVER itself against 127.0.0.1 -- the
# `iif "lo" accept` rule should let this through regardless of any knock or
# always_allow_ports, the same way an SSM-forwarded connection would land.
check_port_loopback() {
    local port=$1
    local out rc
    set +e
    out=$(ip netns exec "$NS_SERVER" curl -s -o /dev/null -w '%{http_code}' --max-time 2 \
        "http://127.0.0.1:$port/" 2>/dev/null)
    rc=$?
    set -e
    case "$rc" in
        28) echo "TIMEOUT" ;;
        7)  echo "REFUSED" ;;
        0)  echo "OK:$out" ;;
        *)  echo "OTHER:$rc" ;;
    esac
}

echo "--- 1) always_allow_ports reachable with no knock at all ---"
RESULT_ALWAYS_BEFORE=$(check_port "$ALWAYS_PORT")
echo "always_allow port result (before any knock): $RESULT_ALWAYS_BEFORE"

echo "--- 2) an unlisted port is dropped (timeout), not just closed ---"
RESULT_UNLISTED_BEFORE=$(check_port "$UNLISTED_PORT")
echo "unlisted port result: $RESULT_UNLISTED_BEFORE"

echo "--- 3) target_port is dropped before any knock ---"
RESULT_TARGET_BEFORE=$(check_port "$TARGET_PORT")
echo "target_port result (before knock): $RESULT_TARGET_BEFORE"

echo "--- 3b) target_port still reachable over loopback despite default_deny + no knock ---"
RESULT_LOOPBACK_BEFORE=$(check_port_loopback "$TARGET_PORT")
echo "loopback result (before any knock): $RESULT_LOOPBACK_BEFORE"

echo "--- 4) knocking channel 0 ---"
if [[ ! -d "$CLIENT_DIR/.venv" ]]; then
    echo "client/.venv not found; run 'python3 -m venv .venv && .venv/bin/pip install -r requirements.txt' in client/ first" >&2
    exit 1
fi
ip netns exec "$NS_CLIENT" env PYTHONPATH="$CLIENT_DIR" "$CLIENT_DIR/.venv/bin/python" -m knockc.cli \
    --config "$WORK_DIR/knock.conf" --target "$SRV_IP"
sleep 0.5

echo "--- 5) target_port now reachable, always_allow_port still reachable, unlisted port still dropped ---"
RESULT_TARGET_AFTER=$(check_port "$TARGET_PORT")
RESULT_ALWAYS_AFTER=$(check_port "$ALWAYS_PORT")
RESULT_UNLISTED_AFTER=$(check_port "$UNLISTED_PORT")
echo "target_port result (after knock): $RESULT_TARGET_AFTER"
echo "always_allow port result (after knock): $RESULT_ALWAYS_AFTER"
echo "unlisted port result (after knock): $RESULT_UNLISTED_AFTER"

echo "--- results ---"
PASS=1
[[ "$RESULT_ALWAYS_BEFORE" == "OK:200" ]] || { echo "FAIL: always_allow_port not reachable before any knock"; PASS=0; }
[[ "$RESULT_UNLISTED_BEFORE" == "TIMEOUT" ]] || { echo "FAIL: unlisted port not dropped before any knock (got $RESULT_UNLISTED_BEFORE)"; PASS=0; }
[[ "$RESULT_TARGET_BEFORE" == "TIMEOUT" ]] || { echo "FAIL: target_port not dropped before knock (got $RESULT_TARGET_BEFORE)"; PASS=0; }
[[ "$RESULT_LOOPBACK_BEFORE" == "OK:200" ]] || { echo "FAIL: target_port not reachable over loopback despite no knock (got $RESULT_LOOPBACK_BEFORE)"; PASS=0; }
[[ "$RESULT_TARGET_AFTER" == "OK:200" ]] || { echo "FAIL: target_port not reachable after a valid knock (got $RESULT_TARGET_AFTER)"; PASS=0; }
[[ "$RESULT_ALWAYS_AFTER" == "OK:200" ]] || { echo "FAIL: always_allow_port broken after a knock (got $RESULT_ALWAYS_AFTER)"; PASS=0; }
[[ "$RESULT_UNLISTED_AFTER" == "TIMEOUT" ]] || { echo "FAIL: unlisted port opened up after an unrelated knock (got $RESULT_UNLISTED_AFTER)"; PASS=0; }

if [[ "$PASS" == "1" ]]; then
    echo "PASS: default_deny mode behaved as expected"
    exit 0
else
    echo "--- debug: knockd.log ---"
    cat "$WORK_DIR/knockd.log" || true
    echo "--- debug: nft ruleset in server namespace ---"
    ip netns exec "$NS_SERVER" nft list ruleset || true
    exit 1
fi
