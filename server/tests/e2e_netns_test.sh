#!/usr/bin/env bash
# End-to-end test: two network namespaces connected by a veth pair, so the
# real nftables integration is exercised without touching the host's
# firewall. Must be run as root (needs CAP_NET_ADMIN/CAP_NET_RAW).
#
# Usage: sudo bash server/tests/e2e_netns_test.sh
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "must be run as root (sudo bash $0)" >&2
    exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERVER_DIR="$ROOT_DIR/server"
CLIENT_DIR="$ROOT_DIR/client"
WORK_DIR="$(mktemp -d)"

NS_SERVER=knock_srv_test
NS_CLIENT=knock_cli_test
VETH_SRV=veth-srv-t
VETH_CLI=veth-cli-t
SRV_IP=10.201.0.1
CLI_IP=10.201.0.2
TARGET_PORT=2222
OPEN_DURATION=8

KNOCKD_PID=""
HTTPD_PID=""

cleanup() {
    echo "--- cleaning up ---"
    [[ -n "$KNOCKD_PID" ]] && kill "$KNOCKD_PID" 2>/dev/null || true
    [[ -n "$HTTPD_PID" ]] && ip netns exec "$NS_SERVER" kill "$HTTPD_PID" 2>/dev/null || true
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

echo "--- setting up channel 1's command (touches a marker file) ---"
cat > "$WORK_DIR/channel1.sh" <<EOF
#!/bin/sh
touch "$WORK_DIR/channel1_marker"
EOF
chmod +x "$WORK_DIR/channel1.sh"

echo "--- starting a plain HTTP server as the 'protected service' on port $TARGET_PORT ---"
# Bound to all addresses (not just $SRV_IP) so step 4b below can also reach
# it over loopback, from inside the server namespace itself -- proving the
# new `iif "lo" accept` rule, not just the veth-facing knock/deny rules.
ip netns exec "$NS_SERVER" python3 -m http.server "$TARGET_PORT" --bind 0.0.0.0 \
    >"$WORK_DIR/httpd.log" 2>&1 &
HTTPD_PID=$!
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

[channel.1]
command = $WORK_DIR/channel1.sh
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

echo "--- starting knockd in the server namespace ---"
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

test_curl() {
    ip netns exec "$NS_CLIENT" curl -s -o /dev/null -w '%{http_code}' \
        --max-time 2 "http://$SRV_IP:$TARGET_PORT/" || true
}

echo "--- 1) before knocking: request should be refused/timeout ---"
CODE_BEFORE=$(test_curl)
echo "http code before knock: $CODE_BEFORE"

echo "--- 2) sending the knock sequence from the client namespace ---"
if [[ ! -d "$CLIENT_DIR/.venv" ]]; then
    echo "client/.venv not found; run 'python3 -m venv .venv && .venv/bin/pip install -r requirements.txt' in client/ first" >&2
    exit 1
fi
ip netns exec "$NS_CLIENT" env PYTHONPATH="$CLIENT_DIR" "$CLIENT_DIR/.venv/bin/python" -m knockc.cli \
    --config "$WORK_DIR/knock.conf" --target "$SRV_IP"

sleep 0.5
echo "--- 3) after knocking: request should succeed ---"
CODE_AFTER=$(test_curl)
echo "http code after knock: $CODE_AFTER"

echo "--- 4) waiting for open_duration (${OPEN_DURATION}s) to expire ---"
sleep "$((OPEN_DURATION + 3))"
CODE_EXPIRED=$(test_curl)
echo "http code after expiry: $CODE_EXPIRED"

echo "--- 4b) loopback bypasses the knock gate even with no valid set entry ---"
CODE_LOOPBACK=$(ip netns exec "$NS_SERVER" curl -s -o /dev/null -w '%{http_code}' \
    --max-time 2 "http://127.0.0.1:$TARGET_PORT/" || true)
echo "http code via loopback (post-expiry, unknocked): $CODE_LOOPBACK"

echo "--- 5) sending a channel-1 knock (run_command action, not port-opening) ---"
rm -f "$WORK_DIR/channel1_marker"
ip netns exec "$NS_CLIENT" env PYTHONPATH="$CLIENT_DIR" "$CLIENT_DIR/.venv/bin/python" -m knockc.cli \
    --config "$WORK_DIR/knock.conf" --target "$SRV_IP" --channel 1
sleep 0.5
CHANNEL1_MARKER_EXISTS=0
[[ -f "$WORK_DIR/channel1_marker" ]] && CHANNEL1_MARKER_EXISTS=1 || true
echo "channel 1 marker file present: $CHANNEL1_MARKER_EXISTS"

echo "--- results ---"
PASS=1
[[ "$CODE_BEFORE" != "200" ]] || { echo "FAIL: request succeeded before knocking"; PASS=0; }
[[ "$CODE_AFTER" == "200" ]] || { echo "FAIL: request did not succeed after knocking"; PASS=0; }
[[ "$CODE_EXPIRED" != "200" ]] || { echo "FAIL: request still succeeds after open_duration expired"; PASS=0; }
[[ "$CODE_LOOPBACK" == "200" ]] || { echo "FAIL: loopback request blocked despite no valid knock (got $CODE_LOOPBACK)"; PASS=0; }
[[ "$CHANNEL1_MARKER_EXISTS" == "1" ]] || { echo "FAIL: channel 1's command did not run"; PASS=0; }

if [[ "$PASS" == "1" ]]; then
    echo "PASS: end-to-end port-knock cycle behaved as expected"
    exit 0
else
    echo "--- debug: knockd.log ---"
    cat "$WORK_DIR/knockd.log" || true
    echo "--- debug: nft ruleset in server namespace ---"
    ip netns exec "$NS_SERVER" nft list ruleset || true
    echo "--- debug: httpd.log ---"
    cat "$WORK_DIR/httpd.log" || true
    exit 1
fi
