#!/usr/bin/env bash
# End-to-end test for the OpenWrt deployment model: knockd running next to an
# fw4-style firewall (its own `inet fw4` table, input policy drop, LAN zone
# accepts everything) WITHOUT any change to that firewall. Must be run as
# root.
#
# What it proves:
#   - knockd's chain (priority -10) runs before fw4's (priority 0), so its
#     `drop` for un-knocked sources is final, while its `accept` for knocked
#     sources just falls through to fw4's own LAN accept.
#   - channel 0 opens the SSH-like port, channel 1 (open_port) opens the
#     LuCI-like port, independently.
#   - an unprotected port stays reachable throughout.
#   - replacing the whole fw4 table (what `fw4 reload` does) doesn't touch
#     knockd's table.
#   - restarting knockd doesn't duplicate rules (startup is idempotent).
#
# Usage: sudo bash server/tests/e2e_netns_fw4_lan_test.sh
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "must be run as root (sudo bash $0)" >&2
    exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERVER_DIR="$ROOT_DIR/server"
CLIENT_DIR="$ROOT_DIR/client"
WORK_DIR="$(mktemp -d)"

NS_SERVER=knock_srv_fw4
NS_CLIENT=knock_cli_fw4
VETH_SRV=veth-srv-f
VETH_CLI=veth-cli-f
SRV_IP=10.202.0.1
CLI_IP=10.202.0.2
SSH_PORT=2222      # channel 0 (target_port), stands in for SSH/22
LUCI_PORT=8080     # channel 1 (open_port), stands in for LuCI/80
OPEN_PORT=9090     # not knock-protected, must always stay reachable
OPEN_DURATION=8

KNOCKD_PID=""
HTTPD_PIDS=()

cleanup() {
    echo "--- cleaning up ---"
    [[ -n "$KNOCKD_PID" ]] && kill "$KNOCKD_PID" 2>/dev/null || true
    for p in "${HTTPD_PIDS[@]}"; do ip netns exec "$NS_SERVER" kill "$p" 2>/dev/null || true; done
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

# Mirrors the shape of what `nft list ruleset` showed on the real OpenWrt
# 23.05 router: base `input` chain (priority filter = 0, policy drop) that
# jumps to a LAN chain which accepts everything from the LAN interface.
install_fake_fw4() {
    ip netns exec "$NS_SERVER" nft -f - <<EOF
table inet fw4 {
    chain input {
        type filter hook input priority filter; policy drop;
        iifname "lo" accept
        ct state established,related accept
        iifname "$VETH_SRV" jump input_lan
    }
    chain input_lan {
        jump accept_from_lan
    }
    chain accept_from_lan {
        iifname "$VETH_SRV" accept
    }
}
EOF
}
install_fake_fw4

echo "--- generating a fresh shared secret ---"
openssl rand -out "$WORK_DIR/secret.key" 32
chmod 600 "$WORK_DIR/secret.key"

echo "--- starting three plain HTTP servers (SSH-like, LuCI-like, unprotected) ---"
for port in "$SSH_PORT" "$LUCI_PORT" "$OPEN_PORT"; do
    ip netns exec "$NS_SERVER" python3 -m http.server "$port" --bind 0.0.0.0 \
        >"$WORK_DIR/httpd_$port.log" 2>&1 &
    HTTPD_PIDS+=($!)
done
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
target_port = $SSH_PORT
open_duration = $OPEN_DURATION
base_chain_priority = -10

[channel.1]
open_port = $LUCI_PORT
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

start_knockd() {
    ip netns exec "$NS_SERVER" "$SERVER_DIR/knockd" --config "$WORK_DIR/knockd.conf" \
        >>"$WORK_DIR/knockd.log" 2>&1 &
    KNOCKD_PID=$!
    sleep 1
    if ! kill -0 "$KNOCKD_PID" 2>/dev/null; then
        echo "knockd failed to start, log follows:" >&2
        cat "$WORK_DIR/knockd.log" >&2
        exit 1
    fi
}

echo "--- starting knockd ---"
start_knockd

if [[ ! -d "$CLIENT_DIR/.venv" ]]; then
    echo "client/.venv not found; run 'python3 -m venv .venv && .venv/bin/pip install -r requirements.txt' in client/ first" >&2
    exit 1
fi

code() { # port -> http status from the client namespace ("000" if blocked)
    ip netns exec "$NS_CLIENT" curl -s -o /dev/null -w '%{http_code}' \
        --max-time 2 "http://$SRV_IP:$1/" || true
}
knock() { # [channel]
    ip netns exec "$NS_CLIENT" env PYTHONPATH="$CLIENT_DIR" "$CLIENT_DIR/.venv/bin/python" -m knockc.cli \
        --config "$WORK_DIR/knock.conf" --target "$SRV_IP" "$@"
    sleep 0.5
}

echo "--- 1) before any knock ---"
B_SSH=$(code "$SSH_PORT"); B_LUCI=$(code "$LUCI_PORT"); B_OPEN=$(code "$OPEN_PORT")
echo "ssh=$B_SSH luci=$B_LUCI open=$B_OPEN"

echo "--- 2) channel 0 knock: only the SSH-like port opens ---"
knock
C0_SSH=$(code "$SSH_PORT"); C0_LUCI=$(code "$LUCI_PORT")
echo "ssh=$C0_SSH luci=$C0_LUCI"

echo "--- 3) channel 1 knock: LuCI-like port opens ---"
knock --channel 1
C1_LUCI=$(code "$LUCI_PORT")
echo "luci=$C1_LUCI"

echo "--- 4) simulate 'fw4 reload': replace the whole fw4 table ---"
ip netns exec "$NS_SERVER" nft delete table inet fw4
install_fake_fw4
KNOCKD_TABLE_SURVIVED=0
ip netns exec "$NS_SERVER" nft list table inet knockd >/dev/null 2>&1 && KNOCKD_TABLE_SURVIVED=1 || true
R_SSH=$(code "$SSH_PORT")
echo "knockd table survived: $KNOCKD_TABLE_SURVIVED, ssh still open right after reload: $R_SSH"

echo "--- 5) after open_duration (${OPEN_DURATION}s) both re-close, unprotected stays open ---"
sleep "$((OPEN_DURATION + 3))"
E_SSH=$(code "$SSH_PORT"); E_LUCI=$(code "$LUCI_PORT"); E_OPEN=$(code "$OPEN_PORT")
echo "ssh=$E_SSH luci=$E_LUCI open=$E_OPEN"

echo "--- 6) restart knockd: rules must not duplicate ---"
kill "$KNOCKD_PID"; wait "$KNOCKD_PID" 2>/dev/null || true
start_knockd
DROP_RULES=$(ip netns exec "$NS_SERVER" nft list chain inet knockd knockd_input | grep -c "tcp dport $SSH_PORT drop" || true)
echo "drop rules for port $SSH_PORT after restart: $DROP_RULES"

echo "--- results ---"
PASS=1
chk() { [[ "$1" == "$2" ]] || { echo "FAIL: $3 (got '$1', want '$2')"; PASS=0; }; }
chknot() { [[ "$1" != "$2" ]] || { echo "FAIL: $3 (got '$1')"; PASS=0; }; }
chknot "$B_SSH" 200 "ssh port open before knock"
chknot "$B_LUCI" 200 "luci port open before knock"
chk "$B_OPEN" 200 "unprotected port should always be reachable"
chk "$C0_SSH" 200 "ssh port not open after channel-0 knock"
chknot "$C0_LUCI" 200 "channel-0 knock also opened the luci port"
chk "$C1_LUCI" 200 "luci port not open after channel-1 knock"
chk "$KNOCKD_TABLE_SURVIVED" 1 "knockd table vanished when fw4 table was replaced"
chk "$R_SSH" 200 "ssh access lost across simulated fw4 reload"
chknot "$E_SSH" 200 "ssh port still open after expiry"
chknot "$E_LUCI" 200 "luci port still open after expiry"
chk "$E_OPEN" 200 "unprotected port became unreachable"
chk "$DROP_RULES" 1 "duplicate/missing drop rules after restart"

if [[ "$PASS" == "1" ]]; then
    echo "PASS: knockd gates ports next to an fw4-style firewall without modifying it"
    exit 0
else
    echo "--- debug: knockd.log ---"; cat "$WORK_DIR/knockd.log" || true
    echo "--- debug: nft ruleset ---"; ip netns exec "$NS_SERVER" nft list ruleset || true
    exit 1
fi
