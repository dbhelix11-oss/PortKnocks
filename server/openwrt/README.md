# knockd on OpenWrt

Target: Linksys MR8300 (`ipq40xx/generic`, ARMv7 musl), OpenWrt **25.12.x**.
Goal (Phase A): a knock on the LAN bridge (`br-lan`) opens router SSH
(channel 0) or LuCI (channel 1). No fw4 configuration is changed.

## Why no fw4 changes are needed

knockd's `inet knockd` table hooks `input` at priority -10, before fw4's
(0). A `drop` there is final; an `accept` is not, so knocked hosts fall
through to fw4's own LAN accept. `fw4 reload` only replaces `inet fw4`,
so knockd's table survives it. Proven in
`server/tests/e2e_netns_fw4_lan_test.sh` (run it as root first). That test
imitates the fw4 layout seen on 23.05.5; re-check the real ruleset after
upgrading (see "After upgrading").

## Step 0: upgrade the router first (23.05.5 -> 24.10.8 -> 25.12.5)

23.05 is end-of-life (security support ended 2025-08-31) and 23.05.5 is
affected by CVE-2025-62526 (`ubusd`, fixed in 24.10.4+) and CVE-2026-53921
(`odhcpd` DHCPv6, fixed in 24.10.8/25.12.5).

The full step-by-step upgrade procedure (backup, both flashes, checksums,
recovery) and a plain-language walkthrough of both CVEs now live in the
router's own project folder, not here:
`~/Documents/ClaudeProject/OpenWRT_Secure/ROUTER_UPGRADE_GUIDE.md` and
`~/Documents/ClaudeProject/OpenWRT_Secure/CVE_HANDS_ON_GUIDE.md`. The
downloaded firmware and SDK are in
`~/Documents/ClaudeProject/OpenWRT_Secure/firmware/`. Do that first, then
come back here.

## After upgrading

```
cat /etc/openwrt_release
nft list ruleset | head -60        # confirm fw4 still has input policy drop + LAN accept
apk list --installed | grep -E 'libpcap|openssl|nft|libstdcpp'
```

25.12 replaced `opkg` with `apk`. Do NOT run `apk upgrade` on the router
(the OpenWrt cheatsheet warns it can brick devices because of incomplete
dependencies); use attended sysupgrade for whole-system updates.

## Build (on the dev PC, not the router)

1. The SDK is already downloaded, in
   `~/Documents/ClaudeProject/OpenWRT_Secure/firmware/25.12.5/openwrt-sdk-25.12.5-ipq40xx-generic_gcc-14.3.0_musl_eabi.Linux-x86_64.tar.zst`.
   Unpack it with `tar --zstd -xf` (or `unzstd` then `tar -xf`; needs the
   `zstd` package on the host). Use the SDK version matching the firmware
   actually on the router; if you flashed a newer 25.12.x, get that
   version's SDK from
   `https://downloads.openwrt.org/releases/<version>/targets/ipq40xx/generic/`.
2. Lay the package out inside the SDK:
   ```
   SDK=~/openwrt-sdk-*      # adjust
   mkdir -p $SDK/package/knockd/src
   cp server/openwrt/Makefile server/openwrt/knockd.init server/openwrt/knockd.conf.example $SDK/package/knockd/
   cp -r server/src server/include server/Makefile $SDK/package/knockd/src/
   ```
3. `cd $SDK && ./scripts/feeds update -a && ./scripts/feeds install libpcap openssl`
   then `make defconfig && make package/knockd/compile V=s`.
4. Find the result with `find bin -name 'knockd*'`. On 25.12 it should be an
   `.apk` under `bin/packages/arm_cortex-a7_neon-vfpv4/base/` (the SDK docs
   page I found still says `.ipk`, so confirm the extension you actually
   get). Check that the dependency names in `server/openwrt/Makefile`
   (`libpcap`, `libopenssl`, `libstdcpp`, `nftables-json`) still exist in
   25.12; the compile step will fail loudly if not.

## Install (on the router, with a LAN fallback path open)

`libstdcpp` and `libopenssl` are not installed by default; `apk` pulls them
in as dependencies from the OpenWrt package repository (the router needs
working internet for that).

```
scp knockd-*.apk root@192.168.1.1:/tmp/
ssh root@192.168.1.1
apk add --allow-untrusted /tmp/knockd-*.apk
```

`--allow-untrusted` is needed because this is a locally built,
self-signed package.

Put the shared secret in place (32 bytes, same file the client uses) and
check the clock before starting:

```
chmod 600 /etc/knockd/secret.key
date; /etc/init.d/sysntpd status
```

### Dead-man switch for the first run

Until a knock is verified, arm a timer that removes knockd's table if you
get locked out. Run this in the same shell BEFORE starting knockd:

```
( sleep 300; nft delete table inet knockd ) &
/etc/init.d/knockd enable
/etc/init.d/knockd start
logread -e knockd
```

From a LAN machine, run the client with `--target 192.168.1.1` (channel 0
for SSH, `--channel 1` for LuCI) and confirm the ports open, then close
after `open_duration`. Once satisfied, cancel the timer (`kill %1`, or find
the `sleep 300` with `ps` and kill it).

## Rollback / recovery

- Normal: `/etc/init.d/knockd stop` (deletes the table) or
  `nft delete table inet knockd`.
- If knockd hard-crashes the table persists with its drops. Procd respawns
  the daemon, which rebuilds the table. If that also fails and you are
  locked out, use OpenWrt failsafe mode (hold the reset button during boot),
  or wait for the dead-man switch when it is armed.
- Disable at boot: `/etc/init.d/knockd disable`.

## Not covered yet

- Phase B (WAN listening + DNAT forwards to LAN hosts) is planned but not
  built. Note the WAN sits at a private address (10.0.0.156), i.e. behind
  another NAT.
