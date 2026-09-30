# knockd on OpenWrt

Target: Linksys MR8300, OpenWrt 23.05.5, `ipq40xx/generic` (ARMv7, musl).
Goal (Phase A): a knock on the LAN bridge (`br-lan`) opens router SSH
(channel 0) or LuCI (channel 1). No fw4 configuration is changed.

## Why no fw4 changes are needed

knockd's `inet knockd` table hooks `input` at priority -10, before fw4's
(0). A `drop` there is final; an `accept` is not, so knocked hosts fall
through to fw4's own LAN accept. `fw4 reload` only replaces `inet fw4`,
so knockd's table survives it. Proven in
`server/tests/e2e_netns_fw4_lan_test.sh` (run it as root first).

## Build (on the dev PC, not the router)

1. Download the OpenWrt 23.05.5 SDK for `ipq40xx/generic` from
   `https://downloads.openwrt.org/releases/23.05.5/targets/ipq40xx/generic/`
   (a file named like `openwrt-sdk-23.05.5-ipq40xx-generic_gcc-12.3.0_musl_eabi.Linux-x86_64.tar.xz`;
   check the directory listing for the exact name) and unpack it.
2. Lay the package out inside the SDK:
   ```
   SDK=~/openwrt-sdk-*      # adjust
   mkdir -p $SDK/package/knockd/src
   cp server/openwrt/Makefile server/openwrt/knockd.init server/openwrt/knockd.conf.example $SDK/package/knockd/
   cp -r server/src server/include server/Makefile $SDK/package/knockd/src/
   ```
3. `cd $SDK && ./scripts/feeds update -a && ./scripts/feeds install libpcap openssl`
   then `make defconfig && make package/knockd/compile V=s`.
4. The result is `bin/packages/arm_cortex-a7_neon-vfpv4/base/knockd_*.ipk`.

## Install (on the router, with a LAN fallback path open)

`libstdcpp` and `libopenssl` are not installed by default; `opkg` pulls
them in as dependencies of the ipk.

```
scp knockd_*.ipk root@192.168.1.1:/tmp/
ssh root@192.168.1.1
opkg install /tmp/knockd_*.ipk
```

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
