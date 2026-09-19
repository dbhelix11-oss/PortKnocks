import argparse
import sys
import time

from .config import load_config
from .derive import NUM_CHANNELS, derive_ports, time_counter
from .keyfile import KeyfilePermissionError, load_secret
from .preview import render_preview
from .sender import send_knocks
from .sshconfig import resolve_target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="knockc", description="Send a derived port-knock sequence")
    parser.add_argument("--config", required=True, help="Path to knock.conf")
    parser.add_argument("--target", required=True,
                         help="Target host to knock (IP, hostname, or an ~/.ssh/config Host alias)")
    parser.add_argument("--channel", type=int, default=0,
                         help=f"Channel to knock, 0-{NUM_CHANNELS - 1} (default 0 = open the configured "
                              f"target port(s); 1-{NUM_CHANNELS - 1} run a server-configured action -- "
                              f"a command, or opening that channel's own port(s))")
    parser.add_argument("--preview", action="store_true",
                         help="Show the derivation and the exact packet bytes, then exit without sending")
    parser.add_argument("--reveal-secret", action="store_true",
                         help="With --preview, show the raw secret bytes instead of a fingerprint")
    parser.add_argument("--inspect", action="store_true",
                         help="Interactive byte-cursor packet inspector (arrow keys), then exit without sending")
    args = parser.parse_args(argv)

    if not (0 <= args.channel < NUM_CHANNELS):
        print(f"error: --channel must be between 0 and {NUM_CHANNELS - 1}", file=sys.stderr)
        return 2

    resolved_target, was_alias = resolve_target(args.target)
    if was_alias:
        print(f"resolved --target {args.target!r} via ~/.ssh/config to {resolved_target}", file=sys.stderr)
        args.target = resolved_target

    cfg = load_config(args.config)

    try:
        secret = load_secret(cfg.keyfile)
    except KeyfilePermissionError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if args.inspect:
        from .inspector import run_inspector  # curses import stays local to this path
        run_inspector(secret, args.target, cfg.time_step, cfg.n_ports, cfg.port_low, cfg.port_high,
                      args.channel)
        return 0

    if args.preview:
        render_preview(secret, args.config, args.target, cfg.time_step, cfg.n_ports,
                        cfg.port_low, cfg.port_high, channel_id=args.channel, reveal_secret=args.reveal_secret)
        return 0

    counter = time_counter(time.time(), cfg.time_step)
    ports = derive_ports(secret, counter, cfg.n_ports, cfg.port_low, cfg.port_high, args.channel)

    print(f"knocking {args.target} with {len(ports)} ports (window {counter}, channel {args.channel}): {ports}")
    send_knocks(cfg.knock_proto, args.target, ports, cfg.knock_interval_ms)
    print("done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
