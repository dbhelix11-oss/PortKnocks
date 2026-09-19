"""Resolve a --target argument against ~/.ssh/config Host aliases.

Not a general ssh_config parser (no Match/Include/wildcard support) --
just enough to let `--target <alias>` pick up the same HostName an
`ssh <alias>` invocation would use, since scapy/socket resolution never
understands ssh's own config file.
"""
import os
import pwd
from pathlib import Path


def _invoking_home() -> str:
    """The real user's home directory, even under `sudo` (where plain
    `~`/$HOME resolve to root's) -- sending raw packets needs root, but
    the ssh config we want to read belongs to whoever ran `sudo`.
    """
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and os.geteuid() == 0:
        try:
            return pwd.getpwnam(sudo_user).pw_dir
        except KeyError:
            pass
    return os.path.expanduser("~")


def resolve_target(target: str, config_path: str | None = None) -> tuple[str, bool]:
    """Return (resolved_target, was_alias). If `target` matches a literal
    `Host` alias in the config file and that block has a `HostName`, the
    resolved HostName is returned. Otherwise `target` is returned unchanged.
    """
    if config_path is None:
        path = Path(_invoking_home()) / ".ssh" / "config"
    else:
        path = Path(os.path.expanduser(config_path))
    if not path.is_file():
        return target, False

    in_matching_block = False
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        keyword, value = parts[0].lower(), parts[1].strip()

        if keyword == "host":
            aliases = value.split()
            in_matching_block = target in aliases
            continue

        if in_matching_block and keyword == "hostname":
            return value, True

    return target, False
