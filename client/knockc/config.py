import configparser
from dataclasses import dataclass


@dataclass(frozen=True)
class KnockConfig:
    keyfile: str
    time_step: int = 30
    n_ports: int = 6
    port_low: int = 20000
    port_high: int = 60000
    knock_interval_ms: int = 100
    knock_proto: str = "tcp-syn"

    def __post_init__(self):
        if self.knock_proto != "tcp-syn":
            raise ValueError(f"unsupported knock_proto {self.knock_proto!r} (only 'tcp-syn' is implemented)")


def load_config(path: str) -> KnockConfig:
    parser = configparser.ConfigParser()
    parser.read(path)
    section = parser["knock"]
    return KnockConfig(
        keyfile=section["keyfile"],
        time_step=section.getint("time_step", fallback=30),
        n_ports=section.getint("n_ports", fallback=6),
        port_low=section.getint("port_low", fallback=20000),
        port_high=section.getint("port_high", fallback=60000),
        knock_interval_ms=section.getint("knock_interval_ms", fallback=100),
        knock_proto=section.get("knock_proto", fallback="tcp-syn"),
    )
