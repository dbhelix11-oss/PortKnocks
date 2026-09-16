import os
import stat


class KeyfilePermissionError(RuntimeError):
    pass


def load_secret(path: str, expected_len: int = 32, *, enforce_perms: bool = True) -> bytes:
    st = os.stat(path)
    if enforce_perms and (st.st_mode & (stat.S_IRWXG | stat.S_IRWXO)):
        raise KeyfilePermissionError(
            f"{path} is readable/writable by group or other; run `chmod 600 {path}`"
        )
    with open(path, "rb") as f:
        secret = f.read()
    if len(secret) != expected_len:
        raise ValueError(f"{path} contains {len(secret)} bytes, expected {expected_len}")
    return secret
