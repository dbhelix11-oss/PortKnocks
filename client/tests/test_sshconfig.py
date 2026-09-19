from knockc.sshconfig import resolve_target

SAMPLE_CONFIG = """
Host aws-honeypot
     Hostname 3.23.201.67
     User admin
     Port 1221

Host multi-alias another-name
     HostName 10.0.0.5

Host no-hostname
     User someone
"""


def write_config(tmp_path, contents=SAMPLE_CONFIG):
    path = tmp_path / "config"
    path.write_text(contents)
    return str(path)


def test_resolves_known_alias(tmp_path):
    cfg = write_config(tmp_path)
    assert resolve_target("aws-honeypot", cfg) == ("3.23.201.67", True)


def test_leaves_ip_or_unknown_hostname_unchanged(tmp_path):
    cfg = write_config(tmp_path)
    assert resolve_target("192.168.1.1", cfg) == ("192.168.1.1", False)
    assert resolve_target("not-an-alias.example.com", cfg) == ("not-an-alias.example.com", False)


def test_matches_any_of_multiple_aliases_on_one_host_line(tmp_path):
    cfg = write_config(tmp_path)
    assert resolve_target("multi-alias", cfg) == ("10.0.0.5", True)
    assert resolve_target("another-name", cfg) == ("10.0.0.5", True)


def test_alias_without_hostname_is_left_unresolved(tmp_path):
    cfg = write_config(tmp_path)
    assert resolve_target("no-hostname", cfg) == ("no-hostname", False)


def test_missing_config_file_leaves_target_unchanged(tmp_path):
    missing = str(tmp_path / "does-not-exist")
    assert resolve_target("aws-honeypot", missing) == ("aws-honeypot", False)
