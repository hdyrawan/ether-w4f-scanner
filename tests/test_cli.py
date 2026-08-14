"""CLI tests: argument parsing, --version, --target-json, error paths."""

from __future__ import annotations

import json

from w4f.cli import _load_targets_from_json, _validate_hostport, build_parser


class TestTargetJson:
    def test_subdomainfinder_shape(self, tmp_path):
        # The exact shape exported by subdomain enumeration tools
        data = [
            {"subdomain": " cms.example.com", "ip": "1.2.3.4", "cloudflare": "false"},
            {"subdomain": " mbanking.example.com", "ip": "1.2.3.5", "cloudflare": "false"},
            {"subdomain": "cms.example.com", "ip": "1.2.3.4", "cloudflare": "false"},  # dup
        ]
        p = tmp_path / "subs.json"
        p.write_text(json.dumps(data))
        hosts = _load_targets_from_json(str(p))
        # leading-space trimmed, deduped case-insensitively, order kept
        assert hosts == ["cms.example.com", "mbanking.example.com"]

    def test_array_of_strings(self, tmp_path):
        p = tmp_path / "hosts.json"
        p.write_text(json.dumps(["a.example.com", " b.example.com", ""]))
        assert _load_targets_from_json(str(p)) == ["a.example.com", "b.example.com"]

    def test_dict_with_subdomains_key(self, tmp_path):
        p = tmp_path / "obj.json"
        p.write_text(json.dumps({"subdomains": ["x.example.com"]}))
        assert _load_targets_from_json(str(p)) == ["x.example.com"]

    def test_dict_with_hosts_key(self, tmp_path):
        p = tmp_path / "hosts-key.json"
        p.write_text(json.dumps({"hosts": ["a.example.com", "b.example.com"]}))
        assert _load_targets_from_json(str(p)) == ["a.example.com", "b.example.com"]

    def test_dict_with_targets_key(self, tmp_path):
        p = tmp_path / "targets-key.json"
        p.write_text(json.dumps({"targets": ["a.example.com"]}))
        assert _load_targets_from_json(str(p)) == ["a.example.com"]

    def test_dict_with_results_key(self, tmp_path):
        p = tmp_path / "results-key.json"
        p.write_text(json.dumps({"results": ["a.example.com"]}))
        assert _load_targets_from_json(str(p)) == ["a.example.com"]

    def test_dict_with_host_field_in_objects(self, tmp_path):
        # object entries may carry "host" or "name" instead of "subdomain"
        p = tmp_path / "host-field.json"
        p.write_text(json.dumps([{"host": "a.example.com"},
                                 {"name": "b.example.com"},
                                 {"subdomain": "c.example.com"}]))
        assert _load_targets_from_json(str(p)) == ["a.example.com", "b.example.com", "c.example.com"]

    def test_missing_file(self, tmp_path):
        import pytest
        with pytest.raises(FileNotFoundError):
            _load_targets_from_json(str(tmp_path / "nope.json"))

    def test_bad_json(self, tmp_path):
        import pytest
        p = tmp_path / "bad.json"
        p.write_text("not json")
        with pytest.raises(json.JSONDecodeError):
            _load_targets_from_json(str(p))


class TestParser:
    def test_version_flag(self):
        from w4f import __version__
        ap = build_parser()
        # argparse's version action raises SystemExit with the string on stdout
        import io
        import sys
        old = sys.stdout
        sys.stdout = buf = io.StringIO()
        try:
            with pytest_raises_systemexit():
                ap.parse_args(["--version"])
        finally:
            sys.stdout = old
        out = buf.getvalue()
        assert "w4f" in out
        assert __version__ in out

    def test_no_targets_error_path(self):
        ap = build_parser()
        ns = ap.parse_args([])
        assert ns.target is None
        assert ns.target_json is None

    def test_target_and_target_json_combine(self):
        ap = build_parser()
        ns = ap.parse_args(["--target", "a.com", "--target-json", "x.json"])
        assert ns.target == ["a.com"]
        assert ns.target_json == "x.json"

    def test_verify_flag_defaults_off(self):
        ap = build_parser()
        assert ap.parse_args(["--target", "a.com"]).verify is False
        assert ap.parse_args(["--target", "a.com", "--verify"]).verify is True

    def test_no_targets_exits_2(self):
        from w4f.cli import main
        assert main([]) == 2


class TestHostportValidation:
    """Security review: malicious --target-json input must be rejected."""

    def test_valid_hostname_ok(self):
        ok, msg = _validate_hostport("api.example.com")
        assert ok and msg == ""

    def test_valid_hostport_ok(self):
        ok, msg = _validate_hostport("api.example.com:8443")
        assert ok and msg == ""

    def test_empty_rejected(self):
        ok, msg = _validate_hostport("")
        assert not ok and "empty" in msg

    def test_control_character_rejected(self):
        ok, _ = _validate_hostport("api.example.com\nrm -rf /")
        assert not ok
        ok2, _ = _validate_hostport("api\x00example.com")
        assert not ok2

    def test_uri_scheme_rejected(self):
        ok, _ = _validate_hostport("file:///etc/passwd")
        assert not ok
        ok2, _ = _validate_hostport("http://api.example.com")
        assert not ok2

    def test_whitespace_in_hostname_rejected(self):
        ok, _ = _validate_hostport("api example.com")
        assert not ok

    def test_overlong_hostname_rejected(self):
        ok, _ = _validate_hostport("a" * 300 + ".example.com")
        assert not ok

    def test_private_ip_warned_not_dropped(self):
        # private/internal scanning is a legitimate use — warn, keep
        ok, msg = _validate_hostport("10.0.0.5")
        assert ok and "private" in msg
        ok2, _ = _validate_hostport("127.0.0.1")
        assert ok2
        ok3, msg3 = _validate_hostport("192.168.1.1")
        assert ok3 and "private" in msg3

    def test_public_ip_no_warning(self):
        ok, msg = _validate_hostport("8.8.8.8")
        assert ok and msg == ""


class TestThrottle:
    def test_base_delay_unchanged(self):
        from w4f.cli import Throttle
        t = Throttle(0.0)
        assert t.delay_for("example.com") == 0.0

    def test_bump_doubles_and_reset_restores(self):
        from w4f.cli import Throttle
        t = Throttle(0.5)
        assert t.delay_for("example.com") == 0.5
        t.bump("example.com")   # 1.0
        t.bump("example.com")   # 2.0
        assert t.delay_for("example.com") == 2.0
        t.reset("example.com")
        assert t.delay_for("example.com") == 0.5

    def test_bump_capped(self):
        from w4f.cli import Throttle
        t = Throttle(5.0)
        t.bump("x.com")  # 10
        t.bump("x.com")  # would be 20 -> capped at 10
        assert t.delay_for("x.com") == Throttle.CAP == 10.0

    def test_domains_isolated(self):
        from w4f.cli import Throttle
        t = Throttle(0.1)
        t.bump("busy.com")
        assert t.delay_for("busy.com") == 0.2
        assert t.delay_for("quiet.com") == 0.1

    def test_http_status_code_extraction(self):
        from w4f.cli import _http_status_code
        assert _http_status_code({"tls": {"http": {"status": "HTTP/1.1 429 Too Many Requests"}}}) == 429
        assert _http_status_code({"tls": {"http": {"status": "HTTP/2 200 OK"}}}) == 200
        assert _http_status_code({"tls": {"http": {"status": "ERROR: boom"}}}) is None


def pytest_raises_systemexit():
    import pytest
    return pytest.raises(SystemExit)
