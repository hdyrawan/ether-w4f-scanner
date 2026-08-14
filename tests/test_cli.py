"""CLI tests: argument parsing, --version, --target-json, error paths."""

from __future__ import annotations

import json

from w4f.cli import _load_targets_from_json, build_parser


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


def pytest_raises_systemexit():
    import pytest
    return pytest.raises(SystemExit)
