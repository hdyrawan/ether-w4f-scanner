"""Loader tests: signature discovery, validation, extra-file override."""

from __future__ import annotations

import textwrap


def _make_pkg(tmp_path, monkeypatch, name=None):
    """Create an importable package directory with __init__.py.

    Unique name per call so tests do not collide in sys.modules.
    """
    if name is None:
        import uuid
        name = f"test_sigpkg_{uuid.uuid4().hex[:8]}"
    pkg_dir = tmp_path / name
    pkg_dir.mkdir(exist_ok=True)
    (pkg_dir / "__init__.py").write_text("")
    monkeypatch.syspath_prepend(str(tmp_path))
    return pkg_dir


def _write_mod(pkg_dir, mod_name, body):
    (pkg_dir / f"{mod_name}.py").write_text(textwrap.dedent(body))


class TestSignatureDiscovery:
    def test_package_modules_loaded(self):
        # at least one signature module must be discoverable via the package
        from w4f.signatures import load_signatures
        vendors = load_signatures()
        assert "cloudflare" in vendors
        assert "nginx" in vendors
        assert len(vendors) >= 60

    def test_template_not_loaded_as_vendor(self):
        # _template.py is private — its VENDOR dict must NOT be picked up
        from w4f.signatures import load_signatures
        vendors = load_signatures()
        assert "my-vendor" not in vendors

    def test_name_key_stripped_from_rules(self):
        # assembled dict is the old shape: VENDORS[name] = rules (no 'name')
        from w4f.signatures import load_signatures
        vendors = load_signatures()
        assert "name" not in vendors["cloudflare"]
        assert vendors["cloudflare"]["headers"]["server"]

    def test_single_and_list_exports_both_loaded(self, tmp_path, monkeypatch):
        # a temp package with a VENDOR (single) and a VENDORS (list) module
        from w4f.signatures import load_signatures
        pkg = _make_pkg(tmp_path, monkeypatch)
        _write_mod(pkg, "one", '''
            VENDOR = {"name": "one-edge", "headers": {"server": r"one-edge"}}
        ''')
        _write_mod(pkg, "two", '''
            VENDORS = [
                {"name": "two-a", "headers": {"server": r"two-a"}},
                {"name": "two-b", "headers": {"server": r"two-b"}},
            ]
        ''')
        vendors = load_signatures(pkg.name)
        assert vendors["one-edge"]["headers"]["server"]
        assert "two-a" in vendors and "two-b" in vendors


class TestSignatureValidation:
    def test_duplicate_name_rejected(self, tmp_path, monkeypatch):
        from w4f.signatures import SignatureError, load_signatures
        import pytest
        pkg = _make_pkg(tmp_path, monkeypatch)
        _write_mod(pkg, "a", 'VENDOR = {"name": "dup", "headers": {"server": r"a"}}')
        _write_mod(pkg, "b", 'VENDOR = {"name": "dup", "headers": {"server": r"b"}}')
        with pytest.raises(SignatureError, match="duplicate vendor name"):
            load_signatures(pkg.name)

    def test_bad_regex_rejected(self, tmp_path, monkeypatch):
        from w4f.signatures import SignatureError, load_signatures
        import pytest
        pkg = _make_pkg(tmp_path, monkeypatch)
        _write_mod(pkg, "bad", 'VENDOR = {"name": "bad", "headers": {"server": "("}}')
        with pytest.raises(SignatureError, match="bad regex"):
            load_signatures(pkg.name)

    def test_missing_name_rejected(self, tmp_path, monkeypatch):
        from w4f.signatures import SignatureError, load_signatures
        import pytest
        pkg = _make_pkg(tmp_path, monkeypatch)
        _write_mod(pkg, "noname", 'VENDOR = {"headers": {"server": r"x"}}')
        with pytest.raises(SignatureError, match="missing a string 'name'"):
            load_signatures(pkg.name)

    def test_unknown_key_rejected(self, tmp_path, monkeypatch):
        from w4f.signatures import SignatureError, load_signatures
        import pytest
        pkg = _make_pkg(tmp_path, monkeypatch)
        _write_mod(pkg, "unk", 'VENDOR = {"name": "unk", "bogus": 1}')
        with pytest.raises(SignatureError, match="unknown key"):
            load_signatures(pkg.name)

    def test_bad_netblock_rejected(self, tmp_path, monkeypatch):
        from w4f.signatures import SignatureError, load_signatures
        import pytest
        pkg = _make_pkg(tmp_path, monkeypatch)
        _write_mod(pkg, "badnet", 'VENDOR = {"name": "bn", "nets": ["not-a-net"]}')
        with pytest.raises(SignatureError, match="bad netblock"):
            load_signatures(pkg.name)


class TestExtraFile:
    def test_load_extra_adds_and_overrides(self, tmp_path):
        from w4f.signatures import load_extra
        p = tmp_path / "extra.py"
        p.write_text(textwrap.dedent("""
            VENDOR = {"name": "my-local-edge",
                      "headers": {"server": r"my-local-edge"}}
        """))
        extra = load_extra(str(p))
        assert "my-local-edge" in extra
        assert extra["my-local-edge"]["headers"]["server"]

    def test_extra_override_merges_by_name(self, tmp_path):
        from w4f.signatures import load_extra
        p = tmp_path / "override.py"
        p.write_text(textwrap.dedent("""
            VENDOR = {"name": "nginx",
                      "headers": {"server": r"nginx", "x-my-mark": None}}
        """))
        extra = load_extra(str(p))
        assert extra["nginx"]["headers"]["x-my-mark"] is None

    def test_bad_extra_rejected(self, tmp_path):
        from w4f.signatures import SignatureError, load_extra
        import pytest
        p = tmp_path / "bad.py"
        p.write_text('VENDOR = {"name": "x", "headers": {"server": "("}}\n')
        with pytest.raises(SignatureError):
            load_extra(str(p))

    def test_w4f_signatures_env_override(self, tmp_path, monkeypatch):
        # W4F_SIGNATURES env var adds a local rule at import (stretch)
        import importlib
        p = tmp_path / "env_rules.py"
        p.write_text(textwrap.dedent("""
            VENDOR = {"name": "env-edge", "headers": {"server": r"env-edge"}}
        """))
        monkeypatch.setenv("W4F_SIGNATURES", str(p))
        import w4f.vendors
        importlib.reload(w4f.vendors)
        try:
            assert "env-edge" in w4f.vendors.VENDORS
        finally:
            monkeypatch.delenv("W4F_SIGNATURES")
            importlib.reload(w4f.vendors)
        assert "env-edge" not in w4f.vendors.VENDORS
