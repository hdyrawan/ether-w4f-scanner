"""Error taxonomy tests (v0.1.42 hardening).

The per-host ``error`` string contract is unchanged; ``error_class`` is the
structured axis. These tests lock the classification so a probe failure is
never collapsed into a generic error where the message already tells us
more (DNS no-answer vs NXDOMAIN, connect refused vs timeout, TLS vs cert,
HTTP vs redirect).
"""

from __future__ import annotations

import pytest

from w4f.scanner import _dns_error_class, classify_error, probe_one

HAVE_DNS = True
try:
    import dns.exception  # noqa: F401
    import dns.resolver  # noqa: F401
    import dns.rdatatype  # noqa: F401
except ImportError:
    HAVE_DNS = False


class TestClassifyError:
    def test_dns_blanket(self):
        assert classify_error("DNS did not resolve") == "dns-error"

    def test_connect_refused(self):
        assert classify_error("connect failed: [Errno 111] Connection refused") == "conn-refused"
        assert classify_error("connect failed: Connection refused") == "conn-refused"

    def test_tcp_timeout(self):
        assert classify_error("connect failed: timed out") == "tcp-timeout"
        assert classify_error("connect failed: [Errno 110] Connection timed out") == "tcp-timeout"

    def test_network_unreachable(self):
        assert classify_error("connect failed: [Errno 101] Network is unreachable") == "network-unreachable"
        assert classify_error("connect failed: [Errno 113] No route to host") == "network-unreachable"

    def test_tls_timeout(self):
        assert classify_error("tls failed: timed out") == "tls-timeout"

    def test_tls_cert(self):
        assert classify_error("tls failed: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed") == "cert"
        assert classify_error("tls failed: [SSL: CERTIFICATE_VERIFY_FAILED]") == "cert"

    def test_tls_handshake(self):
        assert classify_error("tls failed: [SSL: WRONG_VERSION_NUMBER] wrong version number") == "tls-handshake"
        assert classify_error("tls failed: [SSL: TLSV1_ALERT_PROTOCOL_VERSION]") == "tls-handshake"

    def test_http_timeout(self):
        assert classify_error("ERROR: timed out") == "http-timeout"

    def test_redirect_failure(self):
        assert classify_error("ERROR: too many redirects") == "redirect"

    def test_http_protocol(self):
        assert classify_error("ERROR: bad status line") == "http-protocol"
        assert classify_error("ERROR: invalid response protocol") == "http-protocol"

    def test_upstream(self):
        assert classify_error("ERROR: connection reset by peer") == "upstream"
        assert classify_error("ERROR: BrokenPipeError") == "upstream"
        assert classify_error("ERROR: broken pipe") == "upstream"

    def test_other(self):
        assert classify_error("probe failed: something weird") == "other"
        assert classify_error("") == "other"


class TestDnsErrorClass:
    def test_nxdomain_message(self):
        # real dnspython NXDOMAIN text
        err = Exception("The DNS query name does not exist: nonexistent.invalid.")
        assert _dns_error_class(err) == "dns-nxdomain"

    def test_noanswer_message(self):
        # the JP apex pattern: the domain EXISTS but has no A/AAAA (site
        # lives at www.*) — materially different from NXDOMAIN
        err = Exception("The DNS response does not contain an answer to the question: mufg.jp. IN A")
        assert _dns_error_class(err) == "dns-noanswer"

    def test_timeout(self):
        class _T(Exception):
            pass
        assert _dns_error_class(_T("timed out")) == "dns-timeout"

    def test_gaierror_nxdomain(self):
        import socket
        assert _dns_error_class(socket.gaierror(socket.EAI_NONAME, "Name or service not known")) == "dns-nxdomain"

    def test_gaierror_again(self):
        import socket
        assert _dns_error_class(socket.gaierror(socket.EAI_AGAIN, "Temporary failure")) == "dns-timeout"


class TestResolveRecordsDnsError:
    def test_nonexistent_domain_records_class(self):
        out = probe_one("nonexistent.invalid", "/", 2.0, do_http=False)
        assert out["error"] == "DNS did not resolve"
        assert out["error_class"].startswith("dns-")
        # the evidence dict is preserved even when DNS failed completely
        assert isinstance(out.get("ips"), list)

    def test_dns_failure_is_error_not_unknown(self):
        out = probe_one("nonexistent.invalid", "/", 2.0, do_http=False)
        assert out["error"] is not None
        assert out["verdict"] == []


class TestHttpErrorPromotion:
    def test_http_timeout_promoted_to_error(self, monkeypatch, tls_server):
        from w4f import scanner
        srv = tls_server()
        def fake_get(*a, **k):
            return {"status": "ERROR: timed out", "headers": {}, "set-cookie-list": []}
        monkeypatch.setattr(scanner, "http_get", fake_get)
        out = probe_one(f"127.0.0.1:{srv.port}", "/", 5.0, do_http=True)
        assert out["error"] == "ERROR: timed out"
        assert out["error_class"] == "http-timeout"

    def test_mtls_certificate_required_is_not_an_error(self, monkeypatch, tls_server):
        # mTLS: the certificate-required alert on the GET IS the finding
        from w4f import scanner
        srv = tls_server()
        def fake_get(*a, **k):
            return {"status": "ERROR: SSL: CERTIFICATE_REQUIRED certificate required",
                    "headers": {}, "set-cookie-list": []}
        monkeypatch.setattr(scanner, "http_get", fake_get)
        out = probe_one(f"127.0.0.1:{srv.port}", "/", 5.0, do_http=True)
        assert out.get("error") is None
        assert out["mtls"] is True
