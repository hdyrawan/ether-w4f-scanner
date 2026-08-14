"""Integration tests: real TLS sockets against a LOCAL server.

These exercise the actual socket/handshake path (tls_probe, http_get,
verify_block, probe_one) without touching the internet — the server is a
127.0.0.1 thread with a self-signed cert. Self-signed means chain_verified
will be False from the default context, which is expected and asserted.
"""

from __future__ import annotations

import pytest

from w4f.scanner import http_get, probe_one, tls_probe, verify_block


@pytest.fixture(autouse=True)
def _anyio_backend():
    pass  # placeholder to keep test layout obvious; no async used


class TestTlsProbe:
    def test_handshake_and_cert(self, tls_server):
        srv = tls_server()
        out = tls_probe("127.0.0.1", srv.port, "/", 5.0, do_http=False)
        assert out["tls_version"] in ("TLSv1.2", "TLSv1.3")
        assert out["chain_verified"] is False  # self-signed
        assert out["cert"] and out["cert"]["issuer_org"] == ""
        assert out["cert"]["subject"]  # parsed CN present

    def test_cert_spki_sha256_present(self, tls_server):
        srv = tls_server()
        out = tls_probe("127.0.0.1", srv.port, "/", 5.0, do_http=False)
        assert len(out["cert"].get("spki_sha256", "")) == 64

    def test_connect_refused(self):
        # bind a socket, grab its port, close it — nothing listens there
        import socket
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        out = tls_probe("127.0.0.1", port, "/", 2.0, do_http=False)
        assert "connect failed" in (out.get("tls_error") or "")


class TestHttpGet:
    def test_status_and_headers(self, tls_server):
        srv = tls_server(status="HTTP/1.1 404 Not Found",
                         headers=["Server: nginx/1.24.0", "X-Custom: yes"],
                         body=b"not found")
        out = http_get("127.0.0.1", srv.port, "/", 5.0)
        assert out["status"] == "HTTP/1.1 404 Not Found"
        assert out["headers"]["server"] == "nginx/1.24.0"
        assert out["headers"]["x-custom"] == "yes"

    def test_multiple_set_cookie(self, tls_server):
        srv = tls_server(headers=[
            "Set-Cookie: TS01a3d6e7=abc; Path=/",
            "Set-Cookie: brks_lb=!xyz==",
        ])
        out = http_get("127.0.0.1", srv.port, "/", 5.0)
        assert len(out["set-cookie-list"]) == 2
        assert out["set-cookie-list"][0].startswith("TS01a3d6e7=")


class TestRedirectFollowing:
    """apex -> www: the WAF lives on the FINAL response, not the redirector."""

    def test_follows_relative_redirect(self, tls_server):
        # first server 301s to a relative path on a SECOND server; the second
        # carries the WAF header. http_get must follow and return server #2.
        target = tls_server(status="HTTP/1.1 200 OK",
                            headers=["Server: AkamaiGHost", "X-WAF: kona"],
                            body=b"www")
        # server A redirects to server B's port
        redir = tls_server(status="HTTP/1.1 301 Moved Permanently",
                           headers=[f"Location: https://127.0.0.1:{target.port}/"],
                           body=b"")
        out = http_get("127.0.0.1", redir.port, "/", 5.0)
        assert out["status"] == "HTTP/1.1 200 OK"
        assert out["headers"]["server"] == "AkamaiGHost"
        assert out["redirects"] == [f"https://127.0.0.1:{target.port}/"]
        assert out["final_host"] == "127.0.0.1"

    def test_stops_after_max_redirects(self, tls_server):
        # a server that 301s to itself forever must not loop past the cap
        redir = tls_server(status="HTTP/1.1 301 Moved Permanently",
                           headers=[f"Location: https://127.0.0.1:{0}/"])
        # patch the Location to its own port (the server got a real port)
        redir.headers = [f"Location: https://127.0.0.1:{redir.port}/"]
        out = http_get("127.0.0.1", redir.port, "/", 5.0, max_redirects=2)
        assert len(out["redirects"]) <= 3  # initial + 2 hops
        assert out["status"].startswith("HTTP/1.1 301")


class TestVerifyBlock:
    def test_fortiweb_block(self, tls_server):
        body = b"x" * 38000 + b"<html><head><title>The URL you requested has been blocked</title></head></html>"
        srv = tls_server(status="HTTP/1.1 500 Internal Server Error", body=body)
        got = verify_block("127.0.0.1", srv.port, 5.0)
        assert got and got["vendor"] == "fortiweb"

    def test_fortiweb_id_block(self, tls_server):
        srv = tls_server(status="HTTP/1.1 500 Internal Server Error",
                         body=b"<html><head><title>The URL Request Tidak Tersedia</title></head></html>")
        got = verify_block("127.0.0.1", srv.port, 5.0)
        assert got and got["vendor"] == "fortiweb"

    def test_f5_asm_block(self, tls_server):
        srv = tls_server(status="HTTP/1.1 200 OK",
                         body=b"<html><head><title>Request Rejected</title></head></html>")
        got = verify_block("127.0.0.1", srv.port, 5.0)
        assert got and got["vendor"] == "f5-asm"

    def test_plain_page_no_match(self, tls_server):
        srv = tls_server(status="HTTP/1.1 200 OK",
                         body=b"<html><head><title>Welcome</title></head></html>")
        assert verify_block("127.0.0.1", srv.port, 5.0) is None

    def test_connection_refused_no_crash(self):
        import socket
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        assert verify_block("127.0.0.1", port, 2.0) is None


class TestProbeOne:
    def test_full_probe_with_fortiweb_server(self, tls_server):
        body = b"<html><head><title>The URL you requested has been blocked</title></head></html>"
        srv = tls_server(status="HTTP/1.1 500 Internal Server Error",
                         headers=["Server: nginx"], body=body)
        out = probe_one(f"127.0.0.1:{srv.port}", "/", 5.0, do_http=True, verify=True)
        assert out["error"] is None
        assert out["tls"]["http"]["headers"]["server"] == "nginx"
        assert [m["vendor"] for m in out["verdict"]] == ["nginx"]
        assert out["block"] and out["block"]["vendor"] == "fortiweb"
        # block page = the edge's own WAF page: high confidence by design
        assert out["block"]["confidence"] == 95

    def test_dns_failure(self):
        out = probe_one("nonexistent.invalid", "/", 2.0, do_http=False)
        assert out["error"] in ("DNS did not resolve", None) or out["resolved"]["ips"] == []


class TestWsGrpcProbes:
    def test_ws_upgrade_101(self, tls_server):
        from w4f.scanner import ws_probe
        srv = tls_server(
            status="HTTP/1.1 101 Switching Protocols",
            headers=["Upgrade: websocket", "Sec-WebSocket-Accept: abc123"],
        )
        out = ws_probe("127.0.0.1", srv.port, "/ws", 5.0)
        assert out["upgrade_supported"] is True
        assert out["sec_websocket_accept"] == "abc123"

    def test_ws_upgrade_rejected(self, tls_server):
        from w4f.scanner import ws_probe
        srv = tls_server(status="HTTP/1.1 403 Forbidden")
        out = ws_probe("127.0.0.1", srv.port, "/ws", 5.0)
        assert out["upgrade_supported"] is False
        assert out["status"].startswith("HTTP/1.1 403")

    def test_ws_connection_refused_no_crash(self):
        from w4f.scanner import ws_probe
        import socket
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        out = ws_probe("127.0.0.1", port, "/ws", 2.0)
        assert out["error"] and out["upgrade_supported"] is False

    def test_grpc_grpc_status_header(self, tls_server):
        from w4f.scanner import grpc_probe
        srv = tls_server(status="HTTP/1.1 200 OK",
                         headers=["Content-Type: application/grpc", "grpc-status: 12"])
        out = grpc_probe("127.0.0.1", srv.port, 5.0)
        assert out["grpc_supported"] is True
        assert out["grpc_status"] == "12"

    def test_grpc_rejected_plain(self, tls_server):
        from w4f.scanner import grpc_probe
        srv = tls_server(status="HTTP/1.1 400 Bad Request")
        out = grpc_probe("127.0.0.1", srv.port, 5.0)
        assert out["grpc_supported"] is False
        assert out["status"].startswith("HTTP/1.1 400")

    def test_grpc_connection_refused_no_crash(self):
        from w4f.scanner import grpc_probe
        import socket
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        out = grpc_probe("127.0.0.1", port, 2.0)
        assert out["error"] and out["grpc_supported"] is False

    def test_probe_one_runs_opt_in_probes(self, tls_server):
        srv = tls_server(status="HTTP/1.1 101 Switching Protocols",
                         headers=["Upgrade: websocket"])
        out = probe_one(f"127.0.0.1:{srv.port}", "/", 5.0, do_http=True,
                        ws_path="/ws", grpc=True)
        assert out["error"] is None
        assert out["ws"]["upgrade_supported"] is True
        assert "grpc" in out  # ran without raising


class TestCsvOutput:
    def test_header_row_stable(self):
        from w4f.report import CSV_HEADER, csv_doc
        out = csv_doc([])
        assert out.splitlines()[0] == ",".join(CSV_HEADER)

    def test_known_vendor_row(self):
        from w4f.report import csv_doc
        import csv
        import io
        results = [{
            "host": "api.example.com", "hostport": "api.example.com:443",
            "port": 443, "ips": ["104.18.1.79"], "cname": ["x.cdn.cloudflare.net"],
            "mtls": False, "spki_sha256": "abc123",
            "tls": {"tls_version": "TLSv1.3", "alpn": "h2",
                    "http": {"status": "HTTP/1.1 200 OK"}},
            "verdict": [{"vendor": "cloudflare", "confidence": 82, "signals": 3,
                         "evidence": []}],
            "block": {"vendor": "cloudflare"}, "error": None,
        }]
        rows = list(csv.reader(io.StringIO(csv_doc(results))))
        assert rows[0][0] == "host"  # header first
        row = rows[1]
        assert row[0] == "api.example.com"
        assert row[1] == "443"
        assert row[4] == "cloudflare"   # verdict
        assert row[5] == "82"           # confidence
        assert row[6] == "3"            # signals
        assert row[12] == "cloudflare"  # block

    def test_csv_escaping_commas_in_ips(self):
        from w4f.report import csv_doc
        import csv
        import io
        results = [{
            "host": "x.com", "hostport": "x.com:443", "port": 443,
            "ips": ["1.2.3.4", "5.6.7.8"], "cname": [], "mtls": False,
            "tls": {"tls_version": "TLSv1.2", "alpn": "http/1.1",
                    "http": {"status": "HTTP/1.1 200 OK"}},
            "verdict": [{"vendor": "nginx", "confidence": 7, "signals": 1,
                         "evidence": []}],
            "block": None, "error": None,
        }]
        rows = list(csv.reader(io.StringIO(csv_doc(results))))
        assert rows[1][2] == "1.2.3.4, 5.6.7.8"  # ips cell round-trips with comma

    def test_cli_writes_csv_with_quiet_and_json(self, tls_server, tmp_path):
        from w4f.cli import main
        import sys
        srv = tls_server()  # fixture is a factory
        csv_p = tmp_path / "out.csv"
        json_p = tmp_path / "out.json"
        monkeypatch_argv = ["w4f", "--target", f"127.0.0.1:{srv.port}",
                            "--no-http", "--quiet", "--csv", str(csv_p),
                            "--json", str(json_p), "--timeout", "5"]
        old_argv, old_stdin = sys.argv, sys.stdin
        sys.argv = monkeypatch_argv
        class Tty:
            def isatty(self):
                return True
        sys.stdin = Tty()
        try:
            rc = main()
        finally:
            sys.argv, sys.stdin = old_argv, old_stdin
        assert rc == 0
        assert csv_p.exists()
        assert json_p.exists()
        import json as _json
        j = _json.loads(json_p.read_text())
        assert j and j[0]["hostport"] == f"127.0.0.1:{srv.port}"
        assert csv_p.read_text().splitlines()[0].startswith("host,port")
