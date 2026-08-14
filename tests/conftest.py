"""Shared pytest fixtures: a local TLS server with a self-signed cert.

Tests exercise the real socket path (DNS-free: connect to 127.0.0.1) but
never touch the internet. The server answers every request with a
configurable response body, so the block-page probe and HTTP parsing can be
integration-tested offline.
"""

from __future__ import annotations

import datetime
import ipaddress
import socket
import ssl
import tempfile
import threading

import pytest

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover - exercised in the minimal CI job
    HAVE_CRYPTO = False

requires_crypto = pytest.mark.skipif(
    not HAVE_CRYPTO, reason="cryptography not installed (integration tests need a local TLS cert)"
)


def _make_cert_pem(host: str = "127.0.0.1"):
    """Return (cert_pem, key_pem) for a self-signed cert valid ~2 years."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=730))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(host), x509.IPAddress(ipaddress.ip_address(host))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


class LocalTLSServer:
    """Threaded TLS server; serves a canned response to every request."""

    def __init__(self, status: str = "HTTP/1.1 200 OK",
                 headers: list[str] | None = None, body: bytes = b"ok"):
        self.status = status
        self.headers = headers or []
        self.body = body
        cert_pem, key_pem = _make_cert_pem()
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as cf:
            cf.write(cert_pem)
            self._cert_file = cf.name
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as kf:
            kf.write(key_pem)
            self._key_file = kf.name
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(self._cert_file, self._key_file)
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind(("127.0.0.1", 0))
        self._server_sock.listen(5)
        self.port = self._server_sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while True:
            try:
                conn, _ = self._server_sock.accept()
            except OSError:
                return
            conn.settimeout(5)  # don't hang forever on a stalled handshake
            try:
                with self._ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.settimeout(5)
                    tls.recv(4096)  # read the request
                    resp = self.status + "\r\n"
                    for h in self.headers:
                        resp += h + "\r\n"
                    resp += f"Content-Length: {len(self.body)}\r\n\r\n"
                    tls.sendall(resp.encode() + self.body)
            except Exception:
                pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

    def close(self):
        self._server_sock.close()
        for f in (self._cert_file, self._key_file):
            try:
                __import__("os").unlink(f)
            except Exception:
                pass


@pytest.fixture
def tls_server():
    if not HAVE_CRYPTO:
        pytest.skip("cryptography not installed (local TLS server needs a cert)")
    servers = []

    def make(status="HTTP/1.1 200 OK", headers=None, body=b"ok"):
        s = LocalTLSServer(status, headers, body)
        servers.append(s)
        return s

    yield make
    for s in servers:
        s.close()
