"""w4f — passive TLS / CDN / WAF / edge fingerprinting.

Public API:
    fingerprint_host(host, port=443, timeout=8, verify=False, path="/",
                     no_http=False, ws_path=None, grpc=False, **kwargs)
        Fingerprint one host and return the same dict structure the CLI's
        ``--json`` output produces for a single host.
"""

from __future__ import annotations

__version__ = "0.1.43"

__all__ = ["fingerprint_host"]


def fingerprint_host(host: str, port: int = 443, timeout: float = 8.0,
                     verify: bool = False, path: str = "/",
                     no_http: bool = False, ws_path: str | None = None,
                     grpc: bool = False, **kwargs) -> dict:
    """Fingerprint a single host without going through the CLI.

    Runs the same probe the CLI runs (DNS, one SNI TLS handshake, one GET,
    optional opt-in probes) and returns the same per-host dict the ``--json``
    output contains: ``host``, ``hostport``, ``port``, ``resolved``, ``tls``,
    ``verdict`` (vendor matches ranked by confidence, each with
    ``categories`` naming the signal kinds behind it), ``block`` (when
    ``verify=True`` finds a WAF block page), and ``error`` (never raises for
    scan failures — a bad host is a field, not an exception).

    Extra keyword arguments are accepted for forward compatibility and
    ignored. Callers can pass a ``host`` already containing ``:port``
    (``"example.com:8443"``); an explicit ``port`` wins.
    """
    from w4f.scanner import probe_one

    # A host that already carries :port keeps it unless an explicit port
    # was passed (matches how the CLI treats "host:port" targets).
    if ":" in host and port == 443:
        hostport = host
    else:
        hostport = f"{host}:{port}"
    # probe_one(hostport, path, timeout, do_http, verify, ws_path, grpc)
    return probe_one(hostport, path, timeout, not no_http, verify,
                     ws_path, grpc)
