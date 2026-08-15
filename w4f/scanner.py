"""Probing: DNS, TLS handshake with SNI, one HTTP/1.1 GET. Never raises."""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
import ssl
from datetime import datetime, timezone

from w4f.attribution import attribute

log = logging.getLogger(__name__)

try:
    import dns.resolver
    import dns.reversename
    HAVE_DNS = True
    _DNS = dns
except ImportError:
    HAVE_DNS = False
    _DNS = None

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import ExtensionOID, NameOID
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

UA = ("Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36")


def classify_error(msg: str) -> str:
    """Map a probe error message to a stable error class.

    The per-host ``error`` string contract is unchanged; this is the
    structured axis (v0.1.42). Categories: dns-*, conn-refused,
    tcp-timeout, network-unreachable, tls-timeout, tls-handshake, cert,
    http-timeout, redirect, http-protocol, upstream, other.
    """
    m = (msg or "").lower()
    if "dns did not resolve" in m:
        return "dns-error"
    if "connect failed" in m:
        if "timed out" in m or "timeout" in m:
            return "tcp-timeout"
        if "refused" in m:
            return "conn-refused"
        if ("network is unreachable" in m or "no route" in m
                or "errno 101" in m or "errno 113" in m):
            return "network-unreachable"
        if "certificate" in m:
            return "cert"
        return "connect"
    if "tls failed" in m:
        if "timed out" in m or "timeout" in m:
            return "tls-timeout"
        if "certificate" in m or "verify" in m:
            return "cert"
        if ("handshake" in m or "wrong version" in m or "alert" in m
                or "sslv3" in m or "tlsv1" in m):
            return "tls-handshake"
        return "tls"
    if m.startswith("error:") or "too many redirects" in m:
        if "too many redirects" in m or "redirect" in m:
            return "redirect"
        if "timed out" in m or "timeout" in m:
            return "http-timeout"
        if "connection reset" in m or "broken pipe" in m or "brokenpipe" in m:
            return "upstream"
        if "protocol" in m or "bad status" in m:
            return "http-protocol"
        return "http"
    if "refused" in m:
        return "conn-refused"
    if "timed out" in m or "timeout" in m:
        return "tcp-timeout"
    return "other"


def _dns_error_class(exc: Exception | None) -> str:
    """Classify a DNS failure beyond the blanket 'DNS did not resolve'."""
    if exc is None:
        return "dns-error"
    name = type(exc).__name__.lower()
    msg = str(exc).lower()
    if "nxdomain" in name or "non-existent" in msg or "does not exist" in msg:
        return "dns-nxdomain"
    if "noanswer" in name or "does not contain an answer" in msg:
        return "dns-noanswer"
    if "timeout" in name or "timed out" in msg:
        return "dns-timeout"
    if "nonameservers" in name or "no nameservers" in msg:
        return "dns-nonameserver"
    if getattr(exc, "errno", None) in (socket.EAI_NONAME, socket.EAI_NODATA):
        return "dns-nxdomain"
    if getattr(exc, "errno", None) == socket.EAI_AGAIN:
        return "dns-timeout"
    return "dns-error"


def resolve(host: str) -> dict:
    """A+AAAA with PTR, and the CNAME chain. Never raises.

    On total DNS failure the returned dict carries ``dns_error`` (a class
    from :func:`_dns_error_class`) and ``dns_error_detail`` so callers can
    distinguish NXDOMAIN from no-answer (the classic apex-has-only-www
    case) from a resolver timeout — without collapsing them into one
    blanket message.
    """
    out: dict = {"cname": [], "ips": [], "ptr": []}
    dns_fail: Exception | None = None
    try:
        ip = ipaddress.ip_address(host)
        out["ips"] = [str(ip)]
        if HAVE_DNS:
            try:
                rev = _DNS.reversename.from_address(str(ip))
                for r in _DNS.resolver.resolve(rev, "PTR"):
                    out["ptr"].append(str(r.target).rstrip("."))
            except Exception as e:
                log.debug("PTR lookup failed for %s: %s", ip, e)
        return out
    except ValueError:
        pass
    if HAVE_DNS:
        try:
            for r in _DNS.resolver.resolve(host, "CNAME"):
                c = str(r.target).rstrip(".")
                if c.lower() != host.lower():
                    out["cname"].append(c)
        except Exception as e:
            log.debug("CNAME lookup failed for %s: %s", host, e)
            dns_fail = e
        for qtype in ("A", "AAAA"):
            try:
                for r in _DNS.resolver.resolve(host, qtype):
                    out["ips"].append(str(r))
            except Exception as e:
                log.debug("%s lookup failed for %s: %s", qtype, host, e)
                dns_fail = e
        for ip in out["ips"]:
            try:
                rev = _DNS.reversename.from_address(ip)
                for r in _DNS.resolver.resolve(rev, "PTR"):
                    out["ptr"].append(str(r.target).rstrip("."))
            except Exception as e:
                log.debug("PTR lookup failed for %s: %s", ip, e)
    else:
        try:
            infos = socket.getaddrinfo(host, None)
            for info in infos:
                ip = info[4][0]
                if ip not in out["ips"]:
                    out["ips"].append(str(ip))
        except Exception as e:
            log.debug("getaddrinfo failed for %s: %s", host, e)
            dns_fail = e
    if not out["ips"]:
        out["dns_error"] = _dns_error_class(dns_fail)
        out["dns_error_detail"] = str(dns_fail or "")
    if not out["cname"]:
        try:
            # getaddrinfo returns (family, type, proto, canonname, sockaddr);
            # only the canonical name is a string. info[0] is the AF enum.
            for info in socket.getaddrinfo(host, None):
                canon = info[3]
                if canon and canon not in out["cname"]:
                    out["cname"].append(canon)
        except Exception as e:
            log.debug("canonical-name lookup failed for %s: %s", host, e)
    return out


def _extract_org(name) -> str:
    if name is None:
        return ""
    orgs = [attr.value for attr in name if attr.oid == NameOID.ORGANIZATION_NAME]
    return orgs[0] if orgs else ""


def _parse_cert(der: bytes) -> dict | None:
    if not HAVE_CRYPTO:
        return {"note": "cryptography not installed; install python3-cryptography for cert details"}
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as e:
        return {"note": f"cert parse failed: {e}"}

    def _name(n):
        if n is None:
            return ""
        parts = []
        for attr in n:
            oid = attr.oid
            if oid in (NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME,
                       NameOID.ORGANIZATIONAL_UNIT_NAME, NameOID.COUNTRY_NAME):
                parts.append(f"{oid._name}={attr.value}")
        return ", ".join(parts)

    def _oid_str(oid):
        return getattr(oid, "_name", None) or oid.dotted_string

    subject = cert.subject
    issuer = cert.issuer
    san = ""
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = ", ".join(ext.value.get_values_for_type(x509.DNSName))
    except Exception:
        pass
    try:
        pub = cert.public_key()
        key_size = getattr(pub, "key_size", 0)
        key_type = pub.__class__.__name__.replace("PublicKey", "")
    except Exception:
        key_size, key_type = 0, ""
    try:
        spki = cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        spki_sha = hashes.Hash(hashes.SHA256())
        spki_sha.update(spki)
        spki_sha256 = spki_sha.finalize().hex()
    except Exception:
        spki_sha256 = ""

    # cryptography >= 42 exposes not_valid_before_utc; older builds only have
    # the tz-naive not_valid_before. getattr avoids an AttributeError that the
    # bare except would otherwise swallow (silently degrading the cert dict).
    # Normalize the fallback to aware UTC so the days_remaining math below
    # works with an aware `now`.
    nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
    na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
    if nb.tzinfo is None:
        nb = nb.replace(tzinfo=timezone.utc)
    if na.tzinfo is None:
        na = na.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    return {
        "subject": _name(subject) or "(empty)",
        "issuer": _name(issuer) or "(empty)",
        "issuer_org": _extract_org(issuer),
        "subject_org": _extract_org(subject),
        "san": san,
        "not_before": nb.isoformat(),
        "not_after": na.isoformat(),
        "days_remaining": (na - now).days,
        "serial": format(cert.serial_number, "x"),
        "sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "spki_sha256": spki_sha256,
        "signature": _oid_str(cert.signature_algorithm_oid),
        "key_type": key_type,
        "key_size": key_size,
        "chain_verified": None,  # filled by caller
    }


def _unverified_ctx() -> ssl.SSLContext:
    """Public-API unverified context (fingerprinting needs to read certs that
    chain validation would reject — self-signed, expired, wrong hostname).

    ssl._create_unverified_context() is a private API; the documented public
    equivalent is a default context with verification disabled. This is
    intentional for a fingerprinting tool — the cert is evidence, not trust.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def tls_probe(host: str, port: int, path: str, timeout: float, do_http: bool) -> dict:
    """One SNI TLS handshake + optional GET (http/1.1 ALPN). Never raises."""
    out: dict = {"port": port, "mtls": False, "http": None, "tls_error": None}
    ctx = ssl.create_default_context()
    verified = False
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except Exception as e:
        out["tls_error"] = f"connect failed: {e}"
        return out
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        try:
            with ctx.wrap_socket(sock, server_hostname=host) as ts:
                sock = None  # ownership moved to ts
                verified = True
                _collect_tls(ts, out)
                out["chain_verified"] = True
            # GET over a SEPARATE http/1.1-only connection: if the first
            # handshake negotiated h2, an HTTP/1.1 request on that socket gets
            # a binary HTTP/2 frame back, which reads as garbage. Do it only
            # AFTER the handshake connection is closed (single-threaded
            # servers block on the first socket otherwise).
            if do_http:
                http = http_get(host, port, path, timeout)
                out["http"] = http
                if not out.get("mtls") and http.get("status", "").startswith("ERROR"):
                    # TLS 1.3 mTLS: server asks for the client cert AFTER the
                    # handshake, so the alert lands on the first app data.
                    if "certificate required" in http["status"].lower():
                        out["mtls"] = True
            return out
        except ssl.SSLError as e:
            msg = str(e).lower()
            if "certificate required" in msg or "certificate required" in getattr(e, "strerror", ""):
                out["mtls"] = True
            else:
                log.debug("TLS verification failed for %s:%s: %s", host, port, e)
            # fall through: retry unvalidated to still grab the cert
            if sock is not None:
                try:
                    sock.close()  # don't leak the failed-verification socket
                except Exception:
                    pass
            try:
                sock = socket.create_connection((host, port), timeout=timeout)
                ctx2 = _unverified_ctx()
                ctx2.set_alpn_protocols(["h2", "http/1.1"])
                try:
                    with ctx2.wrap_socket(sock, server_hostname=host) as ts:
                        sock = None  # ownership moved to ts
                        _collect_tls(ts, out)
                        out["chain_verified"] = False
                finally:
                    if sock is not None:
                        try:
                            sock.close()
                        except Exception:
                            pass
                # Close the handshake connection BEFORE the HTTP GET: a
                # single-threaded server blocks on the first connection's
                # socket while we open a second one, and the second then
                # times out. Never hold one connection across another.
                if do_http:
                    http = http_get(host, port, path, timeout)
                    out["http"] = http
                    if "certificate required" in http.get("status", "").lower():
                        out["mtls"] = True
            except Exception as e2:
                if not out.get("tls_error"):
                    out["tls_error"] = f"tls failed: {e2}"
    except Exception as e:
        if sock is not None:
            try:
                sock.close()  # non-SSLError failure (timeout/OSError) — don't leak
            except Exception:
                pass
        log.debug("TLS probe failed for %s:%s: %s", host, port, e)
        out["tls_error"] = f"tls failed: {e}"
    out["chain_verified"] = verified if "chain_verified" not in out else out["chain_verified"]
    return out


def _collect_tls(ts: ssl.SSLSocket, out: dict) -> None:
    out["tls_version"] = ts.version()
    cipher = ts.cipher()
    out["cipher"] = cipher[0] if cipher else None
    out["alpn"] = ts.selected_alpn_protocol()
    der = ts.getpeercert(binary_form=True)
    if der:
        out["cert"] = _parse_cert(der)


# Statuses a WAF uses to refuse a request. Seeing one on a NORMAL GET means
# the block page is already in front of us — no active probe needed.
_BLOCKING_STATUS = ("403", "406", "418", "419", "429", "494", "501", "503")
_BLOCK_BODY_MAX = 65536


def status_is_blocking(status_line: str) -> bool:
    """True when an HTTP status line carries a refusal code."""
    parts = (status_line or "").split()
    return len(parts) > 1 and parts[1] in _BLOCKING_STATUS


def _is_blocking_status(data: bytes) -> bool:
    """True when the status line of a raw response carries a blocking code."""
    return status_is_blocking(data.split(b"\r\n", 1)[0].decode("latin-1", "replace"))


def http_get(host: str, port: int, path: str, timeout: float,
             max_redirects: int = 5) -> dict:
    """One HTTP/1.1 GET, following redirects (apex -> www -> ...).

    Many hosts 301 from the bare domain to www and only the *final*
    response carries the WAF (Akamai Kona on www.example-news.com, Cloudflare on
    www.example-registrar.com, ...). Probing the apex alone would fingerprint the
    redirector, not the edge. Follows up to max_redirects hops; the final
    response is returned with the redirect chain recorded.
    """
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {UA}\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n"
    )

    def _once(verify: bool, h: str, p: int, pth: str) -> dict:
        sock = None
        try:
            sock = socket.create_connection((h, p), timeout=timeout)
            ctx = ssl.create_default_context() if verify else _unverified_ctx()
            ctx.set_alpn_protocols(["http/1.1"])
            with ctx.wrap_socket(sock, server_hostname=h) as ts:
                sock = None  # ownership moved to ts; the with closes it
                ts.settimeout(timeout)
                ts.sendall(req.replace(f"Host: {host}", f"Host: {h}").encode())
                data = b""
                while b"\r\n\r\n" not in data and len(data) < 65536:
                    chunk = ts.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                # A blocking-shaped status means the WAF answered the NORMAL
                # request with its own page — the vendor is named in a body
                # we would otherwise throw away (the loop above stops at the
                # header terminator). Keep reading only in that case: no
                # extra request, and an ordinary 200 costs nothing. FortiWeb
                # puts its <title> at the end of a ~39KB page, hence 64KB.
                if _is_blocking_status(data) and len(data) < _BLOCK_BODY_MAX:
                    while len(data) < _BLOCK_BODY_MAX:
                        try:
                            chunk = ts.recv(8192)
                        except socket.timeout:
                            break
                        if not chunk:
                            break
                        data += chunk
            parsed = parse_http_response(data)
            return {"status": parsed["status"], "headers": parsed["headers"],
                    "set-cookie-list": parsed["set-cookie-list"],
                    "title": parsed["title"], "head_text": parsed["head_text"],
                    "body_text": parsed["body_text"]}
        except Exception as e:
            if sock is not None:
                try:
                    sock.close()  # don't leak a failed-verification socket
                except Exception:
                    pass
            return {"status": f"ERROR: {e}", "headers": {}, "set-cookie-list": []}

    def _probe(verify: bool, h: str, p: int, pth: str) -> dict:
        result = _once(verify, h, p, pth)
        if result["status"].startswith("ERROR") and "certificate" in result["status"].lower():
            # Chain not trusted from this client — headers are still
            # fingerprint evidence, so retry without validation.
            result = _once(False, h, p, pth)
        return result

    cur_host, cur_port, cur_path = host, port, path
    redirects: list[str] = []
    result: dict = {"status": "ERROR: no response", "headers": {}, "set-cookie-list": []}
    for _hop in range(max_redirects + 1):
        result = _probe(True, cur_host, cur_port, cur_path)
        if result["status"].startswith("ERROR"):
            return result
        loc = (result.get("headers") or {}).get("location", "")
        if loc and result["status"].startswith(("HTTP/1.1 3", "HTTP/1.0 3", "HTTP/2 3")):
            redirects.append(loc)
            if loc.startswith("http"):
                from urllib.parse import urlparse
                u = urlparse(loc)
                cur_host = u.hostname or cur_host
                cur_port = u.port or (443 if u.scheme == "https" else 80)
                cur_path = u.path or "/"
                if u.query:
                    cur_path += "?" + u.query
            elif loc.startswith("/"):
                cur_path = loc
            else:
                break  # unparseable location, keep what we have
            continue
        break

    result["redirects"] = redirects
    result["final_host"] = cur_host
    return result


# Confidence weights per signal category (0-100 total). These are the
# default; a vendor rule can override with its own "weights" dict.
CONF_WEIGHTS = {
    "netblock": 30,  # IP ownership is hard to spoof
    "cert": 25,      # cert issuance is authoritative
    "cname": 20,     # DNS delegation is intentional
    "ptr": 15,       # can be generic or missing
    "headers": 7,    # weak alone — anyone can set a header
    "cookies": 3,    # weakest — easily fabricated
}

# Signal categories strongest-first — the order verdict['categories'] is
# reported in, so a reader sees what the verdict actually rests on
# ("netblock+cert" is hard evidence, "headers" alone is spoofable).
CONF_CATEGORY_ORDER = ["netblock", "cert", "cname", "ptr", "headers", "cookies"]


def fingerprint(result: dict) -> list[dict]:
    """Ranked vendor matches with the signals that matched.

    The HTTP layer lives under result['tls']['http'] (probe_one stores the
    whole tls dict), NOT at the top level — reading result.get('http') was a
    bug that silently disabled ALL header/cookie matching (F5, cookie-based
    vendors, etc.). Also accept the mirrored top-level form for compat.
    """
    from w4f.vendors import VENDORS, vendor_nets

    http_layer = (result.get("tls") or {}).get("http") or result.get("http") or {}
    headers = dict(http_layer.get("headers") or {})
    # expose the HTTP status as a pseudo-header so rules can match on it
    # (e.g. aws-waf = 403 + x-cache: Error from cloudfront). None when no GET.
    status = http_layer.get("status") or ""
    if status:
        m = re.search(r"\s(\d{3})\s", status)
        if m:
            headers["_status"] = m.group(1)
    set_cookies = http_layer.get("set-cookie-list") or []
    cert = result.get("cert") or {}
    cert_text = " ".join([
        str(cert.get("issuer", "")), str(cert.get("issuer_org", "")),
        str(cert.get("subject", "")), str(cert.get("subject_org", "")),
    ]).lower()
    cnames = " ".join(result.get("cname", [])).lower()
    ptrs = " ".join(result.get("ptr", [])).lower()
    ips = result.get("ips", [])

    matches = []
    for name, rules in VENDORS.items():
        evidence = []
        # Structured mirror of `evidence`, recorded where the category is
        # already known so the attribution layer never has to re-parse the
        # formatted strings. Additive: `evidence` keeps its exact shape.
        items: list[dict] = []
        cats: set[str] = set()
        for hname, hre in rules.get("headers", {}).items():
            # A trailing "*" is a PREFIX match against any header name:
            # "x-tyk-*" matches x-tyk-request-id, x-tyk-api-key, ... Exact
            # keys stay exact (arvancloud lesson: a glob never fires against
            # the exact lookup — but a prefix is a real, useful match).
            if hname.endswith("*"):
                prefix = hname[:-1].lower()
                for hk, hv in headers.items():
                    if hk.lower().startswith(prefix) and (
                            hre is None or re.search(hre, hv, re.I)):
                        evidence.append(f"header {hk}: {hv[:60]}")
                        items.append({"category": "headers", "detail": f"{hk}: {hv[:60]}"})
                        cats.add("headers")
            else:
                val = headers.get(hname)
                if val is None:
                    continue
                if hre is None or re.search(hre, val, re.I):
                    evidence.append(f"header {hname}: {val[:60]}")
                    items.append({"category": "headers", "detail": f"{hname}: {val[:60]}"})
                    cats.add("headers")
        for cre in rules.get("cookies", []):
            for cval in set_cookies:
                if re.search(cre, cval):
                    evidence.append(f"cookie: {cval[:60]}")
                    items.append({"category": "cookies", "detail": cval[:60]})
                    cats.add("cookies")
        cre = rules.get("cert")
        if cre and re.search(cre, cert_text):
            evidence.append(f"cert: {cert.get('issuer_org') or cert.get('issuer')}")
            items.append({"category": "cert",
                          "detail": str(cert.get('issuer_org') or cert.get('issuer'))})
            cats.add("cert")
        cname_re = rules.get("cname")
        if cname_re and re.search(cname_re, cnames):
            first = (result.get("cname") or [""])[0]
            evidence.append(f"cname: {first}")
            items.append({"category": "cname", "detail": first})
            cats.add("cname")
        ptr_re = rules.get("ptr")
        if ptr_re and re.search(ptr_re, ptrs):
            first = (result.get("ptr") or [""])[0]
            evidence.append(f"ptr: {first}")
            items.append({"category": "ptr", "detail": first})
            cats.add("ptr")
        for net in vendor_nets(name):
            for ip in ips:
                try:
                    if ipaddress.ip_address(ip) in net:
                        evidence.append(f"netblock: {ip} in {net}")
                        items.append({"category": "netblock", "detail": f"{ip} in {net}"})
                        cats.add("netblock")
                        break
                except ValueError:
                    pass
        if evidence and _required_signals_ok(rules, headers, set_cookies,
                                             cert_text, cnames, ptrs, ips):
            weights = {**CONF_WEIGHTS, **(rules.get("weights") or {})}
            conf = sum(weights.get(c, 0) for c in cats)
            match = {"vendor": name, "signals": len(evidence),
                     "confidence": min(conf, 100),
                     "categories": [c for c in CONF_CATEGORY_ORDER if c in cats],
                     "evidence": evidence, "evidence_items": items}
            # How the vendor sits in front of the origin — this is what
            # decides whether an interception route can target one IP at all.
            # Absent for vendors sold BOTH ways (Imperva Incapsula vs
            # SecureSphere); there only an observed block page can say which.
            if rules.get("deployment"):
                match["deployment"] = rules["deployment"]
            matches.append(match)

    # Rank by CONFIDENCE, not evidence count. Ranking by len(evidence) let a
    # vendor matched only by several headers (all one category, 7% total)
    # outrank one proven by a netblock (30%) — so a Cloudflare-fronted host
    # running a Kong gateway summarised as "kong (7%)" with cloudflare
    # demoted to a secondary line. Signal count breaks ties, then the name
    # so the order is stable across runs.
    matches.sort(key=lambda m: (-m["confidence"], -m["signals"], m["vendor"]))
    return matches


def _required_signals_ok(rules: dict, headers: dict, set_cookies: list,
                         cert_text: str, cnames: str, ptrs: str, ips: list) -> bool:
    """AND/OR-gate for multi-signal rules via the optional ``requires`` field.

    The base fingerprint loop ORs every signal kind within a vendor — a
    single matching header is enough to fire. That is right for most vendors
    but dangerously loose for composite rules (e.g. aws-waf must not fire on
    *any* 403; it needs an AWS-specific marker too).

    ``requires`` is a list of alternatives; the vendor fires if ANY one of
    them is satisfied (OR across alternatives). Each alternative is either a
    single signal spec, or a list of specs that must ALL match (AND within
    a list):

        {"requires": [
            # alternative 1: CloudFront+WAF shape — both must match
            [{"kind": "header", "name": "_status", "re": r"403"},
             {"kind": "header", "name": "x-cache", "re": r"error from cloudfront"}],
            # alternative 2: ALB/API-GW shape — x-amz-id presence is enough
            {"kind": "header", "name": "x-amz-id"},
        ]}

    Supported kinds: header, cookie, cert, cname, ptr, netblock.
    """
    reqs = rules.get("requires")
    if not reqs:
        return True

    def _spec_ok(spec: dict) -> bool:
        kind = spec["kind"]
        if kind == "header":
            val = headers.get(spec["name"])
            if val is None:
                return False
            return not spec.get("re") or bool(re.search(spec["re"], val, re.I))
        if kind == "cookie":
            return any(re.search(spec["re"], c) for c in set_cookies)
        if kind == "cert":
            return bool(re.search(spec["re"], cert_text))
        if kind == "cname":
            return bool(re.search(spec["re"], cnames))
        if kind == "ptr":
            return bool(re.search(spec["re"], ptrs))
        if kind == "netblock":
            nets = [ipaddress.ip_network(n) for n in spec["nets"]]
            return any(ipaddress.ip_address(ip) in nets for ip in ips)
        return False

    for alt in reqs:
        if isinstance(alt, list):
            if all(_spec_ok(s) for s in alt):
                return True
        else:
            if _spec_ok(alt):
                return True
    return False


def parse_http_response(data: bytes) -> dict:
    """Parse a raw HTTP/1.x response (head + body bytes) into a dict.

    Pure function — no I/O — so it is directly unit-testable. Returns:
    {status, headers, set-cookie-list, head_text, body_text, title}
    """
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1", "replace").split("\r\n")
    status = lines[0] if lines else ""
    headers: dict[str, str] = {}
    set_cookie_list: list[str] = []
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            k, v = k.strip().lower(), v.strip()
            if k == "set-cookie":
                set_cookie_list.append(v)
            else:
                headers[k] = v
    head_text = head.decode("latin-1", "replace").lower()
    body_lower = body[:65536].decode("latin-1", "replace").lower()
    # extract the title from the ORIGINAL body (case preserved, for display)
    title = ""
    m = re.search(r"<title[^>]*>(.*?)</title>", body[:65536].decode("latin-1", "replace"),
                  re.I | re.S)
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()
    return {
        "status": status,
        "headers": headers,
        "set-cookie-list": set_cookie_list,
        "head_text": head_text,
        "body_text": body_lower,
        "title": title,
    }


# CAs that belong to a TLS-INSPECTION middlebox rather than to a public trust
# program. Seeing one means something BETWEEN w4f and the target re-signed the
# connection, so the certificate, the SPKI pin and any block page describe that
# box — not the target's edge. This matters most for the pin: w4f's headline
# output is "the value an app's custom pinner compares against", and a re-signed
# chain silently yields the middlebox's pin instead.
_INSPECTION_CA_ISSUERS = (
    "fortinet", "zscaler", "blue coat", "bluecoat", "proxysg", "palo alto",
    "netskope", "forcepoint", "sophos", "mcafee web gateway", "skyhigh",
    "cisco umbrella", "opendns", "kaspersky", "bitdefender", "mitmproxy",
)


def detect_interception(cert: dict, block: dict | None = None) -> dict | None:
    """Flag a connection re-signed by a TLS-inspection middlebox.

    Returns {by, evidence} or None. This never changes the vendor verdict —
    attributing the middlebox to the target would fingerprint the scanner's
    own network on every host it scans, which is the opposite of useful.
    """
    issuer = f"{cert.get('issuer_org') or ''} {cert.get('issuer') or ''}".lower()
    for ca in _INSPECTION_CA_ISSUERS:
        if ca in issuer:
            return {"by": ca,
                    "evidence": f"cert issuer: {cert.get('issuer_org') or cert.get('issuer')}"}
    if block and block.get("interception"):
        return {"by": block.get("vendor", ""),
                "evidence": f"block page: {block.get('title', '')}"}
    return None


def match_block_page(title: str, head_text: str, body_text: str, status: str) -> dict | None:
    """Match a WAF block page by its <title> / body markers.

    Pure function so the signature table is unit-testable without sockets.
    Returns {vendor, title, status} or None when nothing matches.
    """
    t = title.lower()
    for name, rule in _block_rules():
        if "title" in rule and not re.search(rule["title"], t):
            continue
        if any(m not in body_text for m in rule.get("body", ())):
            continue
        if "body_any" in rule and not any(m in body_text for m in rule["body_any"]):
            continue
        if any(m not in head_text for m in rule.get("head", ())):
            continue
        out = {"vendor": rule.get("vendor", name), "title": title, "status": status}
        if rule.get("interception"):
            out["interception"] = True
        if rule.get("deployment"):
            out["deployment"] = rule["deployment"]
        return out
    return None


def _block_rules() -> list[tuple[str, dict]]:
    """(vendor, rule) pairs ordered by priority, built once from the table.

    Order is load-bearing: specific rules must beat generic ones (an Imperva
    SecureSphere page also contains an incident id; a CloudFront error is
    only an AWS WAF block when it says "Request blocked."). Vendors declare
    `priority` explicitly rather than relying on file discovery order.
    """
    global _BLOCK_RULE_CACHE
    if _BLOCK_RULE_CACHE is None:
        from w4f.vendors import VENDORS
        pairs: list[tuple[str, dict]] = []
        for name, rules in VENDORS.items():
            blk = rules.get("block")
            if not blk:
                continue
            for rule in (blk if isinstance(blk, list) else [blk]):
                pairs.append((name, rule))
        pairs.sort(key=lambda nr: (nr[1].get("priority", 100), nr[0]))
        _BLOCK_RULE_CACHE = pairs
    return _BLOCK_RULE_CACHE


_BLOCK_RULE_CACHE: list[tuple[str, dict]] | None = None


def verify_block(host: str, port: int, timeout: float) -> dict | None:
    """OPT-IN active probe: send one benign attack-shaped query and check
    for a WAF block page.

    Passive fingerprinting cannot see WAFs that only reveal themselves when
    they block something (FortiWeb, F5 ASM…). This sends a single harmless
    query-string `<script>` marker (no exploit — nothing executes, the WAF
    just decides whether to answer with a block page) and matches the
    response against known block-page signatures. Off by default; enable
    with --verify.

    Returns a dict {vendor, title, status} or None when nothing matches.
    """
    req = (
        f"GET /?q=%3Cscript%3Everify%28%29%3B%3C%2Fscript%3E&z=1%27%20OR%20%271%27%3D%271 HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {UA}\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n"
    )
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        ctx = _unverified_ctx()
        ctx.set_alpn_protocols(["http/1.1"])
        with ctx.wrap_socket(sock, server_hostname=host) as ts:
            sock = None  # ownership moved to ts
            ts.settimeout(timeout)
            ts.sendall(req.encode())
            data = b""
            # Read until close / timeout — WAF block pages put <title> at
            # arbitrary offsets (FortiWeb's is near the END of a 39KB page),
            # so a header-stop read misses it.
            while len(data) < 65536:
                try:
                    chunk = ts.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
    except Exception:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
        return None

    parsed = parse_http_response(data)
    return match_block_page(
        parsed["title"], parsed["head_text"], parsed["body_text"], parsed["status"]
    )


def ws_probe(host: str, port: int, path: str, timeout: float) -> dict:
    """WebSocket upgrade probe: ask the server to switch protocols.

    A WAF/CDN often treats the Upgrade request differently from a plain
    GET — it may block the upgrade (challenge page), proxy it through, or
    answer 101 from a different component than the one serving the GET.
    Reports the status line and the upgrade-relevant headers so consumers
    can see which identity answered the upgrade.
    """
    path = path or "/"
    key = "dGhlIHNhbXBsZSBub25jZQ=="  # RFC 6455 example key
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {UA}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    out: dict = {"upgrade_supported": False, "error": None}
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        ctx = _unverified_ctx()
        ctx.set_alpn_protocols(["http/1.1"])
        with ctx.wrap_socket(sock, server_hostname=host) as ts:
            sock = None
            ts.settimeout(timeout)
            ts.sendall(req.encode())
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 65536:
                chunk = ts.recv(4096)
                if not chunk:
                    break
                data += chunk
        parsed = parse_http_response(data)
        out["status"] = parsed["status"]
        out["headers"] = parsed["headers"]
        out["upgrade_supported"] = parsed["status"].startswith("HTTP/1.1 101")
        if out["upgrade_supported"]:
            out["sec_websocket_accept"] = parsed["headers"].get("sec-websocket-accept")
    except Exception as e:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
        out["error"] = f"ws probe failed: {e}"
    return out


def grpc_probe(host: str, port: int, timeout: float) -> dict:
    """gRPC health-check probe (best-effort, HTTP/1.1 framing).

    Real gRPC is HTTP/2, which this tool deliberately avoids (h2 frames
    would read as garbage on the http/1.1 GET path). Many gRPC gateways
    (Envoy, AWS App Runner, grpc-gateway) still answer an HTTP/1.1 request
    with a grpc-status header — if the endpoint is gRPC-only it usually
    rejects the plain-text framing with 400/426 and a grpc-message, which
    is itself a detection signal. The probe reports whatever came back.
    """
    # grpc.health.v1.Health/Check with an empty request = one 5-byte frame
    # (compression flag 0 + 4-byte length 0) inside an HTTP/1.1 POST.
    body = b"\x00\x00\x00\x00\x00"
    req = (
        f"POST /grpc.health.v1.Health/Check HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {UA}\r\n"
        "Content-Type: application/grpc\r\n"
        "TE: trailers\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n"
    )
    out: dict = {"grpc_supported": False, "error": None}
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        ctx = _unverified_ctx()
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        with ctx.wrap_socket(sock, server_hostname=host) as ts:
            sock = None
            ts.settimeout(timeout)
            ts.sendall(req.encode() + body)
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 65536:
                chunk = ts.recv(4096)
                if not chunk:
                    break
                data += chunk
        parsed = parse_http_response(data)
        out["status"] = parsed["status"]
        out["headers"] = parsed["headers"]
        grpc_status = parsed["headers"].get("grpc-status")
        if grpc_status is not None:
            out["grpc_supported"] = True
            out["grpc_status"] = grpc_status
            out["grpc_message"] = parsed["headers"].get("grpc-message")
        elif parsed["status"].startswith("HTTP/2 ") or (
                data and not parsed["status"].startswith("HTTP/")):
            # the server negotiated h2 and answered with binary HTTP/2
            # frames (not a text HTTP/1.x response) — that IS a gRPC-capable
            # signal; the ALPN observation flags the framing view
            out["grpc_supported"] = True
            out["note"] = "server answered over HTTP/2 (binary framing)"
    except Exception as e:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
        out["error"] = f"grpc probe failed: {e}"
    return out


def probe_one(hostport: str, path: str, timeout: float, do_http: bool,
              verify: bool = False, ws_path: str | None = None,
              grpc: bool = False) -> dict:
    host, _, port_s = hostport.rpartition(":")
    if not host:
        host = hostport
        port = 443
    else:
        try:
            port = int(port_s)
        except ValueError:
            host = hostport
            port = 443
    result: dict = {
        "host": host,
        "hostport": f"{host}:{port}",
        "port": port,
        "resolved": None,
        "tls": None,
        "verdict": [],
        "error": None,
    }
    try:
        resolved = resolve(host)
        result["resolved"] = resolved
        # fingerprint() reads these from the TOP level — mirror them up.
        result["cname"] = resolved.get("cname", [])
        result["ptr"] = resolved.get("ptr", [])
        result["ips"] = resolved.get("ips", [])
        if not resolved["ips"]:
            result["error"] = "DNS did not resolve"
            result["error_class"] = resolved.get("dns_error") or "dns-error"
            result["dns_error_detail"] = resolved.get("dns_error_detail")
            return result
        tls = tls_probe(host, port, path, timeout, do_http)
        result["tls"] = tls
        # HTTP-level failures (timeout, redirect loop, protocol errors)
        # surface as `status: ERROR: ...` inside the http layer. Promote
        # them to the per-host error contract so a failed GET is as visible
        # as a failed handshake. mTLS is exempt: there the alert IS the
        # finding (`mtls`), not an error.
        _http_status = (tls.get("http") or {}).get("status", "")
        if _http_status.startswith("ERROR") and "certificate required" not in _http_status.lower():
            result["error"] = _http_status
            result["error_class"] = classify_error(_http_status)
        # A handshake that never ESTABLISHED (no tls_version) means the host
        # was never actually probed — connect refused, timed out, network
        # unreachable. Without this the host came back error=None with an
        # empty verdict, i.e. indistinguishable from a scanned host whose
        # edge matched no signature: a sweep read 13 unreachable hosts as
        # "unknown edge" (signature gaps) and still exited 0, contradicting
        # the documented exit-code contract ("connect refused" = exit 1).
        # Deliberately NOT an early return: DNS-level signals (CNAME, PTR,
        # netblock) were already collected and still fingerprint fine, so a
        # host can legitimately report BOTH an error and a DNS-based verdict.
        # mTLS is unaffected — there the handshake completes (tls_version is
        # set) and the certificate-required alert lands on the GET instead.
        if tls.get("tls_error") and not tls.get("tls_version"):
            result["error"] = tls["tls_error"]
            result["error_class"] = classify_error(tls["tls_error"])
        # ALPN observation: the TLS handshake advertises h2+http/1.1 but the
        # GET is sent over a separate http/1.1-only connection (h2 frames
        # would read as garbage). Report the negotiated ALPN distinctly and
        # flag when the edge chose h2 — its HTTP/2 behavior (headers,
        # challenge pages) is NOT what the fingerprint saw, so consumers know
        # the header view is the http/1.1 view.
        negotiated = tls.get("alpn")
        result["alpn_negotiated"] = negotiated
        if do_http and negotiated == "h2":
            result["http2_negotiated"] = True
            result["note"] = ("edge negotiated HTTP/2 but the GET used "
                              "HTTP/1.1 — header view may differ under h2")
        # fold cert-level fields up for convenience (and for fingerprint())
        cert = tls.get("cert")
        if cert:
            result["cert"] = cert
            for k in ("issuer_org", "subject_org", "sha256", "spki_sha256", "san"):
                if k in cert:
                    result[k] = cert[k]
            result["chain_verified"] = tls.get("chain_verified")
        result["mtls"] = tls.get("mtls", False)
        result["verdict"] = fingerprint(result)
        # The edge may have answered the NORMAL request with its own block
        # page (403 + a WAF page, e.g. reputation/geo blocking of the client
        # rather than of the request shape). That page names the vendor, so
        # match it here instead of requiring --verify. The passive/active
        # split is preserved via `source` — a consumer must still be able to
        # tell a page we were handed from one an active probe provoked.
        http_layer = tls.get("http") or {}
        # transient: matching material must not reach --json (a 64KB body per
        # host would bloat the tree and put page content in the output)
        title = http_layer.pop("title", "")
        head_text = http_layer.pop("head_text", "")
        body_text = http_layer.pop("body_text", "")
        # ONLY on a refusal status. match_block_page() was written for the
        # --verify response, where a block is already presumed, so several of
        # its rules are not status-safe on their own: the Imperva rule keys on
        # the `incap_ses` cookie, which Imperva sets on EVERY response, so
        # calling it on a 200 reported healthy Imperva-fronted hosts as
        # serving a block page. The gate matches the body-read gate above, so
        # the matcher only ever sees a response that actually refused us.
        if status_is_blocking(http_layer.get("status", "")):
            passive_blk = match_block_page(title, head_text, body_text,
                                           http_layer.get("status", ""))
            if passive_blk:
                passive_blk["confidence"] = 95
                passive_blk["source"] = "passive"
                # An interception page is NOT the target's WAF — keep it out
                # of `block` so --csv/--sarif never report it as a finding
                # about the host.
                if not passive_blk.get("interception"):
                    result["block"] = passive_blk
                else:
                    result["_intercept_page"] = passive_blk
        intercept = detect_interception(cert or {}, result.pop("_intercept_page", None))
        if intercept:
            result["interception"] = intercept
        if verify:
            blk = verify_block(host, port, timeout)
            if blk:
                # A block page is the edge's OWN WAF page — the strongest
                # possible signal, so it carries high confidence (it comes
                # from verify_block/match_block_page, not fingerprint()).
                blk["confidence"] = 95
                blk["source"] = "verify"   # provoked, not handed to us
                # Same rule as the passive path: a page from a box on OUR
                # path is not a finding about the host. Provoking it with
                # --verify does not make it the target's WAF — an egress
                # filter answers the attack-shaped query too.
                if blk.get("interception"):
                    result["interception"] = detect_interception(cert or {}, blk)
                else:
                    result["block"] = blk
        if ws_path:
            result["ws"] = ws_probe(host, port, ws_path, timeout)
        if grpc:
            result["grpc"] = grpc_probe(host, port, timeout)
    except Exception as e:
        result["error"] = f"probe failed: {e}"
        result["error_class"] = classify_error(str(e))
    # Interpretation layer, last: what the collected evidence adds up to
    # (state, primary candidate, alternatives). Additive — `verdict` keeps
    # its exact shape, so existing --json/--csv/--sarif consumers are
    # unaffected. Runs even on the failure path so an errored host still
    # reports whatever independent evidence survived.
    result["attribution"] = attribute(result)
    return result
