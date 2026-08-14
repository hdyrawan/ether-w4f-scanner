"""Probing: DNS, TLS handshake with SNI, one HTTP/1.1 GET. Never raises."""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
import ssl
from datetime import datetime, timezone

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


def resolve(host: str) -> dict:
    """A+AAAA with PTR, and the CNAME chain. Never raises."""
    out = {"cname": [], "ips": [], "ptr": []}
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
        for qtype in ("A", "AAAA"):
            try:
                for r in _DNS.resolver.resolve(host, qtype):
                    out["ips"].append(str(r))
            except Exception as e:
                log.debug("%s lookup failed for %s: %s", qtype, host, e)
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
                    out["ips"].append(ip)
        except Exception as e:
            log.debug("getaddrinfo failed for %s: %s", host, e)
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
            parsed = parse_http_response(data)
            return {"status": parsed["status"], "headers": parsed["headers"],
                    "set-cookie-list": parsed["set-cookie-list"]}
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
                        cats.add("headers")
            else:
                val = headers.get(hname)
                if val is None:
                    continue
                if hre is None or re.search(hre, val, re.I):
                    evidence.append(f"header {hname}: {val[:60]}")
                    cats.add("headers")
        for cre in rules.get("cookies", []):
            for cval in set_cookies:
                if re.search(cre, cval):
                    evidence.append(f"cookie: {cval[:60]}")
                    cats.add("cookies")
        cre = rules.get("cert")
        if cre and re.search(cre, cert_text):
            evidence.append(f"cert: {cert.get('issuer_org') or cert.get('issuer')}")
            cats.add("cert")
        cname_re = rules.get("cname")
        if cname_re and re.search(cname_re, cnames):
            first = (result.get("cname") or [""])[0]
            evidence.append(f"cname: {first}")
            cats.add("cname")
        ptr_re = rules.get("ptr")
        if ptr_re and re.search(ptr_re, ptrs):
            first = (result.get("ptr") or [""])[0]
            evidence.append(f"ptr: {first}")
            cats.add("ptr")
        for net in vendor_nets(name):
            for ip in ips:
                try:
                    if ipaddress.ip_address(ip) in net:
                        evidence.append(f"netblock: {ip} in {net}")
                        cats.add("netblock")
                        break
                except ValueError:
                    pass
        if evidence and _required_signals_ok(rules, headers, set_cookies,
                                             cert_text, cnames, ptrs, ips):
            weights = {**CONF_WEIGHTS, **(rules.get("weights") or {})}
            conf = sum(weights.get(c, 0) for c in cats)
            matches.append({"vendor": name, "signals": len(evidence),
                            "confidence": min(conf, 100), "evidence": evidence})

    matches.sort(key=lambda m: -m["signals"])
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


def match_block_page(title: str, head_text: str, body_text: str, status: str) -> dict | None:
    """Match a WAF block page by its <title> / body markers.

    Pure function so the signature table is unit-testable without sockets.
    Returns {vendor, title, status} or None when nothing matches.
    """
    t = title.lower()
    # FortiWeb localizes its title ("The URL Request Tidak Tersedia" on the
    # Indonesian fleet), so match both the English and ID fragments.
    if "the url you requested has been blocked" in t \
            or ("tidak tersedia" in t and "url" in t):
        return {"vendor": "fortiweb", "title": title, "status": status}
    if t.startswith("request rejected") and "f5" in head_text:
        return {"vendor": "f5-asm", "title": title, "status": status}
    if t.startswith("request rejected"):
        return {"vendor": "f5-asm", "title": title, "status": status}
    if "attention required" in t and "cloudflare" in body_text:
        return {"vendor": "cloudflare", "title": title, "status": status}
    # Akamai Kona WAF / Bot Manager block page.
    if "access denied" in t and "akamai" in body_text:
        return {"vendor": "akamai", "title": title, "status": status}
    # Sucuri firewall block page.
    if "sucuri firewall" in body_text:
        return {"vendor": "sucuri", "title": title, "status": status}
    # Wordfence WAF block page.
    if "wordfence" in body_text:
        return {"vendor": "wordfence", "title": title, "status": status}
    # Wallarm block page (nginx + Wallarm WAF).
    if "wallarm" in body_text and "blocked" in body_text:
        return {"vendor": "wallarm", "title": title, "status": status}
    if "incapsula" in body_text or "incap_ses" in head_text:
        return {"vendor": "imperva", "title": title, "status": status}
    # AWS WAF fronted by CloudFront: a 403 with CloudFront's generic error
    # title. Distinguish a WAF BLOCK from an ordinary CloudFront 4xx by the
    # "Request blocked." reason line (other CloudFront errors say
    # "Bad request.", "The distribution ...", etc.) — the title alone would
    # mislabel every CloudFront error as a WAF.
    if "the request could not be satisfied" in t and "request blocked" in body_text:
        return {"vendor": "aws-waf", "title": title, "status": status}
    return None


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
        ctx = ssl._create_unverified_context()
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


def probe_one(hostport: str, path: str, timeout: float, do_http: bool,
              verify: bool = False) -> dict:
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
            return result
        tls = tls_probe(host, port, path, timeout, do_http)
        result["tls"] = tls
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
        if verify:
            blk = verify_block(host, port, timeout)
            if blk:
                result["block"] = blk
    except Exception as e:
        result["error"] = f"probe failed: {e}"
    return result
