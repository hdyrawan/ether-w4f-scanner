"""Probing: DNS, TLS handshake with SNI, one HTTP/1.1 GET. Never raises."""

from __future__ import annotations

import ipaddress
import re
import socket
import ssl
from datetime import datetime, timezone

try:
    import dns.resolver
    import dns.reversename
    HAVE_DNS = True
except ImportError:
    HAVE_DNS = False

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
        return out
    except ValueError:
        pass
    if HAVE_DNS:
        try:
            for r in dns.resolver.resolve(host, "CNAME"):
                c = str(r.target).rstrip(".")
                if c.lower() != host.lower():
                    out["cname"].append(c)
        except Exception:
            pass
        for qtype in ("A", "AAAA"):
            try:
                for r in dns.resolver.resolve(host, qtype):
                    out["ips"].append(str(r))
            except Exception:
                pass
        for ip in out["ips"]:
            try:
                rev = dns.reversename.from_address(ip)
                for r in dns.resolver.resolve(rev, "PTR"):
                    out["ptr"].append(str(r.target).rstrip("."))
            except Exception:
                pass
    else:
        try:
            infos = socket.getaddrinfo(host, None)
            for info in infos:
                ip = info[4][0]
                if ip not in out["ips"]:
                    out["ips"].append(ip)
        except Exception:
            pass
    if not out["cname"]:
        try:
            # getaddrinfo returns (family, type, proto, canonname, sockaddr);
            # only the canonical name is a string. info[0] is the AF enum.
            for info in socket.getaddrinfo(host, None):
                canon = info[3]
                if canon and canon not in out["cname"]:
                    out["cname"].append(canon)
        except Exception:
            pass
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

    nb = cert.not_valid_before_utc
    na = cert.not_valid_after_utc
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


def tls_probe(host: str, port: int, path: str, timeout: float, do_http: bool) -> dict:
    """One SNI TLS handshake + optional GET (http/1.1 ALPN). Never raises."""
    out: dict = {"port": port, "mtls": False, "http": None, "tls_error": None}
    ctx = ssl.create_default_context()
    verified = False
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except Exception as e:
        out["tls_error"] = f"connect failed: {e}"
        return out
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        try:
            with ctx.wrap_socket(sock, server_hostname=host) as ts:
                verified = True
                _collect_tls(ts, out)
                out["chain_verified"] = True
            # GET over a SEPARATE http/1.1-only connection: if the first
            # handshake negotiated h2, an HTTP/1.1 request on that socket gets
            # a binary HTTP/2 frame back, which reads as garbage.
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
            # fall through: retry unvalidated to still grab the cert
            try:
                sock = socket.create_connection((host, port), timeout=timeout)
                ctx2 = ssl._create_unverified_context()
                ctx2.set_alpn_protocols(["h2", "http/1.1"])
                with ctx2.wrap_socket(sock, server_hostname=host) as ts:
                    _collect_tls(ts, out)
                    out["chain_verified"] = False
                    if do_http:
                        http = http_get(host, port, path, timeout)
                        out["http"] = http
                        if "certificate required" in http.get("status", "").lower():
                            out["mtls"] = True
            except Exception as e2:
                if not out.get("tls_error"):
                    out["tls_error"] = f"tls failed: {e2}"
    except Exception as e:
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


def http_get(host: str, port: int, path: str, timeout: float) -> dict:
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {UA}\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n"
    )

    def _once(verify: bool) -> dict:
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            ctx = ssl.create_default_context() if verify else ssl._create_unverified_context()
            ctx.set_alpn_protocols(["http/1.1"])
            with ctx.wrap_socket(sock, server_hostname=host) as ts:
                ts.settimeout(timeout)
                ts.sendall(req.encode())
                data = b""
                while b"\r\n\r\n" not in data and len(data) < 65536:
                    chunk = ts.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            head, _, _ = data.partition(b"\r\n\r\n")
            lines = head.decode("latin-1", "replace").split("\r\n")
            status = lines[0] if lines else ""
            headers = {}
            set_cookie_list = []
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    k, v = k.strip().lower(), v.strip()
                    if k == "set-cookie":
                        set_cookie_list.append(v)
                    else:
                        headers[k] = v
            return {"status": status, "headers": headers, "set-cookie-list": set_cookie_list}
        except Exception as e:
            return {"status": f"ERROR: {e}", "headers": {}, "set-cookie-list": []}

    result = _once(verify=True)
    if result["status"].startswith("ERROR") and "certificate" in result["status"].lower():
        # Chain not trusted from this client — headers are still fingerprint
        # evidence (server header, cookies), so retry without validation.
        result = _once(verify=False)
    return result


def fingerprint(result: dict) -> list[dict]:
    """Ranked vendor matches with the signals that matched.

    The HTTP layer lives under result['tls']['http'] (probe_one stores the
    whole tls dict), NOT at the top level — reading result.get('http') was a
    bug that silently disabled ALL header/cookie matching (F5, cookie-based
    vendors, etc.). Also accept the mirrored top-level form for compat.
    """
    from w4f.vendors import VENDORS, vendor_nets

    http_layer = (result.get("tls") or {}).get("http") or result.get("http") or {}
    headers = http_layer.get("headers") or {}
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
        for hname, hre in rules.get("headers", {}).items():
            val = headers.get(hname)
            if val is None:
                continue
            if hre is None or re.search(hre, val, re.I):
                evidence.append(f"header {hname}: {val[:60]}")
        for cre in rules.get("cookies", []):
            for cval in set_cookies:
                if re.search(cre, cval):
                    evidence.append(f"cookie: {cval[:60]}")
        cre = rules.get("cert")
        if cre and re.search(cre, cert_text):
            evidence.append(f"cert: {cert.get('issuer_org') or cert.get('issuer')}")
        cname_re = rules.get("cname")
        if cname_re and re.search(cname_re, cnames):
            evidence.append(f"cname: {result['cname'][0]}")
        ptr_re = rules.get("ptr")
        if ptr_re and re.search(ptr_re, ptrs):
            evidence.append(f"ptr: {result['ptr'][0]}")
        for net in vendor_nets(name):
            for ip in ips:
                try:
                    if ipaddress.ip_address(ip) in net:
                        evidence.append(f"netblock: {ip} in {net}")
                        break
                except ValueError:
                    pass
        if evidence:
            matches.append({"vendor": name, "signals": len(evidence), "evidence": evidence})

    matches.sort(key=lambda m: -m["signals"])
    return matches


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
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        ctx = ssl._create_unverified_context()
        ctx.set_alpn_protocols(["http/1.1"])
        with ctx.wrap_socket(sock, server_hostname=host) as ts:
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
        head, _, body = data.partition(b"\r\n\r\n")
        lines = head.decode("latin-1", "replace").split("\r\n")
        status = lines[0] if lines else ""
        head_txt = head.decode("latin-1", "replace").lower()
        body_text = body[:65536].decode("latin-1", "replace").lower()
        title = ""
        m = re.search(r"<title[^>]*>(.*?)</title>", body_text, re.I | re.S)
        if m:
            title = re.sub(r"\s+", " ", m.group(1)).strip()
    except Exception:
        return None

    # Block-page signatures — title fragments are the strongest, most
    # stable marker (FortiWeb / F5 ASM use the same titles across builds).
    # FortiWeb localizes its title ("The URL Request Tidak Tersedia" on the
    # Indonesian fleet), so match both the English and ID fragments.
    if ("the url you requested has been blocked" in title
            or ("tidak tersedia" in title and "url" in title)):
        return {"vendor": "fortiweb", "title": title, "status": status}
    if title.lower().startswith("request rejected") and "f5" in head_txt:
        return {"vendor": "f5-asm", "title": title, "status": status}
    if title.lower().startswith("request rejected"):
        return {"vendor": "f5-asm", "title": title, "status": status}
    if "attention required" in title and "cloudflare" in body_text:
        return {"vendor": "cloudflare", "title": title, "status": status}
    if "incapsula" in body_text or "incap_ses" in head_txt:
        return {"vendor": "imperva", "title": title, "status": status}
    return None


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
