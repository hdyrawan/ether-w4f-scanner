"""Output formatting: per-host console blocks and a doc-ready markdown sweep."""

from __future__ import annotations

import re

from w4f.vendors import INTERESTING_HEADERS


def fmt_verdict(verdict: list[dict]) -> str:
    if not verdict:
        return "unknown-edge (no signature matched)"
    return ", ".join(f"{m['vendor']}({m['signals']})" for m in verdict)


def fmt_block(r: dict) -> str:
    lines = [f"### {r['hostport']}"]
    if r.get("error"):
        lines.append(f"- **ERROR**: {r['error']}")
        return "\n".join(lines)
    res = r.get("resolved") or {}
    tls = r.get("tls") or {}
    cert = tls.get("cert") or {}
    ver = r.get("verdict") or []

    lines.append(f"- **IPs**: {', '.join(res.get('ips', ['-']))}")
    if res.get("ptr"):
        lines.append(f"- **PTR**: {', '.join(res['ptr'][:3])}")
    if res.get("cname"):
        lines.append(f"- **CNAME**: {', '.join(res['cname'][:5])}")
    lines.append(f"- **TLS**: {tls.get('tls_version') or '-'}  ·  {tls.get('cipher') or '-'}"
                 f"  ·  ALPN {tls.get('alpn') or '-'}")
    if tls.get("mtls"):
        lines.append("- **MTLS**: **server wants a CLIENT certificate**")
    lines.append(f"- **Chain verified** from this client: {r.get('chain_verified')}")
    if cert.get("subject"):
        lines.append(f"- **Cert subject**: {cert.get('subject')}")
    if cert.get("issuer"):
        lines.append(f"- **Cert issuer**: {cert.get('issuer')}")
    if cert.get("san"):
        lines.append(f"- **SAN**: {cert.get('san')}")
    if cert.get("days_remaining") is not None:
        lines.append(f"- **Valid**: {cert.get('not_before','')[:10]} → {cert.get('not_after','')[:10]} "
                     f"({cert.get('days_remaining')}d left)")
    lines.append(f"- **Cert SHA-256**: {cert.get('sha256','-')}")
    if cert.get("spki_sha256"):
        lines.append(f"- **SPKI SHA-256** (pin value): {cert.get('spki_sha256')}")
    if cert.get("signature"):
        lines.append(f"- **Key/sig**: {cert.get('key_type')} {cert.get('key_size','')} · {cert.get('signature')}")
    http = tls.get("http")
    if http:
        lines.append(f"- **HTTP**: {http.get('status','-')}")
        interesting = []
        for h, v in (http.get("headers") or {}).items():
            if any(re.match(hp, h) for hp in INTERESTING_HEADERS):
                interesting.append(f"{h}: {v[:80]}")
        if interesting:
            lines.append(f"- **Headers**: {', '.join(interesting)}")
    if ver:
        lines.append("- **Verdict**:")
        for m in ver:
            lines.append(f"  - {m['vendor']} — " + "; ".join(m["evidence"]))
    else:
        lines.append("- **Verdict**: no CDN/WAF signature matched (unknown edge)")
    return "\n".join(lines)


def md_doc(results: list[dict]) -> str:
    rows = []
    for r in results:
        host = r["hostport"]
        ip = ", ".join((r.get("resolved") or {}).get("ips", ["-"])[:2])
        ver = r.get("verdict") or []
        verdict = fmt_verdict(ver)
        issuer = (r.get("tls") or {}).get("cert") and (r["tls"]["cert"].get("issuer_org") or "-") or "-"
        mtls = "**mTLS!**" if r.get("mtls") else ""
        err = r.get("error") or ""
        rows.append(f"| `{host}` | `{ip}` | {issuer} | {verdict} {mtls} | {err} |")
    return (
        "# Endpoint fingerprint sweep\n\n"
        "| Endpoint | Resolved IP | Cert issuer | CDN/WAF verdict | Notes |\n"
        "|---|---|---|---|---|\n" + "\n".join(rows) + "\n\n"
        "## Per-host detail\n\n" +
        "\n\n".join(fmt_block(r) for r in results) + "\n"
    )
