"""Output formatting: per-host console blocks and a doc-ready markdown sweep.

Console output is deliberately plain: aligned `label   value` lines, no
markdown bold/bullets, color only for the verdict. The markdown sweep
(--md) is separate and keeps full markdown for embedding in docs.
"""

from __future__ import annotations

import re

from w4f.vendors import INTERESTING_HEADERS

# ANSI
_CYAN = "\033[36m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_RED = "\033[31m"
_DIM = "\033[2m"
_RESET = "\033[0m"

_LABEL = 10  # column width for the left-hand label


def _row(label: str, value: str) -> str:
    return f"{label:<{_LABEL}}{value}"


def fmt_verdict(verdict: list[dict]) -> str:
    if not verdict:
        return "unknown-edge (no signature matched)"
    return ", ".join(
        f"{m['vendor']}({m['signals']}, {m.get('confidence', 0)}%)" for m in verdict
    )


def _verdict_line(ver: list[dict]) -> str:
    """Color the vendor names; plain text otherwise."""
    if not ver:
        return f"{_row('verdict', _DIM + 'no signature matched (unknown edge)' + _RESET)}"
    parts = []
    for m in ver:
        ev = "; ".join(m["evidence"])
        parts.append(f"{_GREEN}{m['vendor']}{_RESET} {_DIM}({m['signals']}, {m.get('confidence', 0)}%){_RESET}: {ev}")
    return _row("verdict", "  |  ".join(parts))


def fmt_block(r: dict) -> str:
    if r.get("error"):
        return f"{r['hostport']}\n{_row('error', _RED + r['error'] + _RESET)}"

    res = r.get("resolved") or {}
    tls = r.get("tls") or {}
    cert = tls.get("cert") or {}
    ver = r.get("verdict") or []

    lines = [
        _CYAN + r["hostport"] + _RESET,
        _row("ip", ", ".join(res.get("ips", ["-"]))),
    ]
    if res.get("ptr"):
        lines.append(_row("ptr", ", ".join(res["ptr"][:3])))
    if res.get("cname"):
        lines.append(_row("cname", ", ".join(res["cname"][:5])))
    lines.append(
        _row(
            "tls",
            f"{tls.get('tls_version') or '-'}  {tls.get('cipher') or '-'}"
            f"  ALPN {tls.get('alpn') or '-'}",
        )
    )
    if r.get("http2_negotiated"):
        lines.append(_row("  http2", _YELLOW + "negotiated h2; GET used HTTP/1.1 (header view is the 1.1 view)" + _RESET))
    if tls.get("mtls"):
        lines.append(_row("mtls", _RED + "server wants a CLIENT certificate" + _RESET))
    if cert.get("subject"):
        subj = cert.get("subject") or ""
        lines.append(_row("cert", f"{cert.get('issuer_org') or cert.get('issuer')}"))
        lines.append(_row("  san", cert.get("san") or "-"))
    if cert.get("days_remaining") is not None:
        lines.append(
            _row(
                "  valid",
                f"{cert.get('not_before','')[:10]} -> {cert.get('not_after','')[:10]}"
                f"  ({cert.get('days_remaining')}d left)",
            )
        )
    if cert.get("spki_sha256"):
        lines.append(_row("  spki", cert.get("spki_sha256")))
    if cert.get("key_type"):
        lines.append(
            _row("  key", f"{cert.get('key_type')} {cert.get('key_size','')}  {cert.get('signature')}")
        )

    http = tls.get("http")
    if http:
        status = http.get("status", "-")
        # truncate long error tails like "( _ssl.c:2578)" — the useful part is
        # the alert name, not the C source location.
        if status.startswith("ERROR:"):
            status = re.sub(r"\s*\(_ssl\.c:\d+\)$", "", status)
        lines.append(_row("http", status[:90]))
        interesting = []
        for h, v in (http.get("headers") or {}).items():
            if any(re.match(hp, h) for hp in INTERESTING_HEADERS):
                interesting.append(f"{h}={v[:70]}")
        if interesting:
            # one header per line so long cookies/server strings don't wrap ugly
            for hdr in interesting[:8]:
                lines.append(_row("  hdr", hdr))

    lines.append(_verdict_line(ver))

    blk = r.get("block")
    if blk:
        lines.append(
            _row("block", _YELLOW + f"{blk['vendor']} — {blk['title']}"
                 f" ({blk.get('status','')})" + _RESET)
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Markdown sweep (--md) — for docs, keeps markdown on purpose.
# ---------------------------------------------------------------------------


def _fmt_md_block(r: dict) -> str:
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
        lines.append("- **MTLS**: server wants a **CLIENT certificate**")
    if cert.get("subject"):
        lines.append(f"- **Cert subject**: {cert.get('subject')}")
    if cert.get("issuer"):
        lines.append(f"- **Cert issuer**: {cert.get('issuer')}")
    if cert.get("san"):
        lines.append(f"- **SAN**: {cert.get('san')}")
    if cert.get("days_remaining") is not None:
        lines.append(f"- **Valid**: {cert.get('not_before','')[:10]} → {cert.get('not_after','')[:10]} "
                     f"({cert.get('days_remaining')}d left)")
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
    blk = r.get("block")
    if blk:
        lines.append(f"- **Block probe** (--verify): **{blk['vendor']}** — "
                     f"{blk['title']} ({blk.get('status','')})")
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
        "\n\n".join(_fmt_md_block(r) for r in results) + "\n"
    )
