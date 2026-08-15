"""Attribution model: observations -> evidence -> attribution -> state.

The scanner collects **observations** (DNS, TLS, certificate, HTTP, cookies,
redirects). ``fingerprint()`` turns the subset that matches a signature into
**evidence**, keeping the existing category/weight semantics. This module is
the layer above: it reads a finished result dict and says what the evidence
adds up to — which vendor, how strongly, on what basis, which alternatives
were in play, and, crucially, whether a single answer is warranted at all.

Pure functions over the existing result dict — no I/O, no new scanner data
structures, nothing to keep in sync. ``probe_one`` stores the output under
``result["attribution"]``; ``verdict`` is left untouched for compatibility.

The states exist because "no vendor name" has several very different causes,
and collapsing them loses the decision:

``ATTRIBUTED``   one candidate is best-evidenced; the vendor is named.
``AMBIGUOUS``    two or more edge candidates are too close to separate —
                 reported side by side rather than silently picking one.
``UNKNOWN``      the host was scanned and nothing matched. A real finding:
                 the observations are the lead for the next signature.
``INTERCEPTED``  something on the SCANNER's path re-signed the connection,
                 so the observed identity may belong to that box, not the
                 target. Never carries a vendor attribution.
``ERROR``        the host could not be probed at all AND no independent
                 evidence survived. A connect failure that still resolved a
                 vendor CNAME stays ATTRIBUTED with the error alongside —
                 DNS-level evidence is collected before the handshake and
                 does not stop being true because the socket failed.
"""

from __future__ import annotations

STATE_ATTRIBUTED = "ATTRIBUTED"
STATE_AMBIGUOUS = "AMBIGUOUS"
STATE_UNKNOWN = "UNKNOWN"
STATE_INTERCEPTED = "INTERCEPTED"
STATE_ERROR = "ERROR"

HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"

# Bands over the existing 0-100 category-weight sum. HIGH needs more than any
# single category can supply (netblock 30 + cert 25 + cname 20 = 75), so it
# means several independent kinds of evidence agreed. LOW is the range a
# header/cookie-only match lands in — spoofable by the origin.
HIGH_AT = 70
MEDIUM_AT = 30

# Two edge candidates this close, both at MEDIUM or better, are not separable
# by the evidence — saying so beats picking the higher one and sounding sure.
AMBIGUITY_MARGIN = 8
AMBIGUITY_FLOOR = MEDIUM_AT

# Human labels for the signal categories, used by the verbose EVIDENCE block.
CATEGORY_LABELS = {
    "netblock": "Network",
    "cert": "Certificate",
    "cname": "CNAME",
    "ptr": "PTR",
    "headers": "HTTP",
    "cookies": "Cookie",
}


def confidence_band(score: float | None) -> str | None:
    """HIGH / MEDIUM / LOW for a 0-100 score, or None when there is none."""
    if score is None:
        return None
    if score >= HIGH_AT:
        return HIGH
    if score >= MEDIUM_AT:
        return MEDIUM
    return LOW


def role_of(match: dict) -> str:
    """`edge` (sits in front) or `origin` (the stack being fronted).

    Derived from the vendor's own `deployment`, so an origin layer under a
    real edge is never mistaken for a competing claim about the edge. Falls
    back to the signature table when the match itself carries no deployment
    — result trees written before that field existed, and any consumer that
    hand-builds a verdict entry, would otherwise promote every origin to a
    rival edge candidate and make attributions look ambiguous.
    """
    dep = match.get("deployment")
    if dep is None:
        from w4f.vendors import VENDORS
        dep = (VENDORS.get(match.get("vendor", "")) or {}).get("deployment")
    return "origin" if dep == "origin" else "edge"


def _candidate(match: dict) -> dict:
    """Project a verdict entry into the attribution view (no new facts)."""
    score = match.get("confidence", 0)
    out = {
        "vendor": match.get("vendor", ""),
        "score": score,
        "confidence": confidence_band(score),
        "basis": list(match.get("categories") or []),
        "role": role_of(match),
    }
    if match.get("deployment"):
        out["deployment"] = match["deployment"]
    return out


def evidence_for(match: dict) -> list[dict]:
    """Evidence behind one candidate, grouped by category, strongest first.

    Uses the structured items the fingerprint loop records. Result trees
    written before this existed carry only the formatted strings, so those
    degrade to an ungrouped list rather than raising.
    """
    items = match.get("evidence_items")
    if not items:
        return [{"category": "", "label": "", "detail": d}
                for d in (match.get("evidence") or [])]
    order = {c: i for i, c in enumerate(CATEGORY_LABELS)}
    grouped: dict[str, list[str]] = {}
    for item in items:
        grouped.setdefault(item.get("category", ""), []).append(item.get("detail", ""))
    out = []
    for cat in sorted(grouped, key=lambda c: order.get(c, 99)):
        out.append({
            "category": cat,
            "label": CATEGORY_LABELS.get(cat, cat or "?"),
            "detail": " · ".join(d for d in grouped[cat] if d),
        })
    return out


def observations(result: dict) -> list[tuple[str, str]]:
    """(label, value) facts the scan collected, independent of any vendor.

    What UNKNOWN and INTERCEPTED hosts are reported with: the scan found
    something, it just does not name a vendor. Deliberately a view over the
    result dict — the scanner keeps owning the facts.
    """
    tls = result.get("tls") or {}
    cert = tls.get("cert") or result.get("cert") or {}
    http = tls.get("http") or {}
    out: list[tuple[str, str]] = []
    ips = result.get("ips") or []
    if ips:
        out.append(("IP", ", ".join(ips[:3])))
    if result.get("cname"):
        out.append(("CNAME", result["cname"][0]))
    if result.get("ptr"):
        out.append(("PTR", result["ptr"][0]))
    if tls.get("tls_version"):
        alpn = f" {tls['alpn']}" if tls.get("alpn") else ""
        out.append(("TLS", f"{tls['tls_version'].replace('TLSv', '')}{alpn}"))
    issuer = cert.get("issuer_org") or cert.get("issuer")
    if issuer:
        out.append(("Issuer", str(issuer).split(",")[0]))
    if cert.get("spki_sha256"):
        out.append(("SPKI", cert["spki_sha256"][:16] + "…"))
    server = (http.get("headers") or {}).get("server")
    if server:
        out.append(("HTTP", server))
    elif http.get("status"):
        out.append(("HTTP", http["status"]))
    return out


def attribute(result: dict) -> dict:
    """Interpret a finished result: state, primary candidate, alternatives.

    Precedence is deliberate. Interception outranks everything because the
    identity on the wire may not be the target's at all; a surviving verdict
    outranks an error because DNS evidence is collected before the handshake
    and remains valid after it fails.
    """
    verdict = result.get("verdict") or []
    candidates = [_candidate(m) for m in verdict]
    attribution: dict = {
        "state": STATE_UNKNOWN,
        "vendor": None,
        "score": None,
        "confidence": None,
        "basis": [],
        "role": None,
        "alternatives": [],
        "evidence": [],
    }
    if result.get("error"):
        attribution["error"] = result["error"]

    if result.get("interception"):
        # The observed identity may belong to the box on our path. Report the
        # interception and the raw observations; never a vendor attribution.
        attribution["state"] = STATE_INTERCEPTED
        attribution["interception"] = result["interception"]
        attribution["observations"] = observations(result)
        return attribution

    if not candidates:
        attribution["state"] = STATE_ERROR if result.get("error") else STATE_UNKNOWN
        attribution["observations"] = observations(result)
        return attribution

    primary, rest = candidates[0], candidates[1:]
    # Only EDGE candidates compete for the edge. An origin stack underneath a
    # real edge (imperva in front of nginx) is a layer, not a rival claim.
    edges = [c for c in candidates if c["role"] == "edge"]
    tied = [c for c in edges
            if c["score"] >= AMBIGUITY_FLOOR
            and edges[0]["score"] - c["score"] <= AMBIGUITY_MARGIN] if edges else []

    if len(tied) > 1:
        attribution["state"] = STATE_AMBIGUOUS
        attribution["candidates"] = tied
        attribution["alternatives"] = [c for c in candidates if c not in tied]
        # evidence for each tied candidate, so the reader can break the tie
        by_vendor = {m.get("vendor"): m for m in verdict}
        for cand in tied:
            cand["evidence"] = evidence_for(by_vendor.get(cand["vendor"], {}))
        return attribution

    attribution["state"] = STATE_ATTRIBUTED
    attribution["vendor"] = primary["vendor"]
    attribution["score"] = primary["score"]
    attribution["confidence"] = primary["confidence"]
    attribution["basis"] = primary["basis"]
    attribution["role"] = primary["role"]
    if primary.get("deployment"):
        attribution["deployment"] = primary["deployment"]
    attribution["alternatives"] = rest
    attribution["evidence"] = evidence_for(verdict[0])
    return attribution


__all__ = [
    "CATEGORY_LABELS", "HIGH", "LOW", "MEDIUM",
    "STATE_AMBIGUOUS", "STATE_ATTRIBUTED", "STATE_ERROR",
    "STATE_INTERCEPTED", "STATE_UNKNOWN",
    "attribute", "confidence_band", "evidence_for", "observations", "role_of",
]
