# ether-w4f-scanner

**Passive TLS / CDN / WAF / edge fingerprinting for API endpoints.**

A single-command scanner that, for any `host[:port]`, walks the standard
client path — DNS (A/AAAA/CNAME/PTR), one SNI TLS handshake, one GET — and
then matches the collected signals against a vendor signature table (response
headers, cookies, certificate issuer/org, CNAME/PTR suffixes, IP netblocks) to
name the CDN/WAF/edge in front of the origin.

```
w4f --target api.example.com
```

No attack payloads. Nothing is validated the way a client trusts a chain —
this is fingerprinting, not trusting — so self-signed and privately-pinned
endpoints are fingerprinted too, and the **SPKI-SHA-256 pin value** is
reported for each certificate, which is exactly the value an app's custom
pinner compares against.

## Why this exists

Knowing what edge sits in front of a host decides which interception route can
work at all:

- **Cloudflare / anycast** — a DNAT written against one resolved IP matches
  zero packets, because your resolver and the device's resolver return
  different IPs. The route is SNI-based, not IP-based.
- **Imperva edge** — the host may demand a **client certificate** at the TLS
  layer (mutual TLS). A proxy that can't present one gets `stream reset by
  client` after a perfectly correct app-side pinning bypass.
- **CloudFront / GFE / ELB** — the origin is behind a managed edge; whether
  the origin itself is reachable by name tells you where the capture ceiling
  is.
- **Self-signed** — the app's pinning is native or custom; a system CA mount
  will not help.

This tool makes that a 2-second decision instead of an hour of guessing.

## Install

Requires Python 3.10+, and `cryptography` for full certificate details
(without it the scanner still works, but cert fields are omitted). DNS
resolution uses `dnspython` when present and falls back to `socket`.

```bash
pip install -e .
```

Or run without installing:

```bash
python3 -m w4f --target api.example.com
```

## Usage

```
w4f --target host[:port] [--target host2[:port] ...] \
    [--path /] [--timeout 8] [--workers 8] \
    [--json out.json] [--md out.md] [--no-http] [--quiet]

    --target    DNS name or IP, optional :port (default 443). Repeatable.
    --path      HTTP path to GET (default /)
    --timeout   connect/TLS/HTTP timeout per host (default 8s)
    --workers   parallel host count (default 8)
    --json      write the full machine-readable result tree to FILE
    --md        write markdown per-host blocks (for docs) to FILE
    --no-http   TLS/cert/DNS only, skip the HTTP request
    --quiet     suppress the per-host console block (useful with --json/--md)
```

Multiple targets are scanned in parallel; results are printed sorted by host.

## What it reports

Per host:

| Signal | Source |
|---|---|
| resolved IPs (A+AAAA) + PTR | DNS |
| CNAME chain | DNS |
| TLS version / cipher / ALPN | TLS handshake |
| leaf cert: subject, issuer org, SAN, validity, SHA-256, **SPKI-SHA-256**, key/sig | TLS handshake |
| mTLS flag (server wants a client cert) | TLS alert, incl. TLS 1.3 post-handshake |
| HTTP status + interesting headers | one GET |
| CDN/WAF verdict + matching evidence | signature match |

## Reading a verdict

Vendor names are matched with weights: a host behind nginx directly gets
`nginx` only; a host behind Imperva gets `imperva` from headers **and** cert
**and** netblock, each signal listed as evidence. A blank verdict means the
edge is not in the signature table — treat it as "unknown origin, no WAF/CDN
signature", not "no WAF".

## Vendor coverage

Cloudflare, Imperva, Akamai, AWS CloudFront / WAF / ELB / S3, Fastly, Azure
Front Door / Application Gateway, Google GFE, F5 BIG-IP, NetScaler, Sucuri,
StackPath, OpenResty, nginx, Apache, Envoy, HAProxy, Caddy, LiteSpeed,
Varnish, ArvanCloud, Baidu Yunjiasu, FortiWeb, ModSecurity, NAXSI, Wallarm,
Wordfence, Zenedge, Zscaler, DDoS-Guard, Edgecast, MaxCDN, KeyCDN, Barracuda,
Huawei Cloud WAF, SafeDog.

## License

MIT — see [LICENSE](LICENSE).
