# w4f

```
                 █████ █████     ██████
                ░░███ ░░███     ███░░███
 █████ ███ █████ ░███  ░███ █  ░███ ░░░
░░███ ░███░░███  ░███████████ ███████
 ░███ ░███ ░███  ░░░░░░░███░█░░░███░
 ░░███████████         ░███░   ░███
  ░░████░████          █████   █████
   ░░░░ ░░░░          ░░░░░   ░░░░░
 passive TLS / CDN / WAF / edge fingerprinting · v0.1.19
```

[![tests](https://github.com/hdyrawan/w4f/actions/workflows/ci.yml/badge.svg)](https://github.com/hdyrawan/w4f/actions/workflows/ci.yml)
[![pypi](https://img.shields.io/pypi/v/w4f?cache_bust=1)](https://pypi.org/project/w4f/)
[![python](https://img.shields.io/badge/python-3.10--3.12-blue)](https://pypi.org/project/w4f/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

[Release notes → CHANGELOG.md](CHANGELOG.md)

Passive **TLS / CDN / WAF / edge fingerprinting** for API endpoints. For any
`host[:port]` it walks the standard client path — DNS (A/AAAA/CNAME/PTR), one
SNI TLS handshake, one GET — and matches the collected signals (response
headers, cookies, certificate issuer/org, CNAME/PTR suffixes, IP netblocks)
against a vendor signature table to **name the edge in front of the origin**.

```bash
w4f --target api.example.com
```

No attack payloads. Nothing is chain-validated the way a client trusts it —
this is fingerprinting, not trusting — so self-signed and privately-pinned
endpoints are fingerprinted too, and the **SPKI-SHA-256 pin value** is
reported per certificate, which is exactly the value an app's custom pinner
compares against.

An optional `--verify` flag sends **one benign `<script>` query** to catch
silent WAFs (FortiWeb, F5 ASM) that answer normal requests with plain nginx
and only reveal themselves when they block something. Off by default.

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
- **Silent WAFs (FortiWeb)** — serve `nginx` headers to every passive
  request; only an attack-shaped query gets their block page back. Passive
  scanning alone would report them as a bare origin.

This tool makes that a 2-second decision instead of an hour of guessing.

## Install

**Requirements:** Python **3.10–3.12**, nothing mandatory. `cryptography`
adds full certificate details (issuer, SAN, SPKI pin, key/sig) and `dnspython`
adds proper CNAME/PTR resolution; without either the scanner degrades
gracefully (socket fallback for DNS, cert fields omitted) and the test suite
still passes.

### Option 1 — pipx (recommended, isolated CLI install)

```bash
pipx install w4f
w4f --version
```

### Option 2 — uv tool

```bash
uv tool install w4f
w4f --version
```

### Option 3 — plain pip

Prefer a virtual environment so the `w4f` script lands on your PATH:

```bash
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install w4f
w4f --version
```

Install with the optional extras (certificate + DNS depth) in one step:

```bash
pip install "w4f[full]"
```

### Option 4 — unreleased `main`, or a clone

```bash
pipx install git+https://github.com/hdyrawan/w4f.git   # or uv tool / pip
```

Or from a clone:

```bash
git clone https://github.com/hdyrawan/w4f.git && cd w4f
pip install .
w4f --version
```

### Option 5 — run without installing

From a clone you can run it directly, no install step at all:

```bash
git clone https://github.com/hdyrawan/w4f.git && cd w4f
python3 -m w4f --target api.example.com
```

### For development

```bash
git clone https://github.com/hdyrawan/w4f.git && cd w4f
python3 -m venv .venv && source .venv/bin/activate
pip install -e .            # editable: code changes apply immediately
python3 -m pytest           # run the test suite
```

### Verify & uninstall

```bash
w4f --version        # e.g. "w4f 0.1.9 — passive TLS / CDN / WAF / edge fingerprinting"
w4f --help           # full usage
pipx uninstall w4f   # or: uv tool uninstall w4f / pip uninstall w4f
```

## Usage

```bash
# one host
w4f --target api.example.com

# several hosts, one pass
w4f --target mapi.example.com --target api.example.net --target api.example.org

# a non-443 port (the DATA socket banks use)
w4f --target mbanking.example.co.id:6552

# an IP literal (PTR is still resolved)
w4f --target 34.206.8.44

# scan every subdomain from a subdomain-enumeration export
w4f --target-json subdomains.json --json out.json --md out.md

# catch silent WAFs with the one-query active probe
w4f --target api.example.com --verify

# machine-readable + markdown sweep, quiet console
w4f --target api.example.com --quiet --json out.json --md out.md

# TLS/cert/DNS only — skip the HTTP request entirely
w4f --target api.example.com --no-http
```

### Flags

| flag | meaning |
|---|---|
| `--target HOST[:PORT]` | DNS name or IP, optional `:port` (default 443). Repeatable. |
| `--target-json FILE` | targets from a JSON file — subdomain-enumeration export (array of `{"subdomain","ip","cloudflare"}` objects, e.g. subdomainfinder.c99.nl), array of strings, or `{subdomains:[...]}`. Each is scanned like a `--target`. |
| `--path PATH` | HTTP path to GET (default `/`) |
| `--timeout SECONDS` | connect/TLS/HTTP timeout per host (default 8) |
| `--workers N` | parallel host count (default 8) |
| `--json FILE` | write the full machine-readable result tree to FILE |
| `--md FILE` | write a markdown sweep (table + per-host blocks) to FILE |
| `--no-http` | TLS/cert/DNS only, skip the HTTP request |
| `--verify` | **OPT-IN active probe** — one benign `<script>` query per host; reports the WAF block page (FortiWeb / F5 ASM / Cloudflare / Imperva) |
| `--version` | print version and exit |
| `--quiet` | suppress the console banner and per-host blocks (for `--json`/`--md`) |

At least one of `--target` / `--target-json` is required. Targets scan in
parallel; results print sorted by host. Progress and file paths go to stderr,
the report to stdout — so `w4f ... > report.txt` and `w4f ... --quiet --json
out.json | jq ...` keep the machine output clean.

The banner is the Rebel figlet "w4f" (patorjk taag style, x=none full-width)
with `w` in red and `f` in blue. It prints on every non-quiet run, on
**stderr**, so stdout stays parseable.

### Example output

```bash
$ w4f --target api.example.com --target shop.example.net --timeout 6
```

```
                 █████ █████     ██████
                ░░███ ░░███     ███░░███
 █████ ███ █████ ░███  ░███ █  ░███ ░░░
░░███ ░███░░███  ░███████████ ███████
 ░███ ░███ ░███  ░░░░░░░███░█░░░███░
 ░░███████████         ░███░   ░███
  ░░████░████          █████   █████
   ░░░░ ░░░░          ░░░░░   ░░░░░
  passive TLS / CDN / WAF / edge fingerprinting   v0.1.19

api.example.com:443
ip        45.60.16.239
cname     api.example.com.impervadns.net
tls       TLSv1.3  TLS_AES_128_GCM_SHA256  ALPN h2
mtls      server wants a CLIENT certificate
cert      Example Security CA
  san     api.example.com, www.api.example.com
  valid   2025-12-02 -> 2026-12-27  (134d left)
  spki    6905ab38dc27d7d6562fdbfd26cedf1238783b1ef25c76fd47245a695b3b11df
  key     RSA 2048  sha256WithRSAEncryption
http      ERROR: [SSL: TLSV13_ALERT_CERTIFICATE_REQUIRED] tlsv13 alert certificate required
verdict   imperva (2): cname: api.example.com.impervadns.net; netblock: 45.60.16.239 in 45.60.0.0/16

shop.example.net:443
ip        104.18.1.79, 104.18.0.79, 2606:4700::6812:4f, 2606:4700::6812:14f
cname     shop.example.net.cdn.cloudflare.net
tls       TLSv1.3  TLS_AES_256_GCM_SHA384  ALPN h2
cert      Example CA, Inc.
  san     shop.example.net, www.shop.example.net
  valid   2026-05-27 -> 2026-12-11  (118d left)
  spki    343d1536f3666f92ea868d751d138dd8658d3020426b4de28801cb259f5bdde7
  key     RSA 2048  sha256WithRSAEncryption
http      HTTP/1.1 404 Not Found
  hdr     server=cloudflare
  hdr     cf-cache-status=DYNAMIC
  hdr     cf-ray=a2af62ede853e78f-CGK
verdict   cloudflare (7): header server: cloudflare; header cf-ray: ...;
          cookie: _cfuvid=...; cname: shop.example.net.cdn.cloudflare.net;
          netblock: 104.18.1.79 in 104.16.0.0/13; netblock: 2606:4700::6812:4f in ...
```

(The hosts above are illustrative — run it against any real host to see your
own output.)

Colors are enabled automatically when stdout is a TTY — host in cyan, vendor
verdict in green, mTLS/errors in red, `--verify` block findings in yellow.
Disable with `NO_COLOR` (honoured for output, though console blocks stay
plain text by design — no markdown).

## What it reports

| signal | source |
|---|---|
| resolved IPs (A+AAAA) + PTR | DNS |
| CNAME chain | DNS |
| TLS version / cipher / ALPN | TLS handshake |
| leaf cert: subject, issuer org, SAN, validity, SHA-256, **SPKI-SHA-256**, key/sig | TLS handshake |
| mTLS flag (server wants a client cert, incl. TLS 1.3 post-handshake) | TLS alert / first app data |
| HTTP status + interesting headers | one GET |
| CDN/WAF verdict + matching evidence | signature match |
| `block` — WAF block page (vendor, title, status) | `--verify` active probe |

## Reading a verdict

Vendor names are matched with weights: a host behind nginx directly gets
`nginx` only; a host behind Imperva gets `imperva` from headers **and** cert
**and** netblock, each signal listed as evidence with a count
(`imperva (2)`). The top match is the one with the most evidence.

- **A blank verdict** means the edge is not in the signature table — treat it
  as "unknown origin, no WAF/CDN signature", **not** "no WAF".
- **A passive "direct nginx" verdict is NOT proof of a bare origin.** FortiWeb
  and F5 ASM serve plain nginx to normal requests; run `--verify` before
  concluding the origin is exposed.
- **`--verify` findings** are reported separately (`block fortiweb — ...`)
  so the passive and active layers never blur.

## Security notes

- **Input validation.** Targets from `--target-json` are validated at load:
  control characters, URI schemes (`file://` etc.), whitespace-in-hostname,
  and overlong names (>253 chars) are dropped with a warning. **Private /
  internal IPs (10.x, 192.168.x, 127.x, 169.254.x) are warned but NOT
  dropped** — scanning internal infrastructure is a legitimate use. Only run
  w4f against targets you are authorised to scan.
- **The reported SPKI-SHA-256 is a fingerprint, not a trust anchor.** w4f
  reports the pin value the edge presents; it does not verify it against any
  expected set (this is a fingerprinting tool, not a certificate-verification
  tool). A reported pin implies nothing about whether the endpoint is
  legitimate — an attacker's certificate has a pin value too.
- **Output can disclose infrastructure details.** `--json` includes cert
  chains, SPKI pins, CNAME/PTR records and resolved IPs (including internal
  ones when you scan them). Treat the output as sensitive and do not share it
  inadvertently.
- **The unverified TLS context is deliberate.** Certificate verification is
  disabled (via the public `ssl.create_default_context()` + `CERT_NONE`) so
  that self-signed / expired / wrong-hostname certs can still be read as
  evidence — which is the entire point of edge fingerprinting. This means an
  active MITM between w4f and the target is not detected; the tool reports
  what it was actually presented.

**v0.1.14 note — AWS Global Accelerator detected.** The AWS edge that
resolves to Global Accelerator ranges (`15.197.0.0/16`, `3.33.0.0/16`,
PTR `*.awsglobalaccelerator.com`) has no `elb.amazonaws.com` CNAME, so it
fell through every AWS rule. Found via the Indonesian bank subdomain sweep
(15.197.x/3.33.x, 301s to a corporate portal). Added
`aws-global-accelerator` netblock + PTR rules.

**v0.1.13 note — Kong API gateway detected.** `X-Kong-Upstream-Latency` /
`X-Kong-Proxy-Latency` headers (and `Server: kong` on older builds). Added
`kong` vendor rule.

**v0.1.12 note — AWS WAF on CloudFront is now detected.** Indonesian-ecosystem
hunt (user-led: example-hospital.com) found CloudFront + **AWS WAF managed
rules** silently blocking attack-shaped queries with `403` +
`x-cache: Error from cloudfront` + the block page "ERROR: The request could
not be satisfied / Request blocked". Passive
scan sees only `aws-cloudfront` (a normal GET returns 200); `--verify` now
matches the AWS WAF block page (`aws-waf`), and the passive `aws-waf` rule
fires on the 403 + error-cache shape via a new `_status` pseudo-header.
Confirmed deployments: example-hospital.com, a bank's API host, example.com,
example-travel.com. **Do not write "CloudFront, no WAF" for a host without a
`--verify` run** — AWS WAF is silent to passive probes, same trap as FortiWeb.

**v0.1.11 note — internet-wide accuracy sweep.** A 138-host cross-check
against an independent active WAF detector closed the two biggest accuracy
gaps: (1) **redirect-following** — most sites 301 from the apex to `www`
and only the final response carries the WAF, so w4f now follows up to 5
hops (`example-news.com` apex said `varnish`, `www.example-news.com` is Akamai Kona);
(2) **Akamai Kona signals** — `AkamaiGHost`, `akamai-grn`, `x-grn`,
`x-akamai-transformed`, `akamai-request-bc` (12 hosts were missed). New
vendors: `tengine` (Alibaba), `tencent-gateway` (stgw/tRPC-Gateway),
`bytedance` (TikTok TLB), `pepyaka` (Wix), `azure-app-service`
(ARRAffinity). Disagreements vs the oracle dropped 31 → 6, and the 6
remainders are semantic-layer differences where w4f is more specific
(e.g. TikTok is ByteDance's edge, not the Akamai node in its chain).
Evidence: `experiments/accuracy-sweep-2026-08-14/`.

### Signature coverage

Cloudflare, Imperva, Akamai (incl. Kona WAF signals), AWS CloudFront / WAF /
ELB / S3 / EC2, Fastly, Azure Front Door / Application Gateway / App
Service, Google GFE / Cloud Armor, F5 BIG-IP, NetScaler, GTM/GSLB DNS LB,
Sucuri, StackPath, OpenResty, nginx, Apache, HAProxy (server + stick
cookie), Envoy, Caddy, LiteSpeed, Varnish, ArvanCloud, Tencent EdgeOne /
Tencent CDN / Tencent gateway (stgw/tRPC), Alibaba Tengine, ByteDance TLB,
Wix Pepyaka, Baidu Yunjiasu, FortiWeb, ModSecurity, NAXSI, Wallarm,
Wordfence, Zenedge, Zscaler, DDoS-Guard, Edgecast, MaxCDN, KeyCDN,
Barracuda, Huawei Cloud WAF, SafeDog — plus block-page signatures for
FortiWeb (EN + localized ID), F5 ASM, Cloudflare, Imperva and **AWS WAF**
("ERROR: The request could not be satisfied") under `--verify`.

Signatures are a snapshot; a new edge version can change headers, so re-run
sweeps before trusting a blank verdict for a host whose writeup is old.

## JSON output

`--json` writes the full per-host result tree. Every host is one object;
errors are a field, not an exception — a bad host never aborts the run:

```json
[
  {
    "host": "api.example.com",
    "hostport": "api.example.com:443",
    "port": 443,
    "resolved": { "cname": ["api.example.com.cdn.cloudflare.net"], "ips": ["104.18.1.79"], "ptr": [] },
    "tls": {
      "tls_version": "TLSv1.3",
      "cipher": "TLS_AES_256_GCM_SHA384",
      "alpn": "h2",
      "mtls": false,
      "chain_verified": true,
      "cert": { "subject": "CN=api.example.com", "issuer": "O=Cloudflare, Inc.", "issuer_org": "Cloudflare, Inc.", "spki_sha256": "343d1536...", "key_type": "RSA", "key_size": 2048, "days_remaining": 118 },
      "http": { "status": "HTTP/1.1 404 Not Found", "headers": { "server": "cloudflare", "cf-ray": "a2af..." }, "set-cookie-list": [] }
    },
    "verdict": [
      { "vendor": "cloudflare", "signals": 7, "evidence": ["header server: cloudflare", "cname: api.example.com.cdn.cloudflare.net", ...] }
    ],
    "block": null
  }
]
```

### Scripting

```bash
# the verdict for every host
w4f --target-json subdomains.json --quiet --json out.json
jq -r '.[] | "\(.hostport)\t\(.verdict[0].vendor // "unknown")"' out.json

# only hosts behind a specific edge
jq -r '.[] | select(.verdict[].vendor == "cloudflare") | .hostport' out.json

# every host whose --verify probe found a WAF block page
jq -r '.[] | select(.block) | "\(.hostport)\t\(.block.vendor)"' out.json

# fail if any host errored (exit code already does this, but jq can too)
jq -e '[.[] | select(.error)] | length == 0' out.json > /dev/null

# SPKI-SHA-256 pin values for every host
jq -r '.[] | "\(.hostport)\t\(.tls.cert.spki_sha256)"' out.json
```

### Exit codes

| code | meaning |
|---|---|
| `0` | everything scanned cleanly |
| `1` | at least one host errored (DNS failure, connect refused, probe exception) — results still written |
| `2` | usage error — no `--target`/`--target-json`, unreadable `--target-json` |

## Testing

```bash
pip install .[dev]
python -m pytest
```

71 tests, offline — a local TLS server with a self-signed cert exercises the
real socket path without touching the internet. Coverage: fingerprint
matching against real-world cases from the Indonesian bank sweep +
false-positive guards; the `--verify` block-page matcher (FortiWeb EN/ID,
F5 ASM, Cloudflare, Imperva, the title-at-end-of-39KB-body trap); vendor
table sanity (every regex compiles, every netblock valid); CLI/report/banner;
and end-to-end `probe_one` against the local server.

CI (GitHub Actions) runs the suite on Python 3.10/3.11/3.12 with full extras,
a no-optional-deps job proving graceful degradation, and a CLI smoke check.

## Known limits

- **Passive layer cannot see silent WAFs.** FortiWeb and F5 ASM serve plain
  nginx to normal requests; only the opt-in `--verify` probe (one benign
  `<script>` query) makes them answer with a block page. `--verify` is still
  not a full exploit-style sweep.
- **The signature table is a snapshot.** New edge versions can change
  headers/cookies; re-run before trusting a blank verdict for an old writeup.
- **`--verify` reads the block page title** — a WAF that localizes its block
  page beyond the EN + ID fragments matched here would need a new signature.
- **Bare IP targets resolve PTR but not CNAME** (there is no CNAME for an IP).

## License

MIT — see [LICENSE](LICENSE).
