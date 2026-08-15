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
 passive TLS / CDN / WAF / edge fingerprinting · v0.1.43
```

[![tests](https://github.com/hdyrawan/w4f/actions/workflows/ci.yml/badge.svg)](https://github.com/hdyrawan/w4f/actions/workflows/ci.yml)
[![pypi](https://img.shields.io/pypi/v/w4f?cache_bust=1)](https://pypi.org/project/w4f/)
[![python](https://img.shields.io/badge/python-3.10--3.12-blue)](https://pypi.org/project/w4f/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

[Release notes → CHANGELOG.md](CHANGELOG.md) ·
[Vendor signature reference → docs/vendor-signatures.md](docs/vendor-signatures.md) ·
[Attribution model → docs/attribution-model.md](docs/attribution-model.md)

Passive **TLS / CDN / WAF / edge fingerprinting** for API endpoints. For any
`host[:port]` it walks the standard client path — DNS (A/AAAA/CNAME/PTR), one
SNI TLS handshake, one GET — and matches the collected signals (response
headers, cookies, certificate issuer/org, CNAME/PTR suffixes, IP netblocks)
against a vendor signature table to **name the edge in front of the origin**.

w4f performs evidence-based attribution of the Internet-facing edge and
explicitly handles ambiguity, layering, interception, weak evidence, and
verification-only WAF behavior.

```bash
w4f --target-file hosts.txt
```

```
HOST                  EDGE              CONF  BASIS                       TLS     CERT               HTTP  NOTES
www.example.com:443   cloudflare +2  HIGH 85  net+cert+cname+http+cookie  1.3 h2  Cloudflare 55d      200
shop.example.net:443  AMBIGUOUS       MED 42  cname+ptr+http              1.3 h2  Amazon 60d          200
edge.example.io:443   unknown              -  -                           1.3 h2  Let's Encrypt 40d   200
inspected.example.org:443  INTERCEPTED          -  -                           1.3 h2  Fortinet -168d      403  INTERCEPTED
www.example.net:443   akamai          LOW 20  cname                       -       -                     -  ERR connect failed: timed out

# www.example.com is cleanly attributed — its table row says it all, so it
# gets no block. Only the hosts that need a look do:

shop.example.net:443
  EDGE    AMBIGUOUS
    aws-cloudfront                MEDIUM 42
    cloudflare                    MEDIUM 37
  BASIS
    aws-cloudfront      cname + ptr + http
    cloudflare          net + http

edge.example.io:443
  EDGE    UNKNOWN
  leads   cname edge.provider.net · server: acme-edge · x-acme-pop: sin1

inspected.example.org:443  INTERCEPTED
  EDGE    NOT DETERMINED
  PATH    INTERCEPTED by fortinet
          the identity below may belong to the interception device, not this host
  OBSERVED
    IP        198.51.100.40
    Issuer    Fortinet
    SPKI      9701081eeeeeeeee…

www.example.net:443  ERR connect failed: timed out
  akamai                        LOW    20
  cname   (cloud)
  error   connect failed: timed out
```

`BASIS` is the column that decides whether to believe the row: `net+cert`
is ownership evidence, a bare `hdr` is a string the origin can set. Default
mode is **table-first**: cleanly attributed hosts are just their table row,
and only hosts that need a look (unknown, ambiguous, intercepted, error,
block page, mTLS, a competing edge) get a detail block; the sweep ends with a
rollup. `-v`/`--verbose` prints the full block for every host — see
[Example output](#example-output).

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
w4f --version        # e.g. "w4f 0.1.36 — passive TLS / CDN / WAF / edge fingerprinting"
w4f --help           # full usage
pipx uninstall w4f   # or: uv tool uninstall w4f / pip uninstall w4f
```

## Library use

The same engine the CLI drives is exposed as a plain Python function —
useful for scheduling, scripting, or building your own sweep tooling:

```python
from w4f import fingerprint_host

r = fingerprint_host("api.example.com", verify=True)
top = r["verdict"][0]                         # ranked by confidence
print(top["vendor"], top["confidence"])       # cloudflare 82
print(top["categories"])                      # ['netblock', 'cert', 'cname', 'headers']
print(r["block"]["vendor"] if r["block"] else "no WAF block")    # needs verify=True
```

`verdict` is ranked by **confidence**, so `verdict[0]` is the best-evidenced
vendor. `categories` (added 0.1.32) lists the signal kinds behind the score,
strongest first — a verdict whose categories are only `headers`/`cookies`
rests on strings the origin can set.

Returns the same per-host dict the CLI's `--json` output contains (`host`,
`hostport`, `port`, `resolved`, `tls`, `verdict`, `block`, `error`). Accepts
`port`, `timeout`, `path`, `no_http`, `verify`, `ws_path`, `grpc` — the CLI
flag equivalents. Errors are a field, never an exception: a host that fails
DNS comes back with `error` set and `verdict == []`.

## Usage

```bash
# one host
w4f --target api.example.com

# several hosts, one pass
w4f --target mapi.example.com --target api.example.net --target api.example.org

# a non-443 port (API/data sockets often sit off 443)
w4f --target api.example.net:6552

# an IP literal (PTR is still resolved)
w4f --target 203.0.113.10

# scan every subdomain from a subdomain-enumeration export
w4f --target-json subdomains.json --json out.json --md out.md

# plain-text host list (one per line; # comments and blanks ignored)
w4f --target-file hosts.txt

# CSV target list (uses the host/subdomain column when present, else column 1)
w4f --target-csv targets.csv

# pipeline: subdomain enumeration straight into w4f (stdin is read when no
# explicit target source is given and stdin is not a TTY)
subfinder -d example.com -silent | w4f --csv sweep.csv

# flat CSV output for spreadsheets (primary verdict per host)
w4f --target-file hosts.txt --csv sweep.csv

# SARIF 2.1.0 for security dashboards / GitHub Code Scanning
w4f --target-file hosts.txt --sarif scan.sarif

# WebSocket upgrade probe (RFC 6455) against a path
w4f --target ws.example.com --ws /socket.io

# gRPC health-check probe (grpc.health.v1.Health/Check)
w4f --target grpc.example.com --grpc

# pace requests: --delay N seconds between per-host submissions
# (per-domain backoff: 429/503 doubles the delay up to 10s, success resets)
w4f --target-file hosts.txt --delay 0.5 --csv sweep.csv

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
| `--target-file FILE` | plain-text host list, one `host[:port]` per line; `#` comments and blank lines ignored |
| `--target-csv FILE` | CSV target list — uses the column named `host`/`subdomain` when the first row is a header, else the first column |
| `--path PATH` | HTTP path to GET (default `/`) |
| `--timeout SECONDS` | connect/TLS/HTTP timeout per host (default 8) |
| `--workers N` | parallel host count (default 8) |
| `--delay SECONDS` | base pacing between per-host submissions (default 0 = as fast as possible). Per-domain adaptive backoff: a `429`/`503` doubles that domain's delay (cap 10s), a success resets it to the base. |
| `--json FILE` | write the full machine-readable result tree to FILE |
| `--md FILE` | write a markdown sweep (table + per-host blocks) to FILE |
| `--csv FILE` | write a flat CSV — one row per host, primary verdict: host, port, ips, cname, verdict, confidence, signals, mtls, tls_version, alpn, spki, http_status, block, error, basis, final_host |
| `--sarif FILE` | write a SARIF 2.1.0 report for security dashboards / GitHub Code Scanning — one result per host, rule ids `w4f/<vendor>`, `w4f/block`, `w4f/mtls`, `w4f/probe-error`, `w4f/unknown-edge` |
| `--sort risk\|host\|edge` | console ordering (default `risk`: errors, block pages, mTLS, unknown and header-only verdicts first). `host` = alphabetical, `edge` = grouped by vendor. File outputs are always host-sorted. |
| `-v`, `--verbose` | show the FULL per-host detail (cert, SPKI, response headers, verdict evidence) instead of the compact triage view — the summary table prints either way |
| `--no-banner` | suppress the ASCII banner + version tagline — output starts at the summary table (for piping the table into scripts) |
| `--no-http` | TLS/cert/DNS only, skip the HTTP request |
| `--ws PATH` | **OPT-IN** — send an RFC 6455 WebSocket upgrade request to this path and report whether the edge answers `101` (plus `Sec-WebSocket-Accept`) |
| `--grpc` | **OPT-IN** — send a `grpc.health.v1.Health/Check` request and report `grpc-status` / `grpc-message`, or the HTTP/2 binary-framing answer (real gRPC is h2; pairs with the ALPN observation) |
| `--verify` | **OPT-IN active probe** — one benign `<script>` query per host; reports the WAF block page (FortiWeb / F5 ASM / Cloudflare / Imperva) |
| `--version` | print version and exit |
| `--quiet` | suppress ALL console output (banner, summary table, per-host blocks, rollup) — use with `--json`/`--md`/`--csv` for automation |

Targets may come from `--target`, `--target-json`, `--target-file`,
`--target-csv`, or — when none of those is given and stdin is not a TTY —
from stdin (one host per line). All sources go through the same validation
(control chars / URI schemes / overlong names dropped with a warning) and
are deduplicated after validation. Targets scan in
parallel; the console orders them by risk (`--sort`) while file outputs stay
sorted by host for clean run-over-run diffs. Progress and file paths go to stderr,
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
  passive TLS / CDN / WAF / edge fingerprinting   v0.1.39

HOST                    EDGE         CONF     BASIS               TLS     CERT                 HTTP  NOTES
dead.example.io:443     -            -                            -       -                       -  ERR DNS did not resolve
api.example.com:443     imperva +1   MED 62   net+cert+hdr        1.3 h2  Imperva Inc 64d       403  mTLS  BLOCK imperva!
edge.example.io:443     UNKNOWN      -                            1.3 h2  GlobalSign nv… 161d   200
origin.example.org:443  nginx        LOW 7    hdr                 1.3 h2  Let's Encrypt 21d     200
shop.example.net:443    cloudflare   HIGH 82  net+cert+cname+hdr  1.3 h2  SSL Corporati… 73d    200  ->www.shop.example.net

dead.example.io:443  ERR DNS did not resolve
  error   DNS did not resolve

api.example.com:443  mTLS  BLOCK imperva!
  imperva                       MEDIUM 62
  net + cert + hdr
  layer   imperva → nginx

edge.example.io:443
  EDGE    UNKNOWN
  leads   server: acme-edge · x-acme-pop: sin1 · x-acme-request-id

── 5 hosts · 3.4s ──────────────────────────────────────────────────────
edges     cloudflare 1 · imperva 1 · nginx 1
unknown   1  (edge.example.io:443)
flags     mTLS 1 · BLOCK 1 · errors 1
weak      1 verdict rests on headers only (spoofable) — confirm with --verify
```

Default mode is the **triage view** and is deliberately **table-first**: a
summary table of every host, then a sweep rollup, and a per-host block **only
for the hosts that need a look** — an error, a block page, mTLS, an unknown
edge, an ambiguous or intercepted result, or a genuinely competing edge. The
two cleanly-attributed hosts above (`shop.example.net`, `origin.example.org`)
are fully described by their table row, so they get no block — that is what
keeps a 50-host sweep scannable. Reach for `-v`/`--verbose` (below) when you
want the full analytical block for *every* host.

Each block is shaped by the result **state**, because "no vendor name" has
several very different causes and collapsing them loses the decision:

| state | meaning |
|---|---|
| `ATTRIBUTED` (named vendor) | one candidate is best-evidenced; the vendor is named |
| `AMBIGUOUS` | edge candidates too close to separate — both are shown, rather than silently picking the higher |
| `UNKNOWN` | scanned, nothing matched. The observations/leads are the start of the next signature |
| `INTERCEPTED` | something on the **scanner's** path re-signed the connection; no vendor is attributed and the cert/pin may be the middlebox's |
| `ERROR` | the host could not be probed. A host that failed *but* resolved a vendor CNAME still reports that vendor — DNS resolves before the handshake |

`layer` is the stack, not a rival: an origin underneath the edge
(`cloudflare → varnish`) is reported as a **layer**, while `alt` lists only
competing *edge* candidates. Presenting an origin as an alternative edge was
the misreading this split removes.

`CONF` is the confidence **band** first (`HIGH` ≥ 70, `MED` ≥ 30, `LOW`
below) and the score second. The score is a sum of category weights, not a
probability, so `HIGH` means several independent kinds of evidence agreed —
more than the strongest single category can supply alone. `BASIS` names
those categories (`net` netblock, `cert`, `cname`, `ptr`, `hdr` header,
`cookie`); a bare `hdr` is a string the origin can set, and the block marks
it *headers only — spoofable*.

The full model is documented in
[`docs/attribution-model.md`](docs/attribution-model.md).

Add `-v` / `--verbose` for the analytical view — the same observations plus
**why** the attribution was reached: the evidence behind it grouped by
category, and the alternatives that were in play.

```
$ w4f -v --target www.example.com

www.example.com:443
ip        104.18.1.79
cname     www.example.com.cdn.cloudflare.net
tls       TLSv1.3  TLS_AES_256_GCM_SHA384  ALPN h2
cert      Cloudflare, Inc.  (chain verified)
  san     www.example.com, *.example.com
  valid   2026-06-05 -> 2026-12-11  (55d left)
  spki    343d1536f3666f92ea868d751d138dd8658d3020426b4de28801cb259f5bdde7
http      HTTP/1.1 200 OK
  hdr     server=cloudflare
  hdr     x-varnish=1234567 7654321

EDGE
  cloudflare                    HIGH   85
    net + cert + cname + http + cookie   (cloud)

EVIDENCE
  Network
    104.18.1.79 in 104.16.0.0/13
  Certificate
    Cloudflare, Inc.
  CNAME
    www.example.com.cdn.cloudflare.net
  HTTP
    server: cloudflare
  Cookie
    __cf_bm=xyz

LAYER
  cloudflare
      ↓
  varnish

ALTERNATIVES
  cloudflare-waf                LOW     3
    cookie
```

`EVIDENCE` is one category per heading and one observation per line, so it
answers "what would have to be false for this to be wrong" — a verdict
resting on a netblock and a certificate is a different claim from one
resting on a header. `LAYER` draws the stack the edge fronts; `ALTERNATIVES`
holds only competing edges. Scores appear as one number per candidate; the
arithmetic behind them stays out of the output.

The `chain`/`final` rows matter more than they look: the apex is often a
bare redirector and the WAF only sits on `www`, so they say which host the
headers above actually describe.

(The hosts above are illustrative — run it against any real host to see your
own output.)

Colors are enabled automatically when stdout is a TTY (piped output is plain
text), and disabled with `NO_COLOR`. The host line is cyan, **critical flags
(mTLS / BLOCK / ERR) are bold bright red**, redirect markers and `--verify`
block findings yellow — and each **vendor name has its own color** so a glance names the
edge: Cloudflare bright-yellow, Akamai blue, Fastly red, AWS family cyan,
Azure family bright-blue, Tencent family bright-magenta, Google GFE
magenta, F5/netscaler bright-red, FortiWeb bright-yellow, Kong bright-cyan,
and plain origin stacks (nginx, Apache, IIS, Varnish, …) are **dimmed** so
the edge vs origin distinction is instantly visible. The color map is in
`w4f/report.py` (`VENDOR_COLORS`) — a new vendor gets a green default; add
an entry there if it deserves its own hue.

## What it reports

| signal | source |
|---|---|
| resolved IPs (A+AAAA) + PTR | DNS |
| CNAME chain | DNS |
| TLS version / cipher / ALPN | TLS handshake |
| leaf cert: subject, issuer org, SAN, validity, SHA-256, **SPKI-SHA-256**, key/sig | TLS handshake |
| mTLS flag (server wants a client cert, incl. TLS 1.3 post-handshake) | TLS alert / first app data |
| HTTP status + interesting headers | one GET |
| WebSocket upgrade support (`--ws`) | RFC 6455 upgrade request |
| gRPC health-check support (`--grpc`) | grpc.health.v1.Health/Check |
| redirect chain + final host (apex → www) | one GET, up to 5 hops |
| CDN/WAF verdict + evidence + confidence + signal categories + cloud/on-prem | signature match |
| `interception` — a TLS-inspection box on the scanner's own path | cert issuer / its refusal page |
| `block` — WAF block page (vendor, title, status) | `--verify` active probe |

## Reading a verdict

A host behind nginx directly gets `nginx` only; a host behind Imperva gets
`imperva` from headers **and** cert **and** netblock, every matching signal
listed as evidence:

```
imperva (62%, net+cert+hdr): header x-iinfo: 7-1234567-…; netblock: … ; cert: Imperva Inc
```

Every match carries a **confidence (0–100)** summed from weighted signal
categories, **each category counted once**:

| category | weight | why |
|---|---|---|
| `net` netblock | 30 | IP ownership is hard to spoof |
| `cert` issuer | 25 | cert issuance is authoritative |
| `cname` chain | 20 | DNS delegation is deliberate |
| `ptr` record | 15 | real evidence, but often generic or missing |
| `hdr` headers | 7 | weak alone — anyone can set a `Server:` header |
| `cookie` cookies | 3 | weakest — trivially fabricated |

Because each category counts once, **the percentage is not a probability and
signal count is not confidence**: six matching headers still score 7, while
one netblock hit scores 30. That is why the category list (`BASIS` in the
table, `categories` in the JSON) is the part to read — it says whether a
verdict rests on evidence the origin cannot fabricate. A verdict built only
from `hdr`/`cookie` is marked *headers only — spoofable*.

**Verdicts are ranked by confidence**, so `verdict[0]` — the vendor the
table, `--csv` and SARIF call the edge — is the best-evidenced one. A second
entry is usually the origin behind that edge (`imperva` in front of
`nginx`), shown as `+1` in the table and on a `layer` line in the block
(default mode prints that block only when the host also warrants a look; see
the triage-view note above).
Per-vendor `weights` overrides are allowed; see
[`docs/vendor-signatures.md`](docs/vendor-signatures.md) for the full table
and the "why" behind each signal.

- **A blank verdict** means the edge is not in the signature table — treat it
  as "unknown origin, no WAF/CDN signature", **not** "no WAF". The block
  prints a `leads` line with the fingerprintable headers that matched
  nothing, which is where a new signature starts.
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

**AWS WAF on CloudFront is silent to passive probes** — a normal GET returns
200 and only `--verify` sees the 403 block page. **Do not write "CloudFront,
no WAF" for a host without a `--verify` run** — same trap as FortiWeb (which
serves plain nginx to normal requests). See
[`docs/vendor-signatures.md`](docs/vendor-signatures.md) and the
[CHANGELOG](CHANGELOG.md) for the version-by-version detection additions
(AWS Global Accelerator, Kong, AWS WAF, Tencent EdgeOne, squarespace, ...).

### Signature coverage

**102 vendors** across seven families — each one a file under
`w4f/signatures/` (copy `_template.py` to add one; see
[`docs/vendor-signatures.md`](docs/vendor-signatures.md) for the
contributor guide and
[`docs/regional-coverage-matrix.md`](docs/regional-coverage-matrix.md) for
the regional research decisions):

- **CDN/edge** (45): Cloudflare, Cloudflare WAF, Imperva, Akamai (incl.
  Kona + Bot Manager `E3D=`), AWS CloudFront / WAF / ELB / Global
  Accelerator / S3 / EC2, Fastly (+ WAF/Signal Sciences), Azure Front Door,
  Azure App Gateway, ArvanCloud, Tencent EdgeOne / CDN, Baidu Yunjiasu,
  Baidu BFE, Baidu CDN, Alibaba CDN, Wangsu, ChinaCache, Huawei Cloud CDN,
  Volcengine DCDN, ByteDance, 360 PanYun, Baishan, NetEase CDN,
  Qiniu, JD Cloud, Airee, Azion, **Bunny, Gcore, WEDOS, Naver, Kakao,
  CDNetworks, Sakura**, Edgecast, MaxCDN, KeyCDN, StackPath,
  Zenedge, DDoS-Guard.
- **WAF/protection** (24): FortiWeb, F5 BIG-IP ASM, NetScaler, GTM/GSLB,
  Sucuri, ModSecurity, NAXSI, Wallarm, Wordfence, Zscaler, Google Cloud
  Armor, Radware, Reblaze, Barracuda, Huawei Cloud WAF, SafeDog, Jiasule,
  Wangsu WAF (wswaf), Knownsec Chuang Yu Shield, 360 WangZhanBao (WZWS),
  Qrator, Variti, UCloud WAF (uewaf), **Myra**.
- **Bot management** (5): DataDome, PerimeterX/HUMAN, Kasada, Shape
  Security, Arkose.
- **API gateways / platform edges** (15): Kong, Tyk, Apigee, Azure API
  Management, Tencent gateway (stgw/tRPC), Envoy, HAProxy, Tengine,
  OpenResty, Cloudflare Workers, Vercel, Google Cloud Run, AWS App Runner,
  SGW (Shopee/Sea), **WSO2** (API Manager / Carbon gateway).
- **Plain origins** (6): nginx, Apache, IIS, Caddy, LiteSpeed, Varnish.
- **Platforms** (6): Google GFE, Wix Pepyaka, Squarespace, Azure App
  Service, ByteDance TLB, **WordPress VIP** (`x-rq` POP header +
  `go-vip.net` CNAME).
- **Middleboxes** (1): **Fortinet WebFilter** — an appliance on the
  *scanner's* own path, not the target's edge. Reported as `INTERCEPTED`
  (never as a verdict) because a re-signed chain means the SPKI pin belongs
  to the middlebox, not the host.

Plus `--verify` block-page signatures for FortiWeb (EN + localized ID),
F5 ASM, Cloudflare, Imperva and **AWS WAF** ("ERROR: The request could not
be satisfied"), Akamai Kona, Sucuri, Wordfence, Wallarm.

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
      "http": { "status": "HTTP/1.1 404 Not Found", "headers": { "server": "cloudflare", "cf-ray": "a2af..." }, "set-cookie-list": [], "redirects": [], "final_host": "api.example.com" }
    },
    "verdict": [
      { "vendor": "cloudflare", "signals": 7, "confidence": 82, "categories": ["netblock", "cert", "cname", "headers"], "evidence": ["header server: cloudflare", "cname: api.example.com.cdn.cloudflare.net", ...] }
    ],
    "block": null
  }
]
```

`verdict` is ordered by confidence (best-evidenced first). `categories` is
strongest-first and is what the console renders as `BASIS`.

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

# verdicts resting only on spoofable headers/cookies — re-check these
jq -r '.[] | select((.verdict | length) > 0 and (.verdict[0].categories | inside(["headers","cookies"])))
       | "\(.hostport)\t\(.verdict[0].vendor)"' out.json

# unknown edges: the queue for the next signature file
jq -r '.[] | select(.error == null and (.verdict | length) == 0) | .hostport' out.json

# SPKI-SHA-256 pin values for every host
jq -r '.[] | "\(.hostport)\t\(.tls.cert.spki_sha256)"' out.json
```

### Exit codes

| code | meaning |
|---|---|
| `0` | everything scanned cleanly |
| `1` | at least one host errored (DNS failure, connect refused, probe exception) — results still written |
| `2` | usage error — no target source at all, unreadable `--target-json` |

## Testing

```bash
pip install .[dev]
python -m pytest
```

287 tests, offline — a local TLS server with a self-signed cert exercises the
real socket path without touching the internet. Coverage: fingerprint
matching against real-world cases from live sweep corpora + false-positive
guards (requires-gate positives/negatives, Cloudflare-WAF low-confidence,
fastly cache-node vs marketing-site, regional CloudFront
netblocks); confidence-first verdict ranking; the `--verify` block-page
matcher (FortiWeb EN/ID, F5 ASM,
Cloudflare, Imperva, AWS WAF, Akamai Kona, the title-at-end-of-39KB-body
trap); the modular signature loader (package discovery, nested subpackages,
duplicate-name / bad-regex / missing-name / unknown-key / bad-netblock
rejection, `W4F_SIGNATURES` env override); rate limiting; WS/gRPC probes;
SARIF schema shape; CSV/JSON/MD writers; CLI/report/banner (summary-table
columns and alignment under color, triage-block facts, unknown-edge leads,
sweep rollup, display ordering, per-vendor verdict colors); and end-to-end
`probe_one` against the local server.

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
