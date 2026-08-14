# Changelog

All notable changes to **w4f** — passive TLS / CDN / WAF / edge
fingerprinting. Versions are semver; a `v*` tag push triggers the
trusted-publisher release to PyPI (a version-bump commit alone does not
publish — see AGENTS.md).

## [0.1.28] — 2026-08-14

New vendor: **wso2** (API Manager / Carbon gateway).

- `w4f/signatures/gateways/wso2.py` — `server: WSO2 Carbon Server` (set by
  WSO2's own Tomcat connector config in product-is and product-apim
  `catalina-server.xml`, confirmed from source) plus the `x-wso2-*` header
  prefix (gateway metadata headers). The API Manager gateway's fault JSON
  body (`{"fault":{"code":9009xx,...}}`) is documented as the body-side
  signal but is not expressible in the signature schema (headers/cookies/
  cert/cname/ptr/nets only).
- `wso2` gets bright-red in the verdict color map (distinct from the CDN
  hues).
- README coverage list 70 → 71; docs signal-family + color-table entries.
- +3 tests (212 total): server-header positive, x-wso2-* prefix positive,
  plain-nginx negative.

## [0.1.27] — 2026-08-14

Public Python API — fingerprint a host without the CLI.

- **`w4f.fingerprint_host(host, port=443, timeout=8, verify=False, path="/",
  no_http=False, ws_path=None, grpc=False, **kwargs)`** — runs the same
  probe the CLI runs (reuses `scanner.probe_one`, no duplicated
  handshake/HTTP logic) and returns the same per-host dict the `--json`
  output contains. Errors are a field, never an exception.
- Exported from `w4f/__init__.py` (`__all__ = ["fingerprint_host"]`) with a
  short docstring; extra kwargs accepted and ignored for forward compat.
- README "Library use" section with a 5-line example.
- +4 tests (208 total) against the local TLS fixture: JSON-shape keys,
  verify→block, no_http, error-as-field.

## [0.1.26] — 2026-08-14

Per-vendor verdict colors + README/docs refresh.

- **Vendor names are now colored per-vendor** so a glance names the edge
  (Cloudflare bright-yellow, Akamai blue, Fastly red, AWS family cyan,
  Azure bright-blue, Tencent bright-magenta, GFE magenta, F5 bright-red,
  Kong bright-cyan, FortiWeb bright-yellow, Imperva yellow). Plain origin
  stacks (nginx, Apache, IIS, Varnish, Envoy, HAProxy, …) are **dimmed**
  so edge vs origin is visible at a glance. Default green for new vendors.
  Map: `w4f/report.py` `VENDOR_COLORS` (+ family-prefix fallback).
- **Colors now honor the documented TTY + NO_COLOR contract**: previously
  ANSI codes were emitted unconditionally (even piped); now they only appear
  when stdout is a TTY and `NO_COLOR` is unset — piped output is genuinely
  plain (README already claimed this).
- **Signatures restructured to per-vendor files under per-category
  folders**: `w4f/signatures/{cdn,waf,bot,gateways,origins,platforms}/<vendor>.py`
  (70 files), loader walks subpackages recursively. The assembled table is
  byte-identical to v0.1.24/25 (verified by diff) — behavior unchanged.
  A one-time `scripts/split_signatures.py` did the mechanical split.
- **README refresh**: current version banner; new flags (`--delay`,
  `--ws`, `--grpc`) in usage + table; example output shows confidence
  (`cloudflare (7, 65%)`) and the h2 note; per-vendor color section;
  full 70-vendor coverage list by family; stale v0.1.11–14 notes
  consolidated into a pointer to the CHANGELOG; testing section now 204.
- **Docs**: `docs/vendor-signatures.md` updated to the nested layout +
  a "Console colors per vendor" reference table.

+5 tests (204 total): per-vendor distinctness, NO_COLOR off, non-TTY plain,
  nested-subpackage discovery.

## [0.1.25] — 2026-08-14

Packaging fix: the `w4f.signatures` subpackage was excluded from the wheel
(`pyproject.toml` pinned `packages = ["w4f"]`), so an installed w4f failed
with `ModuleNotFoundError: No module named 'w4f.signatures'` — caught by CI
after 0.1.24 shipped. Now `packages = {find = {include = ["w4f", "w4f.*"]}}`
auto-discovers subpackages; verified by installing the wheel into a clean
venv (70 vendors load). Content otherwise identical to 0.1.24.

## [0.1.24] — 2026-08-14

Modular vendor signatures.

- **Signatures moved to `w4f/signatures/`** — one file per vendor (or a
  small logical family: `cdn.py`, `waf.py`, `bot.py`, `gateways.py`,
  `origins.py`, `platforms.py`). Adding a vendor is now a PR that adds one
  file under that package (copy `_template.py`) plus a test — no changes to
  the matcher, CLI, or confidence engine.
- **Validating loader** (`w4f/signatures/__init__.py`): imports every
  non-private module, validates each vendor (unique `name`, allowed keys
  only, compilable regexes, valid `requires`/`weights`/netblocks), and
  assembles the exact table the fingerprint loop consumes
  (`VENDORS[name] = rules`, `name` stripped). A bad signature fails fast
  with `SignatureError` at import time.
- **`w4f/vendors.py` is now engine + assembly only** — it loads the
  signatures package and exposes the same public surface (`VENDORS`,
  `INTERESTING_HEADERS`, `vendor_nets`).
- **Optional stretch — `W4F_SIGNATURES=/path/to/rules.py`**: load extra
  local rules at startup, same schema, override/merge by name (local wins).
  No flag needed; auto-load is the default behavior.
- **Behavior preserved**: all 70 vendor rule dicts byte-identical to the
  pre-modular table, verified by an automated diff; existing tests pass
  unchanged. One pre-existing dead regex fixed en route:
  `azure-api-management` CNAME was over-escaped (`azure-api\\.net` never
  matched) and now correctly matches `azure-api.net`.
- **Docs**: `docs/vendor-signatures.md` gains the directory layout, the
  signature schema, the `requires`/`weights` reference, and a step-by-step
  "add a vendor" contributor guide.
- **Tests**: +13 loader tests (package discovery, template exclusion,
  duplicate-name / bad-regex / missing-name / unknown-key / bad-netblock
  rejection, extra-file add+override, `W4F_SIGNATURES` env hook).

200 tests total.

## [0.1.23] — 2026-08-14

SARIF 2.1.0 output for security dashboards.

- **`--sarif FILE`** — writes a SARIF 2.1.0 report (GitHub Code Scanning,
  DefectDojo, other security dashboards): one result per scanned host, rule
  ids `w4f/<vendor>` (edge identified), `w4f/block` (--verify WAF block
  page), `w4f/mtls` (server demands a client cert), `w4f/probe-error`
  (host could not be scanned), `w4f/unknown-edge` (no signature matched).
  Levels map to severity: error (probe failure), warning (edge/block/mTLS),
  note (unknown edge). The host is the SARIF location; confidence, signals,
  evidence, IPs, CNAME, TLS version, ALPN, SPKI and HTTP status ride in
  `properties`. Tool driver = w4f with the declared rules.
- Validated against the official `sarif-2.1.0.json` schema.
- Works with `--quiet` alongside `--json`/`--md`/`--csv`.
- README flags table + usage example.

+4 tests (187 total).

## [0.1.22] — 2026-08-14

Stdin/file target inputs + flat CSV output.

- **stdin pipeline mode.** When no `--target`/`--target-json`/`--target-file`/
  `--target-csv` is given and stdin is not a TTY, hosts are read from stdin
  (one `host[:port]` per line, `#` comments and blanks ignored) —
  `subfinder -d example.com -silent | w4f` works directly.
- **`--target-file FILE`** — plain-text host list, one host per line,
  comments/blanks ignored.
- **`--target-csv FILE`** — CSV target list; uses the `host`/`subdomain`
  column when the first row is a header, else the first column.
- **All sources share the existing validation** (control chars / URI
  schemes / overlong names dropped with warnings, private IPs warned) and
  are deduplicated case-insensitively after validation; `--target` mixes
  freely with file/stdin sources.
- **`--csv FILE`** — flat CSV output for spreadsheets: one row per host,
  primary (top) verdict; stable header `host,port,ips,cname,verdict,
  confidence,signals,mtls,tls_version,alpn,spki,http_status,block,error`
  via the stdlib `csv` module. Works with `--quiet` alongside `--json`/`--md`.
- README usage examples + flags table updated (pipeline example included).

+9 tests (183 total).

## [0.1.21] — 2026-08-14

Confidence accuracy fixes (found live on a CloudFront-fronted host).

- **CloudFront netblock table gap fixed.** The Jakarta edge (`3.168.0.0/14`,
  and the `3.160.0.0/14` / `108.156.0.0/14` peers) was missing, so a
  PTR-confirmed CloudFront host scored only 22% (headers 7 + ptr 15) — the
  netblock category (30) never fired. Now `aws-cloudfront` scores 52 on the
  same host (netblock 30 + headers 7 + ptr 15). Verified against AWS's
  published CLOUDFRONT ranges (the other large /14s were already present).
- **Block confidence.** `--verify` block pages now carry `confidence: 95` —
  a block page is the edge's OWN WAF page (the strongest possible signal),
  but it comes from `verify_block`/`match_block_page`, which never passed
  through `fingerprint()`. Console and `--md` show it (`[95% conf]`).
  `block.confidence` is set in probe_one.

+2 tests (174 total).

## [0.1.20] — 2026-08-14

Rate limiting, WS/gRPC probes, vendor-signature docs.

- **Per-domain adaptive rate limiting (`--delay`).** `Throttle` class with
  per-domain delay tracking: the submit loop sleeps `--delay` (default 0 =
  no pacing) between submissions; on a 429/503 the domain's delay doubles
  (cap 10s) and a success resets it. Keeps sweeps polite against
  rate-limited targets without slowing scans that never hit a limit.
  +5 tests.
- **WebSocket upgrade probe (`--ws PATH`).** Sends an RFC 6455 upgrade
  request and reports whether the edge answers `101 Switching Protocols`
  (and the `Sec-WebSocket-Accept`), or which component rejects it — WAF/CDN
  edges often treat Upgrade differently from a plain GET. +4 tests.
- **gRPC health-check probe (`--grpc`).** POSTs a gRPC health-check frame
  and reports `grpc-status`/`grpc-message` or the HTTP/2 binary-framing
  answer — best-effort, since real gRPC is HTTP/2 and w4f's GET is
  deliberately HTTP/1.1 (pairs with the ALPN observation). +3 tests.
- **Vendor signature reference (`docs/vendor-signatures.md`).** Why each
  signal family (headers/cookies/cert/CNAME/PTR/netblock) identifies its
  vendor, the confidence weights, required-signal gating, and how to read
  multi-layer answers. Linked from the README.
- **Housekeeping:** the last private `ssl._create_unverified_context()`
  call site (verify_block) now uses the public `_unverified_ctx()`.

+12 tests (172 total).

## [0.1.19] — 2026-08-14

Review-driven improvements (P0 confidence scoring + ALPN observation, vendor
coverage expansion).

**P0 — Fingerprint confidence scoring.** Each verdict match now carries a
`confidence` field (0–100) computed from weighted signal categories:
netblock 30, cert issuer 25, CNAME 20, PTR 15, headers 7, cookies 3 —
each category counted once, per-vendor `weights` override supported. A
5-category Cloudflare match scores ~82, a lone `Server: nginx` header
scores 7, so consumers can triage `--json` without guessing. Signal-count
ranking stays the default sort; confidence is an additional field shown
alongside it in console/`--md` output. Backward-compatible.

**P0 — ALPN observation.** `alpn_negotiated` is reported on every result
(the handshake already negotiated ALPN; now it's surfaced distinctly), and
when the edge negotiates `h2` but the GET used HTTP/1.1 (h2 frames would
read as garbage), `http2_negotiated: true` + a note explain that the header
view is the HTTP/1.1 view. Shown as a `http2` console row.

**Vendor coverage +16 vendors (54 total).** Bot-management edges:
`datadome`, `perimeterx` (HUMAN), `kasada`, `shape-security`, `arkose`,
`reblaze`, `radware`. API-gateway / platform edges: `tyk`, `apigee`,
`azure-api-management`, `cloudflare-workers`, `gcp-armor`. Plus `squarespace`
(from the big sweep, already in 0.1.18).

**Header prefix matching.** Header rules may end in `*` for prefix matching
(`x-tyk-*` matches `x-tyk-request-id`); exact keys stay exact. The
arvancloud lesson is preserved — a glob that never fires is a dead rule,
but a prefix against variable-suffix headers is a real match.

+18 tests (160 total).

## [0.1.18] — 2026-08-14

Big internet sweep (275 hosts, oracle-validated) — accuracy batch.

**New mechanism: `requires` (AND/OR gate for composite rules).** The
fingerprint loop previously OR'd every signal kind within a vendor, so a
single matching signal could fire a composite rule. `requires` adds an
optional gate: a list of alternatives (OR across), each a single spec or a
list that must ALL match (AND within). Used to fix:
- **aws-waf no longer fires on any bare 403** — the CloudFront+WAF shape
  needs 403 AND `x-cache: error from cloudfront`; the ALB shape needs an
  x-amz-* marker. A Cloudflare challenge 403 (berkeley.edu) was claiming
  aws-waf before.
- **google-gfe no longer phantoms on GTS-issued certs** — Cloudflare (and
  many others) now use Google Trust Services CAs, so a GTS issuer alone
  claimed google-gfe on every Cloudflare host (58 noisy co-matches →
  2, both real Google-Cloud origins: linkedin, tiket).

**False-positive fixes (found by the sweep):**
- **fastly `x-served-by` requires a cache node** (`cache-<po>`) — mere
  presence matched Cloudflare's own `x-served-by: marketing-site` and
  claimed fastly on cloudflare.com.

**New vendor:** `squarespace` (managed platform edge, `server:
Squarespace`) — the oracle named it, w4f was UNKNOWN.

**Accuracy vs oracle (254 reached hosts): 150 agree / 68 w4f-better / 11
disagree / 25 blank, 0 w4f errors = 94% correct-or-better.** All 11
remaining disagreements are oracle false positives (Envoy on Akamai hosts,
Shadow Daemon on plain Apache, GCP App Armor on Wix's Pepyaka) or
semantic layers (CloudFront vs AWS-ELB on AWS-family hosts) — no real w4f
gaps. +11 tests (142 total).

## [0.1.17] — 2026-08-14

Security-review batch (5 findings).

- **Input validation on target hostnames** (MEDIUM). `--target` and
  `--target-json` targets are validated at load: control characters
  (newlines/NUL — log injection, weird DNS), URI schemes (`file://` etc.),
  whitespace-in-hostname, and overlong names (>253 chars) are dropped with
  a warning. **Private/internal IPs (10.x, 192.168.x, 127.x, 169.254.x)
  are warned but NOT dropped** — scanning internal infrastructure is a
  legitimate use. +9 tests (`TestHostportValidation`).
- **Public-API unverified TLS context** (MEDIUM). Replaced the private
  `ssl._create_unverified_context()` with `ssl.create_default_context()` +
  `CERT_NONE`/`check_hostname=False` (the documented public equivalent).
  Certificate verification stays off by design — fingerprinting must read
  self-signed/expired certs as evidence — and the README now says so.
- **Test temp-file hygiene** (LOW). The local TLS server fixture now uses a
  `tempfile.TemporaryDirectory` that auto-cleans on close/GC even if a test
  is interrupted; `NamedTemporaryFile(delete=False)` files no longer leak.
- **Disclosure + pin-semantics documentation** (LOW/INFO). README gains a
  "Security notes" section: SPKI-SHA-256 is a fingerprint, not a trust
  anchor; `--json` output (cert chains, pins, CNAME/PTR, IPs) can disclose
  infrastructure and should be treated as sensitive; unverified TLS is
  deliberate and means MITM is not detected.

## [0.1.16] — 2026-08-14

Code-review batch (15 items from the review issue: 2 bugs, vendor
additions, block pages, QA coverage, code quality).

**Bug fixes**
- **bytedance CNAME no longer includes `akamaized`** — that suffix belongs
  to Akamai customers; matching it made every `*.akamaized.net` host also
  claim `bytedance`. ByteDance-owned suffixes only (`bytecdn|byteimg|
  byteacctimg|tikcdn|tiktokcdn`); the TikToken CNAME now fires correctly.
- **aws-waf passive rule anchored** — `x-cache` now matches
  `^error from cloudfront$` so ordinary CloudFront 403s (origin errors) are
  no longer labeled WAF.

**New vendors / signals**
- `cloudflare-waf` — Bot Management / managed-challenge verdicts distinct
  from CDN-only: `cf-mitigated: challenge|blocked`, `cf-chl-bypass`,
  `cf-waf-rule-id`, `__cf_bm` / `cf-waf-token` / `cf_chl_` cookies.
- Cloudflare Turnstile/challenge signals on the base vendor: `cf_turnstile_`,
  `cf_chl_` cookies, `cf-mitigated` header.
- Akamai Bot Manager E3D tag inside the `ak_bmsc` cookie.
- `vercel` (`x-vercel-id`/`x-vercel-cache`/`*.vercel.app`),
  `google-cloud-run` (`x-cloud-trace-context`/`*.run.app`),
  `aws-app-runner` (`x-app-runner-region`/`*.awsapprunner.com`).
- OpenResty `x-openresty` header signal.
- `fastly-waf` — Signal Sciences signals (`signal-attack`, `__SignalShield_`).
- 4 new `--verify` block-page signatures: Akamai Kona ("Access Denied"),
  Sucuri ("Sucuri Firewall"), Wordfence, Wallarm.

**Code quality**
- `cryptography < 42` compat: `not_valid_before_utc` getattr fallback with
  tz-aware normalization (old builds raise AttributeError on the *utc
  accessor; the fallback was silently swallowing it).
- Debug logging for the previously bare `except` sites (DNS resolution, TLS
  probe) — still never raises, but the failure reason is available at
  DEBUG level now.

**QA coverage (+23 tests, 121 total)**
- `_load_targets_from_json` hosts/targets/results dict keys + host/name
  fields in objects; IPv6 literal + DNS-failure resolve; `--no-http` path;
  JSON output schema; multi-vendor ranking; timeout error dict; redirect to
  HTTP scheme; chunked/garbage `parse_http_response`; empty/long
  `match_block_page` titles; new-vendor and block-page cases.

## [0.1.15] — 2026-08-14

Rules mined from the Indonesian bank subdomain sweep's 489-host UNKNOWN
bucket. Verified live against the hosts that exposed them.

- **`azure-frontdoor`** now also fires on `x-cache: CONFIG_NOCACHE` /
  `CONFIG_CACHE` — Front Door's cache-config marker, served by some
  corporate Atlassian intranet hosts with a hidden
  server header and no `x-azure-ref`. Confirmed against Microsoft docs.
- **`sgw`** — `Server: SGW` = Shopee/Sea Group API gateway; bank
  UAT/staging hosts (apm-uat1, notice.staging, ...).
- **`iis`** — plain Microsoft IIS / HTTPAPI origin (mail/webmail/
  autodiscover hosts); naming a bare origin beats "unknown".
- 23/489 UNKNOWNs rescued (6 Azure Front Door + 5 SGW + 12 IIS).
- Tests: 94 passing.

## [0.1.14] — 2026-08-14

- **`aws-global-accelerator`** — AWS Global Accelerator has no
  `elb.amazonaws.com` CNAME, so every AWS rule missed it. Detected via
  `15.197.0.0/16` + `3.33.0.0/16` netblocks (GLOBALACCELERATOR ranges from
  ip-ranges.amazonaws.com) and PTR `*.awsglobalaccelerator.com`.
  Found live on an Indonesian bank's public website: 15.197.x/3.33.x,
  301s to the corporate portal from `ip-*.eu-west-2.compute.internal`;
  the oracle called it "AWS ELB".
- Tests: 91 passing.

## [0.1.13] — 2026-08-14 (code milestone; tagged with 0.1.14)

- **`kong`** — Kong API gateway via `X-Kong-Upstream-Latency` /
  `X-Kong-Proxy-Latency` headers (and `Server: kong` on older builds).
  Verified live: example-ride.com.
- Tests: 88 passing.

## [0.1.12] — 2026-08-14 (code milestone; tagged with 0.1.14)

- **AWS WAF on CloudFront detected.** CloudFront + AWS WAF managed rules
  answer a normal GET with 200 and only block attack-shaped queries with
  403 + `x-cache: Error from cloudfront` + the block page "ERROR: The
  request could not be satisfied / Request blocked" — silent to passive
  probes, the same trap as FortiWeb.
  - `--verify` matches the AWS WAF block page (`aws-waf`).
  - Passive `aws-waf` fires on the 403 + error-cache shape via a new
    `_status` pseudo-header.
  - Confirmed deployments in the Indonesian ecosystem:
    example-hospital.com, a bank's API host, example.com, example-travel.com.
- Standing rule added: never write "CloudFront, no WAF" without a
  `w4f --verify` run.

## [0.1.11] — 2026-08-14 (code milestone; tagged with 0.1.14)

Internet-wide accuracy sweep (138 hosts vs an independent active WAF
detector): disagreements dropped 31 → 6.

- **Redirect-following** (`http_get` now follows up to 5 hops): the WAF
  often lives only on the www response while the apex is a redirector
  (`example-news.com` apex said `varnish`, `www.example-news.com` is Akamai Kona).
  Chain recorded as `redirects` / `final_host`.
- **Akamai Kona signals**: `AkamaiGHost`, `akamai-grn`, `x-grn`,
  `x-akamai-transformed`, `akamai-request-bc` — 12 hosts were missed
  before.
- **5 new vendors**: `tengine` (Alibaba), `tencent-gateway` (stgw/tRPC),
  `bytedance` (TikTok TLB), `pepyaka` (Wix), `azure-app-service`
  (ARRAffinity).
- Result vs oracle: 62 agree + 44 w4f-better + 6 semantic-layer
  differences where w4f is more specific (e.g. TikTok = ByteDance edge,
  not the Akamai node in its chain). Evidence:
  `experiments/accuracy-sweep-2026-08-14/`.

## [0.1.10] — 2026-08-14

- First release on PyPI via the trusted-publisher workflow (`publish.yml`),
  OIDC, no token.
- Release checklist documented in AGENTS.md: bump `__version__` in
  `w4f/__init__.py` + `pyproject.toml`, README banner, `python -m build`,
  `twine check`, tests, `git tag v<version> && git push origin v<version>`.
