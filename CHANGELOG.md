# Changelog

All notable changes to **w4f** — passive TLS / CDN / WAF / edge
fingerprinting. Versions are semver; a `v*` tag push triggers the
trusted-publisher release to PyPI (a version-bump commit alone does not
publish — see AGENTS.md).

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
