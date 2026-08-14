# Changelog

All notable changes to **w4f** — passive TLS / CDN / WAF / edge
fingerprinting. Versions are semver; a `v*` tag push triggers the
trusted-publisher release to PyPI (a version-bump commit alone does not
publish — see AGENTS.md).

## [0.1.15] — 2026-08-14

Rules mined from the Indonesian bank subdomain sweep's 489-host UNKNOWN
bucket. Verified live against the hosts that exposed them.

- **`azure-frontdoor`** now also fires on `x-cache: CONFIG_NOCACHE` /
  `CONFIG_CACHE` — Front Door's cache-config marker, served by EXAMPLE_BANK's
  Atlassian intranet hosts (bitbucket/confluence/eproject) with a hidden
  server header and no `x-azure-ref`. Confirmed against Microsoft docs.
- **`sgw`** — `Server: SGW` = Shopee/Sea Group API gateway; EXAMPLE_BANK
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
  Found live: `bank-example.com` → 15.197.x/3.33.x, 301s to corporate-portal.example.com from
  `ip-*.eu-west-2.compute.internal`; the oracle called it "AWS ELB".
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
  - Confirmed deployments: example-hospital.com, bank-example.co.id, example.com,
    example-travel.com.
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
