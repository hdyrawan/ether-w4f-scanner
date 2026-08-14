# w4f vendor signature reference

Why each signal identifies the vendor it does. The rule table in
`w4f/vendors.py` is the machine-readable source of truth; this file is the
human-readable *why*. For a full list of vendors and their live evidence,
run `w4f --target <host>` and read the `verdict` line.

## How signals are weighted

A verdict match carries a `confidence` (0–100) built from weighted signal
categories, each category counted once:

| category | weight | why it's strong |
|---|---|---|
| netblock | 30 | IP ownership is hard to spoof — the edge's anycast/AS range is assigned by the vendor |
| cert issuer | 25 | cert issuance is authoritative — only the vendor (or its CA program) issues certs under its own name |
| CNAME chain | 20 | DNS delegation is intentional — pointing a host at a vendor CNAME is a deliberate routing decision |
| PTR record | 15 | moderate — PTRs are often generic or missing, but a vendor-shaped PTR is real evidence |
| headers | 7 | weak alone — anyone can set a `Server:` header |
| cookies | 3 | weakest — cookies are trivially fabricated |

A host inside Cloudflare's netblock with a Cloudflare-issued cert, a
`.cdn.cloudflare.net` CNAME, and Cloudflare headers scores ~82/100. A bare
`Server: nginx` header scores 7. Use the number to triage: high confidence =
almost certainly that vendor; low confidence = a single weak signal that a
different component could also emit.

Some rules gate on *required* signals (AND/OR semantics via the `requires`
field) so a single weak signal can never fire a composite rule — e.g.
`aws-waf` needs a 403 **and** an AWS-specific marker, never a bare 403.

## The signal families

### Headers

- `server` — the easiest signal, and the easiest to fake. Real edges set it
  honestly (Cloudflare, Fastly, AkamaiGHost, Pepyaka, TLB, …); origins
  behind them set it to their own stack (nginx, Apache, …). A `server`
  match is never high-confidence alone.
- `via` — proxies/gateways append themselves. `via: 1.1 varnish` (Varnish),
  `via: …cloudfront.net` (CloudFront), `via: ens-cache…` (NetScaler).
- `x-cache` — cache result line. CloudFront uses `Hit from cloudfront` /
  `Miss from cloudfront` / **`Error from cloudfront`** (the WAF-block
  marker). Fastly/CDN77 use their own tokens.
- `x-served-by` — Fastly cache nodes name themselves `cache-<po>` (e.g.
  `cache-sin-wsap440094-SIN`). **Presence alone is NOT enough** —
  Cloudflare's own marketing site sends `x-served-by: marketing-site`.
- `x-timer` — Fastly's request-timing header.
- `cf-ray` / `cf-cache-status` / `cf-mitigated` — Cloudflare. `cf-mitigated:
  challenge|blocked` is a **Bot-Management verdict** (see cloudflare-waf).
- `x-iinfo` + `incap_ses_*`/`visid_incap_*` — **Imperva**. `x-iinfo` is
  Imperva's decision/score header; the incap cookies are its session tokens.
- `x-amz-cf-id` / `x-amz-cf-pop` — CloudFront request id + point-of-presence.
- `x-amz-id` / `x-amz-request-id` / `x-blocked-by-waf` — **AWS WAF** on
  ALB/API Gateway. `x-blocked-by-waf: awsmanagedrules` names the rule set.
- `x-azure-ref` — Azure Front Door / CDN request id.
- `x-sucuri-id` / `x-sucuri-cache` — Sucuri CloudProxy.
- `eo-log-uuid` / `eo-cache-status` — Tencent EdgeOne.
- `x-kpsdk-ct` / `x-datadome` / `x-px-*` / `x-tyk-*` — bot-management and
  gateway products (Kasada, DataDome, PerimeterX, Tyk). Prefix rules
  (`x-tyk-*`) match variable-suffix headers.

### Cookies

- `TS[hex]{6,12}=` — **F5 BIG-IP ASM** anti-bot challenge cookie. Too-short
  patterns miss the real builds.
- `ak_bmsc` / `bm_sz` / `_abck` / `akavpau_` — **Akamai Bot Manager**.
  `ak_bmsc` carrying an `E3D=` tag is the current Bot Manager session.
- `ARRAffinity` — Azure App Service (stickiness cookie).
- `incap_ses_*` — Imperva.
- `__cf_bm` / `cf_chl_*` / `cf_turnstile_*` — Cloudflare Bot Management /
  Turnstile challenge.
- `datadome=`, `_pxhd`, `kpsdk_ct`, `shape_`, `arkose`, `rbzid`, `mpev_` —
  DataDome, PerimeterX, Kasada, Shape, Arkose, Reblaze, Radware.
- `HWWAFSESID=` (Huawei Cloud WAF), `FORTIWAFSID=` (FortiWeb),
  `__ddg` (DDoS-Guard).

### Certificate issuer

The CA name in the leaf cert. `cert: Cloudflare, Inc.` is Cloudflare (they
run their own CA program); `cert: Google Trust Services` is **not** Google
— GTS now issues for Cloudflare and many others, so a GTS issuer alone
never fires google-gfe (it needs a `server: gws|gfe|esf` or a
1e100.net PTR).

### CNAME chain

A deliberate delegation. `.cdn.cloudflare.net`, `*.akamaized.net`,
`*.fastly.net`, `*.azure-api.net`, `*.eo.dnse4.com` (Tencent EdgeOne),
`*.dnsv1.com.cn` (Tencent Cloud CDN). A CNAME to `*.akamaized.net` is
Akamai — and **not** ByteDance (akamaized is Akamai-exclusive).

### PTR / reverse DNS

`*.1e100.net` / `*.googleusercontent.com` = Google Cloud origin.
`*.awsglobalaccelerator.com` = AWS Global Accelerator.
`*.cloudfront.net` = CloudFront. `*.deploy.static.akamaitechnologies.com`
= Akamai.

### Netblocks

Vendor-owned IP ranges (anycast for Cloudflare/Akamai/Fastly, ASN-owned for
Imperva, AWS GA's 15.197/3.33, etc.). The strongest single signal because
it cannot be faked by a misbehaving origin.

## Multi-layer answers

w4f reports every vendor that matches — a host is often *edge + origin*:
`cloudflare (edge) + google-gfe (GCP origin PTR)` or
`aws-cloudfront (edge) + aws-s3 (origin server header)`. That is a finding,
not noise: the first name is the edge you fight (WAF/CDN), the rest is the
origin behind it. Ranked by signal count, so the edge with the most
evidence is first.

## Reading a verdict

```
verdict  cloudflare (5, 82%): header server: cloudflare; header cf-ray: …;
         cookie: __cf_bm=…; cert: Cloudflare, Inc.; netblock: 104.18.1.79 in 104.16.0.0/13
```

`(5, 82%)` = five evidence strings, 82% confidence. Every evidence string
names its category so you can judge it yourself.
