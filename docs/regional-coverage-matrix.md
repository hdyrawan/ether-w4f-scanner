# Regional edge coverage matrix — China / Japan / Korea / Europe

Research date: 2026-08-15. Batch: v0.1.40.

Method: for each candidate, gather independent evidence (DNS/CNAME, vendor
docs, live probes of vendor properties and customer hosts, published IP
lists) and decide PROMOTE / REJECT / UNKNOWN. Only evidence-backed rules
entered the signature table; every rejection below is intentional and
documented. Evidence order preference: vendor-published edge ranges >
network ownership > distinctive CNAME > certificate > TLS/HTTP behaviour >
cookies > generic headers. Generic headers are never strong attribution.

## Promoted (added in v0.1.40)

| Vendor | Region | Role | CNAME | Netblock | TLS | HTTP | Cookie | Block | Provenance | Confidence | Decision |
|---|---|---|---|---|---|---|---|---|---|---|---|
| bunny | EU (SI) | CDN | `bunnycdn.com`, `b-cdn.net` | — (published list is churny /32s) | — | `Server: BunnyCDN-<POP>-<id>` | — | live probe of the vendor's own properties 2026-08-15 | HIGH (server token + CNAME) | PROMOTE |
| gcore | EU/RU | CDN/WAF | `*.gcdn.co` (cl-*.gcdn.co per Gcore docs) | — (published API is ~990 churny /32s) | — | — | — | Gcore docs CNAME contract; Malwarebytes/Netify attribution | HIGH (CNAME + docs) | PROMOTE |
| wedos | CZ | CDN/hosting | — | — | — | `x-cdn-provider: WEDOS Global CDN` | — | live probe of the vendor's own site 2026-08-15 | HIGH (explicit provider header) | PROMOTE |
| myra | DE | WAF/CDN | — | — | — | `Server: myracloud` | — | live probe of the vendor's own site 2026-08-15 | HIGH (clean server token) | PROMOTE |
| naver | KR | CDN/portal/cloud | `nheos.com`, `naverncp.com` | — | — | `Server: nfront` | — | live probe of the vendor's own properties + a naverncp customer 2026-08-15 | HIGH (CNAME + server) | PROMOTE |
| kakao | KR | GSLB/edge | `kgslb.com` | — | — | — | — | live probe of Kakao's own portal (kgslb.com CNAME); Netify = Kakao Corp | MEDIUM-HIGH (CNAME only, distinctive) | PROMOTE |
| cdnetworks | KR/JP/global | CDN | `cdngc.net`, `cdnetworks.com` | — | — | corroborating: `Server: PWS/`, `Via: ...(W)` | NOT used: FECW is shared with Wangsu | live probe of the vendor's own site + a Korean media customer 2026-08-15 | MEDIUM-HIGH (CNAME primary; shared FECW explicitly excluded) | PROMOTE |
| sakura | JP | hosting/CDN | `*.gslb*.sakura.ne.jp` | — | — | — | — | live probe of the vendor's own properties 2026-08-15 | HIGH (CNAME, distinctive JP brand) | PROMOTE |

## Investigated and rejected / left passive

| Vendor | Region | Evidence examined | Reason | Decision |
|---|---|---|---|---|
| nhn (Toast Cloud) | KR | `toastoven.net` GTM CNAME on the vendor's own site | GTM-shaped DNS LB, not a distinctive edge; risk of overclaiming the product | REJECT |
| leaseweb | EU (NL) | the vendor's own CNAME (leasewebultracdn.com); the site itself is Fastly-served | their own site is Fastly-served (`x-served-by` Fastly node); CNAME exists but edge identity ambiguous | REJECT (weak) |
| voxility | EU (RO) | `not-a-bot` cookie on voxility.com | cookie name is plausibly generic; single observation | REJECT (weak) |
| xserver | JP | vendor home probes — no CNAME signal from the vendor home | no customer-side CNAME evidence obtained this pass | UNKNOWN — needs customer evidence |
| iij | JP | vendor home probes — plain Apache | no passive signal | REJECT |
| j-stream | JP | no response | no evidence | UNKNOWN |
| kddi | JP | kddi.com — plain Apache | no passive signal | REJECT |
| ntt communications | JP | ntt.com — Akamai edgekey CNAME (their own site on Akamai) | no NTT-specific passive signal | REJECT |
| biglobe | JP | vendor home — CloudFront | no passive signal | REJECT |
| cdnetworks netblocks | KR | ASN aggregators (AS36408/AS38107) only | goal: ASN aggregators ≠ vendor-published ranges; no official list found | no netblock |
| kingsoft (KSYUN) | CN | vendor home self-CNAME only | no customer CNAME evidence this pass | UNKNOWN |
| qingcloud | CN | vendor home self-CNAME only | no CDN CNAME evidence | UNKNOWN |
| ucloud CDN | CN | vendor home CNAME (self) — uewaf already covered | CDN product signal not verified | UNKNOWN (uewaf WAF already in table) |
| kt (KT Cloud) | KR | vendor home probes — no signal | no passive signal | REJECT |
| lg u+ | KR | vendor home — Cloudflare CNAME | no passive signal | REJECT |
| sk broadband | KR | no evidence obtained | — | UNKNOWN |
| link11 | DE | link11.com — WP Polylang cookie only | no edge signal | REJECT |
| cdn77 | EU | vendor home — no response to probes | no evidence | UNKNOWN |
| gcore netblocks | EU/RU | official API (api.gcore.com/cdn/public-ip-list) = ~990 individual /32s | /32-granular + churns; no stable covering prefixes; per goal only add ranges representing the edge product | no netblock |
| bunny netblocks | EU | official plain list (api.bunny.net/system/edgeserverlist/plain) = 588 individual IPs | same /32-granular + churn; covering prefixes would include unrelated space | no netblock |

## Netblock rules added in this batch

None. No candidate met all four netblock gates (vendor-published stable
ranges + edge-product scope + boundary tests + no overlap). This is a
deliberate outcome: v0.1.39's sucuri batch set the bar; bunny/gcore publish
lists but at /32 granularity with churn, which fails the stability gate.

## Remaining regional coverage gaps (provisional)

- China: Kingsoft KSYUN CDN, QingCloud CDN, UCloud CDN (product-level)
  CNAME evidence still needed — the WAF layer (uewaf) is covered.
- Japan: XServer CDN (need customer CNAME), J-Stream video CDN.
- Korea: KT Cloud CDN, NHN Toast CDN (product-level CNAME evidence), SK.
- Europe: CDN77, Link11, Voxility (weak/generic signals only), national
  CDNs — evidence insufficient this pass.
- Netblocks for any regional vendor remain open until a stable
  vendor-published range list is found (bunny/gcore churn at /32).

## Weak/provisional evidence notes

- kakao: single-domain (kgslb.com) CNAME rule — strong within Kakao
  properties, unproven elsewhere; no netblock corroboration.
- cdnetworks: PWS server token + (W) via nodes are corroborating but the
  rule keys on CNAME only to avoid the FECW shared-marker trap.
- naver: `nfront` server token verified on two Naver properties; naverncp
  CNAME verified on one Korean media host.
