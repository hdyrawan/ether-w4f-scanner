# Changelog

All notable changes to **w4f** — passive TLS / CDN / WAF / edge
fingerprinting. Versions are semver; a `v*` tag push triggers the
trusted-publisher release to PyPI (a version-bump commit alone does not
publish — see AGENTS.md).

## [0.1.40] — 2026-08-15

Regional edge coverage batch (KR / JP / EU) — research-first, per the
regional-coverage goal. **8 new vendors (94 → 102)**, every one backed by
independently verified evidence with provenance recorded in
[`docs/regional-coverage-matrix.md`](docs/regional-coverage-matrix.md).

New vendors:

- **Korea (3):** `naver` (`nheos.com` / `naverncp.com` CNAMEs + `server:
  nfront`), `kakao` (`kgslb.com` GSLB CNAME — Kakao's own portal → daum-*.kgslb.com),
  `cdnetworks` (`cdngc.net` / `cdnetworks.com` CNAMEs — CDN Global Cache).
- **Japan (1):** `sakura` (`*.gslb*.sakura.ne.jp` CNAME).
- **Europe (4):** `bunny` (`Server: BunnyCDN-<POP>-<id>` + bunnycdn.com /
  b-cdn.net CNAMEs), `gcore` (`cl-*.gcdn.co` CNAME per Gcore's own docs),
  `wedos` (`x-cdn-provider: WEDOS Global CDN` header), `myra` (`Server:
  myracloud`).

Evidence discipline:

- **No netblocks added.** bunny and gcore both publish official edge lists
  (api.bunny.net/system/edgeserverlist/plain; api.gcore.com/cdn/
  public-ip-list) but both are /32-granular and churn — they fail the
  stability gate from v0.1.39's sucuri methodology. Documented in the
  matrix.
- **Shared markers excluded:** the FECW cookie (CDNetworks + Wangsu) and
  `server: ATS` (WEDOS's Apache Traffic Server is generic) are NOT signals;
  the cdnetworks rule keys on CNAME only.
- **Rejected with documentation:** NHN Toast (GTM-shaped CNAME), Leaseweb
  (own site Fastly-served), Voxility (`not-a-bot` cookie too generic),
  XServer/IIJ/J-Stream/KDDI/NTT/BIGLOBE/KT/LG U+/Link11/CDN77 (no passive
  signal), Kingsoft/QingCloud/UCloud CDN (self-CNAME only, no customer
  evidence this pass).

Tests: +23 (416 passed, 5 skipped) — positive/negative per new rule, the
FECW shared-cookie collision negative, and 3 new attribution-corpus
fixtures (regional_naver, regional_bunny with a varnish LAYER,
regional_shared_cookie_unknown). Corpus tally (11 fixtures): 6 correct /
1 ambiguous / 2 unknown / 1 intercepted / 1 error / 0 incorrect.

## [0.1.39] — 2026-08-15

Netblock coverage — first batch. `sucuri` gains its officially-published
edge ranges, the strongest (weight-30) signal type, extending the set of
vendors carried by IP ownership from six to seven.

- **`sucuri` netblocks.** Sucuri is a pure-play cloud WAF/CDN, so a fronted
  host resolves into Sucuri's own anycast space — the netblock corroborates
  the header/block-page match and, more usefully, still fingerprints Sucuri
  when it cloaks the origin's headers or refuses the passive GET (DNS +
  netblock need no HTTP at all). Ranges are Sucuri's OWN published Firewall
  IP list (`docs.sucuri.net`, verified 2026-08-15), not ASN/BGP-derived
  prefixes; a dated provenance note lives in the signature file.
- **Scope discipline.** Only pure-play edges whose entire IP space *is* their
  edge are eligible — product-tier variants that share a parent's IPs
  (`cloudflare-waf`, `fastly-waf`) must never inherit the parent's ranges, or
  every plain-CDN host would false-match the WAF tier. `stackpath`/`maxcdn`
  (CDN discontinued 2023 → reassignment risk) and `ddos-guard` (no official
  list, only third-party ASN aggregators) were evaluated and deliberately
  left header/cookie-only.
- +3 tests (393 total): Sucuri netblock positive (four ranges), negative
  (addresses just outside the ranges must not match — a wrong netblock is a
  false positive on the strongest signal), and hard-evidence band. The
  `test_no_cross_vendor_netblock_overlap` guard (0.1.38) covers the new
  ranges.

## [0.1.38] — 2026-08-15

Stabilization pass (external review): make the default output calm and
table-first, fix one clear false-positive bug, and document the model for
operators. No new attribution states/fields, no scoring changes, no new
vendor families.

- **Default output is now table-first.** The summary table remains the
  primary glanceable view; a per-host block is printed **only for hosts that
  need a look** — UNKNOWN, AMBIGUOUS, INTERCEPTED, ERROR, a block page, mTLS,
  or a genuinely competing edge (a MEDIUM+ alternative). A cleanly attributed
  host is fully described by its table row and gets no block, so a large
  sweep stays scannable instead of scrolling one dense block per host. New
  `report.needs_detail_block()` encodes the rule; `--verbose` is unchanged
  and still prints the full analytical block for every host.
- **The default block no longer restates the table.** The triage block
  dropped the rows that merely repeat table columns (path, TLS, cert
  issuer/expiry, SPKI pin) and the SAN row; those are the table cells and the
  `--verbose` view. An UNKNOWN block is now leads-only — and the CNAME/PTR
  (often the CDN's own naming, the strongest lead for the next signature) are
  surfaced in the `leads` line rather than buried in a dropped OBSERVED block.
- **Bug fix — imperva carried a Cloudflare netblock.** `103.21.244.0/22` is a
  published Cloudflare range but was also listed under `imperva`, so a host
  in it double-matched on netblock and read as a spurious cloudflare/imperva
  ambiguity. Removed. A new loader test (`test_no_cross_vendor_netblock_overlap`)
  fails the build if any two vendors ever claim the same range again.
- **Docs.** The README "Example output" and state table now reflect the
  table-first behavior and name every state (ATTRIBUTED / AMBIGUOUS /
  UNKNOWN / INTERCEPTED / ERROR); the existing "Reading a verdict" section
  already explains that confidence is a weighted evidence sum, not a
  probability.
- Tests updated for the intentionally-changed default block (SAN/SPKI/path →
  `--verbose`); `+` new `needs_detail_block` coverage. Full suite green.

## [0.1.37] — 2026-08-15

Automation ergonomics (user request): `--no-banner`.

- **`--no-banner`** suppresses the ASCII banner + version tagline so the
  output starts directly at the summary table — for piping the triage table
  into scripts/column parsers without a 9-line figlet header. Composes with
  the rest: `--quiet` still suppresses everything; `--verbose`/table output
  are unaffected. (This is deliberately NOT `--banner-only` — that flag
  duplicated default behaviour and was removed; suppressing noise for
  automation is a different job.)
- +3 tests (384 total): parser default/flag, output starts at the table
  with no art/tagline.

## [0.1.36] — 2026-08-15

Makes the 0.1.35 attribution model explainable to an analyst. No new
dependencies, no new CLI flags, no scoring change, no new vendor signatures.

**LAYER is not an ALTERNATIVE.** An origin under a real edge
(`cloudflare → varnish`) was listed among the alternatives, which invited
reading it as a competing edge vendor. `attribute()` now splits the two
using the `deployment` the vendors already declare: `alternatives` holds
competing **edge** candidates, `layers` holds what the edge fronts. The
default block gains a `layer` row and `--verbose` a `LAYER` section drawn as
a stack. A weaker *edge* candidate is still an alternative.

**`EVIDENCE` is now readable as evidence.** One category per heading and one
observation per line, instead of a run-on joined string:

```
EVIDENCE
  Network
    104.18.1.79 in 104.16.0.0/13
  CNAME
    www.example.com.cdn.cloudflare.net
  HTTP
    server: cloudflare
```

`attribution.evidence[]` therefore carries `details` (a list) in place of
`detail` (a joined string) — the only shape change, in a field one release
old.

**Category naming.** The header category renders as `http` rather than
`hdr`, matching the `HTTP` evidence label. Affects the console `BASIS` cell
and the `basis` CSV column.

**Default block** gains explicit `TLS` and `SPKI` rows (the pin was `pin`,
and TLS was buried inside the `path` row).

**Duplication removed** — the review the goal asked for found two copies of
knowledge the model already owned:

- `_ORIGIN_VENDORS`, a hand-maintained list of origin stacks in `report.py`,
  had already drifted from the signature table (missing `aws-ec2`). Origin
  colouring now reads the declared `deployment`.
- `_HARD_CATS` / `_is_weak()` restated evidence strength in the renderer;
  `attribution.HARD_CATEGORIES` / `is_weak()` own it, and `cli.py` uses it
  for risk ordering.

**Validation corpus** (`tests/fixtures/attribution/`, 8 fixtures). Each
stores **observations only**, so a case runs the real pipeline — signature
matching, then interpretation — rather than pre-baked verdicts; a signature
change that quietly breaks attribution fails there. Covers strong
multi-category attribution, partial connectivity (DNS survives a failed
handshake), weak header-only attribution, ambiguous competing edges,
unknown, interception, edge-over-origin layering, and a host error with
nothing surviving. All synthetic: RFC 5737 addresses, `example.*` names, and
the published vendor infrastructure the signatures match on.

`test_attribution_corpus.py` tallies outcomes — correct, ambiguous, unknown,
intercepted, error, and **incorrect** (a confident answer that is wrong).
Current corpus: 4 correct / 1 ambiguous / 1 unknown / 1 intercepted /
1 error / **0 incorrect**. Deliberately small — a regression harness, not a
benchmark, and the tally makes no statistical claim.

- +9 tests (372 total).

## [0.1.35] — 2026-08-15

Evidence-based attribution. The scanner already separated *collecting* facts
from *matching* them; what was missing was a layer that says what the match
adds up to — and, more importantly, when a single answer is not warranted.
No new dependencies (the new module is stdlib-only), no new CLI flags, no
change to the signature format or to how scores are computed.

**The model** (`w4f/attribution.py`, pure functions over the result dict,
documented in [`docs/attribution-model.md`](docs/attribution-model.md)):

```
observations  ->  evidence  ->  attribution  ->  state
 (scanner)      (fingerprint)  (attribution.py)
```

- **Observations** — the facts the scan collected, unchanged and still owned
  by the scanner; `observations()` is a view over them, not a copy.
- **Evidence** — observations that matched a signature, each carrying the
  category it came from. Verdict entries gain `evidence_items`
  (`{category, detail}`) recorded where the category is already known, so
  nothing downstream re-parses a formatted string. `evidence` is unchanged.
- **Attribution** — `result["attribution"]`: state, vendor, score,
  confidence band, basis, role, deployment, alternatives, grouped evidence.
  Additive; `verdict` keeps its exact shape.
- **State** — `ATTRIBUTED`, `AMBIGUOUS`, `UNKNOWN`, `INTERCEPTED`, `ERROR`.

**Why the states matter.** "No vendor name" had several very different
causes and they all rendered the same way:

- **`AMBIGUOUS`** — two edge candidates within 8 points, both at MEDIUM or
  better, are now reported side by side with their separate bases instead of
  collapsing to the higher one and sounding sure. Only *edge* candidates
  compete: an origin under a real edge (`imperva` over `nginx`) is a layer,
  not a rival claim, so it never triggers ambiguity.
- **`INTERCEPTED`** — never carries a vendor attribution, in the console
  **and** now in SARIF, which previously filed such a host under
  `w4f/<vendor>` — reporting the middlebox's re-signed identity as the
  target's edge. It now files under `w4f/interception`.
- **`ERROR` vs `UNKNOWN`** — a host that failed to connect but resolved a
  vendor CNAME stays attributed, with the error alongside. DNS resolves
  before the handshake; a socket failure does not make the CNAME untrue.

**Confidence bands.** `HIGH` ≥ 70, `MEDIUM` ≥ 30, `LOW` below — shown band
first, score second. The score is a category-weight sum, not a probability,
so `HIGH` means several independent kinds of evidence agreed (more than the
strongest single category can supply alone).

**Output.** Default stays concise and decision-oriented, now shaped by the
state. `--verbose` becomes the analytical view: an `EDGE` section naming the
call, `EVIDENCE` grouped by category label (Network / Certificate / CNAME /
PTR / HTTP / Cookie), and `ALTERNATIVES` for what else was in play. Score
arithmetic is never printed. `--csv` appends a `state` column (appended, so
existing column indexes stay valid); SARIF reports `state` and
`confidence_band` in properties.

- `role_of()` falls back to the signature table when a verdict entry carries
  no `deployment`, so older `--json` trees do not promote every origin to a
  rival edge candidate.
- Removed `_verdict_line()`, dead once the verbose view moved to the
  evidence sections; its test coverage was retargeted at the live renderer.
- +40 tests (363 total), including regressions for strong attribution,
  weak/single-category attribution, ambiguous candidates, unknown results,
  interception, and host errors with surviving DNS evidence.

## [0.1.34] — 2026-08-15

Findings from a 139-host production sweep across three regional markets.
Every rule here was verified independently (own probe + vendor documentation)
before being written; sweep output stays out of this repo.

**Two scanner bugs the sweep exposed:**

- **A failed handshake was reported as "unknown edge".** `tls_probe` recorded
  `tls_error` but `probe_one` never promoted it, so a host that refused the
  connection came back `error=None` with an empty verdict — indistinguishable
  from a scanned host whose edge matched no signature. 13 of 139 hosts read as
  signature gaps when they were simply unreachable, and the run still exited 0
  against a documented contract that makes "connect refused" exit 1. Now
  surfaced as a host error, WITHOUT an early return: DNS-level signals resolve
  before the handshake, so a host can legitimately report both an error and a
  CNAME-based verdict, and the report shows both.
- **A block page on the NORMAL request was discarded.** `http_get` stops at the
  header terminator and dropped the parsed title/body, while `match_block_page`
  was wired only to `--verify`. A WAF that refuses the plain GET already handed
  us its page. The body is now read only on a refusal status (no extra request;
  an ordinary 200 costs nothing) and matched, tagged `source: "passive"` so the
  passive and active layers never blur.

**New/fixed signatures:**

- **FortiWeb, passively.** `cookiesession1` — FortiWeb sets it on the first
  response to every client, per Fortinet's own docs, and the name cannot be
  changed. The reference "silent WAF" no longer needs `--verify`.
- **Akamai `edgekey.net` + `akamaiedge.net`** — its two most common delivery
  CNAMEs, both missing (`akamai\.net` cannot match `akamaiedge.net`). An
  Akamai-fronted host scored headers-only, or unknown when the edge sent no
  `akamai-*` header.
- **Imperva SecureSphere** block page (on-prem: `<title>Error</title>` + "the
  incident ID is"), which answers 200 OK — only `--verify` can reach it.
- **Fortinet WebFilter** as a `middlebox/` vendor (new seventh family).

**`deployment`: cloud | on-prem | origin.** New per-vendor field carried into
the verdict — the field that decides whether an interception route can target
one IP at all. 89 vendors tagged; vendors sold both ways (Imperva) are left
unset on purpose, with the observed block page reporting the variant instead.

**Block pages are now per-vendor.** They lived in a hardcoded if-chain in
`scanner.py`, so adding one edited the matcher and broke the package's promise
that a vendor is ONE file. They are declared in the vendor's own file
(`block`, with explicit `priority` because specific rules must beat generic
ones) and the matcher iterates the table.

**TLS-interception detection.** A cert issued by an inspection CA means
something between w4f and the target re-signed the connection — so the
reported SPKI pin is the middlebox's, not the host's, silently breaking the
tool's headline output. Flagged `INTERCEPTED`, never as a verdict: two
unrelated hosts returned a byte-identical Fortinet page, and attributing it
would have fingerprinted our own network on every host scanned.

- Fixed a false positive introduced during this work: calling the block
  matcher regardless of status reported eleven healthy Imperva-fronted hosts
  (200/301/302) as serving a block page — its Imperva rule keys on the
  `incap_ses` cookie, which Imperva sets on every response.
- Fixed a second one caught on a live `--verify` run: interception pages were
  routed away from `block` on the passive path but not the active one, so an
  egress filter's page became a finding about the target. Provoking a box on
  our own path does not make it the target's WAF — it answers the
  attack-shaped query too.
- AGENTS.md traps #7 and #8 record both lessons.
- +27 tests (324 total).

## [0.1.33] — 2026-08-15

SAN in the default triage view (user review). The certificate's SAN list is
where sibling hostnames and wildcard reach show up — the thing a sweep is
actually looking for — so it belongs in the per-host block, not behind
`--verbose`.

- **`san` row in the triage block**, after `cert`, capped at 3 entries with a
  `(+N more)` tail. `--verbose` keeps its 6. A wildcard cert carrying 50+
  SANs would otherwise push the block off one screen; the full list stays in
  `--json`.
- Both views share one `_san_summary()` helper instead of duplicating the
  split/truncate logic.
- The row is omitted entirely when the cert carries no SAN data (the
  no-`cryptography` degradation path) rather than printing an empty label.
- +3 tests (290 total): SAN present in the triage block, triage cap tighter
  than verbose, no row when the cert has none.

## [0.1.32] — 2026-08-15

Output depth pass (user review): 0.1.31 moved every fact behind `--verbose`
and left a default view whose per-host block only restated the table row.
The triage view now carries the facts the table has no room for, and the
summary itself says what a verdict rests on.

**Verdict ranking fix (behavior).** `verdict` was sorted by evidence COUNT,
so a vendor matched by three headers (all one category, 7%) outranked one
proven by a netblock (30%) — a Cloudflare-fronted host running a Kong
gateway summarised as `kong (7%)` with the real edge demoted to a secondary
line. Ranking is now confidence-first (signals, then name, break ties).
`verdict[0]` — what the EDGE column and `--csv`/`--sarif` call the edge — is
now the best-evidenced vendor, not the most-matched one.

- **Signal categories are kept.** Each verdict carries `categories`
  (strongest-first: `netblock`, `cert`, `cname`, `ptr`, `headers`,
  `cookies`) — previously computed for the confidence sum and thrown away.
  Rendered as `BASIS` (`net+cert+hdr`): whether a verdict rests on IP
  ownership or on a string the origin can set matters more than the
  percentage it sums to. Additive to `--json`; new `basis` + `final_host`
  columns appended to `--csv`; `categories`/`basis` in SARIF properties.
- **Wider summary table**: `HOST | EDGE | CONF | BASIS | TLS | CERT | HTTP |
  NOTES`. EDGE marks a layered stack (`imperva +1`), NOTES merges the old
  mTLS/BLOCK/ERR columns and adds a redirect marker (`->www.…`). Columns
  drop right-to-left on a narrow TTY; piped output always gets the full set.
  A host that failed to probe shows `-`, not `unknown`.
- **Per-host block carries facts, not repetition**: verdict evidence, the
  layer stack, the redirect path + status + TLS, cert issuer/expiry/chain
  trust, and the SPKI pin.
- **Unknown edges print `leads`** — the fingerprintable headers/cookies that
  matched NO signature (per-request ids reduced to their name). An unknown
  verdict is a tool gap, so the sweep now hands over the raw material for
  the next signature file instead of a shrug.
- **Sweep rollup** after the blocks: host count + elapsed, vendor
  distribution, named unknowns, flag totals, and a count of verdicts resting
  on headers only.
- **`--sort risk|host|edge`** (default `risk`: errors, block pages, mTLS,
  unknown, then weak verdicts first). Console-only — `--json`/`--md`/
  `--csv`/`--sarif` stay host-sorted so sweep files diff cleanly.
- `--verbose` gains the redirect chain + final host (recorded since 0.1.10,
  never displayed) and cert chain-trust; SAN lists are capped at 6 (+N) so a
  50-SAN wildcard cert stops burying the block, and vendor-ish headers sort
  ahead of generic security headers in the 8-header cap.
- Fixed: unknown-edge line indented 10 spaces instead of 4.
- README: `wordpress-vip` documented (92 → 93 vendors; the 0.1.32 prep
  commit added the signature without the coverage entry).
- +21 tests (287 total): confidence-first ranking incl. the kong/cloudflare
  case, category recording, basis rendering, table columns/alignment under
  color, block facts, leads extraction, rollup, and display ordering.

## [0.1.31] — 2026-08-15

Console UX overhaul (user review) — the daily-driver output is now a triage
view instead of a dense wall of per-host blocks.

- **Summary table first.** After the banner, every host gets one row:
  `HOST | EDGE | CONF | mTLS | BLOCK | ERR`. Edge is colored per-vendor;
  critical flags are bold bright red. A 20-50 host sweep now scans in one
  glance.
- **Progressive detail.** Default mode prints the table + a compact block
  per host (host + critical flags + verdict only). `-v` / `--verbose`
  restores the FULL detail (IPs, cert, SPKI pin, response headers, verdict
  evidence). `--quiet` now suppresses ALL console output (banner, table,
  blocks) for automation.
- **Smarter verdict formatting.** The primary (highest-signal) vendor is on
  its own highlighted line; secondary/origin vendors are dimmed underneath
  (both in the triage view and in `--verbose`).
- **Progress indicator.** Multi-host runs show a live `[12/87] hostname`
  counter on stderr, cleared when done (no more blank screen during a sweep).
- **Aggressive critical flags.** mTLS / BLOCK / ERR are bold bright red
  (`\033[1;91m`), distinct from the vendor colors.
- +10 tests (263 total): summary table shape/flags/no-markdown, compact
  block flags, multi-vendor verdict-line layout, plain-when-piped.

## [0.1.30] — 2026-08-15

Second sweep batch from the continuous harness (`~/sec/w4f-sweep`, hourly
cron) — **7 new vendors (85 → 92)** + an sgw attribution fix, all mined
from the 2,500-host bootstrap corpus + follow-up probes.

New vendors:

- **WAF (4):** `qrator` (`Server: QRATOR` — Qrator Labs, Russian
  anti-DDoS), `360wangzhanbao` (`WZWS-RAY` header + qaxcloudwaf.com /
  icloudwaf.com CNAMEs — QiAnXin/360 网站卫士 cloud WAF), `variti`
  (`Server: Variti/<ver>` — Russian WAF/CDN), `uewaf` (`Server: uewaf/<ver>`
  — UCloud WAF).
- **CDN (3):** `airee` (`Server: Airee/Cloud` + `airee_*` cookies),
  `jd-cloud` (jcloud-cdn.com / qianxun.com CNAMEs — JD Cloud CDN/GSLB),
  `azion` (`x-azion-*` prefix headers — Brazilian edge).

Attribution notes: the `security=true` cookie Azion sets is deliberately
NOT a signal (name too generic). Variti's edge TLS-fingerprints clients —
one observed host blocks w4f's probe while answering curl, so a blank
verdict there is probe-blocking, not a missing rule.

- 7 vendor files under `w4f/signatures/{cdn,waf}/`, colors for each in
  `w4f/report.py`, README coverage list 85 → 92.
- +10 tests (253 total), positive + negative per rule.
- `w4f/signatures/gateways/sgw.py` docstring expanded (Shopee/Sea API
  gateway attribution, RDAP-verified) + anchored-match warning.

## [0.1.29] — 2026-08-14

China + internet-wide signature sweep — **14 new vendors (71 → 85)** and one
false-positive fix, all mined from a live sweep corpus (global top-2000 +
~500 curated Chinese sites; evidence lives in the private sweep workspace,
only rules go in the repo).

New vendors:

- **CDN (11):** `wangsu` (wscdns.com/wscvip.cn/wswebpic.com/wsglb0.com
  CNAMEs + `uproxy` via), `chinacache` (lxdns.com CNAME), `aliyun`
  (tbcache.com / alicdn.com / kunlun*.com CNAMEs + `acw_tc`/`cdn_sec_tc`/
  `aliyungf_tc` ESA WAF cookies + `eagleeye-traceid`), `volcengine`
  (`server: volc-dcdn` + vedcdnlb.com CNAME), `baidu-bfe` (`server: bfe` +
  shifen.com CNAME — Baidu's own front end), `baidu-cdn`
  (`x-bdcdn-cache-status` + `bdcdn` via), `baishan` (bsgslb.cn/bsclink.cn
  CNAME), `netease` (163jiasu.com CNAME), `qiniu` (qiniudns.com CNAME),
  `huawei-cloud-cdn` (cdnhwc*.com CNAME + `x-ccdn-*` headers),
  `360panyun` (`server: panyun` + 360panyun.com CNAME).
- **WAF (3):** `jiasule` (`x-via-jsl` header + `__jsluid_s` cookie),
  `wswaf` (`server: wswaf` — Wangsu WAF product), `knownsec` (365cyd.cn
  CNAME — Chuang Yu Shield).
- **Extended:** bytedance cname + `bytedns1.com` (ByteDance properties).

FP fix: **netscaler `via: ns-cache` matched `ens-cache`** (Alibaba/NetEase
edge nodes) — a bare substring regex shipped a false netscaler verdict on
major Alibaba/NetEase-fronted sites. The regex is now `\bns-cache` with a
dedicated negative test.

Attribution notes recorded in `docs/vendor-signatures.md`: the
`(Cdn Cache Server V2.0)` via marker is shared by Wangsu AND ChinaCache;
`ens-cache` by Alibaba AND NetEase; `x-ser`/`(cloudsvr)` by several Chinese
gov-CDN platforms — none is usable as a standalone signal. Alibaba ESA WAF
cookies cited to Alibaba's own documentation. Oracle cross-check results
are validated by hand; the oracle's "Huawei Cloud Firewall" on a payment
provider's marketing site was a false positive (host is Alibaba —
`aliyungf_tc` cookie + Alibaba IPs).

- 14 vendor files under `w4f/signatures/{cdn,waf}/`, colors for each in
  `w4f/report.py`, README coverage list 71 → 85.
- +32 tests (243 total), each new rule has positive + negative cases.

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
