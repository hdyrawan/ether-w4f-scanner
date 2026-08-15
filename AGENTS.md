# AGENTS.md

Guidance for AI coding agents (Claude Code, Codex, Cursor, etc.) working in
this repo. This file is the single source of truth — do not let docs drift
from it.

## What this repo is

`w4f` is a standalone, package-agnostic **passive TLS / CDN /
WAF / edge fingerprinting** tool. It was extracted from a larger Android
anti-tamper research project (`anti-tamper-probe`) where knowing what edge
sits in front of an API host decides which interception route can work. It
is deliberately **app-agnostic**: no bank names, no package names, no
target-specific offsets — it scans whatever host you give it.

The research that motivated it lives elsewhere (in the user's Obsidian vault
and the `anti-tamper-probe` repo, under `docs/api-endpoints/`). This repo is
the tool and its documentation.

## Non-goals (do not add these)

- **No attack payloads.** The scanner is passive by design: DNS, one SNI TLS
  handshake, one GET. Do not add XSS/SQLi/evasion payloads or active WAF
  triggering — that changes the tool's threat profile and defeats its purpose
  (it is used against production banking endpoints where active probing is
  inappropriate).
- **No web scraping / third-party enrichment APIs** (ipinfo.io, Shodan,
  whois bulk, etc.). Everything must work offline against the target.
- **No target-specific logic.** No bank names, no host lists, no per-app
  pinning knowledge. If you find yourself hardcoding a host, stop — that
  belongs in the consuming research repo, not here.
- **This repo is CODE ONLY — never commit results or evidence.** No sweep
  output (host lists, `--json` result trees, oracle comparisons, block-page
  findings), no endpoint inventories, no bank/host names in code, comments,
  tests, docs, commit messages, tags, or release bodies. The consuming
  research repo and the user's Obsidian vault are where results live. If a
  sweep produced something worth keeping, put it there — never here. A
  violation in history is a `git filter-repo` purge job (see the release
  checklist verification step).
- **No license-borrowed detection code.** The vendor signature table was
  written from scratch. Do not copy detection rules verbatim from other WAF
  fingerprinting projects (several are restrictively licensed).

## Conventions

- **CLI contract:** the entry point is `w4f --target host[:port]`. The
  `--target` flag is repeatable, and `--target-json FILE` accepts a
  subdomain-enumeration export (array of `{"subdomain","ip","cloudflare"}`
  objects, array of strings, or `{subdomains:[...]}`) — each subdomain is
  scanned like a `--target`. At least one of the two is required; combine
  freely. Keep the flag names stable — other repos and docs reference them.
- **Banner:** `w4f/banner.py` embeds the Rebel figlet glyphs for "w4f"
  (patorjk taag style, x=none) with per-letter ANSI colors — w red, f blue,
  4 plain. Shown at the top of every non-quiet run; `--quiet` suppresses it.
  The glyph rows are verbatim from DOS Rebel.flf (hardblank `$` → space,
  trailing `@` endmarks stripped, all 11 rows kept) — do not "improve" the
  layout, it must match taag.
- **Testing is mandatory before a release.** `python -m pytest` runs the
  offline suite (87 tests; local TLS server, no internet). The vendor
  signature table has per-regex sanity tests — when adding a vendor or
  signature, add a positive AND a negative case to `tests/`. The
  `--verify` block-page matcher tests the two field traps (title at end of
  body, localized titles). CI runs 3.10/3.11/3.12 + a no-optional-deps job.
- **AWS WAF is silent to passive probes.** CloudFront + AWS WAF managed
  rules answer a normal GET with 200 and only block attack-shaped queries
  with 403 + `x-cache: Error from cloudfront` (block page "ERROR: The
  request could not be satisfied"). Passive `aws-waf` fires on the
  403+error-cache shape via the `_status` pseudo-header; `--verify` matches
  the block page. Never write "CloudFront, no WAF" without a `--verify`
  run (same trap as FortiWeb).
- **http_get follows redirects (apex → www).** The WAF often lives only on
  the www response; the apex is a redirector. Keep `max_redirects` bounded
  (5) and record the chain in `redirects`/`final_host`. Integration tests
  cover both follow and loop-stop.
- **Publishing to PyPI is a tag push.** The `publish.yml` workflow is the
  trusted publisher for hdyrawan/w4f (workflow name must stay `publish.yml`,
  no environment). To release: bump `__version__` in `w4f/__init__.py` AND
  `pyproject.toml` (setup.py reads from `__init__`, so only those two),
  update the README banner version, add the CHANGELOG.md entry, `python -m
  build` + `twine check`, run the tests, commit, then
  `git tag v<version> && git push origin v<version>` — the workflow builds,
  tests, and publishes via OIDC (no token). Then create the GitHub Release
  (`gh release create v<version> --title ... --notes ...` from the CHANGELOG
  entry) so the releases page matches PyPI.
- **Before ANY push (not just releases), verify the history is clean of
  target names.** This repo is public and code-only. Run the full-history
  grep over every commit's blobs AND commit messages — a name that only
  lives in a comment/test (not in the domain list) is exactly what this
  catches:
  ```bash
  # blobs: expect 0 hits
  git grep -oiE "<bank|target-name-pattern>" $(git rev-list --all) | wc -l
  # commit messages: expect 0 hits
  git log --all --format="%s" | grep -ciE "<pattern>"
  # any real hostnames that are not generic placeholders: expect none
  git grep -ohE "[a-z0-9.-]+\.co\.id" $(git rev-list --all) | grep -v example | sort -u
  ```
  If any hit exists, the fix is `git filter-repo --force --replace-text
  <scrub-file> --replace-message <scrub-file>` + force-push, NOT a normal
  commit (a normal commit leaves the name in history).
- **Pure stdlib + two optional deps.** `cryptography` (cert parsing) and
  `dnspython` (CNAME/PTR) are optional; the scanner must degrade gracefully
  without either. Never add a hard dependency.
- **Never raise on a probe.** Per-host errors are captured into the result
  dict (`error`, `tls_error`, HTTP `ERROR:` status) — the scan continues. A
  host that fails DNS gets `"error": "DNS did not resolve"`, not an exception.
- **Evidence-based verdicts.** The `verdict` list carries the signals that
  matched (`header server: cloudflare`, `netblock: 104.18.1.79 in
  104.16.0.0/13`, `cookie: incap_ses…`, …). A verdict without evidence is a
  bug. A blank verdict is "unknown edge", never "no WAF".
- **Sweep output never enters this repo.** If you run a sweep for
  documentation, the raw `--json`/`--md` and any writeup belong in the
  consuming research repo / vault, never here (see the code-only rule).

## Detection methodology

Every new vendor/signature follows this process:

1. **Research.** Identify the actual product and deployment role (edge /
   WAF / CDN / gateway / origin / middlebox).

2. **Evidence collection.** Investigate: vendor-published edge ranges,
   network ownership, DNS/CNAME, certificate/TLS, HTTP, cookies, block
   behavior.

3. **Evidence classification.** Prefer: vendor-published edge ranges >
   network ownership > distinctive CNAME > certificate > distinctive TLS
   behavior > distinctive HTTP behavior > cookies > generic headers.

4. **Specificity check.** Reject signals that are: shared across vendors,
   generic infrastructure markers, inherited from parent/shared cloud
   infrastructure, or only observed on the vendor's own properties without
   customer evidence.

5. **Provenance.** Record the source and verification date for strong
   signals (hostname-free, per the code-only rule).

6. **Validation.** Every promoted signal requires a positive test, a
   negative test, and a collision test where applicable.

7. **Promotion decision.**
   - PROMOTE: evidence is sufficiently specific and reproducible.
   - PASSIVE-ONLY: useful weak signal, but insufficient for strong
     attribution.
   - UNKNOWN: insufficient evidence.
   - REJECT: evidence is too generic or ambiguous.

8. **Netblock-specific gate.** A netblock may be added only when it is
   vendor-published or otherwise authoritative, represents the relevant
   edge product, is stable enough to avoid broad false coverage, is
   boundary tested, and has no cross-vendor overlap.

Adding a signature is a claim about attribution, not merely a record that
a string was observed.

## Verification methodology (passive vs --verify)

w4f has two intentional detection modes; keep their evidence strictly
separate.

**Passive mode** (default) observes DNS / A-AAAA / CNAME / PTR / IP
ownership / TLS / cert issuer-SAN / SPKI / the normal HTTP response /
headers / cookies / redirects / passive refusal indicators. It never sends
anything but one SNI handshake and one GET.

**Verification mode (`--verify`)** sends ONE controlled probe
(`verify_block()`: a script-tag + `OR '1'='1'` query string) and matches
the response against the block-page table. It exists because some WAFs are
intentionally silent to normal traffic (AWS WAF behind CloudFront is the
canonical case) and cannot be identified passively. Use it only when:

- the WAF/signature is documented as requiring verification, or
- passive evidence is insufficient, and
- the target is appropriate for controlled verification.

Verification must stay narrowly scoped to identifying the defensive
control: no exploit payloads, no WAF-evasion logic, no destructive or
fuzz testing. Do NOT remove, weaken, or bypass `--verify`; do NOT label a
silent WAF "absent" merely because the passive scan is quiet when --verify
can establish its presence.

**Provenance is a first-class field.** Every block result carries
`source: "passive"` (a refusal page the edge handed us) or
`source: "verify"` (a page our probe provoked). Consumers must never
confuse the two, and a verified page must not silently become passive
evidence.

**Terminology:**

- **observation** — a raw fact collected (an IP, a header, a CNAME).
- **passive evidence** — an observation used for attribution.
- **verification evidence** — a provoked block/challenge response; a
  separate dimension that may be decisive for silent WAFs.
- **attribution** — the interpretation: state + primary candidate.
- **layer** — an origin component underneath a real edge (never a rival).
- **alternative** — a weaker competing EDGE candidate (a rival claim).
- **interception** — a middlebox on the SCANNER's path; never the target's
  edge.

The promotion flow therefore runs: research → collect passive evidence →
assess whether --verify is required → collect controlled verification
evidence when appropriate → classify evidence strength/provenance → check
shared infrastructure / collision risk → positive test → negative/collision
test → PROMOTE / PASSIVE-ONLY / UNKNOWN / REJECT.

**Error taxonomy (v0.1.42).** Every per-host failure keeps the readable
`error` string AND gains a stable `error_class` (`dns-nxdomain`,
`dns-noanswer`, `dns-timeout`, `conn-refused`, `tcp-timeout`,
`network-unreachable`, `tls-timeout`, `tls-handshake`, `cert`,
`http-timeout`, `redirect`, `http-protocol`, `upstream`, `other`). DNS
no-answer (apex exists but the site lives at www.*) is deliberately
distinct from NXDOMAIN. HTTP-layer failures are promoted to the error
contract (mTLS's certificate-required alert is NOT an error — it is the
`mtls` finding).

**Weak close-call rule (v0.1.42).** If the top edge candidate scores below
the ambiguity floor (30) and the second edge is within the ambiguity margin
(8), the state is UNKNOWN — never ATTRIBUTED to whichever weak candidate
happened to score a few points higher. A correct UNKNOWN beats a
low-confidence coin flip. Strong evidence still wins decisively over weak
generic evidence (netblock > cname/cert > header; origins are layers, not
rivals).

## Known traps (kept for the next reader)

1. **`getaddrinfo` canonical-name fallback** must use `info[3]` (canonname),
   not `info[0]` (the address-family enum). The enum crashes
   `" ".join(cname)` with `expected str instance, AddressFamily found` and the
   whole host is reported as failed.
2. **h2 vs HTTP/1.1.** If the first handshake negotiates ALPN `h2`, sending an
   HTTP/1.1 request on that same socket gets a binary HTTP/2 frame back (reads
   as garbage). Do the GET over a **separate http/1.1-only ALPN connection**.
3. **TLS 1.3 mTLS.** The server asks for the client certificate AFTER the
   handshake, so the `certificate required` alert lands on the first app
   data, not in the handshake. Check the GET error too, not just the connect.
4. **Don't mislabel AWS.** `aws-s3` must match `s3…amazonaws.com` CNAMEs only;
   EC2/ELB PTRs (`compute.amazonaws.com`, `elb.amazonaws.com`) are `aws-elb`.
   A broad `amazonaws.com` PTR rule mislabels every EC2 host as S3.
5. **Multiple `Set-Cookie` headers.** Header parsing must collect cookies into
   a list (`set-cookie-list`), not overwrite — WAF signatures often live in
   the second cookie.
6. **The HTTP layer lives under `result['tls']['http']`, not the top level.**
   `probe_one` stores the whole TLS dict; a `fingerprint()` that reads
   `result.get('http')` silently disables ALL header/cookie matching while
   DNS/cert/netblock verdicts still work — so hosts behind cookie-only
   vendors (F5 BIG-IP ASM's `TS<hex>` JavaScript-challenge cookie) report
   "unknown edge" and look WAF-free. This bug shipped once and made a whole
   fleet look unprotected. F5 detection needs the `TS[a-fA-F0-9]{6,12}=`
   cookie (6–12 hex chars; shorter patterns miss the 10-char builds).
7. **A TLS-inspection middlebox on the SCANNER's path can impersonate the
   target's edge.** A sweep found two unrelated banks in different countries
   returning a byte-identical 403 whose certificate was issued by
   `O=Fortinet, OU=Certificate Authority, CN=FG<appliance-serial>` — an
   egress appliance re-signing the connection and refusing to proxy because
   the upstream cert had expired. The obvious "fix" (adding `cert: fortinet`
   to the fortiweb signature) would have fingerprinted *our own network* on
   every host scanned from behind that box. Two consequences: (a) never
   attribute a cert issued by an inspection CA to the target — that is what
   `detect_interception()` / the `interception` field is for, and it warns
   that **the reported SPKI pin is the middlebox's, not the host's**, which
   silently breaks the tool's headline output; (b) an identical response
   across unrelated targets is the tell that the box is local, not remote.
8. **`match_block_page()` is only status-safe under `--verify`.** It was
   written for a response where a block is already presumed, so some rules
   match things a healthy host also sends — the Imperva rule keys on the
   `incap_ses` cookie, which Imperva sets on *every* response. Calling it on
   the passive GET regardless of status reported eleven healthy
   Imperva-fronted hosts (200/301/302) as serving a block page. The passive
   path must gate on a refusal status (`status_is_blocking`) before matching.
9. **Keep the signature table ahead of the research, not behind it.**
   A bank's EdgeOne-fronted host reported "unknown edge" through v0.1.1 even
   though the consuming research had already documented the Tencent EdgeOne
   edge (`eo-log-uuid`/`eo-cache-status` headers, `eo.dnse4.com` CNAME).
   When a sweep verdict contradicts an existing endpoint write-up, that is a
   tool gap to fix, not evidence to trust. Added v0.1.2.

## Verification

```bash
python3 -m w4f --target example.com            # smoke test
python3 -m w4f --target example.com --no-http  # DNS+TLS only
python3 -m py_compile w4f/*.py                 # syntax
```
