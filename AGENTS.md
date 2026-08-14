# AGENTS.md

Guidance for AI coding agents (Claude Code, Codex, Cursor, etc.) working in
this repo. This file is the single source of truth — do not let docs drift
from it.

## What this repo is

`ether-w4f-scanner` is a standalone, package-agnostic **passive TLS / CDN /
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
- **No license-borrowed detection code.** The vendor signature table was
  written from scratch. Do not copy detection rules verbatim from other WAF
  fingerprinting projects (several are restrictively licensed).

## Conventions

- **CLI contract:** the entry point is `w4f --target host[:port]`. The
  `--target` flag is repeatable. Keep the flag names stable — other repos and
  docs reference them.
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
- **Versioned output.** When running a sweep for documentation, commit the
  raw JSON alongside the writeup (`--json`) and regenerate both together.

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
7. **Keep the signature table ahead of the research, not behind it.**
   `aquarius.banksaqu.co.id` reported "unknown edge" through v0.1.1 even
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
