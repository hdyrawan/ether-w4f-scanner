# The attribution model

How w4f gets from bytes on the wire to a statement about the edge, and why
the steps are kept apart.

```
  observations  ->  evidence  ->  attribution  ->  state
   (scanner)       (fingerprint)  (attribution.py)
```

## 1. Observations — what was seen

Facts the scanner collected, with no interpretation attached: resolved IPs,
CNAME chain, PTR, TLS version/cipher/ALPN, the leaf certificate (issuer,
SAN, validity, **SPKI-SHA-256**), HTTP status and headers, `Set-Cookie`
values, and the redirect chain.

These live where they always have — in the result dict under `resolved`,
`tls`, `tls.http`. `attribution.observations()` is a *view* over them for
display; it copies nothing and the scanner keeps owning the facts.

## 2. Evidence — what supports a vendor

`scanner.fingerprint()` matches observations against the signature table.
An observation becomes evidence only when a rule matches it, and each piece
carries the **category** it came from (`netblock`, `cert`, `cname`, `ptr`,
`headers`, `cookies`). The weights and the scoring are unchanged — see
[`vendor-signatures.md`](vendor-signatures.md).

Each verdict entry carries both forms:

- `evidence` — the human strings, unchanged since 0.1.x
- `evidence_items` — the same facts as `{category, detail}`, recorded where
  the category is already known so nothing downstream has to re-parse a
  formatted string

`attribution.evidence` groups those into `{category, label, details}` where
`details` is a **list** — one observation per entry, so a reader sees each
fact on its own line instead of a run-on string.

## 3. Attribution — what it adds up to

`attribution.attribute(result)` reads a finished result and returns the
interpretation, stored on the result as `attribution`:

| field | meaning |
|---|---|
| `state` | see below |
| `vendor` | the named edge, or `None` |
| `score` | the existing 0-100 category-weight sum |
| `confidence` | `HIGH` ≥ 70, `MEDIUM` ≥ 30, `LOW` below |
| `basis` | the categories behind the score |
| `role` | `edge` (sits in front) or `origin` (the stack being fronted) |
| `deployment` | `cloud` / `on-prem` / `origin`, when the vendor declares one |
| `alternatives` | competing **edge** candidates, weaker than the primary |
| `layers` | candidates *underneath* the edge (origin stacks) — the stack, not rivals |
| `candidates` | on `AMBIGUOUS`, the candidates that could not be separated |
| `evidence` | the primary's evidence, grouped by category |
| `observations` | on `UNKNOWN` / `INTERCEPTED`, the raw facts |
| `error` | set alongside an attribution when the probe also failed |

`verdict` is left exactly as it was, so existing `--json` consumers keep
working; `attribution` is additive.

**Confidence bands are not probabilities.** The score is a sum of category
weights, so `HIGH` means several independent kinds of evidence agreed —
more than the strongest single category (netblock, 30) can supply on its
own. A `LOW` verdict is typically header- or cookie-only: strings the
origin can set.

## 4. State — what kind of answer this is

"No vendor name" has several very different causes, and collapsing them
loses the decision the reader has to make.

| state | meaning |
|---|---|
| `ATTRIBUTED` | one candidate is best-evidenced; the vendor is named |
| `AMBIGUOUS` | two or more **edge** candidates within 8 points, both ≥ 30 — reported side by side instead of silently picking the higher |
| `UNKNOWN` | scanned, nothing matched. A real finding: the observations are the lead for the next signature |
| `INTERCEPTED` | something on the **scanner's** path re-signed the connection. Never carries a vendor attribution |
| `ERROR` | the host could not be probed **and** no independent evidence survived |

Precedence is deliberate:

1. **Interception outranks everything.** The identity on the wire may not be
   the target's at all, so no vendor is asserted and the certificate/SPKI
   are reported as possibly belonging to the middlebox.
2. **A surviving verdict outranks an error.** DNS resolves before the
   handshake, so a host that timed out but returned a vendor CNAME stays
   `ATTRIBUTED` with the error alongside it — a connect failure does not
   make the CNAME untrue.
3. **Only edge candidates compete, and layers are not alternatives.** An
   origin under a real edge (`cloudflare` in front of `varnish`) is a
   *layer*, not a rival claim: it never triggers `AMBIGUOUS`, and it is
   reported in `layers` rather than `alternatives`. The role comes from the
   `deployment` the vendors already declare — no second model — falling back
   to the signature table for older result trees.

## Output

Default stays concise and decision-oriented — the state, the vendor with its
confidence band and score, the basis, the `layer` chain when the edge fronts
an origin, and the response facts a decision needs next (path, cert, SAN,
TLS, SPKI).

`--verbose` is the analytical view, in four sections:

- `EDGE` — the call, with its confidence band and basis
- `EVIDENCE` — one category heading (`Network`, `Certificate`, `CNAME`,
  `PTR`, `HTTP`, `Cookie`) and one observation per line beneath it
- `LAYER` — the stack the edge fronts, drawn as a stack
- `ALTERNATIVES` — competing **edge** candidates only

Scores appear as one number per candidate — never as the arithmetic that
produced them.

Machine outputs carry the state too: `--csv` appends a `state` column
(appended, so existing column indexes stay valid) and `--sarif` reports
`state` / `confidence_band` in properties, with an intercepted host filed
under `w4f/interception` rather than the target's vendor rule.

## Weak evidence

`HARD_CATEGORIES` (`netblock`, `cert`, `cname`, `ptr`) are the ones an origin
cannot fabricate by echoing a header. `is_weak(basis)` is true when a basis
rests only on the rest, and the console marks those *headers only —
spoofable*. This notion lives here, with the model, rather than being
restated in the renderer.

## Validation corpus

`tests/fixtures/attribution/` holds sanitized fixtures — **observations
only**, so each case runs the real pipeline (signature matching, then
interpretation) instead of pre-baked verdicts. A signature change that
quietly breaks attribution fails there.

Covered: strong multi-category attribution, partial connectivity (DNS
survives a failed handshake), weak header-only attribution, ambiguous
competing edges, unknown, interception, edge-over-origin layering, and a
host error with nothing surviving.

`test_attribution_corpus.py` also tallies outcomes — correct, ambiguous,
unknown, intercepted, error, and **incorrect** (a confident answer that is
wrong, the failure mode that matters most). The corpus is deliberately
small: it is a regression and quality harness, and the tally makes no
statistical claim about the internet at large.

Everything in it is synthetic: RFC 5737 documentation addresses, `example.*`
names, and published vendor infrastructure (the netblocks and CNAME suffixes
the signatures match on). No private or proprietary target data is stored in
this repository.
