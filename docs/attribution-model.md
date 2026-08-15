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
| `alternatives` | other candidates, weaker or underneath |
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
3. **Only edge candidates compete.** An origin layer under a real edge
   (`imperva` in front of `nginx`) is a *layer*, not a rival claim, so it
   never triggers `AMBIGUOUS`. The role comes from the vendor's declared
   `deployment`, falling back to the signature table for older result trees.

## Output

Default stays concise and decision-oriented — the state, the vendor with its
confidence band and score, the basis, and the response facts a decision
needs next (path, cert, SAN, pin).

`--verbose` is the analytical view: an `EDGE` section naming the call, an
`EVIDENCE` section listing what supports it grouped by category label
(`Network`, `Certificate`, `CNAME`, `PTR`, `HTTP`, `Cookie`), and an
`ALTERNATIVES` section for what else was in play. Scores appear as one
number per candidate — never as the arithmetic that produced them.

Machine outputs carry the state too: `--csv` appends a `state` column
(appended, so existing column indexes stay valid) and `--sarif` reports
`state` / `confidence_band` in properties, with an intercepted host filed
under `w4f/interception` rather than the target's vendor rule.
