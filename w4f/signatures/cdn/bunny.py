"""bunny — cdn vendor signature. See _template.py for the schema.

bunny.net (BunnyCDN), a European (Slovenia) edge/CDN with PoPs worldwide.
Its edge identifies as `Server: BunnyCDN-<POP>-<id>` and customers CNAME to
`*.bunnycdn.com` (CDN) or `*.b-cdn.net` (storage/stream delivery).
Verified 2026-08-15 on the vendor's own properties (server token + CNAME).
NOTE: bunny.net publishes a plain-text edge-IP list (api.bunny.net/
system/edgeserverlist/plain) but it is individual /32s that churn — not
suitable for a stable netblock rule; CNAME + server token carry the verdict.
"""

VENDOR = {'name': 'bunny',
 'headers': {'server': r'bunnycdn-\w+-\d+'},
 'cname': r'bunnycdn\.com|b-cdn\.net'}
