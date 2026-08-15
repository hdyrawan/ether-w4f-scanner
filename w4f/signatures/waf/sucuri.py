"""sucuri — waf vendor signature. See _template.py for the schema.

Sucuri is a pure-play cloud WAF/CDN: a fronted host resolves into Sucuri's
own anycast ranges, so the netblock corroborates the header/block-page match
and — the real value — still fingerprints Sucuri when it cloaks the origin's
headers or refuses the passive GET (DNS + netblock need no HTTP at all).

`nets` are Sucuri's OWN officially-published Firewall IP ranges (the set
Sucuri documents for allowlisting on the origin), not ASN/BGP-derived
prefixes. Source: docs.sucuri.net "Same IP for All Users" firewall IP-range
list; verified 2026-08-15. Re-verify against that page before trusting a
stale range — a wrong netblock is a false positive on the strongest signal.
"""

VENDOR = {'name': 'sucuri',
 'block': {'body': ['sucuri firewall'], 'priority': 50}, 'deployment': 'cloud',
 'headers': {'server': 'sucuri', 'x-sucuri-id': None, 'x-sucuri-cache': None},
 'nets': ['192.88.134.0/23',
          '185.93.228.0/22',
          '66.248.200.0/22',
          '208.109.0.0/22',
          '2a02:fe80::/29']}
