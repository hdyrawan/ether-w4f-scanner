"""wordpress-vip — platforms vendor signature. See _template.py for the schema.

WordPress VIP (WP VIP) is Automattic's managed WordPress platform, served
off Akamai's edge. Its edge cache adds the `x-rq` response header whose
value names the serving POP (e.g. `sin1 0 40 9980` = Singapore, `lhr3` =
London) — per WordPress VIP's own docs. Customers CNAME to `*.go-vip.net`.
Observed on ~20 media/news hosts in the sweep corpus.
"""

VENDOR = {'name': 'wordpress-vip',
 'headers': {'x-rq': r'^[a-z]{3}\d+ \d+ \d+ \d+$'},
 'cname': r'go-vip\.net'}
