"""chinacache — cdn vendor signature. See _template.py for the schema.

ChinaCache (蓝汛) is an established Chinese CDN. Customers CNAME to
`*.lxdns.com`. Its cache nodes emit the same `(Cdn Cache Server V2.0)` via
marker that Wangsu uses, so the CNAME is the distinguishing signal.
Observed on Chinese railway and media hosts.
"""

VENDOR = {'name': 'chinacache',
 'cname': r'lxdns\.com'}
