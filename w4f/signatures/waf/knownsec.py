"""knownsec — waf vendor signature. See _template.py for the schema.

Knownsec (知道创宇) Chuang Yu Shield (创宇盾) CDN/WAF. Customers CNAME to
`*.cname.365cyd.cn` (cyd = Chuang Yu Dun). The WAF itself is silent on
passive probes (no distinctive response header), so the CNAME suffix is the
signal.
Observed on Chinese government hosts.
"""

VENDOR = {'name': 'knownsec', 'deployment': 'cloud',
 'cname': r'365cyd\.cn'}
