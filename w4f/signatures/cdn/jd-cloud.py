"""jd-cloud — cdn vendor signature. See _template.py for the schema.

JD Cloud CDN (京东云). Customers CNAME to `*.jcloud-cdn.com` (Galileo, JD
Cloud's CDN product) or `*.gslb.qianxun.com` (JD's GSLB).
Observed on JD's own site and a Chinese business-news host.
"""

VENDOR = {'name': 'jd-cloud', 'deployment': 'cloud',
 'cname': r'jcloud-cdn\.com|qianxun\.com'}
