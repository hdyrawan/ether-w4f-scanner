"""wangsu — cdn vendor signature. See _template.py for the schema.

Wangsu (网宿 / ChinaNetCenter) is one of China's largest CDN providers.
Customers CNAME to Wangsu's own DNS suffixes (wscdns.com, wscvip.cn,
wswebpic.com, wsglb0.com — WS = WangSu) and its global LB nodes name
themselves `uproxy-<n>` in the Via header. NOTE: the generic
`(Cdn Cache Server V2.0)` via marker is NOT used — ChinaCache (蓝汛) emits
the same string, so keying on it would mislabel every ChinaCache host.
Observed on Chinese banking, government, media, and e-commerce hosts.
"""

VENDOR = {'name': 'wangsu',
 'headers': {'via': r'uproxy', 'x-via': r'uproxy'},
 'cname': r'wscdns\.com|wscvip\.cn|wswebpic\.com|wsglb\d*\.com'}
