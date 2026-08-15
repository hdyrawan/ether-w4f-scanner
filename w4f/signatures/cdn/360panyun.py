"""360panyun — cdn vendor signature. See _template.py for the schema.

360 PanYun (360盘云, 360's CDN/WAF) edge nodes serve `Server: panyun`
and customers CNAME to `*.360panyun.com`.
Observed on a Chinese provincial government host.
"""

VENDOR = {'name': '360panyun', 'deployment': 'cloud',
 'headers': {'server': 'panyun'},
 'cname': r'360panyun\.com'}
