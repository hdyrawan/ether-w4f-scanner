"""baidu-bfe — cdn vendor signature. See _template.py for the schema.

Baidu Front End (bfe) is Baidu's own edge server for Baidu's properties.
The edge serves `Server: bfe` (UA-dependent — some backend paths echo the
origin's `apache`/`nginx` instead, so the CNAME is the reliable signal) and
Baidu's CDN DNS is `*.shifen.com`.
Observed on Baidu's own properties.
"""

VENDOR = {'name': 'baidu-bfe',
 'headers': {'server': r'bfe(?:/|$)'},
 'cname': r'shifen\.com$'}
