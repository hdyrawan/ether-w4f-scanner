"""naver — cdn vendor signature. See _template.py for the schema.

Naver / Naver Cloud Platform (Korea). Naver's CDN platform is `nheos.com`
and its front server identifies as `Server: nfront` (verified on Naver's
own properties). NCP-hosted customer edges CNAME to `*.lb.naverncp.com`.
Verified 2026-08-15 on vendor properties + a Korean media customer.
"""

VENDOR = {'name': 'naver',
 'headers': {'server': r'nfront'},
 'cname': r'nheos\.com|naverncp\.com'}
