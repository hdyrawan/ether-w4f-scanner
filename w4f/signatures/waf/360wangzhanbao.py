"""360wangzhanbao — waf vendor signature. See _template.py for the schema.

360 网站卫士 (WangZhanBao / QiAnXin cloud WAF family). The edge stamps every
response with a `WZWS-RAY` header (WZWS = 网站卫士) and customers CNAME to
`*.qaxcloudwaf.com` / `*.icloudwaf.com` (QiAnXin cloud WAF suffixes).
Observed on Chinese government hosts.
"""

VENDOR = {'name': '360wangzhanbao', 'deployment': 'cloud',
 'headers': {'wzws-ray': None},
 'cname': r'qaxcloudwaf\.com|icloudwaf\.com'}
