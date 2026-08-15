"""volcengine — cdn vendor signature. See _template.py for the schema.

Volcengine DCDN (火山引擎, ByteDance's cloud) edge nodes identify as
`Server: volc-dcdn`; customers CNAME to `*.vedcdnlb.com`. ByteDance's DNS
suffix bytedns1.com is covered by the bytedance vendor.
Observed on Chinese short-video, e-commerce, and logistics hosts.
"""

VENDOR = {'name': 'volcengine', 'deployment': 'cloud',
 'headers': {'server': r'volc-dcdn(?:/|$)'},
 'cname': r'vedcdnlb\.com'}
