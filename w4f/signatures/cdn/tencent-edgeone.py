"""tencent-edgeone — cdn vendor signature. See _template.py for the schema.

Tencent Cloud EdgeOne (腾讯云边缘安全加速). Delivery CNAMEs end in
eo.dnse\d+.com (dnse2/dnse4 observed), edgeone, dnsv1.com, tencentcs.com,
tcdn; edge nodes name themselves `edgeone`/`tencent` in Server, and the
edge stamps eo-log-uuid / eo-cache-status headers. The dnse\d+ form
(v0.1.43) covers dnse2 as well as dnse4 — observed on a Chinese insurer.
"""

VENDOR = {'name': 'tencent-edgeone', 'deployment': 'cloud',
 'headers': {'eo-log-uuid': None, 'eo-cache-status': None, 'server': 'edgeone|tencent'},
 'cname': r'eo\.dnse\d+\.com|edgeone|dnsv1\.com|tencentcs\.com|tcdn',
 'ptr': 'edgeone|dnse4|dnsv1'}
