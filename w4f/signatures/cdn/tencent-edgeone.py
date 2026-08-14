"""tencent-edgeone — cdn vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'tencent-edgeone',
 'headers': {'eo-log-uuid': None, 'eo-cache-status': None, 'server': 'edgeone|tencent'},
 'cname': 'eo\\.dnse4\\.com|edgeone|dnsv1\\.com|tencentcs\\.com|tcdn',
 'ptr': 'edgeone|dnse4|dnsv1'}
