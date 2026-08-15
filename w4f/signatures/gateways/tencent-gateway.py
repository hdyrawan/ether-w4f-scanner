"""tencent-gateway — gateways vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'tencent-gateway', 'deployment': 'cloud',
 'headers': {'server': 'stgw|trpc-gateway', 'x-upstream-latency': None},
 'cname': 'tencentcs\\.com|dnspod|tcdn'}
