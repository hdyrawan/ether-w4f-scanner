"""kong — gateways vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'kong', 'deployment': 'on-prem',
 'headers': {'server': 'kong', 'x-kong-upstream-latency': None, 'x-kong-proxy-latency': None}}
