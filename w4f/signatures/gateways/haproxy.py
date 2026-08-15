"""haproxy — gateways vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'haproxy', 'deployment': 'origin',
 'headers': {'server': 'haproxy'},
 'cookies': ['^[a-zA-Z0-9_.-]+=![A-Za-z0-9+/]+']}
