"""radware — waf vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'radware',
 'headers': {'x-radware-*': None, 'server': 'radware|appwall'},
 'cookies': ['^mpev_']}
