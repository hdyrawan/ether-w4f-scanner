"""shape-security — bot vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'shape-security', 'deployment': 'cloud',
 'headers': {'x-shape-*': None, 'server': 'shape'},
 'cookies': ['^shape_', '^__shape']}
