"""shape-security — bot vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'shape-security',
 'headers': {'x-shape-*': None, 'server': 'shape'},
 'cookies': ['^shape_', '^__shape']}
