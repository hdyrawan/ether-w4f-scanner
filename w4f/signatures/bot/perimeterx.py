"""perimeterx — bot vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'perimeterx',
 'headers': {'x-px-*': None, 'server': 'perimeterx'},
 'cookies': ['^_px\\d*=', '^_pxhd=', '^_px3=']}
