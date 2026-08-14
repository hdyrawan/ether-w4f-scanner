"""reblaze — waf vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'reblaze', 'headers': {'x-reblaze-*': None, 'server': 'reblaze'}, 'cookies': ['^rbzid=']}
