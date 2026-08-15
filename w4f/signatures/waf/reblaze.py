"""reblaze — waf vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'reblaze', 'deployment': 'cloud', 'headers': {'x-reblaze-*': None, 'server': 'reblaze'}, 'cookies': ['^rbzid=']}
