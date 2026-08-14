"""varnish — origins vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'varnish', 'headers': {'x-varnish': None, 'via': 'varnish'}, 'cookies': ['^cachewall']}
