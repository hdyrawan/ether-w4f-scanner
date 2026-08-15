"""sucuri — waf vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'sucuri',
 'block': {'body': ['sucuri firewall'], 'priority': 50}, 'deployment': 'cloud', 'headers': {'server': 'sucuri', 'x-sucuri-id': None, 'x-sucuri-cache': None}}
