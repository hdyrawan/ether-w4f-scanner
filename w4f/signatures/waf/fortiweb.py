"""fortiweb — waf vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'fortiweb', 'headers': {'server': 'fortiweb|fortigate'}, 'cookies': ['^FORTIWAFSID=']}
