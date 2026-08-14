"""safedog — waf vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'safedog', 'headers': {'server': 'safedog'}, 'cookies': ['^safedog-flow-item=']}
