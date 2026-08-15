"""safedog — waf vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'safedog', 'deployment': 'on-prem', 'headers': {'server': 'safedog'}, 'cookies': ['^safedog-flow-item=']}
