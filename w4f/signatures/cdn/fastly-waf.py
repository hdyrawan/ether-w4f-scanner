"""fastly-waf — cdn vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'fastly-waf', 'deployment': 'cloud',
 'headers': {'fastly-waf-debug': None, 'signal-attack': None},
 'cookies': ['^__SignalShield_']}
