"""airee — cdn vendor signature. See _template.py for the schema.

Airee (Russian CDN/WAF) marks its edge with `Server: Airee/Cloud` and sets
`airee_visitor` / `airee_preloaded` cookies.
Observed on Airee's own site.
"""

VENDOR = {'name': 'airee', 'deployment': 'cloud',
 'headers': {'server': r'airee(?:/|$)'},
 'cookies': [r'^airee_']}
