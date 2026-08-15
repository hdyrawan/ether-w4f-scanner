"""variti — waf vendor signature. See _template.py for the schema.

Variti (Russian WAF/CDN) marks its edge with `Server: Variti/<ver>`.
Observed on a Russian CDN/video host.
"""

VENDOR = {'name': 'variti', 'deployment': 'cloud',
 'headers': {'server': r'variti(?:/|$)'}}
