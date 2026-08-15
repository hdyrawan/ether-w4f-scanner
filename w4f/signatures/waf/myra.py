"""myra — waf vendor signature. See _template.py for the schema.

Myra Security (Munich) — managed security CDN / WAF. Its edge identifies as
`Server: myracloud` (verified on the vendor's own site, 2026-08-15).
"""

VENDOR = {'name': 'myra',
 'headers': {'server': r'myracloud'}}
