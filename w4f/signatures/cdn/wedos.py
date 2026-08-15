"""wedos — cdn vendor signature. See _template.py for the schema.

WEDOS (Czech hosting/CDN provider). Its Global CDN edge stamps the
`x-cdn-provider: WEDOS Global CDN (WEDOS.delivery)` header on responses.
Verified 2026-08-15 on the vendor's own site. The `server: ATS` token is
generic Apache Traffic Server and is NOT a signal on its own.
"""

VENDOR = {'name': 'wedos',
 'headers': {'x-cdn-provider': r'wedos'}}
