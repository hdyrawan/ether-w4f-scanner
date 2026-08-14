"""vercel — gateways vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'vercel',
 'headers': {'x-vercel-id': None, 'x-vercel-cache': None, 'server': 'vercel'},
 'cname': '\\.vercel\\.app$'}
