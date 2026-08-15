"""google-cloud-run — gateways vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'google-cloud-run', 'deployment': 'cloud',
 'headers': {'x-cloud-trace-context': None},
 'cname': '\\.run\\.app$',
 'ptr': 'run\\.app$'}
