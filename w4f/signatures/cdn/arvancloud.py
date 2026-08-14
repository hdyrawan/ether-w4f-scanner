"""arvancloud — cdn vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'arvancloud',
 'headers': {'server': 'arvancloud', 'x-arvan-request-id': None},
 'cname': 'arvan',
 'ptr': 'arvan'}
