"""fastly — cdn vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'fastly',
 'headers': {'server': 'fastly',
             'x-served-by': 'cache-',
             'x-timer': None,
             'x-fastly-request-id': None,
             'via': 'fastly'},
 'cert': 'fastly',
 'cname': 'fastly\\.net|fastlylb\\.net',
 'ptr': 'fastly\\.net',
 'nets': ['151.101.0.0/16', '199.232.0.0/16', '146.75.0.0/16', '172.111.64.0/18']}
