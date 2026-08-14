"""baidu-cdn — cdn vendor signature. See _template.py for the schema.

Baidu Cloud CDN (百度智能云CDN) edge nodes emit the `x-bdcdn-cache-status`
header and name themselves `<ip>-<region>.bdcdn-<po>.ToB` in the Via header.
Distinct from baidu-bfe (Baidu's own front end for baidu.com properties).
Observed on Chinese e-commerce, logistics, and portal hosts.
"""

VENDOR = {'name': 'baidu-cdn',
 'headers': {'x-bdcdn-cache-status': None, 'via': r'bdcdn'}}
