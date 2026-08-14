"""azion — cdn vendor signature. See _template.py for the schema.

Azion (Brazilian edge computing / CDN) stamps `x-azion-request-id` and
`x-azion-edge-location` headers on edge responses (prefix rule `x-azion-*`).
Observed on a Brazilian government financial host.
NOTE: the `security=true` cookie Azion's Edge Firewall sets is NOT used as
a signal — the name is too generic to stand alone.
"""

VENDOR = {'name': 'azion',
 'headers': {'x-azion-*': None}}
