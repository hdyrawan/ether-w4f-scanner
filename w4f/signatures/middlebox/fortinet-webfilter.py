"""fortinet-webfilter — EGRESS appliance on the scanner's path.

Not the target's WAF. A FortiGate/FortiOS web filter doing SSL inspection
re-signs the connection with its built-in CA (`O=Fortinet, OU=Certificate
Authority, CN=FG<appliance-serial>`) and serves this page when it refuses to
proxy — e.g. because the upstream certificate expired.

Observed when two unrelated banks in different countries returned a
byte-identical 403: an identical response across unrelated targets is the
tell that the box is local, not remote. This file carries ONLY a block rule
— it has no header/cookie/cert/cname evidence, so the passive fingerprint
loop can never match it as an edge vendor.
"""

VENDOR = {'name': 'fortinet-webfilter',
          'block': {'title': r'invalid connection', 'body': ['fortinet'],
                    'interception': True, 'priority': 10}}
