"""qrator — waf vendor signature. See _template.py for the schema.

Qrator Labs (Russian anti-DDoS / edge filtering) marks its filtering nodes
with `Server: QRATOR`.
Observed on a Russian hosting provider's site.
"""

VENDOR = {'name': 'qrator',
 'headers': {'server': 'qrator'}}
