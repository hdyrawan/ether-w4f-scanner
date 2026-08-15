"""uewaf — waf vendor signature. See _template.py for the schema.

UCloud WAF (UCloud, Chinese cloud provider) edge token `Server: uewaf/<ver>`.
Observed on UCloud's own site.
"""

VENDOR = {'name': 'uewaf', 'deployment': 'cloud',
 'headers': {'server': r'uewaf(?:/|$)'}}
