"""jiasule — waf vendor signature. See _template.py for the schema.

Jiasule (加速乐) is a Chinese CDN/WAF. Its edge adds the
`X-Via-JSL` response header on every response and sets the `__jsluid_s`
visitor cookie. Customers CNAME to `*.vip.jiasule.org`.
Observed on Chinese government and e-commerce hosts.
"""

VENDOR = {'name': 'jiasule',
 'headers': {'x-via-jsl': None},
 'cookies': [r'^__jsluid_s='],
 'cname': r'jiasule\.org'}
