"""barracuda — waf vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'barracuda', 'deployment': 'on-prem', 'cookies': ['^BNI__BARRACUDA_LB_COOKIE=', '^barra_counter_session=']}
