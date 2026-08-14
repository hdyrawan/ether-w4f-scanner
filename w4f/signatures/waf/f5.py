"""f5 — waf vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'f5',
 'headers': {'server': 'bigip|big-ip', 'x-wa-info': None, 'x-cnection': None},
 'cookies': ['^bigipserver', '^MRHSession', '^F5_', '^TS[a-fA-F0-9]{6,12}='],
 'cert': 'f5 networks'}
