"""f5 — waf vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'f5',
 # BIG-IP ASM's block page. The support-id line is what distinguishes it from
 # any other page titled "Request Rejected"; reported as f5-asm so the ACTIVE
 # finding stays distinguishable from the passive `f5` verdict.
 'block': [{'title': r'^request rejected', 'head': ['f5'],
            'vendor': 'f5-asm', 'priority': 30},
           {'title': r'^request rejected', 'vendor': 'f5-asm', 'priority': 31}], 'deployment': 'on-prem',
 'headers': {'server': 'bigip|big-ip', 'x-wa-info': None, 'x-cnection': None},
 'cookies': ['^bigipserver', '^MRHSession', '^F5_', '^TS[a-fA-F0-9]{6,12}='],
 'cert': 'f5 networks'}
