"""netscaler — waf vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'netscaler', 'deployment': 'on-prem',
 'headers': {'server': 'ns_[a-z]|netscaler',
             'via': r'\bns-cache',
             'cneonction': None,
             'nncoection': None},
 'cookies': ['^ns_af=', '^citrix_ns_id', '^NSC_']}
