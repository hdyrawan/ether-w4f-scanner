"""cloudflare-waf — cdn vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'cloudflare-waf',
 'headers': {'cf-mitigated': 'challenge|blocked', 'cf-chl-bypass': None, 'cf-waf-rule-id': None},
 'cookies': ['^__cf_bm=', '^cf-waf-token=', '^cf_chl_']}
