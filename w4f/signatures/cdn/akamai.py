"""akamai — cdn vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'akamai',
 # Kona WAF / Bot Manager block page.
 'block': {'title': r'access denied', 'body': ['akamai'], 'priority': 41}, 'deployment': 'cloud',
 'headers': {'server': 'akamai',
             'x-akamai': None,
             'x-akamai-transformed': None,
             'akamai-grn': None,
             'x-grn': None,
             'akamai-request-bc': None},
 'cookies': ['^ak_bmsc=',
             '^bm_sz=',
             '^akavpau_',
             '^_abck=',
             '^aka~',
             '^akaalb_',
             '^ak_bmsc=[^;]*;\\s*.*\\bE3D='],
 'cert': 'akamai',
 # edgekey.net (Enhanced TLS / Secure CDN) and akamaiedge.net (Standard TLS)
 # are Akamai's two most common delivery CNAMEs and were both MISSING:
 # `akamai\.net` cannot match "akamaiedge.net" (literal dot), so an
 # Akamai-fronted host scored headers-only (7%) instead of cname+headers
 # (27%) — or nothing at all when the edge sent no akamai-* header.
 # `edgekey[-.]` covers edgekey.net and edgekey-staging.net without matching
 # an unrelated hostname that merely starts with "edgekey" (the ns-cache
 # substring lesson).
 'cname': 'akamaized|akamaihd|edgesuite|edgekey[-.]|akamaiedge|akadns'
          '|akamai\\.net|akamaitechnologies',
 'ptr': 'akamai',
 'nets': ['23.32.0.0/11',
          '104.64.0.0/10',
          '184.24.0.0/13',
          '2.16.0.0/13',
          '23.192.0.0/11',
          '96.6.0.0/15',
          '96.7.0.0/16']}
