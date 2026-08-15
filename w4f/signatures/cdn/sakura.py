"""sakura — cdn vendor signature. See _template.py for the schema.

Sakura Internet (Japan hosting/CDN). Customer edges GSLB through
`site-*.gslb*.sakura.ne.jp` CNAMEs (verified on Sakura's own properties,
2026-08-15). The sakura.ne.jp suffix is Sakura's own DNS brand; the origin
behind it is not a signal.
"""

VENDOR = {'name': 'sakura',
 'cname': r'sakura\.ne\.jp'}
