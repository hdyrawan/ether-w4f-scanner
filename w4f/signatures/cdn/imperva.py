"""imperva — cdn vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'imperva',
 'headers': {'x-iinfo': None, 'x-cdn': 'incap', 'server': 'imperva'},
 'cookies': ['^incap_ses', '^visid_incap', '^incap_visid_'],
 'cert': 'imperva',
 'cname': 'incapdns|impervadns',
 'ptr': 'incap|imperva',
 'nets': ['199.83.128.0/21',
          '198.143.32.0/19',
          '149.126.72.0/21',
          '103.21.244.0/22',
          '45.64.64.0/22',
          '185.11.124.0/22',
          '192.230.64.0/18',
          '107.154.0.0/16',
          '45.60.0.0/16',
          '45.223.0.0/16',
          '2a02:e980::/29']}
