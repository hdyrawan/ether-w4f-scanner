"""imperva — cdn vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'imperva',
 # Imperva ships TWO different block pages. SecureSphere (the on-prem
 # appliance) answers 200 OK with <title>Error</title> + "The incident ID
 # is", so only --verify reaches it and the generic title needs a body pair.
 # Incapsula (cloud) is the incap_ses/incapsula shape. Observed directly.
 'block': [{'title': r'.*', 'body': ['incident id'],
            'body_any': ["this page can't be displayed",
                         'contact support for additional information'],
            'deployment': 'on-prem', 'priority': 60},
           {'body_any': ['incapsula'], 'deployment': 'cloud', 'priority': 61},
           {'head': ['incap_ses'], 'deployment': 'cloud', 'priority': 62}],
 'headers': {'x-iinfo': None, 'x-cdn': 'incap', 'server': 'imperva'},
 'cookies': ['^incap_ses', '^visid_incap', '^incap_visid_'],
 'cert': 'imperva',
 'cname': 'incapdns|impervadns',
 'ptr': 'incap|imperva',
 # NOTE: 103.21.244.0/22 was listed here but is a PUBLISHED CLOUDFLARE
 # range (see cdn/cloudflare.py) — a host in it matched both vendors on
 # netblock (30 pts each) and read as a spurious cloudflare/imperva
 # ambiguity. Removed. Imperva's real neighbour range (103.28.248.0/22)
 # should be re-added only after verification against Imperva's official
 # IP-range publication; do not restore the Cloudflare value.
 'nets': ['199.83.128.0/21',
          '198.143.32.0/19',
          '149.126.72.0/21',
          '45.64.64.0/22',
          '185.11.124.0/22',
          '192.230.64.0/18',
          '107.154.0.0/16',
          '45.60.0.0/16',
          '45.223.0.0/16',
          '2a02:e980::/29']}
