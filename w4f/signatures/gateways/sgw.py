"""sgw — gateways vendor signature. See _template.py for the schema.

`Server: SGW` is the edge server banner of the **Shopee / Sea Group API
gateway** ("SGW" = Shopee Gateway). Verified against the live Shopee/Sea
fleet: the marketplace site, its subdomain variants, the payments app and
the express-logistics site all answer `Server: SGW`, on Shopee-owned
netblocks (RDAP SHOPEE-SG), with `shopee-baggage:` and the Shopee CSP
frame-ancestors list on the full web responses.

The banner is a bare 3-letter token with no version, so keep the match
anchored (`^SGW(?:/|$)`); an unanchored substring match would collide with
`nginx`-style banners containing "sgw" in a path value.
"""
VENDOR = {'name': 'sgw', 'deployment': 'origin', 'headers': {'server': '^SGW(?:/|$)'}}
