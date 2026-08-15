"""fortiweb — waf vendor signature. See _template.py for the schema.

FortiWeb is the reference "silent WAF": it answers a normal request with the
origin's own headers (plain nginx/apache) and only reveals itself on a block
page, which is why --verify exists. The `cookiesession1` cookie changes that
— FortiWeb sets it on the FIRST response to every client, before any attack
shape is sent, so the WAF is identifiable PASSIVELY.

Sourced from Fortinet's own documentation ("FortiWeb embeds a cookie in the
response's Set-Cookie: field ... named cookiesession1", HTTP sessions &
security / waf cookie-security) and from the Fortinet community thread on
renaming it for information-disclosure reasons — the name is fixed, which is
exactly what makes it a signature. Confirmed against hosts whose --verify
probe independently returned the FortiWeb block page.

Deliberately NOT included: some FortiWeb deployments cloak upstream headers
by replacing the value with X's (`server: XXXXXXX`). Header cloaking is
offered by several WAF vendors, so attributing it to FortiWeb would trade a
false negative for a false positive; it surfaces on the console `leads` line
instead.
"""

VENDOR = {'name': 'fortiweb',
 # Block page (--verify, or a refusal to the plain GET). FortiWeb localizes
 # the title — the Indonesian fleet returns "The URL Request Tidak Tersedia".
 'block': [{'title': r'the url you requested has been blocked', 'priority': 20},
           {'title': r'tidak tersedia.*url|url.*tidak tersedia', 'priority': 21}],
          'headers': {'server': 'fortiweb|fortigate'},
          'cookies': ['^FORTIWAFSID=', '^cookiesession1=']}
