"""tencent-cdn — cdn vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'tencent-cdn', 'deployment': 'cloud',
 'headers': {'server': 'tencent', 'x-cache-lookup': None},
 'cname': 'dnsv1\\.com(\\.cn)?|tencentcs\\.com|\\.tcdn\\.'}
