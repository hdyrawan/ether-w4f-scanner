"""gcore — cdn vendor signature. See _template.py for the schema.

Gcore (Gcore Labs), EU/RU edge/CDN/WAF provider. Customers CNAME to
`cl-****.gcdn.co` per Gcore's own docs ("Replace cl-****.gcdn.co with the
value specific to your account"); security vendors attribute gcdn.co to
Gcore Labs CDN.
Verified 2026-08-15: Gcore docs CNAME contract + domain ownership.
NOTE: Gcore publishes a CDN IP API (api.gcore.com/cdn/public-ip-list) but
the list is ~990 individual /32s that churn — not a stable netblock rule;
the CNAME carries the verdict.
"""

VENDOR = {'name': 'gcore',
 'cname': r'gcdn\.co'}
