"""kakao — cdn vendor signature. See _template.py for the schema.

Kakao Corporation (Korea) GSLB / edge. Kakao's own properties resolve
through `*.kgslb.com` (the Kakao GSLB domain, per independent domain
attribution).
Verified 2026-08-15: Kakao's own portal -> daum-*.kgslb.com.
"""

VENDOR = {'name': 'kakao',
 'cname': r'kgslb\.com'}
