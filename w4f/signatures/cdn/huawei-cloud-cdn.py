"""huawei-cloud-cdn — cdn vendor signature. See _template.py for the schema.

Huawei Cloud CDN (华为云CDN) edge. Customers CNAME to `*.c.cdnhwc<nn>.com`
(hwc = Huawei Cloud); cache nodes emit `x-ccdn-*` headers (x-ccdn-expires,
x-ccdn-cachettl) and `x-hcs-proxy-type`.
Observed on Chinese weather and news hosts.
Distinct from the huawei-cloud-waf rule (HWWAFSESID cookie / huaweicloudwaf
server token).
"""

VENDOR = {'name': 'huawei-cloud-cdn',
 'headers': {'x-ccdn-*': None, 'x-hcs-proxy-type': '1'},
 'cname': r'cdnhwc\d*\.com'}
