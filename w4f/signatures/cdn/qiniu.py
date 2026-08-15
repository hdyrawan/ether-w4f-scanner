"""qiniu — cdn vendor signature. See _template.py for the schema.

Qiniu Cloud (七牛云) is a major Chinese CDN/object-storage provider.
Customers CNAME to `*.qiniudns.com` (Qiniu's DNS platform).
Observed on Chinese portal and e-commerce hosts.
"""

VENDOR = {'name': 'qiniu', 'deployment': 'cloud',
 'cname': r'qiniudns\.com|qiniucdn\.com'}
