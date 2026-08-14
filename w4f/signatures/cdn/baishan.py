"""baishan — cdn vendor signature. See _template.py for the schema.

Baishan Cloud (白山云) is a Chinese edge cloud/CDN provider. Its GSLB /
routing domains are bsgslb.cn and bsclink.cn.
Observed on Chinese government and news hosts.
"""

VENDOR = {'name': 'baishan',
 'cname': r'bsgslb\.cn|bsclink\.cn'}
