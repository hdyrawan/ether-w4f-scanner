"""netease — cdn vendor signature. See _template.py for the schema.

NetEase's own CDN (网易加速) DNS suffix is 163jiasu.com. Its edge also emits
the `ens-cache` via marker that Alibaba uses, so the CNAME is the
distinguishing signal.
Observed on NetEase's own properties.
"""

VENDOR = {'name': 'netease',
 'cname': r'163jiasu\.com'}
