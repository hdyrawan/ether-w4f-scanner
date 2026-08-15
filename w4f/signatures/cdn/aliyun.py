"""aliyun — cdn vendor signature. See _template.py for the schema.

Alibaba Cloud CDN / WAF (阿里云). Delivery CNAMEs end in tbcache.com /
alicdn.com / kunlun*.com; Alibaba Cloud WAF (云盾) delivery CNAMEs end in
yundunwaf*.com (added v0.1.43, observed on a Chinese fintech host). The
Alibaba ESA WAF sets acw_tc / cdn_sec_tc / aliyungf_tc cookies and the
eagleeye-traceid header. NOTE: the `ens-cache` Via marker is shared with
NetEase CDN and is deliberately NOT a signal; `spanner` server tokens are
Alibaba-internal and not used.
"""

VENDOR = {'name': 'aliyun', 'deployment': 'cloud',
 'headers': {'eagleeye-traceid': None},
 'cookies': [r'^acw_tc=', r'^cdn_sec_tc=', r'^aliyungf_tc='],
 'cname': r'tbcache\.com|alicdn\.com|kunlun\w*\.com|yundunwaf\d*\.com'}
