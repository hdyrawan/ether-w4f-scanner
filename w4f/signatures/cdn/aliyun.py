"""aliyun — cdn vendor signature. See _template.py for the schema.

Alibaba Cloud CDN / ESA (Edge Security Acceleration). Alibaba's own CDN
domains are tbcache.com and alicdn.com; its ESA WAF inserts the
acw_tc and cdn_sec_tc cookies (per Alibaba's own docs), and Alibaba
observability adds the eagleeye-traceid header. kunlun*.com is Alibaba's
CDN (昆仑) platform.
Observed on Chinese e-commerce and payment hosts.
NOTE: the `ens-cache` via marker is shared with NetEase's CDN and is NOT
used as a signal.
"""

VENDOR = {'name': 'aliyun', 'deployment': 'cloud',
 'headers': {'eagleeye-traceid': None},
 'cookies': [r'^acw_tc=', r'^cdn_sec_tc=', r'^aliyungf_tc='],
 'cname': r'tbcache\.com|alicdn\.com|kunlun\w*\.com'}
