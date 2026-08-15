"""wswaf — waf vendor signature. See _template.py for the schema.

`Server: wswaf` is the server token of Wangsu's (网宿) web application
firewall product. It appears alongside Wangsu CDN markers (wscdns.com CNAME,
uproxy via nodes) on protected hosts.
Observed on Chinese banking and media hosts.
"""

VENDOR = {'name': 'wswaf', 'deployment': 'cloud',
 'headers': {'server': r'wswaf(?:/|$)'}}
