"""kasada — bot vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'kasada', 'deployment': 'cloud',
 'headers': {'x-kpsdk-ct': None, 'x-kasada-*': None},
 'cookies': ['^kpsdk_ct=', '^kpsdk=', '^kpsdkutm=']}
