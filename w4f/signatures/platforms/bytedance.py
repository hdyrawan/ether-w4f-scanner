"""bytedance — platforms vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'bytedance',
 'headers': {'server': 'tlb',
             'x-tt-logid': None,
             'x-tt-trace-id': None,
             'x-bytefaas-request-id': None},
 'cname': 'bytecdn|byteimg|byteacctimg|tikcdn|tiktokcdn|bytedns1'}
