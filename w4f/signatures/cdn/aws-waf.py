"""aws-waf — cdn vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'aws-waf',
 'headers': {'x-amz-id': None,
             'x-amz-request-id': None,
             'x-blocked-by-waf': 'awsmanagedrules|blocked_by_custom_response',
             '_status': '403',
             'x-cache': '^error from cloudfront$'},
 'cookies': ['^aws\\.?alb='],
 'requires': [[{'kind': 'header', 'name': '_status', 're': '403'},
               {'kind': 'header', 'name': 'x-cache', 're': 'error from cloudfront'}],
              {'kind': 'header', 'name': 'x-amz-id'},
              {'kind': 'header', 'name': 'x-amz-request-id'},
              {'kind': 'header', 'name': 'x-blocked-by-waf'}]}
