"""aws-s3 — cdn vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'aws-s3', 'deployment': 'cloud',
 'headers': {'server': 'amazons3', 'x-amz-request-id': None},
 'cname': '\\.s3[.-].*\\.amazonaws\\.com'}
