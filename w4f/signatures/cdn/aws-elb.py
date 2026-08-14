"""aws-elb — cdn vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'aws-elb',
 'headers': {'server': 'awselb/2\\.0'},
 'cname': 'elb\\.amazonaws\\.com',
 'ptr': 'compute\\.amazonaws\\.com'}
