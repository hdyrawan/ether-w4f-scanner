"""aws-app-runner — gateways vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'aws-app-runner',
 'headers': {'x-app-runner-region': None},
 'cname': '\\.awsapprunner\\.com$',
 'ptr': 'awsapprunner\\.com$'}
