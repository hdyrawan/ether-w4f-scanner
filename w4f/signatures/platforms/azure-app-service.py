"""azure-app-service — platforms vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'azure-app-service',
 'cookies': ['^ARRAffinity', '^ARRAffinitySameSite'],
 'cname': 'azurewebsites\\.net|azurefd\\.net'}
