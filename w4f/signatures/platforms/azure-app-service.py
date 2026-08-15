"""azure-app-service — platforms vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'azure-app-service', 'deployment': 'cloud',
 'cookies': ['^ARRAffinity', '^ARRAffinitySameSite'],
 'cname': 'azurewebsites\\.net|azurefd\\.net'}
