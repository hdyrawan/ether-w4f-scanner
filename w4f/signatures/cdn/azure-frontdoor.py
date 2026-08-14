"""azure-frontdoor — cdn vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'azure-frontdoor',
 'headers': {'x-azure-ref': None,
             'server': 'azure-frontdoor|frontdoor',
             'x-cache': 'CONFIG_NOCACHE|CONFIG_CACHE'},
 'cname': 'azurefd\\.net',
 'ptr': 'azurefd\\.net'}
