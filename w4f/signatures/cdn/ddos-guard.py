"""ddos-guard — cdn vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'ddos-guard', 'deployment': 'cloud', 'headers': {'server': 'ddos-guard'}, 'cookies': ['^__ddg']}
