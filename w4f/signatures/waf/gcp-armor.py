"""gcp-armor — waf vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'gcp-armor', 'headers': {'x-goog-*': None, 'server': 'gcloud|gfe.*armor'}}
