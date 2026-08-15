"""wordfence — waf vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'wordfence',
 'block': {'body': ['wordfence'], 'priority': 51}, 'deployment': 'on-prem', 'headers': {'server': 'wf[_-]?waf'}}
