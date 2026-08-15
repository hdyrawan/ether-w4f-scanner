"""wallarm — waf vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'wallarm',
 'block': {'body': ['wallarm', 'blocked'], 'priority': 52}, 'deployment': 'on-prem', 'headers': {'server': 'nginx[_-]wallarm'}}
