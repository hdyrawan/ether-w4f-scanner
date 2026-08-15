"""edgecast — cdn vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'edgecast', 'deployment': 'cloud', 'headers': {'server': '^ecd(?:/|$)|^ecs(?:/|$)', 'x-ec-cache': None}}
