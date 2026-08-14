"""edgecast — cdn vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'edgecast', 'headers': {'server': '^ecd(?:/|$)|^ecs(?:/|$)', 'x-ec-cache': None}}
