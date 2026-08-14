"""google-gfe — platforms vendor signature. See _template.py for the schema."""

VENDOR = {'name': 'google-gfe',
 'headers': {'server': 'gws|gfe|esf'},
 'cert': 'google trust services',
 'ptr': '1e100\\.net|googleusercontent\\.com',
 'requires': [{'kind': 'header', 'name': 'server', 're': 'gws|gfe|esf'},
              {'kind': 'ptr', 're': '1e100\\.net|googleusercontent\\.com'}]}
