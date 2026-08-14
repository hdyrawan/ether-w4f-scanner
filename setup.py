"""Compatibility shim for older pip that does not read [project] from pyproject.toml.

Keep the metadata here in sync with pyproject.toml. The VERSION is read from
w4f/__init__.py so it can never drift between the two files.
"""

import re
from pathlib import Path

from setuptools import setup

_HERE = Path(__file__).parent
_init = (_HERE / "w4f" / "__init__.py").read_text(encoding="utf-8")
m = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', _init)
assert m, "could not read __version__ from w4f/__init__.py"
VERSION = m.group(1)

setup(
    name="w4f",
    version=VERSION,
    description="Passive TLS / CDN / WAF / edge fingerprinting of API endpoints",
    long_description=(_HERE / "README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    packages=["w4f"],
    python_requires=">=3.10",
    entry_points={"console_scripts": ["w4f = w4f.cli:main"]},
)
