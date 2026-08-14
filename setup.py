"""Compatibility shim for older pip that does not read [project] from pyproject.toml.

Keep in sync with pyproject.toml (name, version, entry point).
"""

from setuptools import setup

setup(
    name="ether-w4f-scanner",
    version="0.1.0",
    description="Passive TLS / CDN / WAF / edge fingerprinting of API endpoints",
    packages=["w4f"],
    python_requires=">=3.10",
    entry_points={"console_scripts": ["w4f = w4f.cli:main"]},
)
