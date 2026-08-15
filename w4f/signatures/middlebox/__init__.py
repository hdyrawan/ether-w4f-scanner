"""Middlebox signatures — boxes on the SCANNER's own path, not the target's edge.

A TLS-inspection appliance between w4f and the target re-signs the connection
and can serve its own refusal page. Attributing that to the target would
fingerprint our own network on every host scanned from behind it, so these
carry `interception: True` and are reported separately from the edge verdict.
"""
