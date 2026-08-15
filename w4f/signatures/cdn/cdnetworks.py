"""cdnetworks — cdn vendor signature. See _template.py for the schema.

CDNetworks (Korea/global CDN, strong in KR/JP). Customer delivery CNAMEs
end in `*.cdngc.net` (CDN Global Cache); its edge serves
`Server: PWS/<ver>` with `Via: ... (W)` cache nodes (verified 2026-08-15 on
the vendor's own site + a Korean media customer). The FECW cookie seen on
CDNetworks-hosted sites is a SHARED marker (also on Wangsu) — NOT used.
"""

VENDOR = {'name': 'cdnetworks',
 'cname': r'cdngc\.net|cdnetworks\.com'}
