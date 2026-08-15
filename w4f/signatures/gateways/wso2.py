"""wso2 — WSO2 Carbon / API Manager gateway.

The classic WSO2 fingerprint is the Tomcat connector's `server` attribute:
every WSO2 product (API Manager gateway, Identity Server, Enterprise
Integrator, ...) ships `server="WSO2 Carbon Server"` in its
catalina-server.xml (verified in product-is and product-apim source), so
responses from the management console AND the API gateway carry
`Server: WSO2 Carbon Server`. That is the rule FingerprintHub / nuclei /
BBScan all use, and it comes from WSO2's own config, not copied verbatim
from those databases.

The API Manager gateway's other distinctive artifact is its fault body —
`{"fault": {"code": 9009xx, "message": "...", "description": "..."}}` on
unauthenticated/unauthorized API calls — but the signature schema matches
headers/cookies/cert/cname/ptr/nets, not bodies, so it is not expressible
here (the block-page matcher is the body-side hook, and WSO2 has no block
page signature yet).

`x-wso2-*` headers: WSO2 uses an `x-wso2-` metadata prefix in its gateway
and metadata tooling (e.g. x-wso2-api-id in product-microgateway/apk).
Mostly request-side, but when a response carries any x-wso2-* header it is
a strong WSO2 marker. Prefix keys are exact-lookup-safe: a prefix only
fires when such a header actually exists.
"""

VENDOR = {
    "name": "wso2", "deployment": "on-prem",
    "headers": {
        "server": r"wso2 carbon server|^wso2(?:/|$)",
        "x-wso2-*": None,
    },
}
