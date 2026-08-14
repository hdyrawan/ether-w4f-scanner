"""API-gateway / platform-edge vendors (13).

Each entry is a vendor dict per the modular signature schema
(see _template.py). Gateways sit in front of the API origin and expose
gateway-specific headers; some are also the origin's own server.
"""

VENDORS = [
    {
        "name": "sgw",
        # Shopee/Sea Group API gateway — bank UAT/staging hosts serve
        # `Server: SGW` (apm-uat1, notice.staging, ...).
        "headers": {"server": r"^SGW(?:/|$)"},
    },
    {
        "name": "kong",
        # Kong API gateway — example-ride.com serves X-Kong-* latency headers
        # (and `Server: kong` on older builds).
        "headers": {"server": r"kong", "x-kong-upstream-latency": None,
                    "x-kong-proxy-latency": None},
    },
    {
        "name": "tyk",
        # Tyk API gateway: x-tyk-* headers (api key / request id / trace).
        "headers": {"x-tyk-*": None},
    },
    {
        "name": "apigee",
        # Google Apigee API gateway: apigee-* headers.
        "headers": {"apigee-*": None, "x-apigee-*": None},
    },
    {
        "name": "azure-api-management",
        # Azure API Management: ocp-apim-* headers + azure-api.net host.
        "headers": {"ocp-apim-*": None},
        "cname": r"azure-api\.net",
    },
    {
        "name": "tencent-gateway",
        # Tencent edge gateways: stgw (apex), tRPC-Gateway (www.example.com).
        "headers": {"server": r"stgw|trpc-gateway", "x-upstream-latency": None},
        "cname": r"tencentcs\.com|dnspod|tcdn",
    },
    {
        "name": "envoy",
        "headers": {"server": r"envoy", "x-envoy-upstream-service-time": None},
    },
    {
        "name": "haproxy",
        "headers": {"server": r"haproxy"},
        # HAProxy stick-table persistence cookie: `<name>=!<base64>` (the `!`
        # prefix marks a stick cookie). Observed on a bank's mobile host
        # (`brks_lb=!…`), where no Server header is exposed.
        "cookies": [r"^[a-zA-Z0-9_.-]+=![A-Za-z0-9+/]+"],
    },
    {
        "name": "tengine",
        # Alibaba's nginx fork — example-market.com / tmall / aliexpress family.
        "headers": {"server": r"tengine", "x-server-id": None, "x-eagleeye-id": None},
    },
    {
        "name": "openresty",
        # Some OpenResty deployments add an explicit X-Openresty header
        # beyond the Server token.
        "headers": {"server": r"openresty", "x-openresty": None},
    },
    {
        "name": "cloudflare-workers",
        # Cloudflare Workers / Pages: cf-worker header on responses.
        "headers": {"cf-worker": None},
    },
    {
        "name": "vercel",
        # Vercel edge: x-vercel-id / x-vercel-cache headers, *.vercel.app CNAME.
        "headers": {"x-vercel-id": None, "x-vercel-cache": None, "server": r"vercel"},
        "cname": r"\.vercel\.app$",
    },
    {
        "name": "google-cloud-run",
        # Google Cloud Run: x-cloud-trace-context header, *.run.app CNAME.
        "headers": {"x-cloud-trace-context": None},
        "cname": r"\.run\.app$",
        "ptr": r"run\.app$",
    },
    {
        "name": "aws-app-runner",
        # AWS App Runner: x-app-runner-region header, *.awsapprunner.com CNAME.
        "headers": {"x-app-runner-region": None},
        "cname": r"\.awsapprunner\.com$",
        "ptr": r"awsapprunner\.com$",
    },
]
