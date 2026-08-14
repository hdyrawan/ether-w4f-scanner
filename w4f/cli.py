"""CLI entry point: w4f --target host[:port] [...]"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import sys

from w4f import __version__
from w4f.banner import BANNER
from w4f.report import fmt_block, md_doc
from w4f.scanner import probe_one


_TAGLINE = "passive TLS / CDN / WAF / edge fingerprinting"


def _load_targets_from_json(path: str) -> list[str]:
    """Read a subdomain-enumeration JSON file and return the host list.

    Accepts the subdomainfinder.c99.nl export shape — an array of objects
    like [{"subdomain": "cms.example.com", "ip": "…", "cloudflare": false}]
    — plus any array of strings, or an object with a "subdomains"/"hosts"
    list. The `subdomain` field wins when present; bare strings are used
    as-is. Hosts are trimmed, deduped (case-insensitive), and kept in order.
    """
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    hosts: list[str] = []
    if isinstance(data, dict):
        for key in ("subdomains", "hosts", "targets", "results"):
            if isinstance(data.get(key), list):
                data = data[key]
                break

    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                sub = item.get("subdomain") or item.get("host") or item.get("name")
            elif isinstance(item, str):
                sub = item
            else:
                continue
            sub = str(sub).strip()
            if sub:
                hosts.append(sub)
    return list(dict.fromkeys(h.lower() for h in hosts if h))


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="w4f",
        description="Passive TLS/CDN/WAF/edge fingerprinting of API endpoints "
                    "(DNS + one SNI TLS handshake + one GET; no attack payloads).",
    )
    ap.add_argument("--target", action="append", metavar="HOST[:PORT]",
                    help="DNS name or IP, optional :port (default 443). Repeatable. "
                         "Either --target or --target-json is required.")
    ap.add_argument("--target-json", metavar="FILE",
                    help="JSON file of targets to scan — a subdomain-enumeration "
                         "export (array of {\"subdomain\", \"ip\", \"cloudflare\"} "
                         "objects, e.g. subdomainfinder.c99.nl), an array of strings, "
                         "or an object with a subdomains/hosts list. Each subdomain "
                         "is scanned like a --target.")
    ap.add_argument("--path", default="/", help="HTTP path to GET (default /)")
    ap.add_argument("--timeout", type=float, default=8.0,
                    help="connect/TLS/HTTP timeout per host (default 8s)")
    ap.add_argument("--workers", type=int, default=8,
                    help="parallel host count (default 8)")
    ap.add_argument("--json", metavar="FILE",
                    help="write the full machine-readable result tree to FILE")
    ap.add_argument("--md", metavar="FILE",
                    help="write markdown per-host blocks (for docs) to FILE")
    ap.add_argument("--no-http", action="store_true",
                    help="TLS/cert/DNS only, skip the HTTP request")
    ap.add_argument("--version", action="version",
                    version=f"%(prog)s {__version__} — {_TAGLINE}")
    ap.add_argument("--quiet", action="store_true",
                    help="suppress the per-host console block (useful with --json/--md)")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    targets: list[str] = list(args.target or [])
    if args.target_json:
        targets += _load_targets_from_json(args.target_json)
    if not targets:
        print("error: nothing to scan — pass --target HOST and/or --target-json FILE",
              file=sys.stderr)
        return 2

    results = []
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(probe_one, h, args.path, args.timeout, not args.no_http): h
                   for h in targets}
        for fut in cf.as_completed(futures):
            results.append(fut.result())
    results.sort(key=lambda r: r["hostport"])

    if not args.quiet:
        print(BANNER)
        print(f"  {_TAGLINE}   v{__version__}")
        print()
        for r in results:
            print(fmt_block(r))
            print()

    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"JSON -> {args.json}", file=sys.stderr)
    if args.md:
        with open(args.md, "w") as f:
            f.write(md_doc(results))
        print(f"MD  -> {args.md}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
