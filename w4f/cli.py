"""CLI entry point: w4f --target host[:port] [...]"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import sys

from w4f.report import fmt_block, md_doc
from w4f.scanner import probe_one


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="w4f",
        description="Passive TLS/CDN/WAF/edge fingerprinting of API endpoints "
                    "(DNS + one SNI TLS handshake + one GET; no attack payloads).",
    )
    ap.add_argument("--target", action="append", required=True, metavar="HOST[:PORT]",
                    help="DNS name or IP, optional :port (default 443). Repeatable.")
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
    ap.add_argument("--quiet", action="store_true",
                    help="suppress the per-host console block (useful with --json/--md)")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    results = []
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(probe_one, h, args.path, args.timeout, not args.no_http): h
                   for h in args.target}
        for fut in cf.as_completed(futures):
            results.append(fut.result())
    results.sort(key=lambda r: r["hostport"])

    if not args.quiet:
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
