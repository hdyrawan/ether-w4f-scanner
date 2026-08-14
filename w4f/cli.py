"""CLI entry point: w4f --target host[:port] [...]"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import re
import sys
import threading
import time

from w4f import __version__
from w4f.banner import BANNER
from w4f.report import csv_doc, fmt_block, md_doc
from w4f.scanner import probe_one


_TAGLINE = "passive TLS / CDN / WAF / edge fingerprinting"

# Max hostname length per RFC 1035/1123 (253 chars) + port allowance.
_MAX_HOST_LEN = 253


def _is_private_ip(host: str) -> bool:
    """True for RFC1918 / loopback / link-local / CGNAT / documentation IPs.

    Scanning these is a legitimate use (private bank infrastructure,
    loopback in tests), so this only WARNS — it never blocks. The caller
    decides what to do with the warning.
    """
    try:
        import ipaddress
        ip = ipaddress.ip_address(host.split("%")[0])  # strip zone id
    except ValueError:
        return False
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast)


def _validate_hostport(hostport: str) -> tuple[bool, str]:
    """Reject targets that cannot be legitimate scan input.

    Returns (ok, message). A message with ok=True is a warning (kept);
    ok=False means the target is dropped with the reason. Guards against
    malicious --target-json input: control characters / newlines (log
    injection, weird DNS), URI schemes (file:// etc.), and absurdly long
    hostnames (DNS-lookup DoS).
    """
    h = hostport.strip()
    if not h:
        return False, "empty target"
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in h):
        return False, "control character in target"
    if "://" in h:
        return False, "URI scheme not allowed (hostname only)"
    host = h.split(":", 1)[0]
    if len(host) > _MAX_HOST_LEN:
        return False, f"hostname too long ({len(host)} > {_MAX_HOST_LEN})"
    if any(c.isspace() for c in host):
        return False, "whitespace in hostname"
    if _is_private_ip(host):
        return True, f"note: {host} is a private/internal address (scanning anyway)"
    return True, ""


def _domain(hostport: str) -> str:
    """Extract a throttle domain from a host[:port] target."""
    h = hostport.split(":", 1)[0]
    # strip a leading dot-joined hostname down to its registrable-ish part:
    # throttle per-hostname is fine (per-domain tracking per the proposal).
    return h.lower()


class Throttle:
    """Per-domain adaptive delay between probes.

    The submit loop sleeps ``base_delay`` between submissions (a flat
    pacing that keeps sweeps polite). On a 429/503 response the per-domain
    delay doubles (cap 10s) so the domain gets breathing room; a success
    resets it to the base. ``--delay 0`` (default) preserves the old
    no-pacing behavior.
    """

    CAP = 10.0
    MULT = 2.0

    def __init__(self, base_delay: float = 0.0):
        self.base = base_delay
        self._delays: dict[str, float] = {}
        self._lock = threading.Lock()

    def delay_for(self, hostport: str) -> float:
        with self._lock:
            return self._delays.get(_domain(hostport), self.base)

    def bump(self, hostport: str) -> float:
        """Called after a 429/503: double the domain delay (capped)."""
        d = _domain(hostport)
        with self._lock:
            cur = self._delays.get(d, self.base) or self.base
            nxt = min(cur * self.MULT, self.CAP)
            self._delays[d] = nxt
            return nxt

    def reset(self, hostport: str) -> None:
        """Called after a success: drop the domain back to base."""
        d = _domain(hostport)
        with self._lock:
            self._delays.pop(d, None)


def _http_status_code(result: dict) -> int | None:
    """Extract the numeric HTTP status from a probe result, if any."""
    try:
        status = ((result.get("tls") or {}).get("http") or {}).get("status") or ""
        m = re.search(r" (\d{3}) ", status)
        return int(m.group(1)) if m else None
    except Exception:
        return None


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


def _read_host_lines(lines) -> list[str]:
    """One host[:port] per line; blank lines and # comments ignored.

    Shared by stdin and --target-file so both behave identically.
    """
    hosts: list[str] = []
    for raw in lines:
        ln = raw.strip()
        if not ln or ln.startswith("#"):
            continue
        hosts.append(ln)
    return hosts


def _load_targets_from_file(path: str) -> list[str]:
    """Read a plain-text host list: one host[:port] per line, # comments
    and blank lines ignored."""
    with open(path, encoding="utf-8") as f:
        return _read_host_lines(f)


def _load_targets_from_csv(path: str) -> list[str]:
    """Read a CSV target list.

    Uses the column named ``host`` or ``subdomain`` when the first row is a
    header; otherwise treats every row's FIRST column as the host (bare
    column lists). Skips the header row in the header case. Never raises on
    a malformed row — the caller's validation drops whatever is junk.
    """
    import csv

    hosts: list[str] = []
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    if not rows:
        return hosts
    header = [h.strip().lower() for h in rows[0]]
    # a header is present iff some cell names a host-ish column
    host_idx = None
    for i, name in enumerate(header):
        if name in ("host", "subdomain", "hostname"):
            host_idx = i
            break
    if host_idx is not None:
        for row in rows[1:]:
            if row and len(row) > host_idx:
                hosts.append(row[host_idx])
    else:
        for row in rows:
            if row and row[0].strip():
                hosts.append(row[0])
    return hosts


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
    ap.add_argument("--target-file", metavar="FILE",
                    help="plain-text host list, one host[:port] per line; "
                         "# comments and blank lines ignored")
    ap.add_argument("--target-csv", metavar="FILE",
                    help="CSV target list — uses the column named host/subdomain "
                         "when the first row is a header, else the first column")
    ap.add_argument("--path", default="/", help="HTTP path to GET (default /)")
    ap.add_argument("--timeout", type=float, default=8.0,
                    help="connect/TLS/HTTP timeout per host (default 8s)")
    ap.add_argument("--workers", type=int, default=8,
                    help="parallel host count (default 8)")
    ap.add_argument("--delay", type=float, default=0.0,
                    help="seconds to sleep between submissions (default 0 = no "
                         "pacing); on a 429/503 the per-domain delay doubles up "
                         "to 10s and resets on success")
    ap.add_argument("--json", metavar="FILE",
                    help="write the full machine-readable result tree to FILE")
    ap.add_argument("--md", metavar="FILE",
                    help="write markdown per-host blocks (for docs) to FILE")
    ap.add_argument("--csv", metavar="FILE",
                    help="write a flat CSV — one row per host (primary verdict) "
                         "with host, port, ips, cname, verdict, confidence, "
                         "signals, mtls, tls_version, alpn, spki, http_status, "
                         "block, error")
    ap.add_argument("--no-http", action="store_true",
                    help="TLS/cert/DNS only, skip the HTTP request")
    ap.add_argument("--verify", action="store_true",
                    help="OPT-IN active probe: send one benign <script> query and "
                         "report the WAF block page (catches silent WAFs like "
                         "FortiWeb/F5-ASM that passive scanning cannot see)")
    ap.add_argument("--ws", metavar="PATH", default=None,
                    help="OPT-IN WebSocket upgrade probe: request an upgrade at "
                         "PATH (default /) and report whether the edge answers "
                         "101 Switching Protocols (and from which identity)")
    ap.add_argument("--grpc", action="store_true",
                    help="OPT-IN gRPC health-check probe: POST a gRPC "
                         "health-check frame and report grpc-status / gateway "
                         "identity (best-effort; real gRPC is HTTP/2)")
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
    if args.target_file:
        targets += _load_targets_from_file(args.target_file)
    if args.target_csv:
        targets += _load_targets_from_csv(args.target_csv)
    # Pipeline mode: no explicit target source and stdin is not a TTY
    # (e.g. `subfinder -d example.com | w4f`). Same one-per-line format as
    # --target-file, same validation below.
    if not targets and not sys.stdin.isatty():
        targets += _read_host_lines(sys.stdin)

    # Input validation: drop anything that cannot be a legitimate hostname
    # (control chars, URI schemes, overlong names) — a hostile --target-json
    # file must not turn the scan into a DNS DoS or log-injection vector.
    # Private IPs are warned, not dropped: scanning internal infrastructure
    # is a legitimate use of this tool.
    cleaned: list[str] = []
    for t in targets:
        ok, msg = _validate_hostport(t)
        if not ok:
            print(f"warning: dropping target {t!r}: {msg}", file=sys.stderr)
            continue
        if msg:
            print(f"warning: {msg}", file=sys.stderr)
        cleaned.append(t)
    # Deduplicate after validation (case-insensitive), preserving order.
    targets = list(dict.fromkeys(t.lower() for t in cleaned))

    if not targets:
        print("error: nothing to scan — pass --target HOST and/or --target-json "
              "--target-file --target-csv FILE (or pipe hosts on stdin)",
              file=sys.stderr)
        return 2

    results = []
    throttle = Throttle(args.delay)
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {}
        for h in targets:
            # per-domain adaptive pacing between submissions
            d = throttle.delay_for(h)
            if d > 0:
                time.sleep(d)
            futures[ex.submit(probe_one, h, args.path, args.timeout,
                              not args.no_http, args.verify, args.ws,
                              args.grpc)] = h
        for fut in cf.as_completed(futures):
            r = fut.result()
            results.append(r)
            # adaptive backoff: 429/503 doubles the domain delay, success resets
            code = _http_status_code(r)
            if code in (429, 503):
                throttle.bump(futures[fut])
            elif code is not None:
                throttle.reset(futures[fut])
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
    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            f.write(csv_doc(results))
        print(f"CSV -> {args.csv}", file=sys.stderr)

    # A host that failed is a real failure: signal it so scripts can tell
    # "all clean" from "some hosts errored" without parsing the JSON.
    if any(r.get("error") for r in results):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
