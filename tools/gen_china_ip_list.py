"""
Furun VPN - China IPv4 CIDR list generator.

Fetches APNIC's official delegation file and emits an accurate, minimal set of
CIDR blocks allocated to China (CN). Replaces the hand-maintained supernets in
geoip.py, which over-claimed foreign space (e.g. 36.0.0.0/7 swallowed RIPE's
37.0.0.0/8; 42.0.0.0/7 swallowed Tencent Japan's 43.x) and routed those
overseas IPs DIRECT into the GFW where they fail.

Usage:
    python tools/gen_china_ip_list.py [--out client/config/china_ip_list.txt]

The APNIC record format (delegated-apnic-latest) is pipe-delimited:
    apnic|CN|ipv4|1.0.1.0|256|20110414|allocated
                  ^start    ^count(hosts, not a prefix length)
A count is a power-of-two host span but not necessarily aligned to a single
CIDR, so each range is decomposed into the minimal list of aligned CIDRs, then
the whole set is collapsed with ipaddress.collapse_addresses.
"""

import argparse
import ipaddress
import sys
import urllib.request

APNIC_URL = "https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"
DEFAULT_OUT = "client/config/china_ip_list.txt"


def fetch(url: str) -> str:
    with urllib.request.urlopen(url, timeout=90) as resp:
        return resp.read().decode("utf-8", errors="replace")


def parse_cn_ipv4(text: str) -> list[ipaddress.IPv4Network]:
    nets: list[ipaddress.IPv4Network] = []
    for line in text.splitlines():
        if "|CN|ipv4|" not in line:
            continue
        parts = line.split("|")
        # registry|cc|type|start|count|date|status[|...]
        if len(parts) < 7 or parts[6] not in ("allocated", "assigned"):
            continue
        start, count = parts[3], int(parts[4])
        first = int(ipaddress.IPv4Address(start))
        # Decompose [first, first+count) into aligned CIDRs.
        for net in ipaddress.summarize_address_range(
                ipaddress.IPv4Address(first),
                ipaddress.IPv4Address(first + count - 1)):
            nets.append(net)
    return nets


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--url", default=APNIC_URL)
    args = ap.parse_args()

    print(f"fetching {args.url} ...", file=sys.stderr)
    text = fetch(args.url)
    nets = parse_cn_ipv4(text)
    merged = list(ipaddress.collapse_addresses(nets))
    merged.sort(key=lambda n: int(n.network_address))

    with open(args.out, "w", encoding="utf-8") as f:
        f.write("# China IPv4 CIDR list -- generated from APNIC delegated-latest\n")
        f.write("# Regenerate with: python tools/gen_china_ip_list.py\n")
        f.write(f"# {len(merged)} CIDR blocks\n")
        for net in merged:
            f.write(str(net) + "\n")

    print(f"wrote {len(merged)} merged CIDRs to {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
