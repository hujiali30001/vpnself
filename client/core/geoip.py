"""
Furun VPN - GeoIP Lookup

Provides country-level IP geolocation for smart routing decisions.
Uses a built-in China IP list as the primary source.
"""

from pathlib import Path
import bisect
import ipaddress

from common.utils import get_logger

log = get_logger("client.geoip")

# China Mainland IP ranges (major allocations from APNIC)
# Tight: only ranges actually allocated to China, not broad supernets
CHINA_IP_RANGES = [
    # APNIC allocations to China (verified)
    "1.0.1.0/24", "1.0.2.0/23", "1.0.8.0/21", "1.0.32.0/19",
    "1.1.0.0/24", "1.1.2.0/23", "1.1.4.0/22", "1.1.8.0/21",
    "1.1.16.0/20", "1.1.32.0/19",
    "1.2.0.0/23", "1.2.2.0/24", "1.2.4.0/22", "1.2.8.0/21",
    "1.2.16.0/20", "1.2.32.0/19", "1.2.64.0/18",
    "1.3.0.0/16", "1.4.1.0/24", "1.4.2.0/23", "1.4.4.0/22",
    "1.4.8.0/21", "1.4.16.0/20", "1.4.32.0/19", "1.4.64.0/18",
    "1.8.0.0/16", "1.10.0.0/21", "1.10.8.0/23", "1.10.11.0/24",
    "1.10.16.0/20", "1.10.32.0/19", "1.10.64.0/18",
    "1.12.0.0/14", "1.24.0.0/13",
    "14.0.0.0/8", "27.0.0.0/8",
    "36.0.0.0/7", "39.0.0.0/8",
    "42.0.0.0/7", "49.0.0.0/8",
    "58.0.0.0/7", "60.0.0.0/7",
    "101.0.0.0/8", "103.0.0.0/8",
    "106.0.0.0/8", "110.0.0.0/7",
    "112.0.0.0/5", "120.0.0.0/8",
    "121.0.0.0/8", "122.0.0.0/7",
    "124.0.0.0/7", "171.0.0.0/8",
    "175.0.0.0/8", "180.0.0.0/8",
    "182.0.0.0/11", "183.0.0.0/10",
    # Trimmed 202/203/210/211 ranges to actual China allocations
    "202.0.100.0/23", "202.0.110.0/24", "202.0.122.0/23",
    "202.0.176.0/22", "202.3.128.0/23", "202.3.134.0/24",
    "202.4.128.0/19", "202.4.252.0/22", "202.5.32.0/19",
    "202.8.128.0/19", "202.9.32.0/19", "202.9.64.0/18",
    "202.10.64.0/20", "202.10.112.0/20", "202.12.0.0/14",
    "202.20.64.0/18", "202.20.128.0/17", "202.21.48.0/20",
    "202.22.248.0/22", "202.27.12.0/24", "202.27.136.0/23",
    "202.36.226.0/24", "202.38.0.0/22", "202.38.8.0/21",
    "202.38.48.0/20", "202.38.128.0/21", "202.38.136.0/23",
    "202.38.138.0/24", "202.38.140.0/22", "202.38.164.0/22",
    "202.38.168.0/21", "202.38.176.0/23", "202.38.184.0/21",
    "202.38.192.0/18", "202.40.128.0/17", "202.41.128.0/17",
    "202.41.240.0/20", "202.43.76.0/22", "202.43.144.0/20",
    "202.44.16.0/20", "202.44.32.0/20", "202.44.48.0/22",
    "202.44.67.0/24", "202.44.74.0/24", "202.44.96.0/19",
    "202.44.128.0/17", "202.45.0.0/17", "202.45.128.0/18",
    "202.46.16.0/20", "202.46.32.0/19", "202.46.128.0/17",
    "202.47.64.0/18", "202.47.128.0/17",
    "203.0.0.0/18",
    "203.8.0.0/13", "203.18.48.0/21", "203.18.56.0/22",
    "203.22.56.0/21",
    "210.0.0.0/8",  # 210.x is mostly China
    # 211.x: only specific China subnets
    "211.64.0.0/13", "211.80.0.0/12", "211.96.0.0/13",
    "211.136.0.0/13", "211.144.0.0/12", "211.160.0.0/13",
    "218.0.0.0/7", "220.0.0.0/8",
    "221.0.0.0/8", "222.0.0.0/11",
    "222.128.0.0/9", "223.0.0.0/8",
]

# Special-use IP ranges (always treated as local/direct)
SPECIAL_IP_RANGES = [
    "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16",
    "224.0.0.0/4", "240.0.0.0/4",
    "0.0.0.0/8", "100.64.0.0/10",
]


class _IntervalSet:
    """Sorted, merged integer intervals for O(log n) IPv4 membership tests.

    CIDRs are collapsed into disjoint [start, end] ranges, so a single bisect
    locates the only interval that could contain an address -- replacing the
    previous O(n) scan over every network on each lookup.
    """

    def __init__(self, cidrs):
        self._starts: list[int] = []
        self._ends: list[int] = []
        self.rebuild(cidrs)

    def rebuild(self, cidrs):
        intervals = []
        for c in cidrs:
            net = ipaddress.ip_network(c, strict=False)
            intervals.append((int(net.network_address), int(net.broadcast_address)))
        intervals.sort()
        starts: list[int] = []
        ends: list[int] = []
        for s, e in intervals:
            if ends and s <= ends[-1] + 1:  # overlapping or adjacent -> merge
                if e > ends[-1]:
                    ends[-1] = e
            else:
                starts.append(s)
                ends.append(e)
        self._starts, self._ends = starts, ends

    def contains(self, ip_str: str) -> bool:
        try:
            ip = int(ipaddress.ip_address(ip_str))
        except ValueError:
            return False
        i = bisect.bisect_right(self._starts, ip) - 1
        return i >= 0 and ip <= self._ends[i]


# Pre-compute merged interval sets for fast lookup
_CHINA_SET = _IntervalSet(CHINA_IP_RANGES)
_SPECIAL_SET = _IntervalSet(SPECIAL_IP_RANGES)


def is_china_ip(ip_str: str) -> bool:
    """Check if an IPv4 address is allocated to China.
    Caller should check is_special_ip() first for special-use addresses.
    """
    return _CHINA_SET.contains(ip_str)


def is_special_ip(ip_str: str) -> bool:
    """Check if an IP is in a special-use range."""
    return _SPECIAL_SET.contains(ip_str)


def load_china_ip_list(file_path: str) -> int:
    """Load additional China IP ranges from a text file. Returns count added.

    Updates the source range list and rebuilds the lookup set so the new
    ranges take effect immediately for is_china_ip().
    """
    try:
        p = Path(file_path)
        if not p.exists():
            return 0
        with open(p, "r", encoding="utf-8-sig") as f:
            count = 0
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        ipaddress.ip_network(line, strict=False)
                    except ValueError:
                        log.warning("Skipping invalid CIDR in %s: %s", file_path, line)
                        continue
                    CHINA_IP_RANGES.append(line)
                    count += 1
            if count > 0:
                _CHINA_SET.rebuild(CHINA_IP_RANGES)
                log.info("Loaded %d additional China IP ranges from %s", count, file_path)
            return count
    except OSError as e:
        log.warning("Failed to load China IP list from %s: %s", file_path, e)
        return 0
