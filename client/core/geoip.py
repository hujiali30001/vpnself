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

# China Mainland IPv4 ranges, sourced from APNIC's authoritative delegation file
# (delegated-apnic-latest) and collapsed to minimal CIDRs. This is an accurate,
# per-allocation table -- NOT the hand-maintained /5..8 supernets used before,
# which wrongly swept in foreign space (e.g. 43.x Tencent-Japan, 37.x RIPE,
# 112.196.x) and routed it DIRECT into the GFW. Regenerate the underlying data
# with:  python tools/gen_china_ip_list.py
#
# The list lives in an auto-generated module so PyInstaller bundles it as an
# ordinary import (robust across source and every frozen build mode). If that
# import ever fails, fall back to an EMPTY list: an unknown IP then routes via
# PROXY (slower, still works) rather than mis-classifying foreign IPs as China
# and leaking them past the tunnel -- fail safe, not fail open.
try:
    from client.config.china_ip_data import CHINA_IP_RANGES as _GENERATED_RANGES
    CHINA_IP_RANGES = list(_GENERATED_RANGES)
except Exception as e:  # pragma: no cover - defensive; import should always work
    log.error("Failed to import bundled China IP data (%s) -- China detection "
              "disabled; overseas routing unaffected, CN traffic will use PROXY", e)
    CHINA_IP_RANGES = []

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
            new_cidrs = []
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        ipaddress.ip_network(line, strict=False)
                    except ValueError:
                        log.warning("Skipping invalid CIDR in %s: %s", file_path, line)
                        continue
                    new_cidrs.append(line)
            count = len(new_cidrs)
            if count == 0:
                return 0
            # Atomic swap: build new merged set, then replace module globals in
            # two pointer-sized assignments (each atomic under the GIL), so a
            # concurrent is_china_ip() call always sees a consistent pair.
            new_ranges = list(CHINA_IP_RANGES) + new_cidrs
            new_set = _IntervalSet(new_ranges)
            CHINA_IP_RANGES[:] = new_ranges          # update in-place for any holders of the reference
            _CHINA_SET._starts = new_set._starts
            _CHINA_SET._ends = new_set._ends
            log.info("Loaded %d additional China IP ranges from %s", count, file_path)
            return count
    except OSError as e:
        log.warning("Failed to load China IP list from %s: %s", file_path, e)
        return 0
