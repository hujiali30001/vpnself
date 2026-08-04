"""Regression tests for the multi-agent audit fixes (2026-07).

Each test pins one confirmed defect so it cannot silently return:
  - protocol: oversized declared length must resync (not stall/OOM); offset parse
  - utils: ip_in_network must accept host-bits-set CIDRs (strict=False)
  - rule_engine: match_explicit distinguishes no-match from default-action match
  - circuit_breaker: _prune must keep the defaultdict (no KeyError crash-loop)
  - settings: atomic save + corrupt/non-dict config falls back without crashing
"""
import json
import struct

import pytest

from common.protocol import (
    unpack_frame, pack_frame, unpack_connect, pack_connect, Cmd,
    FRAME_HEADER_SIZE, MAX_FRAME_SIZE,
)
from common.utils import ip_in_network
from client.core.rule_engine import RuleEngine, DomainRule, IpCidrRule, Action
from client.core.circuit_breaker import CircuitBreaker, MAX_ENTRIES
from client.config import settings


# --- protocol -----------------------------------------------------------------

def test_oversized_frame_resyncs_instead_of_stalling():
    # Header claims ~4GB: must resync (dummy PONG) rather than return None, which
    # would look like "need more bytes" forever (pre-auth OOM / parser stall).
    header = struct.pack("!IIB", 0xFFFFFFFF, 7, int(Cmd.DATA))
    result = unpack_frame(header, 0)
    assert result is not None
    assert result[1] == Cmd.PONG


def test_incomplete_valid_frame_still_returns_none():
    partial = pack_frame(1, Cmd.DATA, b"abcdef")[:-2]
    assert unpack_frame(partial, 0) is None


def test_unpack_frame_offset_parses_in_place():
    buf = pack_frame(1, Cmd.DATA, b"hello") + pack_frame(2, Cmd.CLOSE, b"")
    assert unpack_frame(buf, 0) == (1, Cmd.DATA, b"hello")
    assert unpack_frame(buf, FRAME_HEADER_SIZE + 5) == (2, Cmd.CLOSE, b"")


def test_max_frame_boundary_is_accepted():
    payload = b"x" * (MAX_FRAME_SIZE - FRAME_HEADER_SIZE)
    frame = pack_frame(1, Cmd.DATA, payload)
    assert unpack_frame(frame, 0) == (1, Cmd.DATA, payload)


def test_unpack_connect_rejects_empty_host():
    # An empty host resolves to a machine-dependent address on the server; it
    # must be rejected at the protocol layer, not left to the SSRF guard.
    payload = struct.pack("!H", 0) + struct.pack("!H", 443)
    assert unpack_connect(payload) is None


def test_unpack_connect_rejects_port_zero():
    payload = struct.pack("!H", 3) + b"a.b" + struct.pack("!H", 0)
    assert unpack_connect(payload) is None


def test_unpack_connect_roundtrips_valid_target():
    # A well-formed CONNECT payload must still parse (guard didn't over-reject).
    frame = pack_connect(7, "example.com", 443)
    payload = frame[FRAME_HEADER_SIZE:]
    assert unpack_connect(payload) == ("example.com", 443)


# --- utils --------------------------------------------------------------------

def test_ip_in_network_accepts_host_bits_set():
    # Human-written CIDR with host bits: strict=True would raise -> always False.
    assert ip_in_network("10.0.0.5", "10.0.0.5/24") is True
    assert ip_in_network("10.0.1.5", "10.0.0.0/24") is False


# --- rule_engine --------------------------------------------------------------

def test_match_explicit_none_when_no_rule():
    eng = RuleEngine()
    eng.replace_rules([DomainRule(pattern="*.proxy.me", action=Action.PROXY)], [], Action.DIRECT)
    assert eng.match_explicit("nothing.example") is None


def test_explicit_rule_equal_to_default_is_honoured():
    # A DIRECT rule when default is also DIRECT must still register as a match,
    # so callers don't mistake it for "no rule" and override it with heuristics.
    eng = RuleEngine()
    eng.replace_rules([DomainRule(pattern="cdn.cn", action=Action.DIRECT)], [], Action.DIRECT)
    assert eng.match_explicit("cdn.cn") == Action.DIRECT


def test_ip_rule_matches_resolved_ip():
    eng = RuleEngine()
    eng.replace_rules([], [IpCidrRule(pattern="1.2.3.0/24", action=Action.PROXY)], Action.DIRECT)
    assert eng.match_explicit("host.example", "1.2.3.9") == Action.PROXY


def test_replace_rules_is_atomic_swap():
    eng = RuleEngine()
    eng.replace_rules([DomainRule(pattern="a.com", action=Action.PROXY, priority=1)], [], Action.DIRECT)
    first = eng.get_domain_rules()
    eng.replace_rules([DomainRule(pattern="b.com", action=Action.BLOCK)], [], Action.PROXY)
    # The previously-returned snapshot is unaffected by the swap.
    assert [r.pattern for r in first] == ["a.com"]
    assert eng.default_action == Action.PROXY


# --- circuit_breaker ----------------------------------------------------------

def test_prune_keeps_defaultdict_no_keyerror(tmp_path):
    cb = CircuitBreaker(state_path=str(tmp_path / "cb.json"))
    for i in range(MAX_ENTRIES + 20):
        cb.record_failure(f"10.{i // 256}.{i % 256}.1")
    # After a prune converted _failures, this new IP would KeyError on a plain dict.
    cb.record_failure("8.8.8.8")  # must not raise


def test_blocked_count_snapshot_safe(tmp_path):
    cb = CircuitBreaker(state_path=str(tmp_path / "cb.json"))
    cb.record_failure("1.1.1.1")
    # Getters snapshot with list(...) so they can't raise mid-iteration.
    assert isinstance(cb.get_blocked_count(), int)
    assert isinstance(cb.get_failure_count(), int)


# --- settings -----------------------------------------------------------------

def test_save_is_atomic_and_roundtrips(tmp_path):
    p = tmp_path / "client_config.json"
    cfg = dict(settings.DEFAULT_CONFIG)
    cfg["server_host"] = "1.2.3.4"
    cfg["psk"] = "secret"
    assert settings.save_config(cfg, p) is True
    # No leftover temp file, and the value round-trips.
    assert not (tmp_path / "client_config.json.tmp").exists()
    loaded = settings.load_config(p)
    assert loaded["server_host"] == "1.2.3.4"
    assert loaded["psk"] == "secret"


def test_non_dict_config_falls_back_to_defaults(tmp_path):
    p = tmp_path / "client_config.json"
    p.write_text("[]", encoding="utf-8")  # valid JSON, not an object
    loaded = settings.load_config(p)  # must not raise TypeError
    assert loaded["server_port"] == settings.DEFAULT_CONFIG["server_port"]
    # The bad file is preserved as .bak, not silently discarded.
    assert (tmp_path / "client_config.json.bak").exists()


def test_corrupt_config_backed_up(tmp_path):
    p = tmp_path / "client_config.json"
    p.write_text("{ this is not json", encoding="utf-8")
    loaded = settings.load_config(p)
    assert loaded["server_port"] == settings.DEFAULT_CONFIG["server_port"]
    assert (tmp_path / "client_config.json.bak").exists()


# --- geoip --------------------------------------------------------------------

def test_geoip_does_not_misclassify_foreign_ips_as_china():
    # The old hand-maintained /5../8 supernets swept in foreign space and routed
    # it DIRECT into the GFW. These must now be non-China (APNIC-accurate table).
    from client.core.geoip import is_china_ip
    for ip in ("43.165.178.174",  # Tencent Japan (was inside 42.0.0.0/7)
               "37.16.0.0",        # RIPE / Europe (was inside 36.0.0.0/7)
               "112.196.0.0",      # was inside 112.0.0.0/5
               "8.8.8.8", "1.1.1.1", "104.16.0.1", "13.107.42.14"):
        assert not is_china_ip(ip), f"{ip} must NOT classify as China"


def test_geoip_still_classifies_genuine_china_ips():
    from client.core.geoip import is_china_ip
    for ip in ("114.114.114.114", "223.5.5.5", "119.29.29.29",
               "180.76.76.76", "1.2.4.8", "36.155.0.1"):
        assert is_china_ip(ip), f"{ip} must classify as China"


def test_default_rules_carry_no_china_ip_cidrs():
    # China detection lives in the O(log n) is_china_ip() heuristic, not in the
    # rule set -- so the built-in defaults must not dump thousands of CIDRs into
    # the linearly-scanned _ip_rules (perf) nor shadow user IP rules (intent).
    re = RuleEngine()
    re._load_defaults()
    assert re.get_ip_rules() == []
