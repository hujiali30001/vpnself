"""
Furun VPN - Rule Engine

Evaluates routing decisions based on domain rules, IP rules, and GeoIP.
Rules are loaded from a JSON configuration file.
"""

import json
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

from common.utils import get_logger, is_ip_address
from client.core.geoip import CHINA_IP_RANGES

log = get_logger("client.rule_engine")


class Action(Enum):
    DIRECT = "direct"
    PROXY = "proxy"
    BLOCK = "block"


@dataclass
class Rule:
    """A single routing rule."""
    pattern: str       # Domain pattern (exact, wildcard, or IP CIDR)
    action: Action     # Action to take on match
    priority: int = 0  # Higher = evaluated first
    description: str = ""
    enabled: bool = True

    @classmethod
    def from_dict(cls, d: dict) -> "Rule":
        return cls(
            pattern=d.get("pattern", "*"),
            action=Action(d.get("action", "direct")),
            priority=d.get("priority", 0),
            description=d.get("description", ""),
            enabled=d.get("enabled", True),
        )

    def to_dict(self) -> dict:
        return {
            "pattern": self.pattern,
            "action": self.action.value,
            "priority": self.priority,
            "description": self.description,
            "enabled": self.enabled,
        }


@dataclass
class DomainRule(Rule):
    """Rule matching by domain name. Supports exact match and wildcard (*.example.com)."""

    def matches(self, host: str) -> bool:
        if not self.enabled:
            return False
        host_lower = host.lower()
        pattern_lower = self.pattern.lower()
        if "*" in pattern_lower:
            # Only support *.example.com style (suffix match), which covers all our rules
            if pattern_lower.startswith("*."):
                suffix = pattern_lower[1:]  # .example.com
                return host_lower == pattern_lower[2:] or host_lower.endswith(suffix)
            # Fallback to exact match for other wildcard patterns
            return host_lower == pattern_lower
        return host_lower == pattern_lower


@dataclass
class IpCidrRule(Rule):
    """Rule matching by IP CIDR range."""

    def matches(self, ip_str: str) -> bool:
        if not self.enabled:
            return False
        from common.utils import ip_in_network
        return ip_in_network(ip_str, self.pattern)


class RuleEngine:
    """Evaluates routing rules to determine traffic routing strategy."""

    def __init__(self):
        self._domain_rules: list[DomainRule] = []
        self._ip_rules: list[IpCidrRule] = []
        self.default_action: Action = Action.DIRECT

    def add_domain_rule(self, rule: DomainRule):
        self._domain_rules.append(rule)
        self._domain_rules.sort(key=lambda r: r.priority, reverse=True)

    def add_ip_rule(self, rule: IpCidrRule):
        self._ip_rules.append(rule)
        self._ip_rules.sort(key=lambda r: r.priority, reverse=True)

    def remove_domain_rule(self, index: int) -> bool:
        if 0 <= index < len(self._domain_rules):
            self._domain_rules.pop(index)
            return True
        return False

    def remove_ip_rule(self, index: int) -> bool:
        if 0 <= index < len(self._ip_rules):
            self._ip_rules.pop(index)
            return True
        return False

    def clear_rules(self):
        self._domain_rules.clear()
        self._ip_rules.clear()

    def get_domain_rules(self) -> list[DomainRule]:
        return list(self._domain_rules)

    def get_ip_rules(self) -> list[IpCidrRule]:
        return list(self._ip_rules)

    def evaluate(self, host: str) -> Action:
        """Determine the routing action for a given host."""
        if is_ip_address(host):
            for rule in self._ip_rules:
                if rule.matches(host):
                    log.debug("IP rule match: %s -> %s (%s)", host, rule.action.value, rule.pattern)
                    return rule.action

        for rule in self._domain_rules:
            if rule.matches(host):
                log.debug("Domain rule match: %s -> %s (%s)", host, rule.action.value, rule.pattern)
                return rule.action

        return self.default_action

    def evaluate_with_ip(self, host: str, resolved_ip: str | None = None) -> Action:
        """Evaluate routing with optional pre-resolved IP."""
        action = self.evaluate(host)
        if action != self.default_action:
            return action

        if resolved_ip and resolved_ip != host:
            for rule in self._ip_rules:
                if rule.matches(resolved_ip):
                    log.debug("IP rule match (resolved): %s (%s) -> %s",
                              host, resolved_ip, rule.action.value)
                    return rule.action

        return action

    def load_rules(self, path: str | Path):
        """Load rules from a JSON file."""
        p = Path(path)
        if not p.exists():
            log.warning("Rules file not found: %s, loading built-in defaults", p)
            self._load_defaults()
            return

        try:
            with open(p, "r", encoding="utf-8-sig") as f:  # handles BOM
                data = json.load(f)

            self.default_action = Action(data.get("default_action", "direct"))
            self._domain_rules.clear()
            self._ip_rules.clear()

            for rd in data.get("domain_rules", []):
                rule = DomainRule.from_dict(rd)
                self._domain_rules.append(rule)

            for rd in data.get("ip_rules", []):
                rule = IpCidrRule.from_dict(rd)
                self._ip_rules.append(rule)

            self._domain_rules.sort(key=lambda r: r.priority, reverse=True)
            self._ip_rules.sort(key=lambda r: r.priority, reverse=True)

            log.info("Loaded %d domain rules + %d IP rules (default action: %s)",
                     len(self._domain_rules), len(self._ip_rules),
                     self.default_action.value)

        except (json.JSONDecodeError, OSError, KeyError) as e:
            log.error("Failed to load rules: %s, using defaults", e)
            self._load_defaults()

    def save_rules(self, path: str | Path):
        """Save rules to a JSON file."""
        data = {
            "default_action": self.default_action.value,
            "domain_rules": [r.to_dict() for r in self._domain_rules],
            "ip_rules": [r.to_dict() for r in self._ip_rules],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        log.info("Saved %d domain + %d IP rules to %s",
                 len(self._domain_rules), len(self._ip_rules), path)

    def _load_defaults(self):
        """Load sensible default rules."""
        self.default_action = Action.DIRECT
        self._domain_rules.clear()
        self._ip_rules.clear()

        # Default proxy domains (foreign sites that need proxy from China)
        default_proxy_domains = [
            # Google & services
            ("google.com", 0), ("*.google.com", 0), ("*.googleapis.com", 0),
            ("*.gstatic.com", 0), ("*.googleusercontent.com", 0),
            ("*.googlevideo.com", 0), ("*.gvt2.com", 0), ("*.gvt1.com", 0), ("*.youtube-nocookie.com", 0), ("*.google-analytics.com", 0),
            ("*.googletagmanager.com", 0), ("*.googleadservices.com", 0),
            ("*.doubleclick.net", 0), ("*.chrome.com", 0),
            ("*.goog", 0),  # Google TLD (CRL/PKI/certificate services)
            # YouTube
            ("youtube.com", 0), ("*.youtube.com", 0), ("*.ytimg.com", 0),
            ("*.youtu.be", 0), ("*.ggpht.com", 0),
            # OpenAI / ChatGPT
            ("chatgpt.com", 0), ("*.chatgpt.com", 0),
            ("openai.com", 0), ("*.openai.com", 0),
            ("*.oaistatic.com", 0), ("*.oaiusercontent.com", 0),
            # Other AI services
            ("gemini.google.com", 0),
            ("claude.ai", 0), ("*.claude.ai", 0),
            ("perplexity.ai", 0), ("*.perplexity.ai", 0),
            # Social media
            ("twitter.com", 0), ("*.twitter.com", 0), ("*.twimg.com", 0), ("t.co", 0),
            ("x.com", 0), ("*.x.com", 0),  # Twitter/X
            ("facebook.com", 0), ("*.facebook.com", 0), ("*.fbcdn.net", 0),
            ("instagram.com", 0), ("*.instagram.com", 0), ("*.cdninstagram.com", 0),
            ("discord.com", 0), ("*.discord.com", 0), ("*.discordapp.com", 0),
            ("reddit.com", 0), ("*.reddit.com", 0), ("*.redditmedia.com", 0),
            ("tiktok.com", 0), ("*.tiktok.com", 0), ("*.tiktokcdn.com", 0),
            # Developer
            ("github.com", 0), ("*.github.com", 0), ("*.githubusercontent.com", 0),
            ("*.githubassets.com", 0), ("gitlab.com", 0), ("*.gitlab.com", 0),
            ("stackoverflow.com", 0), ("*.stackoverflow.com", 0),
            ("*.stackexchange.com", 0), ("*.docker.com", 0), ("*.docker.io", 0),
            # Streaming
            ("netflix.com", 0), ("*.netflix.com", 0), ("*.nflxvideo.net", 0),
            ("*.nflxext.com", 0), ("spotify.com", 0), ("*.spotify.com", 0),
            ("*.scdn.co", 0), ("twitch.tv", 0), ("*.twitch.tv", 0),
            # Crypto / Finance
            ("binance.com", 0), ("*.binance.com", 0), ("*.binance.cloud", 0),
            ("*.bnbstatic.com", 0),  # Binance static/CDN resources
            ("bybit.com", 0), ("*.bybit.com", 0),
            ("coinbase.com", 0), ("*.coinbase.com", 0),
            ("okx.com", 0), ("*.okx.com", 0),
            # Other
            ("wikipedia.org", 0), ("*.wikipedia.org", 0),
            ("*.steampowered.com", 0), ("steamcommunity.com", 0),
            ("*.notion.so", 0), ("slack.com", 0), ("*.slack.com", 0),
            ("*.zoom.us", 0), ("*.dropbox.com", 0), ("*.dropboxusercontent.com", 0),
            ("*.intercom.io", 0), ("*.intercomcdn.com", 0),
        ]
        for pattern, priority in default_proxy_domains:
            self._domain_rules.append(DomainRule(
                pattern=pattern, action=Action.PROXY, priority=priority,
                description=f"Default proxy: {pattern}",
            ))

        # Default direct domains
        default_direct_domains = [
            ("*.cn", 100), ("*.*.cn", 100), ("*.*.*.cn", 100),
            ("*.aliyun.com", 50), ("*.alicdn.com", 50), ("*.alipay.com", 50),
            ("*.taobao.com", 50), ("*.tmall.com", 50), ("*.jd.com", 50),
            ("*.baidu.com", 50), ("*.bdstatic.com", 50),
            ("*.bilibili.com", 50), ("*.hdslb.com", 50),
            ("*.qq.com", 50), ("*.gtimg.com", 50),
            ("*.weixin.qq.com", 50), ("*.wechat.com", 50),
            ("*.douyin.com", 50), ("*.ixigua.com", 50), ("*.bytedance.com", 50),
            ("*.zhihu.com", 50), ("*.csdn.net", 50), ("*.mi.com", 50),
            ("*.xiaomi.com", 50), ("*.meituan.com", 50), ("*.dianping.com", 50),
            ("*.ctrip.com", 50), ("*.12306.cn", 50), ("*.pinduoduo.com", 50),
            # Windows / CDN
            ("*.msftconnecttest.com", 60), ("*.msftncsi.com", 60),
            ("e.clarity.ms", 60), ("*.clarity.ms", 60),
            ("mobile.events.data.microsoft.com", 60),
            ("connectivitycheck.gstatic.com", 60),
            ("*.vscode-cdn.net", 60),
        ]
        for pattern, priority in default_direct_domains:
            self._domain_rules.append(DomainRule(
                pattern=pattern, action=Action.DIRECT, priority=priority,
                description=f"Default direct: {pattern}",
            ))

        # China IP CIDR rules (imported from geoip module)
        for cidr in CHINA_IP_RANGES:
            self._ip_rules.append(IpCidrRule(
                pattern=cidr, action=Action.DIRECT, priority=80,
                description=f"China IP: {cidr}",
            ))

        self._domain_rules.sort(key=lambda r: r.priority, reverse=True)
        self._ip_rules.sort(key=lambda r: r.priority, reverse=True)

        log.info("Built-in defaults: %d domain rules + %d IP rules",
                 len(self._domain_rules), len(self._ip_rules))

