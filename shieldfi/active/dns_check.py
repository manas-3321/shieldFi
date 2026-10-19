"""Canary DNS test — detect DNS hijacking / spoofing.

Compares answers from local DNS (system) vs trusted DNS (1.1.1.1/8.8.8.8 via DoH).
Flags loopback, private IP, mismatch.
"""
import socket
import json
import urllib.request
import urllib.error
import ipaddress
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from ..utils.logger import get_logger

log = get_logger()

CANARY_DOMAINS = ["example.com", "google.com", "cloudflare.com"]
TRUSTED_DNS = ["1.1.1.1", "8.8.8.8"]

def _is_suspicious_ip(ip: str) -> bool:
    """Check if resolved IP is private/loopback — suspicious for public domains."""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback:
            return True
        if addr.is_private:
            # Private IP for public domain is suspicious (DNS hijack to local)
            return True
        if addr.is_multicast or addr.is_reserved:
            return True
        return False
    except ValueError:
        return False

def resolve_via_system(domain: str, timeout: float = 3.0) -> List[str]:
    """Resolve using OS DNS (gethostbyname)."""
    try:
        # gethostbyname_ex returns (hostname, aliaslist, ipaddrlist)
        _, _, ips = socket.gethostbyname_ex(domain)
        return ips
    except socket.gaierror as e:
        log.warning(f"System DNS failed for {domain}: {e}")
        return []
    except Exception as e:
        log.warning(f"System DNS error for {domain}: {e}")
        return []

def resolve_via_doh(domain: str, doh_server: str = "1.1.1.1", timeout: float = 4.0) -> List[str]:
    """Resolve via Cloudflare/Google DoH (DNS-over-HTTPS) — trusted reference.

    Uses https://cloudflare-dns.com/dns-query?name=...&type=A
    Fallback returns [] if network off.
    """
    # Map server to DoH endpoint
    doh_urls = {
        "1.1.1.1": f"https://cloudflare-dns.com/dns-query?name={domain}&type=A",
        "8.8.8.8": f"https://dns.google/resolve?name={domain}&type=A",
    }
    url = doh_urls.get(doh_server, doh_urls["1.1.1.1"])
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
            ips = []
            for ans in data.get("Answer", []):
                if ans.get("type") == 1:  # A record
                    ips.append(ans["data"])
            return ips
    except urllib.error.URLError as e:
        log.warning(f"DoH query failed for {domain} via {doh_server}: {e}")
        return []
    except Exception as e:
        log.warning(f"DoH error for {domain}: {e}")
        return []

# Fallback trusted resolver using dnspython if available (more reliable than DoH sometimes)
def resolve_via_dnspython(domain: str, server: str = "1.1.1.1", timeout: float = 3.0) -> List[str]:
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [server]
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(domain, "A")
        return [str(r) for r in answers]
    except ImportError:
        return []
    except Exception as e:
        log.warning(f"dnspython resolve failed for {domain}: {e}")
        return []

@dataclass
class DNSCheckResult:
    domain: str
    system_ips: List[str] = field(default_factory=list)
    trusted_ips: List[str] = field(default_factory=list)
    trusted_server: str = "1.1.1.1"
    is_hijack_suspected: bool = False
    reasons: List[str] = field(default_factory=list)

@dataclass
class CanaryDNSResult:
    results: List[DNSCheckResult] = field(default_factory=list)
    is_hijack_suspected: bool = False
    summary: str = ""

def check_dns_hijack(domains: List[str] = None, trusted_dns_servers: List[str] = None, timeout: float = 3.0, mock: bool = False, mock_scenario: str = "normal") -> CanaryDNSResult:
    """Main entry — run canary test.

    Set mock=True to simulate hijack for demo.
    """
    if mock:
        return _mock_dns_result(mock_scenario)

    domains = domains or CANARY_DOMAINS
    trusted_dns_servers = trusted_dns_servers or TRUSTED_DNS
    canary = CanaryDNSResult()

    for domain in domains:
        sys_ips = resolve_via_system(domain, timeout=timeout)
        # Try DoH first, fallback to dnspython
        trusted_ips = resolve_via_doh(domain, doh_server=trusted_dns_servers[0], timeout=timeout+1)
        if not trusted_ips:
            trusted_ips = resolve_via_dnspython(domain, server=trusted_dns_servers[0], timeout=timeout)
            if not trusted_ips and len(trusted_dns_servers) > 1:
                trusted_ips = resolve_via_dnspython(domain, server=trusted_dns_servers[1], timeout=timeout)

        r = DNSCheckResult(domain=domain, system_ips=sys_ips, trusted_ips=trusted_ips, trusted_server=trusted_dns_servers[0])
        reasons = []

        if not sys_ips:
            reasons.append(f"Local DNS failed to resolve {domain} — network/DNS may be down.")
        elif not trusted_ips:
            reasons.append(f"Trusted DNS (1.1.1.1) failed for {domain} — cannot compare (network offline?). Treating as inconclusive.")
        else:
            # Check for loopback/private IPs in system answer
            for ip in sys_ips:
                if _is_suspicious_ip(ip):
                    reasons.append(f"Local DNS for {domain} returned suspicious IP {ip} (loopback/private). Real {domain} should be public.")
                    r.is_hijack_suspected = True
            # Check mismatch — system IPs none overlap trusted
            if sys_ips and trusted_ips and not set(sys_ips) & set(trusted_ips):
                # Some CDNs legitimately return different IPs per region — but example.com is stable
                # For demo we flag mismatch as suspicious; note it's heuristic
                if domain == "example.com":
                    reasons.append(f"Local DNS answer {sys_ips} does not match trusted DNS {trusted_ips} for {domain} — possible DNS hijack.")
                    r.is_hijack_suspected = True
                else:
                    # For google.com etc., be softer
                    reasons.append(f"Local vs trusted DNS differ for {domain}: local {sys_ips} vs trusted {trusted_ips}. Could be CDN — but verify.")

        r.reasons = reasons
        canary.results.append(r)

    canary.is_hijack_suspected = any(r.is_hijack_suspected for r in canary.results)
    if canary.is_hijack_suspected:
        canary.summary = "Suspicious DNS answers detected — possible hijack. Avoid logging in until you disconnect."
    elif any(not r.system_ips or not r.trusted_ips for r in canary.results):
        canary.summary = "DNS comparison inconclusive (network offline or DNS blocked). Results limited."
    else:
        canary.summary = "Canary DNS looks clean — local DNS matches trusted servers."
    return canary

def _mock_dns_result(scenario: str) -> CanaryDNSResult:
    if scenario == "hijacked":
        # Simulate DNS hijack: example.com resolves to private IP
        canary = CanaryDNSResult(is_hijack_suspected=True, summary="MOCK: DNS hijack simulated!")
        canary.results = [
            DNSCheckResult(domain="example.com", system_ips=["192.168.1.100"], trusted_ips=["93.184.216.34"], is_hijack_suspected=True,
                           reasons=["Local DNS for example.com returned suspicious IP 192.168.1.100 (private). Real example.com should be public (93.184.216.34). Possible DNS hijack."]),
            DNSCheckResult(domain="google.com", system_ips=["192.168.1.100"], trusted_ips=["142.250.80.14"], is_hijack_suspected=True,
                           reasons=["Local DNS answer ['192.168.1.100'] does not match trusted DNS ['142.250.80.14'] — possible hijack."]),
            DNSCheckResult(domain="cloudflare.com", system_ips=["127.0.0.1"], trusted_ips=["104.16.132.229"], is_hijack_suspected=True,
                           reasons=["Local DNS for cloudflare.com returned suspicious IP 127.0.0.1 (loopback). Possible DNS hijack."]),
        ]
        return canary
    # Normal mock
    canary = CanaryDNSResult(is_hijack_suspected=False, summary="MOCK: Canary DNS clean (simulated).")
    canary.results = [
        DNSCheckResult(domain="example.com", system_ips=["93.184.216.34"], trusted_ips=["93.184.216.34"], reasons=[]),
        DNSCheckResult(domain="google.com", system_ips=["142.250.80.14"], trusted_ips=["142.250.80.14"], reasons=[]),
        DNSCheckResult(domain="cloudflare.com", system_ips=["104.16.132.229"], trusted_ips=["104.16.132.229"], reasons=[]),
    ]
    return canary
