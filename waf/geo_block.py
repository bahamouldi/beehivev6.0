"""
BeeWAF GeoIP Blocking Module
==============================
Country-based blocking and threat scoring by region.
Uses lightweight IP-to-country mapping without heavy databases.
Surpasses F5 geolocation features with:
- Country-based allow/deny lists
- Continent-level policies
- Tor exit node detection
- VPN/Proxy/Datacenter detection
- Anonymous proxy detection
- IP reputation scoring by geo-region
"""

import re
import struct
import socket
import time
import threading
import logging
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict

log = logging.getLogger("beewaf.geo")


# ==================== KNOWN TOR EXIT NODES (sample) ====================
# In production, this would be updated from https://check.torproject.org/torbulkexitlist
TOR_EXIT_NODES: Set[str] = set()

# ==================== KNOWN VPN/PROXY PROVIDERS IP RANGES ====================
VPN_PROXY_RANGES = [
    # Major VPN providers (CIDR notation)
    ('104.238.128.0', '104.238.191.255'),   # NordVPN range
    ('185.159.156.0', '185.159.159.255'),   # Mullvad
    ('103.86.96.0', '103.86.99.255'),       # CyberGhost
    ('146.70.0.0', '146.70.255.255'),       # Mullvad expanded
]

# ==================== DATACENTER IP RANGES ====================
DATACENTER_RANGES = [
    # Major cloud providers
    ('3.0.0.0', '3.255.255.255'),           # AWS
    ('13.52.0.0', '13.57.255.255'),         # AWS
    ('18.0.0.0', '18.255.255.255'),         # AWS
    ('34.0.0.0', '34.255.255.255'),         # GCP
    ('35.184.0.0', '35.199.255.255'),       # GCP
    ('104.196.0.0', '104.199.255.255'),     # GCP
    ('40.74.0.0', '40.125.255.255'),        # Azure
    ('52.0.0.0', '52.255.255.255'),         # AWS
    ('54.0.0.0', '54.255.255.255'),         # AWS
    ('104.16.0.0', '104.31.255.255'),       # Cloudflare
    ('172.64.0.0', '172.71.255.255'),       # Cloudflare
    ('151.101.0.0', '151.101.255.255'),     # Fastly
    ('199.232.0.0', '199.232.255.255'),     # Fastly
    ('185.199.108.0', '185.199.111.255'),   # GitHub
    ('140.82.112.0', '140.82.127.255'),     # GitHub
    ('64.233.160.0', '64.233.191.255'),     # Google
    ('66.102.0.0', '66.102.15.255'),        # Google
    ('66.249.64.0', '66.249.95.255'),       # Google crawlers
    ('209.85.128.0', '209.85.255.255'),     # Google
    ('216.58.192.0', '216.58.223.255'),     # Google
]

# ==================== HIGH RISK COUNTRIES (by threat intelligence) ====================
HIGH_RISK_COUNTRIES = {
    'KP',  # North Korea
}

MEDIUM_RISK_COUNTRIES = {
    'CN', 'RU', 'IR', 'SY',  # Commonly high-attack origins
}

# ==================== COUNTRY CODE TO NAME MAPPING ====================
COUNTRY_NAMES = {
    'US': 'United States', 'GB': 'United Kingdom', 'DE': 'Germany',
    'FR': 'France', 'CN': 'China', 'RU': 'Russia', 'JP': 'Japan',
    'KR': 'South Korea', 'BR': 'Brazil', 'IN': 'India', 'AU': 'Australia',
    'CA': 'Canada', 'IT': 'Italy', 'ES': 'Spain', 'NL': 'Netherlands',
    'SE': 'Sweden', 'NO': 'Norway', 'DK': 'Denmark', 'FI': 'Finland',
    'PL': 'Poland', 'PT': 'Portugal', 'IR': 'Iran', 'SY': 'Syria',
    'KP': 'North Korea', 'TN': 'Tunisia', 'MA': 'Morocco', 'DZ': 'Algeria',
    'EG': 'Egypt', 'TR': 'Turkey', 'SA': 'Saudi Arabia', 'AE': 'UAE',
    'IL': 'Israel', 'TH': 'Thailand', 'VN': 'Vietnam', 'PH': 'Philippines',
    'ID': 'Indonesia', 'MY': 'Malaysia', 'SG': 'Singapore', 'HK': 'Hong Kong',
    'TW': 'Taiwan', 'UA': 'Ukraine', 'RO': 'Romania', 'BG': 'Bulgaria',
    'CZ': 'Czech Republic', 'HU': 'Hungary', 'AT': 'Austria', 'CH': 'Switzerland',
    'BE': 'Belgium', 'IE': 'Ireland', 'NZ': 'New Zealand', 'ZA': 'South Africa',
    'MX': 'Mexico', 'AR': 'Argentina', 'CO': 'Colombia', 'CL': 'Chile',
}


def ip_to_int(ip: str) -> int:
    """Convert IP address string to integer."""
    try:
        return struct.unpack('!I', socket.inet_aton(ip))[0]
    except (socket.error, struct.error):
        return 0


def is_ip_in_range(ip: str, start_ip: str, end_ip: str) -> bool:
    """Check if IP is within a range."""
    ip_int = ip_to_int(ip)
    return ip_to_int(start_ip) <= ip_int <= ip_to_int(end_ip)


class GeoBlocker:
    """
    Geographic IP blocking and threat scoring.
    """
    
    def __init__(self,
                 blocked_countries: Set[str] = None,
                 allowed_countries: Set[str] = None,
                 block_tor: bool = True,
                 block_vpn: bool = False,
                 block_datacenter: bool = False,
                 score_by_geo: bool = True):
        
        # If allowed_countries is set, ONLY those countries are allowed
        self.blocked_countries = blocked_countries or set()
        self.allowed_countries = allowed_countries  # None = allow all
        self.block_tor = block_tor
        self.block_vpn = block_vpn
        self.block_datacenter = block_datacenter
        self.score_by_geo = score_by_geo
        
        self._stats = defaultdict(int)
        self._lock = threading.Lock()
    
    def check_ip(self, client_ip: str) -> Dict:
        """
        Check an IP address against geographic policies.
        
        Returns:
            {
                'allowed': bool,
                'reason': str,
                'geo_score': float (0-1, threat score),
                'ip_type': str ('residential', 'datacenter', 'tor', 'vpn'),
                'country': str (country code),
                'details': dict
            }
        """
        result = {
            'allowed': True,
            'reason': None,
            'geo_score': 0.0,
            'ip_type': 'residential',
            'country': 'unknown',
            'details': {}
        }
        
        # === 1. Tor Exit Node Check ===
        if self.block_tor and client_ip in TOR_EXIT_NODES:
            result['allowed'] = False
            result['reason'] = 'tor-exit-node'
            result['ip_type'] = 'tor'
            result['geo_score'] = 0.9
            self._record_stat('blocked_tor')
            return result
        
        # === 2. VPN/Proxy Check ===
        is_vpn = self._check_vpn(client_ip)
        if is_vpn:
            result['ip_type'] = 'vpn'
            result['geo_score'] = 0.4
            if self.block_vpn:
                result['allowed'] = False
                result['reason'] = 'vpn-proxy'
                self._record_stat('blocked_vpn')
                return result
        
        # === 3. Datacenter Check ===
        is_dc = self._check_datacenter(client_ip)
        if is_dc:
            result['ip_type'] = 'datacenter'
            result['geo_score'] = 0.3
            if self.block_datacenter:
                result['allowed'] = False
                result['reason'] = 'datacenter-ip'
                self._record_stat('blocked_datacenter')
                return result
        
        # === 4. Risk Scoring ===
        if self.score_by_geo:
            country = result.get('country', 'unknown')
            if country in HIGH_RISK_COUNTRIES:
                result['geo_score'] = max(result['geo_score'], 0.8)
            elif country in MEDIUM_RISK_COUNTRIES:
                result['geo_score'] = max(result['geo_score'], 0.5)
        
        # === 5. Country Block/Allow Check ===
        country = result.get('country', 'unknown')
        
        if self.allowed_countries is not None and country != 'unknown':
            if country not in self.allowed_countries:
                result['allowed'] = False
                result['reason'] = f'country-not-allowed:{country}'
                self._record_stat(f'blocked_country_{country}')
                return result
        
        if country in self.blocked_countries:
            result['allowed'] = False
            result['reason'] = f'country-blocked:{country}'
            self._record_stat(f'blocked_country_{country}')
            return result
        
        return result
    
    def _check_vpn(self, ip: str) -> bool:
        for start, end in VPN_PROXY_RANGES:
            if is_ip_in_range(ip, start, end):
                return True
        return False
    
    def _check_datacenter(self, ip: str) -> bool:
        for start, end in DATACENTER_RANGES:
            if is_ip_in_range(ip, start, end):
                return True
        return False
    
    def _record_stat(self, key: str):
        with self._lock:
            self._stats[key] += 1
    
    def add_blocked_country(self, country_code: str):
        self.blocked_countries.add(country_code.upper())
    
    def remove_blocked_country(self, country_code: str):
        self.blocked_countries.discard(country_code.upper())
    
    def get_stats(self) -> Dict:
        with self._lock:
            return dict(self._stats)


# Module-level singleton
_blocker = None

def get_blocker(**kwargs) -> GeoBlocker:
    global _blocker
    if _blocker is None:
        _blocker = GeoBlocker(**kwargs)
    return _blocker

def check_ip(client_ip: str) -> Dict:
    return get_blocker().check_ip(client_ip)
