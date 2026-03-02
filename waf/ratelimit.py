from collections import deque
import time
import threading
import os
from typing import Tuple, Set

# Internal/infrastructure IPs that must NEVER be blocked
# (K8s node IPs, HAProxy, loopback — blocking these blocks ALL users)
_INFRA_TRUSTED = {'127.0.0.1', '::1', '207.180.211.157'}
_INFRA_PREFIXES = (
    '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
    '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
    '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
)

def _is_infra_ip(ip: str) -> bool:
    """Check if IP is internal infrastructure — must NEVER be blocked."""
    if not ip:
        return True
    return ip in _INFRA_TRUSTED or ip.startswith(_INFRA_PREFIXES)

class IPBlocklist:
    """Automatic IP blocking for repeated attackers"""
    def __init__(self, block_threshold: int = 10, block_duration: int = 3600):
        self.block_threshold = block_threshold  # Number of attacks before auto-block
        self.block_duration = block_duration    # Block duration in seconds (default 1 hour)
        self._attack_counts = {}     # ip -> count of attacks
        self._blocked_ips = {}       # ip -> unblock_time
        self._lock = threading.Lock()
    
    def record_attack(self, ip: str):
        """Record an attack attempt from an IP.
        SAFETY: Infrastructure IPs (192.168.x, 10.x, K8s nodes) are NEVER blocked.
        """
        # CRITICAL GUARD: never block internal infrastructure IPs
        if _is_infra_ip(ip):
            return False
        with self._lock:
            now = time.time()
            # Clean expired blocks
            self._clean_expired_blocks(now)
            
            # Increment attack count
            self._attack_counts[ip] = self._attack_counts.get(ip, 0) + 1
            
            # Auto-block if threshold exceeded
            if self._attack_counts[ip] >= self.block_threshold:
                self._blocked_ips[ip] = now + self.block_duration
                return True  # IP was auto-blocked
        return False
    
    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is blocked.
        SAFETY: Infrastructure IPs are NEVER considered blocked.
        """
        # CRITICAL GUARD: infra IPs are never blocked
        if _is_infra_ip(ip):
            return False
        with self._lock:
            now = time.time()
            self._clean_expired_blocks(now)
            return ip in self._blocked_ips
    
    def unblock_ip(self, ip: str):
        """Manually unblock an IP"""
        with self._lock:
            if ip in self._blocked_ips:
                del self._blocked_ips[ip]
            if ip in self._attack_counts:
                del self._attack_counts[ip]
    
    def get_blocked_ips(self) -> dict:
        """Get all currently blocked IPs with their unblock times"""
        with self._lock:
            now = time.time()
            self._clean_expired_blocks(now)
            return dict(self._blocked_ips)
    
    def get_attack_stats(self) -> dict:
        """Get attack statistics for all IPs"""
        with self._lock:
            return dict(self._attack_counts)
    
    def _clean_expired_blocks(self, now: float):
        """Remove expired IP blocks"""
        expired = [ip for ip, unblock_time in self._blocked_ips.items() if now >= unblock_time]
        for ip in expired:
            del self._blocked_ips[ip]
            if ip in self._attack_counts:
                del self._attack_counts[ip]

class RateLimiter:
    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self.max_requests = int(os.environ.get('BEEWAF_RATE_LIMIT_MAX', max_requests))
        self.window_seconds = int(os.environ.get('BEEWAF_RATE_LIMIT_WINDOW', window_seconds))
        self._stores = {}  # client_id -> deque[timestamps]
        self._lock = threading.Lock()

    def _now(self) -> float:
        return time.time()

    def allow_request(self, client_id: str) -> Tuple[bool, int]:
        """Return (allowed, remaining_requests).
        SAFETY: Infrastructure IPs (K8s nodes, proxies) are NEVER rate-limited.
        """
        # CRITICAL GUARD: never rate-limit internal infrastructure IPs
        if _is_infra_ip(client_id):
            return True, self.max_requests
        now = self._now()
        window_start = now - self.window_seconds
        with self._lock:
            dq = self._stores.get(client_id)
            if dq is None:
                dq = deque()
                self._stores[client_id] = dq
            # evict old timestamps
            while dq and dq[0] < window_start:
                dq.popleft()
            if len(dq) >= self.max_requests:
                return False, 0
            dq.append(now)
            return True, self.max_requests - len(dq)

    def reset(self, client_id: str):
        with self._lock:
            if client_id in self._stores:
                del self._stores[client_id]

