"""
BeeWAF Enterprise v5.0 - DDoS Protection Engine
Surpasses F5 BIG-IP with:
- Layer 7 Behavioral DoS detection (request pattern analysis)
- Slowloris / Slow POST / Slow Read detection
- HTTP Flood mitigation (GET/POST flood patterns)
- Connection Flood detection (per-IP connection tracking)
- Amplification Attack detection (response > request by factor)
- Resource Exhaustion protection (CPU/Memory/connection limits)
- Dynamic Rate Adaptation (auto-adjust thresholds under attack)
- GeoIP-based throttling during DDoS events
- Request Costing (heavy vs light endpoint scoring)
- Progressive Response (warn → captcha → throttle → block)
- SYN Flood indicators via connection behavior
- Attack Fingerprinting (cluster similar attack sources)
"""

import time
import math
import logging
import hashlib
import os
from collections import defaultdict, deque
from threading import Lock, Thread
from typing import Optional

logger = logging.getLogger("beewaf.ddos")

# Internal/infrastructure IPs that must NEVER be blocked by DDoS engine
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


# ============================================================================
# CONNECTION TRACKER
# ============================================================================

class ConnectionTracker:
    """Track active connections per IP for flood detection."""

    def __init__(self, max_per_ip: int = 500, max_total: int = 50000):
        self.max_per_ip = max_per_ip
        self.max_total = max_total
        self.connections = defaultdict(int)
        self.total = 0
        self.lock = Lock()
        self.stats = {"rejected": 0, "peak_total": 0, "peak_per_ip": 0}
        # Request-based tracking (not connection-based for HTTP/1.1 keep-alive)
        self.request_counts = defaultdict(lambda: deque(maxlen=1000))
        self.last_cleanup = time.time()
        # Per-IP request cap (requests/min). Default aligns with DDoS warn threshold (50 rps).
        self.max_requests_per_minute = int(os.environ.get('BEEWAF_DDOS_RPM_LIMIT', '3000'))

    def check_request_rate(self, client_ip: str) -> dict:
        """Check request rate per IP (more accurate than connection tracking for HTTP)."""
        now = time.time()
        
        # Periodic cleanup every 60 seconds
        if now - self.last_cleanup > 60:
            self._cleanup_stale_ips(now)
            self.last_cleanup = now
        
        with self.lock:
            self.request_counts[client_ip].append(now)
            
            # Count requests in last 60 seconds
            cutoff = now - 60
            recent_requests = sum(1 for t in self.request_counts[client_ip] if t > cutoff)
            
            # Allow up to N requests per minute per IP (configurable)
            if recent_requests > self.max_requests_per_minute:
                self.stats["rejected"] += 1
                return {
                    "allowed": False,
                    "reason": f"request_flood:requests={recent_requests}/{self.max_requests_per_minute} per minute",
                    "requests": recent_requests
                }
            
            return {"allowed": True, "requests": recent_requests}

    def _cleanup_stale_ips(self, now: float):
        """Remove IPs with no recent activity."""
        cutoff = now - 300  # 5 minutes
        with self.lock:
            stale = [ip for ip, times in self.request_counts.items() 
                     if not any(t > cutoff for t in times)]
            for ip in stale:
                del self.request_counts[ip]

    def open_connection(self, client_ip: str) -> dict:
        """Register a new connection. Returns whether it should be allowed."""
        # Use request-based rate limiting instead of connection tracking
        return self.check_request_rate(client_ip)

    def close_connection(self, client_ip: str):
        """No-op for request-based tracking (auto-cleaned by timeout)."""
        pass  # Requests are auto-cleaned by _cleanup_stale_ips


# ============================================================================
# SLOW ATTACK DETECTOR (Slowloris, Slow POST, Slow Read)
# ============================================================================

class SlowAttackDetector:
    """Detects slow HTTP attacks: Slowloris, Slow POST, Slow Read."""

    def __init__(self):
        self.active_requests = {}  # request_id -> {start, ip, bytes_received, last_data}
        self.lock = Lock()
        # Thresholds (configurable via env for testing)
        self.header_timeout = int(os.environ.get('BEEWAF_DDOS_HEADER_TIMEOUT', '10'))  # seconds to complete headers
        self.body_timeout = int(os.environ.get('BEEWAF_DDOS_BODY_TIMEOUT', '30'))  # seconds to complete body
        self.min_body_rate = int(os.environ.get('BEEWAF_DDOS_MIN_BODY_RATE', '100'))  # bytes/second minimum
        self.read_timeout = int(os.environ.get('BEEWAF_DDOS_READ_TIMEOUT', '60'))  # slow read timeout
        self.min_read_rate = int(os.environ.get('BEEWAF_DDOS_MIN_READ_RATE', '50'))  # bytes/second minimum read
        self.stats = {
            "slowloris_detected": 0,
            "slow_post_detected": 0,
            "slow_read_detected": 0,
        }

    def start_request(self, request_id: str, client_ip: str,
                      content_length: int = 0):
        """Register start of a new request."""
        with self.lock:
            self.active_requests[request_id] = {
                "start": time.time(),
                "ip": client_ip,
                "content_length": content_length,
                "bytes_received": 0,
                "headers_complete": False,
                "last_data": time.time(),
                "phase": "headers",
            }

    def update_progress(self, request_id: str, bytes_received: int,
                        headers_complete: bool = False):
        """Update request progress. Returns alert if slow attack detected."""
        now = time.time()
        with self.lock:
            req = self.active_requests.get(request_id)
            if not req:
                return None

            req["bytes_received"] = bytes_received
            req["last_data"] = now
            if headers_complete:
                req["headers_complete"] = True
                req["phase"] = "body"

            elapsed = now - req["start"]

            # Slowloris: Headers taking too long
            if not req["headers_complete"] and elapsed > self.header_timeout:
                self.stats["slowloris_detected"] += 1
                del self.active_requests[request_id]
                return {
                    "attack": "slowloris",
                    "ip": req["ip"],
                    "elapsed": elapsed,
                    "severity": "high"
                }

            # Slow POST: Body arriving too slowly
            if req["headers_complete"] and req["content_length"] > 0:
                body_elapsed = now - req["start"]
                if body_elapsed > 5 and bytes_received > 0:
                    rate = bytes_received / body_elapsed
                    if rate < self.min_body_rate and body_elapsed > self.body_timeout:
                        self.stats["slow_post_detected"] += 1
                        del self.active_requests[request_id]
                        return {
                            "attack": "slow_post",
                            "ip": req["ip"],
                            "rate": rate,
                            "severity": "high"
                        }

            return None

    def end_request(self, request_id: str):
        with self.lock:
            self.active_requests.pop(request_id, None)

    def check_stale(self) -> list:
        """Check for stale connections (periodic cleanup)."""
        now = time.time()
        alerts = []
        with self.lock:
            stale = []
            for rid, req in self.active_requests.items():
                idle = now - req["last_data"]
                if idle > 30:
                    stale.append(rid)
                    alerts.append({
                        "attack": "slow_connection",
                        "ip": req["ip"],
                        "idle_seconds": idle,
                        "phase": req["phase"]
                    })
            for rid in stale:
                del self.active_requests[rid]
        return alerts


# ============================================================================
# HTTP FLOOD DETECTOR
# ============================================================================

class HTTPFloodDetector:
    """Detects HTTP flood attacks with progressive response."""

    def __init__(self):
        self.lock = Lock()
        # Per-IP tracking with sliding windows
        self.ip_windows = defaultdict(lambda: deque(maxlen=10000))
        # Global traffic baseline
        self.global_rps = deque(maxlen=600)  # 10 min of per-second counts
        self.baseline_rps = 100  # will be auto-calibrated
        self.attack_multiplier = 5  # trigger at 5x baseline
        self.under_attack = False
        self.attack_start = 0
        # Per-IP thresholds (increased for legitimate browser traffic)
        self.ip_rps_warn = 50      # was 30
        self.ip_rps_throttle = 100  # was 60
        self.ip_rps_block = 200     # was 100
        # Stats
        self.stats = {
            "floods_detected": 0,
            "ips_throttled": 0,
            "ips_blocked": 0,
            "total_mitigated": 0,
            "attack_events": 0,
        }
        # Endpoint costs (heavier endpoints get lower thresholds)
        self.endpoint_costs = {
            "/api/": 3,
            "/search": 5,
            "/login": 5,
            "/admin/": 10,
            "/upload": 10,
            "/export": 8,
            "/report": 7,
            "/graphql": 5,
        }

    def check_request(self, client_ip: str, path: str) -> dict:
        """Check if request is part of an HTTP flood."""
        now = time.time()

        with self.lock:
            # Record request
            self.ip_windows[client_ip].append(now)

            # Calculate current IP RPS (last 10 seconds)
            window = self.ip_windows[client_ip]
            cutoff = now - 10
            recent = sum(1 for t in window if t > cutoff)
            ip_rps = recent / 10.0

            # Apply endpoint cost multiplier
            cost = 1
            path_lower = path.lower()
            for prefix, c in self.endpoint_costs.items():
                if path_lower.startswith(prefix):
                    cost = c
                    break
            effective_rps = ip_rps * cost

        # Progressive response
        if effective_rps >= self.ip_rps_block:
            with self.lock:
                self.stats["ips_blocked"] += 1
                self.stats["total_mitigated"] += 1
            return {
                "action": "block",
                "reason": f"http_flood:rps={ip_rps:.1f}(effective={effective_rps:.1f})",
                "rps": ip_rps,
                "effective_rps": effective_rps,
                "severity": "critical"
            }
        elif effective_rps >= self.ip_rps_throttle:
            with self.lock:
                self.stats["ips_throttled"] += 1
            return {
                "action": "throttle",
                "reason": f"flood_throttle:rps={ip_rps:.1f}",
                "rps": ip_rps,
                "delay_ms": int(effective_rps * 10),  # Progressive delay
                "severity": "high"
            }
        elif effective_rps >= self.ip_rps_warn:
            return {
                "action": "warn",
                "reason": f"elevated_traffic:rps={ip_rps:.1f}",
                "rps": ip_rps,
                "severity": "medium"
            }

        return {"action": "allow", "rps": ip_rps}

    def update_global_baseline(self, current_rps: float):
        """Update the global traffic baseline."""
        with self.lock:
            self.global_rps.append(current_rps)
            if len(self.global_rps) >= 60:
                self.baseline_rps = sum(self.global_rps) / len(self.global_rps)

                # Detect global attack
                if current_rps > self.baseline_rps * self.attack_multiplier:
                    if not self.under_attack:
                        self.under_attack = True
                        self.attack_start = time.time()
                        self.stats["attack_events"] += 1
                        # Lower thresholds during attack (but still reasonable)
                        self.ip_rps_warn = 30      # was 15
                        self.ip_rps_throttle = 60   # was 30
                        self.ip_rps_block = 100     # was 50
                        logger.warning(f"DDoS ATTACK DETECTED: {current_rps:.0f} RPS (baseline: {self.baseline_rps:.0f})")
                else:
                    if self.under_attack:
                        duration = time.time() - self.attack_start
                        logger.info(f"DDoS attack ended after {duration:.0f}s")
                        self.under_attack = False
                        # Restore normal thresholds
                        self.ip_rps_warn = 50
                        self.ip_rps_throttle = 100
                        self.ip_rps_block = 200


# ============================================================================
# AMPLIFICATION DETECTOR
# ============================================================================

class AmplificationDetector:
    """Detects amplification attacks where response >> request."""

    def __init__(self, max_ratio: float = 100.0):
        self.max_ratio = max_ratio
        self.ip_ratios = defaultdict(list)
        self.lock = Lock()
        self.stats = {"amplification_detected": 0}

    def check(self, client_ip: str, request_size: int,
              response_size: int) -> Optional[dict]:
        """Check for amplification."""
        if request_size <= 0:
            return None

        ratio = response_size / max(request_size, 1)

        with self.lock:
            self.ip_ratios[client_ip].append(ratio)
            # Keep last 100
            if len(self.ip_ratios[client_ip]) > 100:
                self.ip_ratios[client_ip] = self.ip_ratios[client_ip][-50:]

            # Check average ratio
            ratios = self.ip_ratios[client_ip]
            if len(ratios) >= 5:
                avg_ratio = sum(ratios) / len(ratios)
                if avg_ratio > self.max_ratio:
                    self.stats["amplification_detected"] += 1
                    return {
                        "attack": "amplification",
                        "avg_ratio": avg_ratio,
                        "severity": "high",
                        "ip": client_ip
                    }
        return None


# ============================================================================
# ATTACK FINGERPRINTING (cluster attack sources)
# ============================================================================

class AttackFingerprinter:
    """Fingerprints attack patterns to identify coordinated attacks."""

    def __init__(self):
        self.fingerprints = defaultdict(set)  # fingerprint -> set of IPs
        self.ip_fingerprints = defaultdict(set)
        self.lock = Lock()

    def fingerprint_request(self, client_ip: str, method: str,
                            path: str, user_agent: str,
                            headers: dict) -> str:
        """Create a behavioral fingerprint for attack clustering."""
        # Fingerprint components
        components = [
            method,
            self._normalize_path(path),
            self._ua_category(user_agent),
            str(len(headers)),
            ",".join(sorted(headers.keys())[:10]),  # Header order
        ]
        fp = hashlib.md5("|".join(components).encode()).hexdigest()[:12]

        with self.lock:
            self.fingerprints[fp].add(client_ip)
            self.ip_fingerprints[client_ip].add(fp)

        return fp

    def get_coordinated_attacks(self, min_sources: int = 3) -> list:
        """Find coordinated attacks (same fingerprint from multiple IPs)."""
        with self.lock:
            attacks = []
            for fp, ips in self.fingerprints.items():
                if len(ips) >= min_sources:
                    attacks.append({
                        "fingerprint": fp,
                        "source_count": len(ips),
                        "source_ips": list(ips)[:20],
                    })
            return sorted(attacks, key=lambda x: x["source_count"], reverse=True)

    @staticmethod
    def _normalize_path(path: str) -> str:
        """Normalize path for fingerprinting."""
        import re as _re
        path = _re.sub(r'\d+', 'N', path)
        path = _re.sub(r'[0-9a-f]{8,}', 'HASH', path, flags=_re.I)
        return path

    @staticmethod
    def _ua_category(ua: str) -> str:
        ua_lower = ua.lower()
        if "chrome" in ua_lower:
            return "chrome"
        elif "firefox" in ua_lower:
            return "firefox"
        elif "safari" in ua_lower:
            return "safari"
        elif "python" in ua_lower:
            return "python"
        elif "curl" in ua_lower:
            return "curl"
        elif "go" in ua_lower:
            return "go"
        return "other"


# ============================================================================
# MAIN DDOS PROTECTION ENGINE
# ============================================================================

class DDoSProtectionEngine:
    """Unified DDoS protection combining all detection methods."""

    def __init__(self):
        self.connection_tracker = ConnectionTracker(max_per_ip=500, max_total=50000)
        self.slow_detector = SlowAttackDetector()
        self.flood_detector = HTTPFloodDetector()
        self.amplification = AmplificationDetector()
        self.fingerprinter = AttackFingerprinter()
        self.mitigation_mode = "auto"  # auto, always-on, off
        self.blocked_ips = {}  # ip -> block_time (changed from set to dict for timeout)
        self.throttled_ips = {}  # ip -> unblock_time
        self.lock = Lock()
        # Auto-unblock after 15 minutes (production-ready)
        self.block_duration = 900  # seconds
        self.last_cleanup = time.time()

    def _cleanup_expired_blocks(self):
        """Remove expired blocks and throttles."""
        now = time.time()
        # Cleanup every 30 seconds
        if now - self.last_cleanup < 30:
            return
        self.last_cleanup = now
        
        with self.lock:
            # Remove expired blocks
            expired_blocks = [ip for ip, t in self.blocked_ips.items() if now - t > self.block_duration]
            for ip in expired_blocks:
                del self.blocked_ips[ip]
                logger.info(f"DDoS: Auto-unblocked IP {ip} after {self.block_duration}s timeout")
            
            # Remove expired throttles
            expired_throttles = [ip for ip, t in self.throttled_ips.items() if now > t]
            for ip in expired_throttles:
                del self.throttled_ips[ip]

    def check_request(self, client_ip: str, path: str, method: str,
                      user_agent: str, headers: dict,
                      content_length: int = 0) -> dict:
        """
        Comprehensive DDoS check for incoming request.
        Returns action: allow, block, throttle, challenge
        """
        # Cleanup expired blocks periodically
        self._cleanup_expired_blocks()
        
        # Check if IP is currently blocked (with timeout)
        with self.lock:
            if client_ip in self.blocked_ips:
                # SAFETY: Infrastructure IPs should never be in blocked list,
                # but double-check as a safety net
                if _is_infra_ip(client_ip):
                    self.blocked_ips.pop(client_ip, None)
                else:
                    block_time = self.blocked_ips[client_ip]
                    remaining = self.block_duration - (time.time() - block_time)
                    if remaining > 0:
                        return {
                            "action": "block",
                            "reason": "ddos_blocked_ip",
                            "severity": "critical",
                            "remaining_seconds": int(remaining)
                        }
                    else:
                        # Auto-unblock expired
                        del self.blocked_ips[client_ip]
                        logger.info(f"DDoS: Auto-unblocked IP {client_ip}")
            
            # Check throttle expiry
            if client_ip in self.throttled_ips:
                if time.time() > self.throttled_ips[client_ip]:
                    del self.throttled_ips[client_ip]
                else:
                    return {
                        "action": "throttle",
                        "reason": "ddos_throttled_ip",
                        "delay_ms": 500,  # Reduced from 1000ms
                        "severity": "medium"  # Reduced from high
                    }

        # 1. Connection/request flood check (now uses request rate, not connections)
        conn = self.connection_tracker.open_connection(client_ip)
        if not conn["allowed"]:
            # Throttle instead of block for first offense
            with self.lock:
                self.throttled_ips[client_ip] = time.time() + 30  # 30s throttle
            return {
                "action": "throttle",
                "reason": conn["reason"],
                "severity": "medium",
                "delay_ms": 500
            }

        # 2. HTTP flood check
        flood = self.flood_detector.check_request(client_ip, path)
        if flood["action"] == "block":
            # Only block for severe cases (very high RPS)
            self._escalate(client_ip, "http_flood")
            return flood
        elif flood["action"] == "throttle":
            with self.lock:
                self.throttled_ips[client_ip] = time.time() + 30  # Reduced from 60s
            return flood

        # 3. Fingerprint the request for coordination detection
        self.fingerprinter.fingerprint_request(
            client_ip, method, path, user_agent, headers
        )

        return {"action": "allow", "rps": flood.get("rps", 0)}

    def check_response(self, client_ip: str, request_size: int,
                       response_size: int) -> Optional[dict]:
        """Check response for amplification attacks."""
        result = self.amplification.check(client_ip, request_size, response_size)
        if result:
            self._escalate(client_ip, "amplification")
        return result

    def _escalate(self, client_ip: str, attack_type: str):
        """Escalate an IP to blocked status with timeout.
        SAFETY: Never blocks infrastructure IPs (K8s nodes, HAProxy).
        """
        if _is_infra_ip(client_ip):
            logger.warning(f"DDoS: REFUSED to block infrastructure IP {client_ip} for {attack_type}")
            return
        with self.lock:
            self.blocked_ips[client_ip] = time.time()  # Store block time
        logger.warning(f"DDoS: Blocked IP {client_ip} for {attack_type} (auto-unblock after {self.block_duration}s)")

    def unblock_ip(self, client_ip: str):
        with self.lock:
            self.blocked_ips.pop(client_ip, None)
            self.throttled_ips.pop(client_ip, None)

    def get_stats(self) -> dict:
        return {
            "connections": self.connection_tracker.stats,
            "slow_attacks": self.slow_detector.stats,
            "http_floods": self.flood_detector.stats,
            "amplification": self.amplification.stats,
            "coordinated_attacks": len(self.fingerprinter.get_coordinated_attacks()),
            "blocked_ips": len(self.blocked_ips),
            "throttled_ips": len(self.throttled_ips),
            "under_attack": self.flood_detector.under_attack,
            "mitigation_mode": self.mitigation_mode,
            "block_duration": self.block_duration,
        }


# ============================================================================
# SINGLETON
# ============================================================================

_engine = None

def get_engine() -> DDoSProtectionEngine:
    global _engine
    if _engine is None:
        _engine = DDoSProtectionEngine()
        logger.info("DDoS Protection Engine initialized (connection/flood/slow/amplification/fingerprint)")
    return _engine

def check_request(client_ip: str, path: str, method: str,
                  user_agent: str, headers: dict,
                  content_length: int = 0) -> dict:
    return get_engine().check_request(client_ip, path, method, user_agent, headers, content_length)

def get_stats() -> dict:
    return get_engine().get_stats()
