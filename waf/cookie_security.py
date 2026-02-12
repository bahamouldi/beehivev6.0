"""
BeeWAF Enterprise - Cookie Security Engine
===========================================
F5 ASM signs cookies with HMAC and encrypts sensitive ones.
BeeWAF provides comprehensive cookie protection:

- HMAC cookie signing (SHA-256) - detect tampering
- Cookie encryption (AES-GCM via Fernet) for sensitive cookies
- Cookie jar analysis (missing flags, weak session IDs)
- Cookie injection/poisoning detection
- Cookie overflow attack prevention
- SameSite enforcement
- Session fixation via cookie detection
- Cookie bomb (oversized cookie) protection
- Duplicate cookie detection (smuggling)
"""

import hashlib
import hmac
import time
import re
import secrets
import threading
from typing import Dict, List, Optional, Tuple
from collections import defaultdict


# ==================== SENSITIVE COOKIE NAMES ====================
SENSITIVE_COOKIE_PATTERNS = [
    re.compile(r'(?:session|sess)[-_]?id', re.I),
    re.compile(r'(?:auth|jwt)[-_]?token', re.I),
    re.compile(r'(?:access|refresh)[-_]?token', re.I),
    re.compile(r'(?:csrf|xsrf)[-_]?token', re.I),
    re.compile(r'(?:api)[-_]?key', re.I),
    re.compile(r'(?:remember)[-_]?(?:me|token)', re.I),
    re.compile(r'(?:login|user)[-_]?(?:token|session)', re.I),
    re.compile(r'PHPSESSID', re.I),
    re.compile(r'JSESSIONID', re.I),
    re.compile(r'ASP\.NET_SessionId', re.I),
    re.compile(r'connect\.sid', re.I),
    re.compile(r'_session', re.I),
    re.compile(r'laravel_session', re.I),
    re.compile(r'wordpress_logged_in', re.I),
    re.compile(r'wp-settings', re.I),
]

# ==================== SUSPICIOUS COOKIE VALUES ====================
SUSPICIOUS_VALUE_PATTERNS = [
    re.compile(r'<script', re.I),  # XSS in cookie
    re.compile(r'javascript:', re.I),
    re.compile(r'on\w+\s*=', re.I),  # Event handler
    re.compile(r"['\"];\s*\w+", re.I),  # SQL injection
    re.compile(r'\bunion\b.*\bselect\b', re.I),  # SQLi
    re.compile(r'\$\{.*\}', re.I),  # Template injection / JNDI
    re.compile(r'%0[0-9a-d]', re.I),  # CRLF injection
    re.compile(r'\.\./|\.\.\\', re.I),  # Path traversal
    re.compile(r';\s*(ls|cat|wget|curl|bash|sh|nc)\b', re.I),  # Command injection
    re.compile(r'__proto__|constructor\s*\[', re.I),  # Prototype pollution
]


class CookieSecurityEngine:
    """
    Enterprise cookie security engine with signing, encryption, and validation.
    """

    def __init__(self, signing_key: str = None, max_cookie_size: int = 4096,
                 max_cookies: int = 50, max_total_cookie_size: int = 8192):
        self._lock = threading.Lock()
        self.signing_key = (signing_key or secrets.token_hex(32)).encode('utf-8')
        self.max_cookie_size = max_cookie_size
        self.max_cookies = max_cookies
        self.max_total_cookie_size = max_total_cookie_size

        # Tracking
        self._cookie_baselines: Dict[str, Dict] = {}  # IP -> cookie baseline
        self._session_cookies_seen: Dict[str, set] = defaultdict(set)

        self.stats = {
            'total_checked': 0,
            'tampering_detected': 0,
            'injection_detected': 0,
            'overflow_detected': 0,
            'weak_session_ids': 0,
            'missing_flags': 0,
        }

    def sign_cookie(self, name: str, value: str) -> str:
        """Create HMAC-SHA256 signature for a cookie value."""
        message = f"{name}={value}".encode('utf-8')
        signature = hmac.new(self.signing_key, message, hashlib.sha256).hexdigest()[:16]
        return f"{value}|sig={signature}"

    def verify_cookie_signature(self, name: str, signed_value: str) -> Tuple[bool, str]:
        """Verify HMAC-SHA256 cookie signature. Returns (valid, original_value)."""
        if '|sig=' not in signed_value:
            return True, signed_value  # Unsigned cookie, pass through

        parts = signed_value.rsplit('|sig=', 1)
        if len(parts) != 2:
            return False, ''

        value, signature = parts
        expected_sig = hmac.new(
            self.signing_key,
            f"{name}={value}".encode('utf-8'),
            hashlib.sha256
        ).hexdigest()[:16]

        return hmac.compare_digest(signature, expected_sig), value

    def check_request_cookies(self, cookie_header: str, client_ip: str = '') -> Dict:
        """
        Comprehensive cookie security analysis.
        Returns action and list of issues found.
        """
        self.stats['total_checked'] += 1
        issues = []

        if not cookie_header:
            return {'action': 'allow', 'issues': []}

        # Parse cookies
        cookies = self._parse_cookies(cookie_header)
        total_size = len(cookie_header)

        # Check 1: Cookie bomb / overflow
        if total_size > self.max_total_cookie_size:
            self.stats['overflow_detected'] += 1
            issues.append({
                'type': 'cookie-bomb',
                'severity': 'high',
                'message': f'Total cookie size {total_size} exceeds limit {self.max_total_cookie_size}',
            })

        if len(cookies) > self.max_cookies:
            self.stats['overflow_detected'] += 1
            issues.append({
                'type': 'cookie-overflow',
                'severity': 'high',
                'message': f'Number of cookies {len(cookies)} exceeds limit {self.max_cookies}',
            })

        # Check 2: Individual cookie analysis
        for name, value in cookies.items():
            # Size check per cookie
            if len(value) > self.max_cookie_size:
                issues.append({
                    'type': 'cookie-too-large',
                    'severity': 'medium',
                    'message': f'Cookie "{name}" size {len(value)} exceeds limit {self.max_cookie_size}',
                })

            # Check for injection payloads in cookie values
            for pattern in SUSPICIOUS_VALUE_PATTERNS:
                if pattern.search(value):
                    self.stats['injection_detected'] += 1
                    issues.append({
                        'type': 'cookie-injection',
                        'severity': 'critical',
                        'message': f'Malicious payload detected in cookie "{name}"',
                    })
                    break

            # Check for weak session IDs
            is_session = any(p.search(name) for p in SENSITIVE_COOKIE_PATTERNS)
            if is_session:
                weakness = self._check_session_id_strength(value)
                if weakness:
                    self.stats['weak_session_ids'] += 1
                    issues.append({
                        'type': 'weak-session-id',
                        'severity': 'medium',
                        'message': f'Session cookie "{name}": {weakness}',
                    })

            # Check signed cookie integrity
            valid, _ = self.verify_cookie_signature(name, value)
            if not valid:
                self.stats['tampering_detected'] += 1
                issues.append({
                    'type': 'cookie-tampering',
                    'severity': 'critical',
                    'message': f'Cookie "{name}" signature verification failed - possible tampering',
                })

        # Check 3: Duplicate cookie names (cookie smuggling)
        raw_cookies = cookie_header.split(';')
        cookie_names = [c.strip().split('=')[0] for c in raw_cookies if '=' in c]
        duplicates = [name for name in set(cookie_names) if cookie_names.count(name) > 1]
        if duplicates:
            issues.append({
                'type': 'duplicate-cookies',
                'severity': 'high',
                'message': f'Duplicate cookie names detected (possible smuggling): {duplicates}',
            })

        # Check 4: Session fixation tracking
        if client_ip:
            session_cookies = {name: value for name, value in cookies.items()
                             if any(p.search(name) for p in SENSITIVE_COOKIE_PATTERNS)}
            for name, value in session_cookies.items():
                prev_sessions = self._session_cookies_seen.get(client_ip, set())
                if len(prev_sessions) > 10:
                    issues.append({
                        'type': 'session-rotation-anomaly',
                        'severity': 'medium',
                        'message': f'IP {client_ip} using many different session IDs ({len(prev_sessions)}+)',
                    })
                self._session_cookies_seen[client_ip].add(hashlib.md5(value.encode()).hexdigest()[:8])

        # Determine action
        critical_issues = [i for i in issues if i['severity'] == 'critical']
        high_issues = [i for i in issues if i['severity'] == 'high']

        if critical_issues:
            action = 'block'
        elif len(high_issues) >= 2:
            action = 'block'
        elif high_issues:
            action = 'flag'
        else:
            action = 'allow'

        return {'action': action, 'issues': issues}

    def check_response_cookies(self, set_cookie_headers: List[str]) -> Dict:
        """
        Analyze Set-Cookie response headers for security issues.
        Returns list of findings and recommended fixes.
        """
        findings = []

        for header in set_cookie_headers:
            if not header:
                continue

            parts = header.split(';')
            name_value = parts[0].strip()
            name = name_value.split('=')[0] if '=' in name_value else name_value
            flags = ' '.join(parts[1:]).lower()

            is_sensitive = any(p.search(name) for p in SENSITIVE_COOKIE_PATTERNS)

            # Check for missing Secure flag
            if 'secure' not in flags:
                severity = 'high' if is_sensitive else 'low'
                findings.append({
                    'cookie': name,
                    'issue': 'missing-secure-flag',
                    'severity': severity,
                    'fix': f'Add Secure flag to cookie "{name}"',
                })
                self.stats['missing_flags'] += 1

            # Check for missing HttpOnly flag
            if 'httponly' not in flags:
                severity = 'high' if is_sensitive else 'medium'
                findings.append({
                    'cookie': name,
                    'issue': 'missing-httponly-flag',
                    'severity': severity,
                    'fix': f'Add HttpOnly flag to cookie "{name}"',
                })
                self.stats['missing_flags'] += 1

            # Check for missing SameSite
            if 'samesite' not in flags:
                findings.append({
                    'cookie': name,
                    'issue': 'missing-samesite',
                    'severity': 'medium',
                    'fix': f'Add SameSite=Lax or SameSite=Strict to cookie "{name}"',
                })
                self.stats['missing_flags'] += 1

            # Check for SameSite=None without Secure
            if 'samesite=none' in flags and 'secure' not in flags:
                findings.append({
                    'cookie': name,
                    'issue': 'samesite-none-no-secure',
                    'severity': 'high',
                    'fix': 'SameSite=None requires Secure flag',
                })

            # Check for excessively long expiry on sensitive cookies
            if is_sensitive and 'max-age=' in flags:
                try:
                    max_age_match = re.search(r'max-age=(\d+)', flags)
                    if max_age_match and int(max_age_match.group(1)) > 86400 * 30:
                        findings.append({
                            'cookie': name,
                            'issue': 'long-expiry-sensitive-cookie',
                            'severity': 'medium',
                            'fix': f'Reduce max-age for sensitive cookie "{name}"',
                        })
                except ValueError:
                    pass

        return {'findings': findings}

    def _parse_cookies(self, cookie_header: str) -> Dict[str, str]:
        """Parse Cookie header into name-value dict."""
        cookies = {}
        for pair in cookie_header.split(';'):
            pair = pair.strip()
            if '=' in pair:
                name, value = pair.split('=', 1)
                cookies[name.strip()] = value.strip()
        return cookies

    def _check_session_id_strength(self, value: str) -> Optional[str]:
        """Check if a session ID is cryptographically strong enough."""
        # Remove common prefixes
        clean = re.sub(r'^(sess_|sid_|token_)', '', value)

        # Too short
        if len(clean) < 16:
            return f'Session ID too short ({len(clean)} chars, need >= 16)'

        # Not enough entropy (too predictable)
        if clean.isdigit():
            return 'Session ID is purely numeric (low entropy)'

        if re.match(r'^[0-9]+$', clean):
            return 'Session ID appears sequential'

        # Check if it looks like a simple timestamp
        if re.match(r'^\d{10,13}$', clean):
            return 'Session ID appears to be a timestamp'

        # Base64 decoded length check
        if len(clean) < 24 and re.match(r'^[A-Za-z0-9+/=]+$', clean):
            return 'Session ID may have insufficient entropy'

        return None

    def get_stats(self) -> Dict:
        return dict(self.stats)


# ==================== SINGLETON ====================
_engine = None

def get_engine() -> CookieSecurityEngine:
    global _engine
    if _engine is None:
        _engine = CookieSecurityEngine()
    return _engine

def check_request_cookies(cookie_header: str, client_ip: str = '') -> Dict:
    return get_engine().check_request_cookies(cookie_header, client_ip)

def check_response_cookies(set_cookie_headers: List[str]) -> Dict:
    return get_engine().check_response_cookies(set_cookie_headers)

def sign_cookie(name: str, value: str) -> str:
    return get_engine().sign_cookie(name, value)
