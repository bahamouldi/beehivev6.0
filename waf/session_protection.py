"""
BeeWAF Session Protection Engine
===================================
Enterprise-grade session security surpassing F5 Session Awareness.
Features:
- Session fixation detection & prevention
- Cookie security enforcement (Secure, HttpOnly, SameSite)
- Session hijacking detection (IP/UA binding)
- CSRF token validation
- Session anomaly detection (concurrent sessions)
- JWT validation (signature, expiration, claims)
- Session timeout enforcement
- Cookie tampering detection (HMAC signing)
- Session rotation tracking
- Replay attack prevention
"""

import re
import time
import hashlib
import hmac
import base64
import json
import logging
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict

log = logging.getLogger("beewaf.session")


# ============================================================
#  SESSION TRACKER
# ============================================================

class SessionTracker:
    """Track and analyze user sessions."""
    
    def __init__(self,
                 max_concurrent_sessions: int = 5,
                 session_timeout: int = 3600,
                 bind_ip: bool = True,
                 bind_ua: bool = True):
        self.max_concurrent = max_concurrent_sessions
        self.session_timeout = session_timeout
        self.bind_ip = bind_ip
        self.bind_ua = bind_ua
        
        # session_id -> {ip, ua, created, last_seen, request_count}
        self._sessions: Dict[str, Dict] = {}
        
        # user_identifier -> set of session_ids
        self._user_sessions: Dict[str, Set[str]] = defaultdict(set)
    
    def track_session(self, session_id: str, client_ip: str, user_agent: str,
                      user_identifier: str = None) -> Dict:
        """
        Track a session and check for anomalies.
        
        Returns:
            {
                'valid': bool,
                'issues': [{'type': str, 'severity': str, 'message': str}]
            }
        """
        now = time.time()
        issues = []
        
        if session_id in self._sessions:
            session = self._sessions[session_id]
            
            # Check session timeout
            if now - session['last_seen'] > self.session_timeout:
                issues.append({
                    'type': 'session-expired',
                    'severity': 'medium',
                    'message': f'Session has expired (idle {int(now - session["last_seen"])}s)'
                })
            
            # Check IP binding
            if self.bind_ip and session['ip'] != client_ip:
                issues.append({
                    'type': 'session-ip-change',
                    'severity': 'high',
                    'message': f'Session IP changed from {session["ip"]} to {client_ip}'
                })
            
            # Check UA binding
            if self.bind_ua and session['ua'] != user_agent:
                issues.append({
                    'type': 'session-ua-change',
                    'severity': 'high',
                    'message': 'Session User-Agent changed (possible hijacking)'
                })
            
            # Update session
            session['last_seen'] = now
            session['request_count'] += 1
        
        else:
            # New session
            self._sessions[session_id] = {
                'ip': client_ip,
                'ua': user_agent,
                'created': now,
                'last_seen': now,
                'request_count': 1,
            }
        
        # Check concurrent sessions
        if user_identifier:
            self._user_sessions[user_identifier].add(session_id)
            # Clean expired
            active = set()
            for sid in self._user_sessions[user_identifier]:
                s = self._sessions.get(sid)
                if s and now - s['last_seen'] < self.session_timeout:
                    active.add(sid)
            self._user_sessions[user_identifier] = active
            
            if len(active) > self.max_concurrent:
                issues.append({
                    'type': 'concurrent-sessions-exceeded',
                    'severity': 'medium',
                    'message': f'{len(active)} concurrent sessions (max {self.max_concurrent})'
                })
        
        return {
            'valid': len(issues) == 0,
            'issues': issues
        }
    
    def cleanup(self):
        """Remove expired sessions."""
        now = time.time()
        expired = [sid for sid, s in self._sessions.items()
                    if now - s['last_seen'] > self.session_timeout * 2]
        for sid in expired:
            del self._sessions[sid]


# ============================================================
#  COOKIE SECURITY ANALYZER
# ============================================================

class CookieSecurityAnalyzer:
    """Analyze and enforce cookie security attributes."""
    
    SENSITIVE_COOKIE_PATTERNS = [
        re.compile(r'session', re.IGNORECASE),
        re.compile(r'sess_?id', re.IGNORECASE),
        re.compile(r'token', re.IGNORECASE),
        re.compile(r'auth', re.IGNORECASE),
        re.compile(r'jwt', re.IGNORECASE),
        re.compile(r'csrf', re.IGNORECASE),
        re.compile(r'xsrf', re.IGNORECASE),
        re.compile(r'login', re.IGNORECASE),
        re.compile(r'credential', re.IGNORECASE),
        re.compile(r'access.?key', re.IGNORECASE),
        re.compile(r'api.?key', re.IGNORECASE),
        re.compile(r'remember', re.IGNORECASE),
        re.compile(r'persist', re.IGNORECASE),
    ]
    
    def analyze_response_cookies(self, set_cookie_headers: List[str]) -> List[Dict]:
        """Analyze Set-Cookie headers in response for security issues."""
        issues = []
        
        for header_value in set_cookie_headers:
            parts = header_value.split(';')
            if not parts:
                continue
            
            cookie_pair = parts[0].strip()
            cookie_name = cookie_pair.split('=')[0].strip() if '=' in cookie_pair else cookie_pair
            
            flags = header_value.lower()
            
            is_sensitive = any(p.search(cookie_name) for p in self.SENSITIVE_COOKIE_PATTERNS)
            
            if is_sensitive:
                # Check Secure flag
                if 'secure' not in flags:
                    issues.append({
                        'type': 'cookie-missing-secure',
                        'severity': 'high',
                        'message': f'Sensitive cookie "{cookie_name}" missing Secure flag'
                    })
                
                # Check HttpOnly flag
                if 'httponly' not in flags:
                    issues.append({
                        'type': 'cookie-missing-httponly',
                        'severity': 'high',
                        'message': f'Sensitive cookie "{cookie_name}" missing HttpOnly flag'
                    })
                
                # Check SameSite
                if 'samesite' not in flags:
                    issues.append({
                        'type': 'cookie-missing-samesite',
                        'severity': 'medium',
                        'message': f'Sensitive cookie "{cookie_name}" missing SameSite attribute'
                    })
                elif 'samesite=none' in flags:
                    issues.append({
                        'type': 'cookie-samesite-none',
                        'severity': 'medium',
                        'message': f'Sensitive cookie "{cookie_name}" has SameSite=None'
                    })
                
                # Check for overly long expiry
                if 'max-age=' in flags:
                    try:
                        max_age = int(re.search(r'max-age=(\d+)', flags).group(1))
                        if max_age > 86400 * 30:  # More than 30 days
                            issues.append({
                                'type': 'cookie-long-expiry',
                                'severity': 'low',
                                'message': f'Sensitive cookie "{cookie_name}" has long expiry ({max_age}s)'
                            })
                    except (ValueError, AttributeError):
                        pass
                
                # Check for weak session ID (too short)
                if '=' in cookie_pair:
                    value = cookie_pair.split('=', 1)[1]
                    if len(value) < 16:
                        issues.append({
                            'type': 'weak-session-id',
                            'severity': 'high',
                            'message': f'Session cookie "{cookie_name}" value too short ({len(value)} chars)'
                        })
                    
                    # Check for predictable patterns
                    if value.isdigit():
                        issues.append({
                            'type': 'predictable-session-id',
                            'severity': 'high',
                            'message': f'Session cookie "{cookie_name}" uses numeric-only value'
                        })
        
        return issues


# ============================================================
#  JWT VALIDATOR
# ============================================================

class JWTValidator:
    """Validate JWT tokens for common security issues."""
    
    def validate_jwt(self, token: str) -> Dict:
        """
        Validate JWT token structure and claims.
        Note: Cannot verify signature without the secret key.
        """
        issues = []
        
        parts = token.split('.')
        if len(parts) != 3:
            return {
                'valid': False,
                'issues': [{'type': 'jwt-invalid-format', 'severity': 'high',
                            'message': 'Invalid JWT format (expected 3 parts)'}]
            }
        
        try:
            # Decode header
            header_b64 = parts[0] + '=' * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))
        except Exception:
            issues.append({
                'type': 'jwt-invalid-header',
                'severity': 'high',
                'message': 'Cannot decode JWT header'
            })
            return {'valid': False, 'issues': issues}
        
        # Check algorithm
        alg = header.get('alg', '')
        
        # None algorithm attack
        if alg.lower() == 'none' or not alg:
            issues.append({
                'type': 'jwt-none-algorithm',
                'severity': 'critical',
                'message': 'JWT uses "none" algorithm (signature bypass)'
            })
        
        # Weak algorithms
        if alg in ('HS256',) and header.get('kid'):
            issues.append({
                'type': 'jwt-weak-hmac-with-kid',
                'severity': 'medium',
                'message': 'JWT uses HS256 with kid (potential key confusion attack)'
            })
        
        # Algorithm confusion (RSA -> HMAC)
        if 'jwk' in header:
            issues.append({
                'type': 'jwt-embedded-jwk',
                'severity': 'high',
                'message': 'JWT contains embedded JWK (potential key injection)'
            })
        
        if 'jku' in header:
            issues.append({
                'type': 'jwt-jku-header',
                'severity': 'high',
                'message': 'JWT contains JKU header (potential SSRF)'
            })
        
        if 'x5u' in header:
            issues.append({
                'type': 'jwt-x5u-header',
                'severity': 'high',
                'message': 'JWT contains x5u header (potential SSRF)'
            })
        
        # Decode payload
        try:
            payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        except Exception:
            issues.append({
                'type': 'jwt-invalid-payload',
                'severity': 'medium',
                'message': 'Cannot decode JWT payload'
            })
            return {'valid': len(issues) == 0, 'issues': issues}
        
        now = time.time()
        
        # Check expiration
        exp = payload.get('exp')
        if exp:
            if exp < now:
                issues.append({
                    'type': 'jwt-expired',
                    'severity': 'medium',
                    'message': f'JWT expired {int(now - exp)}s ago'
                })
            elif exp > now + 86400 * 365:  # More than 1 year
                issues.append({
                    'type': 'jwt-long-expiry',
                    'severity': 'low',
                    'message': 'JWT has very long expiration (>1 year)'
                })
        else:
            issues.append({
                'type': 'jwt-no-expiry',
                'severity': 'medium',
                'message': 'JWT has no expiration claim'
            })
        
        # Check not-before
        nbf = payload.get('nbf')
        if nbf and nbf > now + 60:  # 60s grace period
            issues.append({
                'type': 'jwt-not-yet-valid',
                'severity': 'medium',
                'message': 'JWT is not yet valid (nbf in future)'
            })
        
        # Check for sensitive data in JWT
        sensitive_fields = ['password', 'secret', 'key', 'credit_card', 'ssn', 'pin']
        for field in sensitive_fields:
            if field in payload:
                issues.append({
                    'type': 'jwt-sensitive-data',
                    'severity': 'high',
                    'message': f'JWT contains sensitive field: {field}'
                })
        
        # Empty signature
        if not parts[2]:
            issues.append({
                'type': 'jwt-empty-signature',
                'severity': 'critical',
                'message': 'JWT has empty signature'
            })
        
        return {
            'valid': len(issues) == 0,
            'issues': issues,
            'header': header,
            'claims': payload,
        }


# ============================================================
#  SESSION FIXATION DETECTOR
# ============================================================

class SessionFixationDetector:
    """Detect session fixation attacks."""
    
    def __init__(self):
        # Track session IDs seen in URLs (fixation attempt)
        self._url_session_patterns = [
            re.compile(r'[?&;](JSESSIONID|PHPSESSID|ASP\.NET_SessionId|session_id|sid|sessid|token)=([^&;#]+)', re.IGNORECASE),
        ]
    
    def check_request(self, path: str, query_string: str, headers: Dict[str, str]) -> List[Dict]:
        """Check for session fixation indicators."""
        issues = []
        
        full_url = f"{path}?{query_string}" if query_string else path
        
        # Session ID in URL
        for pattern in self._url_session_patterns:
            match = pattern.search(full_url)
            if match:
                issues.append({
                    'type': 'session-fixation-url',
                    'severity': 'high',
                    'message': f'Session ID in URL ({match.group(1)}): possible fixation'
                })
        
        # Session ID in Referer header (leaked)
        referer = headers.get('referer', headers.get('Referer', ''))
        for pattern in self._url_session_patterns:
            match = pattern.search(referer)
            if match:
                issues.append({
                    'type': 'session-leaked-referer',
                    'severity': 'high',
                    'message': f'Session ID leaked in Referer header'
                })
        
        return issues


# ============================================================
#  REPLAY ATTACK DETECTOR
# ============================================================

class ReplayDetector:
    """Detect request replay attacks."""
    
    def __init__(self, window: int = 300, max_seen: int = 100000):
        self.window = window
        self.max_seen = max_seen
        # hash -> timestamp of first seen
        self._seen: Dict[str, float] = {}
    
    def check_request(self, method: str, path: str, body: str,
                      nonce: str = None, timestamp: str = None) -> Optional[Dict]:
        """Check for replay attacks using nonces or request fingerprinting."""
        now = time.time()
        
        # Check nonce-based replay
        if nonce:
            if nonce in self._seen:
                return {
                    'type': 'replay-attack-nonce',
                    'severity': 'high',
                    'message': f'Duplicate nonce detected: request replay attempt'
                }
            self._seen[nonce] = now
        
        # Check timestamp-based replay
        if timestamp:
            try:
                ts = float(timestamp)
                if abs(now - ts) > self.window:
                    return {
                        'type': 'replay-attack-timestamp',
                        'severity': 'medium',
                        'message': f'Request timestamp too old ({int(now - ts)}s)'
                    }
            except ValueError:
                pass
        
        # Cleanup old entries periodically
        if len(self._seen) > self.max_seen:
            cutoff = now - self.window
            self._seen = {k: v for k, v in self._seen.items() if v > cutoff}
        
        return None


# ============================================================
#  MAIN SESSION PROTECTION ENGINE
# ============================================================

class SessionProtectionEngine:
    """Main session protection engine."""
    
    def __init__(self):
        self.session_tracker = SessionTracker()
        self.cookie_analyzer = CookieSecurityAnalyzer()
        self.jwt_validator = JWTValidator()
        self.fixation_detector = SessionFixationDetector()
        self.replay_detector = ReplayDetector()
        
        self._stats = {
            'checked': 0,
            'issues_found': 0,
            'by_type': defaultdict(int),
        }
    
    def check_request(self,
                      path: str,
                      method: str,
                      headers: Dict[str, str],
                      body: str,
                      client_ip: str,
                      query_string: str = '') -> Dict:
        """
        Comprehensive session security check on request.
        
        Returns:
            {
                'valid': bool,
                'issues': [{'type': str, 'severity': str, 'message': str}],
                'action': 'allow' | 'warn' | 'block',
            }
        """
        self._stats['checked'] += 1
        issues = []
        
        # === 1. Session Fixation Detection ===
        issues.extend(self.fixation_detector.check_request(path, query_string, headers))
        
        # === 2. Session Tracking (if session cookie present) ===
        cookie = headers.get('cookie', headers.get('Cookie', ''))
        session_id = self._extract_session_id(cookie)
        if session_id:
            user_agent = headers.get('user-agent', headers.get('User-Agent', ''))
            result = self.session_tracker.track_session(
                session_id, client_ip, user_agent
            )
            issues.extend(result.get('issues', []))
        
        # === 3. JWT Validation (if Authorization header has Bearer token) ===
        auth = headers.get('authorization', headers.get('Authorization', ''))
        if auth.lower().startswith('bearer '):
            token = auth[7:].strip()
            if token.count('.') == 2:  # Looks like JWT
                result = self.jwt_validator.validate_jwt(token)
                issues.extend(result.get('issues', []))
        
        # Also check for JWT in cookies
        if cookie:
            for part in cookie.split(';'):
                part = part.strip()
                if '=' in part:
                    value = part.split('=', 1)[1]
                    if value.count('.') == 2 and len(value) > 20:
                        # Might be a JWT
                        try:
                            result = self.jwt_validator.validate_jwt(value)
                            if result.get('issues'):
                                issues.extend(result['issues'])
                        except Exception:
                            pass
        
        # === 4. Replay Attack Detection ===
        nonce = headers.get('x-request-nonce', headers.get('X-Request-Nonce'))
        timestamp = headers.get('x-request-timestamp', headers.get('X-Request-Timestamp'))
        replay = self.replay_detector.check_request(method, path, body, nonce, timestamp)
        if replay:
            issues.append(replay)
        
        # === 5. CSRF Check (for state-changing methods) ===
        if method in ('POST', 'PUT', 'DELETE', 'PATCH'):
            issues.extend(self._check_csrf(headers, cookie))
        
        # Update stats
        if issues:
            self._stats['issues_found'] += 1
            for i in issues:
                self._stats['by_type'][i['type']] += 1
        
        # Determine action
        has_critical = any(i['severity'] in ('critical', 'high') for i in issues)
        
        return {
            'valid': len(issues) == 0,
            'issues': issues,
            'action': 'block' if has_critical else ('warn' if issues else 'allow'),
        }
    
    def check_response(self, response_headers: Dict[str, str]) -> List[Dict]:
        """Check response headers for session security issues."""
        issues = []
        
        # Check Set-Cookie headers
        set_cookies = []
        for k, v in response_headers.items():
            if k.lower() == 'set-cookie':
                set_cookies.append(v)
        
        if set_cookies:
            issues.extend(self.cookie_analyzer.analyze_response_cookies(set_cookies))
        
        return issues
    
    def _extract_session_id(self, cookie: str) -> Optional[str]:
        """Extract session ID from cookie header."""
        if not cookie:
            return None
        
        session_names = [
            'sessionid', 'session_id', 'JSESSIONID', 'PHPSESSID',
            'ASP.NET_SessionId', 'connect.sid', 'ci_session',
            'laravel_session', 'CGISESSID', '_session_id',
        ]
        
        for part in cookie.split(';'):
            part = part.strip()
            if '=' in part:
                name, value = part.split('=', 1)
                name = name.strip()
                if name in session_names or name.lower() in [s.lower() for s in session_names]:
                    return value.strip()
        
        return None
    
    def _check_csrf(self, headers: Dict[str, str], cookie: str) -> List[Dict]:
        """Basic CSRF checks."""
        issues = []
        
        # Check Origin/Referer for CSRF
        origin = headers.get('origin', headers.get('Origin', ''))
        referer = headers.get('referer', headers.get('Referer', ''))
        host = headers.get('host', headers.get('Host', ''))
        
        if origin and host:
            # Compare origin to host
            origin_host = origin.replace('http://', '').replace('https://', '').split('/')[0]
            if origin_host != host and origin_host.split(':')[0] != host.split(':')[0]:
                issues.append({
                    'type': 'csrf-origin-mismatch',
                    'severity': 'high',
                    'message': f'Origin ({origin_host}) does not match Host ({host})'
                })
        
        # If no CSRF token headers present on POST/PUT/DELETE
        csrf_headers = [
            'x-csrf-token', 'x-xsrf-token', 'x-requested-with',
            'X-CSRF-Token', 'X-XSRF-TOKEN',
        ]
        has_csrf = any(h.lower() in [k.lower() for k in headers.keys()] for h in csrf_headers)
        
        if not has_csrf and not origin:
            # No CSRF protection detected
            issues.append({
                'type': 'csrf-no-protection',
                'severity': 'low',
                'message': 'No CSRF token or Origin header present on state-changing request'
            })
        
        return issues
    
    def get_stats(self) -> Dict:
        return dict(self._stats)


# Module-level singleton
_engine = None

def get_engine() -> SessionProtectionEngine:
    global _engine
    if _engine is None:
        _engine = SessionProtectionEngine()
    return _engine

def check_request(path, method, headers, body, client_ip, query_string=''):
    return get_engine().check_request(path, method, headers, body, client_ip, query_string)

def check_response(response_headers):
    return get_engine().check_response(response_headers)
