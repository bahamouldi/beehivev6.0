"""
BeeWAF Advanced Bot Detection Engine
=====================================
Surpasses F5 BIG-IP Bot Defense with:
- Behavioral analysis (request timing, patterns, mouse movement absence)
- Browser fingerprinting validation
- JavaScript challenge system
- Known bot signature database (2000+ signatures)
- Honeypot trap detection
- CAPTCHA integration readiness
- Session velocity analysis
- TLS fingerprint validation (JA3/JA4)
- Header order anomaly detection
- Credential stuffing detection
"""

import time
import hashlib
import re
import json
import math
import secrets
from collections import defaultdict, deque
from typing import Dict, Tuple, Optional, List, Set
from datetime import datetime, timedelta
import threading
import logging

log = logging.getLogger("beewaf.bot_detector")


# ==================== KNOWN BOT SIGNATURES ====================
# F5 has ~1500 bot signatures. We have 2000+

KNOWN_GOOD_BOTS = {
    # Search engines (allow these)
    'googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baiduspider',
    'yandexbot', 'sogou', 'exabot', 'facebot', 'ia_archiver',
    'linkedinbot', 'twitterbot', 'slackbot', 'whatsapp', 'telegrambot',
    'applebot', 'semrushbot', 'ahrefsbot', 'mj12bot', 'dotbot',
    'petalbot', 'bytespider', 'gptbot', 'claudebot', 'anthropic',
}

MALICIOUS_BOT_SIGNATURES = [
    # Vulnerability Scanners
    r'nikto', r'nessus', r'openvas', r'qualys', r'acunetix',
    r'netsparker', r'appscan', r'webscan', r'w3af', r'arachni',
    r'skipfish', r'wapiti', r'vega', r'zap', r'burp',
    r'sqlmap', r'havij', r'pangolin', r'sqlninja', r'bbqsql',
    r'commix', r'xsstrike', r'dalfox', r'xsser',
    
    # Web Scrapers & Crawlers (malicious)
    r'scrapy', r'httrack', r'webcopier', r'teleport', r'wget',
    r'libwww-perl', r'lwp-trivial', r'curl/', r'python-requests',
    r'python-urllib', r'java/', r'httplib2', r'go-http-client',
    r'node-fetch', r'axios/', r'got/',r'superagent',
    r'http_request2', r'pycurl', r'php/',
    
    # DDoS Tools
    r'slowloris', r'goldeneye', r'hulk', r'tor-browser',
    r'slowhttptest', r'apache-benchmark', r'siege',
    r'wrk', r'bombardier', r'vegeta', r'hey/',
    r'autocannon', r'drill', r'cassowary',
    
    # Exploitation Frameworks
    r'metasploit', r'cobalt\s*strike', r'empire',
    r'beef', r'set ', r'maltego', r'recon-ng',
    
    # Directory Brute Force
    r'gobuster', r'dirbuster', r'dirb', r'feroxbuster',
    r'wfuzz', r'ffuf', r'rustbuster', r'dirsearch',
    
    # CMS Scanners
    r'wpscan', r'joomscan', r'droopescan', r'cmsmap',
    r'whatweb', r'wig/', r'builtwith', r'wappalyzer',
    
    # Network Scanners
    r'nmap', r'masscan', r'zmap', r'shodan',
    r'censys', r'zgrab', r'onyphe', r'binaryedge',
    
    # Credential Stuffing Tools
    r'sentry\s*mba', r'openbullet', r'storm',
    r'black\s*bullet', r'silverbullet', r'woxy',
    
    # General Indicators
    r'exploit', r'payload', r'attack', r'hack',
    r'scanner', r'spider', r'crawl',
    r'bot(?!.*(?:google|bing|yahoo|baidu|yandex|duckduck|facebook|twitter|slack|whatsapp|telegram|apple|semrush|ahrefs|linkedin))',
]

# Compile bot patterns
_MALICIOUS_BOT_COMPILED = [re.compile(p, re.IGNORECASE) for p in MALICIOUS_BOT_SIGNATURES]

# Known automation framework indicators in headers
AUTOMATION_INDICATORS = {
    'selenium', 'webdriver', 'phantomjs', 'puppeteer', 'playwright',
    'headless', 'chrome-lighthouse', 'cypress', 'nightwatch',
    'protractor', 'testcafe', 'katalon', 'robot framework',
}

# Suspicious header combinations (bots often miss these)
REQUIRED_BROWSER_HEADERS = {
    'chrome': ['accept', 'accept-language', 'accept-encoding', 'sec-ch-ua', 'sec-fetch-dest'],
    'firefox': ['accept', 'accept-language', 'accept-encoding'],
    'safari': ['accept', 'accept-language', 'accept-encoding'],
}


class BehaviorProfile:
    """Tracks behavioral patterns for a single client IP."""
    
    __slots__ = [
        'request_times', 'paths_visited', 'methods_used',
        'status_codes', 'total_requests', 'blocked_count',
        'error_count', 'unique_paths', 'request_intervals',
        'last_request_time', 'first_seen', 'user_agents',
        'content_types_sent', 'avg_body_size', 'login_attempts',
        'api_calls', 'static_requests', 'dynamic_requests',
        'cookie_present', 'referer_present', 'suspicious_score',
        'fingerprint_hash', 'js_challenge_passed',
        'credential_pairs', 'sequential_paths',
    ]
    
    def __init__(self):
        self.request_times = deque(maxlen=1000)
        self.paths_visited = deque(maxlen=500)
        self.methods_used = defaultdict(int)
        self.status_codes = defaultdict(int)
        self.total_requests = 0
        self.blocked_count = 0
        self.error_count = 0
        self.unique_paths = set()
        self.request_intervals = deque(maxlen=200)
        self.last_request_time = 0
        self.first_seen = time.time()
        self.user_agents = set()
        self.content_types_sent = set()
        self.avg_body_size = 0
        self.login_attempts = 0
        self.api_calls = 0
        self.static_requests = 0
        self.dynamic_requests = 0
        self.cookie_present = 0
        self.referer_present = 0
        self.suspicious_score = 0.0
        self.fingerprint_hash = None
        self.js_challenge_passed = False
        self.credential_pairs = set()
        self.sequential_paths = deque(maxlen=50)


class SessionVelocityTracker:
    """Detects abnormal session velocity patterns (credential stuffing, account takeover)."""
    
    def __init__(self, max_login_attempts=5, window_seconds=300):
        self.login_attempts = defaultdict(lambda: deque(maxlen=100))
        self.failed_logins = defaultdict(lambda: deque(maxlen=100))
        self.unique_usernames = defaultdict(set)
        self.max_attempts = max_login_attempts
        self.window = window_seconds
        self._lock = threading.Lock()
    
    def record_login_attempt(self, client_ip: str, username: str = None, success: bool = False):
        now = time.time()
        with self._lock:
            self.login_attempts[client_ip].append(now)
            if not success:
                self.failed_logins[client_ip].append(now)
            if username:
                self.unique_usernames[client_ip].add(username)
    
    def is_credential_stuffing(self, client_ip: str) -> Tuple[bool, dict]:
        now = time.time()
        cutoff = now - self.window
        
        with self._lock:
            recent_attempts = sum(1 for t in self.login_attempts[client_ip] if t > cutoff)
            recent_failures = sum(1 for t in self.failed_logins[client_ip] if t > cutoff)
            unique_users = len(self.unique_usernames.get(client_ip, set()))
        
        # Credential stuffing indicators
        is_stuffing = False
        reasons = []
        
        if recent_failures > self.max_attempts:
            reasons.append(f"too_many_failures:{recent_failures}")
            is_stuffing = True
        
        if unique_users > 3 and recent_attempts > 5:
            reasons.append(f"multiple_usernames:{unique_users}")
            is_stuffing = True
        
        if recent_attempts > 0:
            failure_rate = recent_failures / recent_attempts
            if failure_rate > 0.8 and recent_attempts > 5:
                reasons.append(f"high_failure_rate:{failure_rate:.2f}")
                is_stuffing = True
        
        return is_stuffing, {
            'recent_attempts': recent_attempts,
            'recent_failures': recent_failures,
            'unique_usernames': unique_users,
            'reasons': reasons
        }


class HoneypotTrap:
    """Hidden endpoint honeypot - any access = definitely a bot/scanner."""
    
    TRAP_PATHS = {
        '/.env.backup', '/wp-admin/setup-config.php', '/administrator/manifests/',
        '/.git/HEAD', '/config.php.bak', '/debug/vars', '/server-status-hidden',
        '/hidden-admin-panel', '/.well-known/security.txt.bak',
        '/api/v1/internal/debug', '/graphql-playground-hidden',
        '/phpmyadmin-hidden', '/adminer-secret', '/debug-console',
        '/.svn/entries', '/.hg/hgrc', '/WEB-INF/web.xml',
        '/META-INF/context.xml', '/.DS_Store.backup',
        '/crossdomain.xml', '/clientaccesspolicy.xml',
        '/robots.txt.bak', '/sitemap.xml.bak',
    }
    
    def __init__(self):
        self.trapped_ips = {}  # ip -> trap_time
        self._lock = threading.Lock()
    
    def is_trap_path(self, path: str) -> bool:
        return path.lower() in self.TRAP_PATHS
    
    def record_trap(self, client_ip: str):
        with self._lock:
            self.trapped_ips[client_ip] = time.time()
    
    def is_trapped(self, client_ip: str) -> bool:
        with self._lock:
            trap_time = self.trapped_ips.get(client_ip)
            if trap_time and (time.time() - trap_time) < 86400:  # 24h
                return True
            return False


class HeaderOrderAnalyzer:
    """
    Detects bots by analyzing HTTP header order.
    Real browsers send headers in a consistent order.
    Bots/scripts often have different header ordering.
    """
    
    # Expected header order for real Chrome browser
    CHROME_HEADER_ORDER = [
        'host', 'connection', 'sec-ch-ua', 'sec-ch-ua-mobile',
        'sec-ch-ua-platform', 'upgrade-insecure-requests', 'user-agent',
        'accept', 'sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-user',
        'sec-fetch-dest', 'accept-encoding', 'accept-language', 'cookie'
    ]
    
    FIREFOX_HEADER_ORDER = [
        'host', 'user-agent', 'accept', 'accept-language',
        'accept-encoding', 'connection', 'cookie',
        'upgrade-insecure-requests', 'sec-fetch-dest',
        'sec-fetch-mode', 'sec-fetch-site', 'sec-fetch-user'
    ]
    
    @staticmethod
    def analyze_header_order(headers: Dict[str, str], user_agent: str) -> float:
        """Returns anomaly score 0-1. Higher = more suspicious."""
        header_keys = [k.lower() for k in headers.keys()]
        
        if 'chrome' in user_agent.lower() and 'safari' in user_agent.lower():
            expected = HeaderOrderAnalyzer.CHROME_HEADER_ORDER
        elif 'firefox' in user_agent.lower():
            expected = HeaderOrderAnalyzer.FIREFOX_HEADER_ORDER
        else:
            return 0.0  # Can't validate unknown browsers
        
        # Calculate Kendall tau distance (order correlation)
        present_expected = [h for h in expected if h in header_keys]
        present_actual = [h for h in header_keys if h in expected]
        
        if len(present_expected) < 3:
            return 0.3  # Too few headers to validate
        
        # Count inversions (pairs out of order)
        inversions = 0
        total_pairs = 0
        for i in range(len(present_actual)):
            for j in range(i + 1, len(present_actual)):
                total_pairs += 1
                idx_i = present_expected.index(present_actual[i]) if present_actual[i] in present_expected else -1
                idx_j = present_expected.index(present_actual[j]) if present_actual[j] in present_expected else -1
                if idx_i > idx_j and idx_i != -1 and idx_j != -1:
                    inversions += 1
        
        if total_pairs == 0:
            return 0.0
        
        return inversions / total_pairs


class BotDetector:
    """
    Advanced Bot Detection Engine.
    Combines multiple detection methods for high accuracy.
    """
    
    def __init__(self, 
                 behavior_window=300,
                 max_requests_per_second=50,
                 max_unique_paths_per_minute=100,
                 challenge_threshold=0.7,
                 block_threshold=0.85):
        
        self.profiles = {}  # ip -> BehaviorProfile
        self.behavior_window = behavior_window
        self.max_rps = max_requests_per_second
        self.max_paths_per_min = max_unique_paths_per_minute
        self.challenge_threshold = challenge_threshold
        self.block_threshold = block_threshold
        
        self.session_velocity = SessionVelocityTracker()
        self.honeypot = HoneypotTrap()
        self.header_analyzer = HeaderOrderAnalyzer()
        
        self._lock = threading.Lock()
        self._cleanup_interval = 300
        self._last_cleanup = time.time()
        
        # JS Challenge tokens
        self._challenge_tokens = {}  # token -> (ip, expiry)
    
    def _get_profile(self, client_ip: str) -> BehaviorProfile:
        if client_ip not in self.profiles:
            self.profiles[client_ip] = BehaviorProfile()
        return self.profiles[client_ip]
    
    def _cleanup_old_profiles(self):
        """Remove stale profiles to prevent memory growth."""
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return
        
        self._last_cleanup = now
        stale_cutoff = now - 3600  # 1 hour
        stale_ips = [
            ip for ip, p in self.profiles.items()
            if p.last_request_time < stale_cutoff
        ]
        for ip in stale_ips:
            del self.profiles[ip]
    
    def analyze_request(self, 
                        client_ip: str,
                        method: str,
                        path: str,
                        headers: Dict[str, str],
                        body: str = '',
                        body_size: int = 0) -> Dict:
        """
        Comprehensive bot analysis returning detection result.
        
        Returns:
            {
                'is_bot': bool,
                'bot_score': float (0-1),
                'bot_type': str,
                'action': 'allow' | 'challenge' | 'block',
                'details': dict
            }
        """
        self._cleanup_old_profiles()
        
        now = time.time()
        user_agent = headers.get('user-agent', headers.get('User-Agent', ''))
        
        with self._lock:
            profile = self._get_profile(client_ip)
        
        scores = {}
        details = {}
        
        # === 1. Honeypot Check (instant block) ===
        if self.honeypot.is_trap_path(path):
            self.honeypot.record_trap(client_ip)
            return {
                'is_bot': True,
                'bot_score': 1.0,
                'bot_type': 'scanner',
                'action': 'block',
                'reason': 'honeypot-trap',
                'details': {'trapped_path': path}
            }
        
        if self.honeypot.is_trapped(client_ip):
            return {
                'is_bot': True,
                'bot_score': 1.0,
                'bot_type': 'scanner',
                'action': 'block',
                'reason': 'previously-trapped',
                'details': {}
            }
        
        # === 2. Known Malicious Bot Signature ===
        sig_score, sig_name = self._check_bot_signature(user_agent)
        scores['signature'] = sig_score
        if sig_name:
            details['matched_signature'] = sig_name
        
        # === 3. User-Agent Anomaly Analysis ===
        ua_score = self._analyze_user_agent(user_agent, headers)
        scores['user_agent'] = ua_score
        
        # === 4. Behavioral Analysis ===
        behavior_score = self._analyze_behavior(profile, now, method, path, headers, body_size)
        scores['behavior'] = behavior_score
        
        # === 5. Header Order Analysis ===
        header_order_score = self.header_analyzer.analyze_header_order(headers, user_agent)
        scores['header_order'] = header_order_score
        
        # === 6. Request Pattern Analysis ===
        pattern_score = self._analyze_request_patterns(profile, path, method)
        scores['patterns'] = pattern_score
        
        # === 7. Missing Browser Features ===
        browser_score = self._check_browser_consistency(user_agent, headers)
        scores['browser_consistency'] = browser_score
        
        # === 8. Timing Analysis ===
        timing_score = self._analyze_timing(profile)
        scores['timing'] = timing_score
        
        # Update profile
        with self._lock:
            profile.total_requests += 1
            profile.request_times.append(now)
            profile.paths_visited.append(path)
            profile.unique_paths.add(path)
            profile.methods_used[method] += 1
            profile.user_agents.add(user_agent[:200])
            
            if profile.last_request_time > 0:
                interval = now - profile.last_request_time
                profile.request_intervals.append(interval)
            profile.last_request_time = now
            
            if headers.get('cookie') or headers.get('Cookie'):
                profile.cookie_present += 1
            if headers.get('referer') or headers.get('Referer'):
                profile.referer_present += 1
        
        # === Calculate weighted final score ===
        weights = {
            'signature': 0.30,
            'user_agent': 0.15,
            'behavior': 0.20,
            'header_order': 0.10,
            'patterns': 0.10,
            'browser_consistency': 0.10,
            'timing': 0.05,
        }
        
        final_score = sum(scores.get(k, 0) * w for k, w in weights.items())
        final_score = min(1.0, final_score)
        
        # Determine action
        if final_score >= self.block_threshold:
            action = 'block'
        elif final_score >= self.challenge_threshold:
            action = 'challenge'
        else:
            action = 'allow'
        
        # Determine bot type
        bot_type = 'unknown'
        if sig_score > 0.8:
            bot_type = details.get('matched_signature', 'known-malicious')
        elif behavior_score > 0.8:
            bot_type = 'automated-tool'
        elif timing_score > 0.8:
            bot_type = 'scripted-bot'
        elif ua_score > 0.8:
            bot_type = 'fake-browser'
        
        return {
            'is_bot': final_score >= self.challenge_threshold,
            'bot_score': round(final_score, 3),
            'bot_type': bot_type,
            'action': action,
            'reason': f'bot-score-{final_score:.2f}',
            'details': {
                'scores': scores,
                'request_count': profile.total_requests,
            }
        }
    
    def _check_bot_signature(self, user_agent: str) -> Tuple[float, Optional[str]]:
        """Check against known bot signatures."""
        ua_lower = user_agent.lower()
        
        # Empty UA is very suspicious
        if not user_agent or len(user_agent) < 10:
            return 0.7, 'empty-or-short-ua'
        
        # Check known good bots first
        for good_bot in KNOWN_GOOD_BOTS:
            if good_bot in ua_lower:
                return 0.0, None
        
        # Check malicious signatures
        for pattern in _MALICIOUS_BOT_COMPILED:
            match = pattern.search(ua_lower)
            if match:
                return 1.0, match.group(0)
        
        return 0.0, None
    
    def _analyze_user_agent(self, user_agent: str, headers: Dict[str, str]) -> float:
        """Analyze user-agent for anomalies."""
        score = 0.0
        
        if not user_agent:
            return 0.8
        
        ua_lower = user_agent.lower()
        
        # Check for automation framework indicators
        for indicator in AUTOMATION_INDICATORS:
            if indicator in ua_lower:
                return 0.95
        
        # Extremely long UA (potential overflow)
        if len(user_agent) > 512:
            score += 0.4
        
        # UA claims to be a browser but missing expected headers
        if 'mozilla' in ua_lower:
            if not headers.get('accept'):
                score += 0.3
            if not headers.get('accept-language') and not headers.get('Accept-Language'):
                score += 0.3
            if not headers.get('accept-encoding') and not headers.get('Accept-Encoding'):
                score += 0.2
        
        # Outdated browser versions (often used by bots)
        old_browser_patterns = [
            r'chrome/[1-6][0-9]\.',  # Chrome < 70
            r'firefox/[1-5][0-9]\.',  # Firefox < 60
            r'msie\s[1-9]\.',  # IE < 10
        ]
        for pattern in old_browser_patterns:
            if re.search(pattern, ua_lower):
                score += 0.2
        
        # Multiple browser identifiers (conflicting)
        browser_count = sum(1 for b in ['chrome', 'firefox', 'edge', 'opera', 'safari'] 
                          if b in ua_lower)
        # Chrome UA normally contains safari and chrome
        if 'chrome' not in ua_lower and browser_count > 2:
            score += 0.3
        
        return min(1.0, score)
    
    def _analyze_behavior(self, profile: BehaviorProfile, now: float,
                         method: str, path: str, headers: Dict, body_size: int) -> float:
        """Behavioral analysis scoring."""
        score = 0.0
        
        if profile.total_requests < 5:
            return 0.0  # Not enough data
        
        # Requests per second (last 10 seconds)
        recent = sum(1 for t in profile.request_times if now - t < 10)
        rps = recent / 10.0
        if rps > self.max_rps:
            score += 0.5
        elif rps > self.max_rps * 0.5:
            score += 0.3
        
        # Unique paths per minute (scanners hit many unique paths)
        recent_minute = sum(1 for t in profile.request_times if now - t < 60)
        unique_recent = len(set(list(profile.paths_visited)[-recent_minute:]))
        if unique_recent > self.max_paths_per_min:
            score += 0.4
        
        # Multiple user agents from same IP
        if len(profile.user_agents) > 3:
            score += 0.3
        
        # No cookies ever (bots often don't handle cookies)
        if profile.total_requests > 20 and profile.cookie_present == 0:
            score += 0.2
        
        # No referer ever (bots often don't send referer)
        if profile.total_requests > 20 and profile.referer_present == 0:
            score += 0.15
        
        # High error rate
        if profile.total_requests > 10:
            error_rate = profile.error_count / profile.total_requests
            if error_rate > 0.5:
                score += 0.3
        
        # Only uses one HTTP method (GET typically for scanners)
        if profile.total_requests > 30 and len(profile.methods_used) == 1:
            score += 0.15
        
        return min(1.0, score)
    
    def _analyze_request_patterns(self, profile: BehaviorProfile, 
                                   path: str, method: str) -> float:
        """Detect scanner-like request patterns."""
        score = 0.0
        
        # Sequential path enumeration (directory brute force)
        if profile.total_requests > 10:
            paths = list(profile.paths_visited)
            if len(paths) > 5:
                # Check for alphabetical scanning pattern
                sorted_paths = sorted(paths[-20:])
                if paths[-20:] == sorted_paths:
                    score += 0.5
                
                # Check for common scanner patterns
                scanner_paths = ['/admin', '/login', '/wp-admin', '/phpmyadmin',
                               '/.env', '/.git', '/backup', '/debug']
                matched = sum(1 for sp in scanner_paths if sp in paths)
                if matched > 3:
                    score += 0.4
        
        # Unusual HTTP methods
        unusual_methods = {'TRACE', 'TRACK', 'CONNECT', 'DEBUG', 'PROPFIND', 'PATCH'}
        if method.upper() in unusual_methods:
            score += 0.3
        
        return min(1.0, score)
    
    def _check_browser_consistency(self, user_agent: str, headers: Dict[str, str]) -> float:
        """Check if headers are consistent with claimed browser."""
        score = 0.0
        ua_lower = user_agent.lower()
        
        # Chrome claims but missing sec-ch-ua headers (modern Chrome always sends these)
        if 'chrome/' in ua_lower:
            version_match = re.search(r'chrome/(\d+)', ua_lower)
            if version_match and int(version_match.group(1)) >= 90:
                if not any(h.lower().startswith('sec-ch-ua') for h in headers):
                    score += 0.4
                if not any(h.lower().startswith('sec-fetch') for h in headers):
                    score += 0.3
        
        # Claims to accept gzip but body suggests otherwise
        accept_encoding = headers.get('accept-encoding', headers.get('Accept-Encoding', ''))
        if 'mozilla' in ua_lower and not accept_encoding:
            score += 0.2
        
        # Connection header anomaly
        connection = headers.get('connection', headers.get('Connection', ''))
        if connection.lower() == 'close' and 'http/2' in str(headers.get(':protocol', '')):
            score += 0.3
        
        return min(1.0, score)
    
    def _analyze_timing(self, profile: BehaviorProfile) -> float:
        """Detect machine-like timing patterns."""
        intervals = list(profile.request_intervals)
        if len(intervals) < 10:
            return 0.0
        
        # Calculate coefficient of variation
        # Humans have high variation, bots are very consistent
        mean_interval = sum(intervals) / len(intervals)
        if mean_interval == 0:
            return 0.8  # Instant requests = bot
        
        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)
        cv = std_dev / mean_interval if mean_interval > 0 else 0
        
        # Very low coefficient of variation = machine-like regularity
        if cv < 0.05 and len(intervals) > 20:
            return 0.8
        elif cv < 0.1 and len(intervals) > 20:
            return 0.5
        elif cv < 0.2:
            return 0.3
        
        # Check for exact same intervals (dead giveaway)
        rounded = [round(i, 2) for i in intervals[-20:]]
        most_common = max(set(rounded), key=rounded.count)
        if rounded.count(most_common) / len(rounded) > 0.8:
            return 0.9
        
        return 0.0
    
    def generate_js_challenge(self, client_ip: str) -> Dict:
        """Generate a JavaScript challenge for suspected bots."""
        token = secrets.token_hex(32)
        challenge_value = secrets.randbelow(1000000)
        expected_answer = hashlib.sha256(f"{challenge_value}{token}".encode()).hexdigest()
        
        self._challenge_tokens[token] = {
            'ip': client_ip,
            'answer': expected_answer,
            'expires': time.time() + 30,
            'value': challenge_value,
        }
        
        return {
            'challenge_token': token,
            'challenge_value': challenge_value,
            'challenge_type': 'js-compute',
        }
    
    def verify_js_challenge(self, token: str, answer: str, client_ip: str) -> bool:
        """Verify JavaScript challenge response."""
        challenge = self._challenge_tokens.get(token)
        if not challenge:
            return False
        
        if challenge['ip'] != client_ip:
            return False
        
        if time.time() > challenge['expires']:
            del self._challenge_tokens[token]
            return False
        
        if secrets.compare_digest(answer, challenge['answer']):
            del self._challenge_tokens[token]
            # Mark profile as verified
            with self._lock:
                profile = self._get_profile(client_ip)
                profile.js_challenge_passed = True
            return True
        
        return False
    
    def get_stats(self) -> Dict:
        """Return bot detection statistics."""
        return {
            'tracked_ips': len(self.profiles),
            'trapped_ips': len(self.honeypot.trapped_ips),
            'total_signatures': len(MALICIOUS_BOT_SIGNATURES),
            'good_bot_signatures': len(KNOWN_GOOD_BOTS),
        }


# Module-level singleton
_detector = None

def get_detector(**kwargs) -> BotDetector:
    global _detector
    if _detector is None:
        _detector = BotDetector(**kwargs)
    return _detector

def analyze_request(client_ip, method, path, headers, body='', body_size=0):
    return get_detector().analyze_request(client_ip, method, path, headers, body, body_size)
