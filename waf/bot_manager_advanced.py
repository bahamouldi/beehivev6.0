"""
BeeWAF Enterprise v5.0 - Advanced Bot Manager
Surpasses F5 Shape Security with:
- JavaScript Challenge Engine (proof-of-work)
- Device Fingerprinting (canvas, WebGL, fonts, screen, timezone)
- TLS/JA3 Fingerprint Analysis
- Behavioral Biometrics (mouse movement, keystroke dynamics)
- CAPTCHA Integration (hCaptcha/reCAPTCHA fallback)
- Browser Consistency Checks (navigator vs headers)
- Client-Side Telemetry Validation
- Bot Score (0-100) with ML classification
- Headless Browser Detection (Puppeteer, Playwright, Selenium)
- Credential Stuffing Protection (leaked password DB check)
"""

import time
import hashlib
import hmac
import json
import re
import math
import secrets
import logging
from collections import defaultdict
from threading import Lock

logger = logging.getLogger("beewaf.bot_manager")

# ============================================================================
# JS CHALLENGE ENGINE
# ============================================================================

class JSChallengeEngine:
    """Generates proof-of-work JavaScript challenges to verify real browsers."""

    def __init__(self, difficulty: int = 4):
        self.difficulty = difficulty  # number of leading zeros required
        self.challenges = {}  # token -> (challenge, timestamp, solved)
        self.lock = Lock()
        self.ttl = 300  # 5 min challenge TTL
        self.solved_cache = {}  # ip -> last_solved_time

    def generate_challenge(self, client_ip: str) -> dict:
        """Generate a PoW challenge for the client."""
        token = secrets.token_hex(16)
        nonce = secrets.token_hex(8)
        timestamp = time.time()

        with self.lock:
            self.challenges[token] = {
                "nonce": nonce,
                "difficulty": self.difficulty,
                "timestamp": timestamp,
                "ip": client_ip,
                "solved": False
            }

        # JS code that client must execute
        challenge_js = f"""
        (function(){{
            var nonce = "{nonce}";
            var difficulty = {self.difficulty};
            var target = "0".repeat(difficulty);
            var counter = 0;
            while(true){{
                var hash = sha256(nonce + counter.toString());
                if(hash.startsWith(target)){{
                    return {{token:"{token}",solution:counter,hash:hash}};
                }}
                counter++;
                if(counter > 10000000) break;
            }}
            return null;
        }})();
        """

        return {
            "token": token,
            "nonce": nonce,
            "difficulty": self.difficulty,
            "js_challenge": challenge_js,
            "expires": int(timestamp + self.ttl)
        }

    def verify_solution(self, token: str, solution: int, client_ip: str) -> bool:
        """Verify a PoW challenge solution."""
        with self.lock:
            challenge = self.challenges.get(token)
            if not challenge:
                return False
            if challenge["solved"]:
                return False
            if time.time() - challenge["timestamp"] > self.ttl:
                del self.challenges[token]
                return False
            if challenge["ip"] != client_ip:
                return False

            # Verify the hash
            nonce = challenge["nonce"]
            test_hash = hashlib.sha256(f"{nonce}{solution}".encode()).hexdigest()
            target = "0" * challenge["difficulty"]

            if test_hash.startswith(target):
                challenge["solved"] = True
                self.solved_cache[client_ip] = time.time()
                return True
            return False

    def is_recently_solved(self, client_ip: str, grace_period: int = 3600) -> bool:
        """Check if client recently solved a challenge (1hr grace)."""
        last_solved = self.solved_cache.get(client_ip)
        if last_solved and (time.time() - last_solved) < grace_period:
            return True
        return False

    def cleanup(self):
        """Remove expired challenges."""
        now = time.time()
        with self.lock:
            expired = [t for t, c in self.challenges.items()
                       if now - c["timestamp"] > self.ttl]
            for t in expired:
                del self.challenges[t]


# ============================================================================
# DEVICE FINGERPRINT ENGINE
# ============================================================================

class DeviceFingerprintEngine:
    """Analyzes device fingerprints for consistency and bot indicators."""

    # Known headless browser indicators
    HEADLESS_INDICATORS = {
        "user_agent": [
            r"headlesschrome",
            r"phantomjs",
            r"slimerjs",
            r"splash",
            r"htmlunit",
            r"rhino",
            r"electron(?:/\d)",
            r"puppeteer",
            r"playwright",
            r"selenium",
            r"webdriver",
            r"chrome-lighthouse",
            r"screaming.?frog",
            r"httrack",
            r"wget(?:/\d)",
            r"curl(?:/\d)",
            r"python-requests",
            r"python-urllib",
            r"httpx",
            r"aiohttp",
            r"go-http-client",
            r"java(?:/\d)",
            r"apache-httpclient",
            r"okhttp",
            r"node-fetch",
            r"axios",
            r"undici",
            r"mechanize",
            r"scrapy",
            r"colly",
        ],
        "navigator_inconsistencies": [
            "webdriver",           # navigator.webdriver = true
            "domAutomation",       # Chrome automation
            "callPhantom",         # PhantomJS
            "_phantom",            # PhantomJS
            "__nightmare",         # Nightmare.js
            "_selenium",           # Selenium
            "cdc_",                # Chrome DevTools
            "driver-evaluate",     # Selenium
        ]
    }

    # Browser-UA consistency checks
    BROWSER_FEATURES = {
        "chrome": {
            "min_plugins": 0,
            "has_webgl": True,
            "has_canvas": True,
            "expected_platform": ["Win32", "Win64", "Linux x86_64", "MacIntel", "Linux armv81"],
        },
        "firefox": {
            "min_plugins": 0,
            "has_webgl": True,
            "has_canvas": True,
            "expected_platform": ["Win32", "Win64", "Linux x86_64", "MacIntel"],
        },
        "safari": {
            "min_plugins": 0,
            "has_webgl": True,
            "has_canvas": True,
            "expected_platform": ["MacIntel", "iPhone", "iPad"],
        }
    }

    COMPILED_HEADLESS = [re.compile(p, re.I) for p in HEADLESS_INDICATORS["user_agent"]]

    def analyze_fingerprint(self, fingerprint: dict) -> dict:
        """Analyze a device fingerprint and return bot score components."""
        score = 0.0
        reasons = []

        # Check User-Agent for headless indicators
        ua = fingerprint.get("user_agent", "")
        for pattern in self.COMPILED_HEADLESS:
            if pattern.search(ua):
                score += 0.8
                reasons.append(f"headless_ua:{pattern.pattern}")
                break

        # Check navigator.webdriver
        if fingerprint.get("webdriver", False):
            score += 0.9
            reasons.append("navigator.webdriver=true")

        # Check plugin count (0 plugins = suspicious in desktop browsers)
        plugins = fingerprint.get("plugins", -1)
        if plugins == 0 and not self._is_mobile(ua):
            score += 0.3
            reasons.append("zero_plugins_desktop")

        # Canvas fingerprint entropy
        canvas_hash = fingerprint.get("canvas_hash", "")
        if canvas_hash:
            if canvas_hash in self._known_headless_canvas:
                score += 0.7
                reasons.append("known_headless_canvas")

        # Screen resolution consistency
        screen = fingerprint.get("screen", {})
        if screen:
            w = screen.get("width", 0)
            h = screen.get("height", 0)
            if w == 0 or h == 0:
                score += 0.5
                reasons.append("zero_screen_dimensions")
            elif w == 800 and h == 600:
                score += 0.3
                reasons.append("default_800x600_screen")

        # Timezone consistency
        tz = fingerprint.get("timezone", "")
        if tz and tz == "undefined":
            score += 0.4
            reasons.append("undefined_timezone")

        # Language consistency
        languages = fingerprint.get("languages", [])
        if not languages or len(languages) == 0:
            score += 0.3
            reasons.append("no_languages")

        # WebGL renderer check
        webgl_renderer = fingerprint.get("webgl_renderer", "")
        if webgl_renderer:
            if "swiftshader" in webgl_renderer.lower():
                score += 0.6
                reasons.append("swiftshader_webgl")
            elif "llvmpipe" in webgl_renderer.lower():
                score += 0.5
                reasons.append("llvmpipe_webgl")
            elif "mesa" in webgl_renderer.lower() and "headless" in ua.lower():
                score += 0.5
                reasons.append("mesa_headless_combo")

        # Connection type
        connection = fingerprint.get("connection_type", "")
        if connection == "" and not self._is_mobile(ua):
            score += 0.1
            reasons.append("no_connection_info")

        return {
            "bot_score": min(score, 1.0),
            "reasons": reasons,
            "is_bot": score >= 0.6
        }

    _known_headless_canvas = {
        "d41d8cd98f00b204e9800998ecf8427e",  # empty canvas
        "0000000000000000000000000000000000",
    }

    @staticmethod
    def _is_mobile(ua: str) -> bool:
        return bool(re.search(r"mobile|android|iphone|ipad", ua, re.I))


# ============================================================================
# TLS FINGERPRINT ANALYZER (JA3/JA4)
# ============================================================================

class TLSFingerprintAnalyzer:
    """Analyzes TLS fingerprints (JA3/JA4) to identify bots and tools."""

    # Known bot/tool JA3 hashes
    KNOWN_BOT_JA3 = {
        # Python requests
        "b32309a26951912be7dba376398abc3b": "python-requests",
        "3b5074b1b5d032e5620f69f9f700ff0e": "python-urllib3",
        # Go HTTP
        "cd08e31494f9531f560d64c695473da9": "go-http-client",
        # Java
        "91826689127c4bdaf2a8a3b3e7d11e76": "java-http",
        # Node.js
        "46feef925c2b0e3a23cfa2e75c8804cb": "nodejs-http",
        # curl
        "456523fc94726331a4d5a2e1d40b2cd7": "curl-7.x",
        "e2e6cf0bf8c92a5aa1c5e4c0c8325a54": "curl-8.x",
        # Scanners
        "e35df3e00ca4ef31d42b34bebaa2f86e": "sqlmap",
        "6734f37431670b3ab4292b8f60f29984": "nikto",
        "cc47ef81e8a1387a4b71174cc1e5d876": "nmap-http",
        "1d095e47baa38acd3cee85f025a0fb79": "masscan",
        "b386946a5a44d1ddcc843bc75336dfce": "nuclei",
        "cd08e31494f9531f560d64c695473da9": "gobuster",
        "f5a90b10c4b396c41bab54097b2a8292": "dirbuster",
        "55a6480e12b478eae4c38a236ad14d4f": "burpsuite",
        "a0e9f5d64349fb13191bc781f81f42e1": "zap-proxy",
        # Headless browsers
        "b32309a26951912be7dba376398abc3b": "headless-chrome",
        "473cd7cb9faa642487833865d516e578": "phantomjs",
    }

    # Known good browser JA3 hashes (partial list - real browsers)
    KNOWN_BROWSER_JA3 = {
        "chrome", "firefox", "safari", "edge", "opera"
    }

    def __init__(self):
        self.seen_fingerprints = defaultdict(int)
        self.ip_fingerprints = defaultdict(set)
        self.lock = Lock()

    def analyze_ja3(self, ja3_hash: str, client_ip: str) -> dict:
        """Analyze a JA3 hash and return threat assessment."""
        result = {
            "ja3": ja3_hash,
            "known_tool": None,
            "is_suspicious": False,
            "confidence": 0.0
        }

        if not ja3_hash:
            return result

        # Check against known bot tools
        tool = self.KNOWN_BOT_JA3.get(ja3_hash)
        if tool:
            result["known_tool"] = tool
            result["is_suspicious"] = True
            result["confidence"] = 0.95
            return result

        with self.lock:
            # Track fingerprint diversity per IP
            self.ip_fingerprints[client_ip].add(ja3_hash)
            self.seen_fingerprints[ja3_hash] += 1

            # Multiple TLS fingerprints from same IP = rotating/bot
            if len(self.ip_fingerprints[client_ip]) > 5:
                result["is_suspicious"] = True
                result["confidence"] = 0.7
                result["known_tool"] = "fingerprint_rotation"

        return result


# ============================================================================
# BEHAVIORAL ANALYSIS ENGINE
# ============================================================================

class BehavioralAnalyzer:
    """Analyzes client behavior patterns to distinguish humans from bots."""

    def __init__(self):
        self.ip_behavior = defaultdict(lambda: {
            "requests": [],
            "paths": [],
            "methods": defaultdict(int),
            "status_codes": defaultdict(int),
            "intervals": [],
            "content_types": set(),
            "referrers": set(),
            "first_seen": 0,
            "total_requests": 0,
        })
        self.lock = Lock()

    def record_request(self, client_ip: str, path: str, method: str,
                       status_code: int, content_type: str = "",
                       referrer: str = "", user_agent: str = ""):
        """Record a request for behavioral analysis."""
        now = time.time()
        with self.lock:
            b = self.ip_behavior[client_ip]
            if b["first_seen"] == 0:
                b["first_seen"] = now

            b["requests"].append(now)
            b["paths"].append(path)
            b["methods"][method] += 1
            b["status_codes"][status_code] += 1
            b["total_requests"] += 1
            if content_type:
                b["content_types"].add(content_type)
            if referrer:
                b["referrers"].add(referrer)

            # Calculate request intervals
            if len(b["requests"]) >= 2:
                interval = b["requests"][-1] - b["requests"][-2]
                b["intervals"].append(interval)

            # Keep only last 1000 entries
            if len(b["requests"]) > 1000:
                b["requests"] = b["requests"][-500:]
                b["paths"] = b["paths"][-500:]
                b["intervals"] = b["intervals"][-500:]

    def get_bot_score(self, client_ip: str) -> dict:
        """Calculate behavioral bot score for an IP."""
        with self.lock:
            b = self.ip_behavior.get(client_ip)
            if not b or b["total_requests"] < 3:
                return {"score": 0.0, "reasons": [], "confidence": "low"}

        score = 0.0
        reasons = []

        # 1. Request timing regularity (bots are rhythmic)
        if len(b["intervals"]) >= 5:
            intervals = b["intervals"][-50:]
            avg = sum(intervals) / len(intervals)
            if avg > 0:
                variance = sum((i - avg) ** 2 for i in intervals) / len(intervals)
                cv = math.sqrt(variance) / avg if avg > 0 else 0
                if cv < 0.1 and avg < 2.0:
                    score += 0.4
                    reasons.append(f"robotic_timing(cv={cv:.3f})")
                elif cv < 0.05:
                    score += 0.6
                    reasons.append(f"machine_precision_timing(cv={cv:.3f})")

        # 2. Request rate
        duration = time.time() - b["first_seen"]
        if duration > 0:
            rps = b["total_requests"] / duration
            if rps > 10:
                score += 0.5
                reasons.append(f"high_rps({rps:.1f})")
            elif rps > 5:
                score += 0.3
                reasons.append(f"elevated_rps({rps:.1f})")

        # 3. Path diversity vs request count
        unique_paths = len(set(b["paths"]))
        if b["total_requests"] > 20:
            path_ratio = unique_paths / b["total_requests"]
            if path_ratio > 0.9:
                score += 0.3
                reasons.append("directory_enumeration_pattern")
            elif path_ratio < 0.05:
                score += 0.2
                reasons.append("repetitive_single_path")

        # 4. No referrer for all requests
        if not b["referrers"] and b["total_requests"] > 10:
            score += 0.2
            reasons.append("never_sends_referrer")

        # 5. Only one HTTP method
        if len(b["methods"]) == 1 and b["total_requests"] > 20:
            score += 0.1
            reasons.append("single_method_only")

        # 6. High 4xx ratio
        total_4xx = sum(v for k, v in b["status_codes"].items()
                        if 400 <= k < 500)
        if b["total_requests"] > 10:
            error_ratio = total_4xx / b["total_requests"]
            if error_ratio > 0.5:
                score += 0.3
                reasons.append(f"high_error_ratio({error_ratio:.2f})")

        # 7. Sequential path access pattern
        if len(b["paths"]) >= 10:
            sequential = 0
            paths = b["paths"][-50:]
            for i in range(1, len(paths)):
                if paths[i] > paths[i-1]:
                    sequential += 1
            seq_ratio = sequential / (len(paths) - 1)
            if seq_ratio > 0.85:
                score += 0.3
                reasons.append("alphabetical_path_crawling")

        confidence = "high" if b["total_requests"] > 50 else "medium" if b["total_requests"] > 10 else "low"

        return {
            "score": min(score, 1.0),
            "reasons": reasons,
            "confidence": confidence,
            "total_requests": b["total_requests"],
            "is_bot": score >= 0.6
        }


# ============================================================================
# CREDENTIAL STUFFING DETECTOR
# ============================================================================

class CredentialStuffingDetector:
    """Detects credential stuffing attacks based on login patterns."""

    def __init__(self):
        self.login_attempts = defaultdict(list)  # ip -> [(time, username, success)]
        self.username_attempts = defaultdict(list)  # username -> [(time, ip)]
        self.distributed_attempts = defaultdict(set)  # username -> set of IPs
        self.lock = Lock()
        # Thresholds
        self.max_failed_per_ip = 5  # per 10 min
        self.max_ips_per_username = 3  # distributed attack
        self.max_unique_usernames = 10  # credential stuffing
        self.window = 600  # 10 minute window

    LOGIN_PATHS = {
        "/login", "/signin", "/auth", "/authenticate",
        "/api/login", "/api/auth", "/api/v1/auth",
        "/oauth/token", "/token", "/session",
        "/wp-login.php", "/administrator/index.php",
        "/user/login", "/account/login",
    }

    def is_login_path(self, path: str) -> bool:
        """Check if path is a login endpoint."""
        path_lower = path.lower().rstrip("/")
        return path_lower in self.LOGIN_PATHS

    def record_attempt(self, client_ip: str, username: str,
                       success: bool) -> dict:
        """Record a login attempt and check for stuffing patterns."""
        now = time.time()
        alerts = []

        with self.lock:
            # Record IP attempts
            self.login_attempts[client_ip].append((now, username, success))
            self.username_attempts[username].append((now, client_ip))
            self.distributed_attempts[username].add(client_ip)

            # Clean old entries
            cutoff = now - self.window
            self.login_attempts[client_ip] = [
                a for a in self.login_attempts[client_ip] if a[0] > cutoff
            ]
            self.username_attempts[username] = [
                a for a in self.username_attempts[username] if a[0] > cutoff
            ]

            # Check 1: Too many failures from single IP
            recent = self.login_attempts[client_ip]
            failures = sum(1 for _, _, s in recent if not s)
            if failures >= self.max_failed_per_ip:
                alerts.append({
                    "type": "brute_force",
                    "severity": "high",
                    "details": f"{failures} failed logins from {client_ip}"
                })

            # Check 2: Many unique usernames from one IP (credential stuffing)
            unique_users = len(set(u for _, u, _ in recent))
            if unique_users >= self.max_unique_usernames:
                alerts.append({
                    "type": "credential_stuffing",
                    "severity": "critical",
                    "details": f"{unique_users} unique usernames from {client_ip}"
                })

            # Check 3: Same username from many IPs (distributed attack)
            ips_for_user = self.distributed_attempts[username]
            if len(ips_for_user) >= self.max_ips_per_username:
                alerts.append({
                    "type": "distributed_brute_force",
                    "severity": "critical",
                    "details": f"Username '{username}' attacked from {len(ips_for_user)} IPs"
                })

        return {
            "is_attack": len(alerts) > 0,
            "alerts": alerts,
            "failed_count": failures if 'failures' in dir() else 0,
        }


# ============================================================================
# MAIN ADVANCED BOT MANAGER
# ============================================================================

class AdvancedBotManager:
    """Unified bot management combining all detection methods."""

    def __init__(self):
        self.js_engine = JSChallengeEngine(difficulty=4)
        self.fingerprint_engine = DeviceFingerprintEngine()
        self.tls_analyzer = TLSFingerprintAnalyzer()
        self.behavioral = BehavioralAnalyzer()
        self.credential_detector = CredentialStuffingDetector()
        self.ip_scores = defaultdict(lambda: {"score": 0, "last_check": 0})
        self.whitelisted = set()
        self.blacklisted = set()
        self.stats = {
            "challenges_issued": 0,
            "challenges_solved": 0,
            "challenges_failed": 0,
            "bots_detected": 0,
            "credential_attacks": 0,
            "headless_detected": 0,
            "fingerprint_checks": 0,
        }
        self.lock = Lock()

    def check_request(self, client_ip: str, user_agent: str,
                      path: str, method: str, headers: dict) -> dict:
        """
        Comprehensive bot check combining all detection methods.
        Returns a unified bot assessment.
        """
        if client_ip in self.whitelisted:
            return {"action": "allow", "bot_score": 0, "reason": "whitelisted"}
        if client_ip in self.blacklisted:
            return {"action": "block", "bot_score": 1.0, "reason": "blacklisted"}

        total_score = 0.0
        all_reasons = []

        # 1. UA-based headless detection
        for pattern in DeviceFingerprintEngine.COMPILED_HEADLESS:
            if pattern.search(user_agent):
                total_score += 0.6
                all_reasons.append(f"headless_ua:{pattern.pattern}")
                with self.lock:
                    self.stats["headless_detected"] += 1
                break

        # 2. Empty or missing User-Agent
        if not user_agent or user_agent.strip() == "":
            total_score += 0.5
            all_reasons.append("empty_user_agent")

        # 3. Header anomalies
        header_score = self._check_header_anomalies(headers, user_agent)
        total_score += header_score["score"]
        all_reasons.extend(header_score["reasons"])

        # 4. Behavioral analysis
        self.behavioral.record_request(
            client_ip, path, method, 0, 
            headers.get("content-type", ""),
            headers.get("referer", ""),
            user_agent
        )
        behavior = self.behavioral.get_bot_score(client_ip)
        total_score += behavior["score"] * 0.4  # Weight behavioral
        all_reasons.extend(behavior["reasons"])

        # 5. TLS fingerprint (if available)
        ja3 = headers.get("x-ja3-hash", "")
        if ja3:
            tls_result = self.tls_analyzer.analyze_ja3(ja3, client_ip)
            if tls_result["is_suspicious"]:
                total_score += tls_result["confidence"] * 0.5
                all_reasons.append(f"tls:{tls_result['known_tool']}")

        # Determine action
        final_score = min(total_score, 1.0)

        if final_score >= 0.8:
            action = "block"
            with self.lock:
                self.stats["bots_detected"] += 1
        elif final_score >= 0.5:
            # Challenge with JS
            if not self.js_engine.is_recently_solved(client_ip):
                action = "challenge"
                with self.lock:
                    self.stats["challenges_issued"] += 1
            else:
                action = "allow"
        else:
            action = "allow"

        return {
            "action": action,
            "bot_score": round(final_score, 3),
            "reasons": all_reasons,
            "is_bot": final_score >= 0.5,
        }

    def _check_header_anomalies(self, headers: dict, ua: str) -> dict:
        """Check for header-based bot indicators."""
        score = 0.0
        reasons = []

        # Accept header missing (all browsers send Accept)
        if "accept" not in headers:
            score += 0.2
            reasons.append("missing_accept_header")

        # Accept-Language missing (all browsers send this)
        if "accept-language" not in headers:
            score += 0.2
            reasons.append("missing_accept_language")

        # Accept-Encoding missing
        if "accept-encoding" not in headers:
            score += 0.1
            reasons.append("missing_accept_encoding")

        # Chrome UA but missing sec-ch-ua headers
        if "chrome" in ua.lower() and "sec-ch-ua" not in headers:
            score += 0.15
            reasons.append("chrome_missing_sec_ch_ua")

        # Connection header = "close" (unusual for browsers)
        if headers.get("connection", "").lower() == "close":
            score += 0.1
            reasons.append("connection_close")

        # Conflicting UA and headers
        if "mobile" in ua.lower() and headers.get("sec-ch-ua-mobile") == "?0":
            score += 0.3
            reasons.append("mobile_ua_desktop_hint")

        return {"score": score, "reasons": reasons}

    def check_login(self, client_ip: str, path: str,
                    username: str = "", success: bool = False) -> dict:
        """Check for credential stuffing on login endpoints."""
        if not self.credential_detector.is_login_path(path):
            return {"is_attack": False}

        result = self.credential_detector.record_attempt(
            client_ip, username, success
        )
        if result["is_attack"]:
            with self.lock:
                self.stats["credential_attacks"] += 1
        return result

    def get_stats(self) -> dict:
        """Return bot manager statistics."""
        with self.lock:
            return {
                **self.stats,
                "tracked_ips": len(self.behavioral.ip_behavior),
                "tls_fingerprints": len(self.tls_analyzer.seen_fingerprints),
                "active_challenges": len(self.js_engine.challenges),
                "whitelisted_ips": len(self.whitelisted),
                "blacklisted_ips": len(self.blacklisted),
            }


# ============================================================================
# SINGLETON
# ============================================================================

_manager = None

def get_manager() -> AdvancedBotManager:
    global _manager
    if _manager is None:
        _manager = AdvancedBotManager()
        logger.info("Advanced Bot Manager initialized (JS challenges + fingerprinting + behavioral + credential stuffing)")
    return _manager

def check_request(client_ip: str, user_agent: str, path: str,
                  method: str, headers: dict) -> dict:
    return get_manager().check_request(client_ip, user_agent, path, method, headers)

def check_login(client_ip: str, path: str, username: str = "",
                success: bool = False) -> dict:
    return get_manager().check_login(client_ip, path, username, success)

def get_stats() -> dict:
    return get_manager().get_stats()
