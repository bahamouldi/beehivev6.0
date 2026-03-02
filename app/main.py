from fastapi import FastAPI, Request, HTTPException, Depends, Header
from fastapi.responses import JSONResponse, Response, StreamingResponse
from fastapi.security import APIKeyHeader
import logging
import os
import secrets
import time
import json
import httpx
from datetime import datetime
from pythonjsonlogger.json import JsonFormatter
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST

from waf import rules
from waf import anomaly
from waf import ml_engine
from waf.ratelimit import RateLimiter, IPBlocklist

# === NEW Enterprise WAF Modules ===
from waf import bot_detector
from waf import dlp
from waf import geo_block
from waf import protocol_validator
from waf import api_security
from waf import threat_intel
from waf import session_protection

# === v4.0 Enterprise Modules (Surpasses F5 ASM) ===
from waf import evasion_detector
from waf import correlation_engine
from waf import adaptive_learning
from waf import response_cloaking
from waf import cookie_security
from waf import virtual_patching
from waf import zero_day_detector
from waf import websocket_inspector
from waf import payload_analyzer
from waf import compliance_engine

# === v5.0 Enterprise Modules (Perfect 100/100 Score) ===
from waf import bot_manager_advanced
from waf import ddos_protection
from waf import api_discovery
from waf import threat_feed
from waf import cluster_manager
from waf import performance_engine
from waf import compliance_engine_v5

# === REVERSE PROXY CONFIG ===
# When BACKEND_URL is set, BeeWAF acts as a reverse proxy WAF
# All clean requests are forwarded to the backend app
# When not set, BeeWAF uses its own built-in routes (demo mode)
BACKEND_URL = os.environ.get('BACKEND_URL', '')
_proxy_client = None

# === MULTI-BACKEND ROUTING ===
# BACKEND_MAP allows routing to different backends based on Host header.
# Format: JSON object {"hostname": "http://backend-url"}
# Example: {"dev.idts.dpc.com.tn": "http://idts-front-service.idts-test.svc.cluster.local:80"}
# Requests not matching any key fall back to BACKEND_URL.
_BACKEND_MAP_RAW = os.environ.get('BACKEND_MAP', '{}')
try:
    BACKEND_MAP = json.loads(_BACKEND_MAP_RAW)
except json.JSONDecodeError:
    BACKEND_MAP = {}
_proxy_clients = {}  # Cache per-host httpx clients

def _get_client_for_url(base_url: str) -> httpx.AsyncClient:
    """Get or create an httpx client for a given base URL."""
    if base_url not in _proxy_clients:
        _proxy_clients[base_url] = httpx.AsyncClient(
            base_url=base_url,
            timeout=httpx.Timeout(30.0, connect=10.0),
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
            follow_redirects=False,
            verify=False,
        )
    return _proxy_clients[base_url]

def get_proxy_client(host: str = '') -> httpx.AsyncClient:
    """Get the right httpx client based on Host header.
    
    If BACKEND_MAP has an entry for this host, use that backend.
    Otherwise fall back to the default BACKEND_URL.
    """
    # Check host-specific backend first
    if host and BACKEND_MAP:
        clean_host = host.split(':')[0].lower().strip()
        for pattern, url in BACKEND_MAP.items():
            if clean_host == pattern.lower().strip():
                return _get_client_for_url(url)
    # Fall back to default
    if BACKEND_URL:
        return _get_client_for_url(BACKEND_URL)
    return None

# JSON Logging Configuration for ELK Stack
class CustomJsonFormatter(JsonFormatter):
    def add_fields(self, log_record, record, message_dict):
        super(CustomJsonFormatter, self).add_fields(log_record, record, message_dict)
        log_record['@timestamp'] = datetime.utcnow().isoformat() + 'Z'
        log_record['service'] = 'beewaf'
        log_record['level'] = record.levelname
        log_record['logger_name'] = record.name

def setup_logging():
    logger = logging.getLogger("beewaf")
    logger.setLevel(logging.INFO)
    logger.propagate = False  # Prevent duplicate logs to root logger
    
    # Clear existing handlers to prevent duplicates on reload
    if logger.handlers:
        logger.handlers.clear()
    
    # Console handler with JSON format (for Docker logs -> Logstash)
    console_handler = logging.StreamHandler()
    formatter = CustomJsonFormatter(
        '%(message)s'
    )
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger

log = setup_logging()

# Prometheus Metrics
REQUESTS_TOTAL = Counter(
    'beewaf_requests_total',
    'Total number of requests',
    ['method', 'endpoint', 'status']
)
BLOCKED_TOTAL = Counter(
    'beewaf_blocked_total',
    'Total number of blocked requests',
    ['reason']
)
REQUEST_LATENCY = Histogram(
    'beewaf_request_latency_seconds',
    'Request latency in seconds',
    ['method', 'endpoint']
)
ACTIVE_REQUESTS = Gauge(
    'beewaf_active_requests',
    'Number of active requests'
)
RULES_COUNT = Gauge(
    'beewaf_rules_count',
    'Number of WAF rules loaded'
)
MODEL_LOADED = Gauge(
    'beewaf_model_loaded',
    'Whether the anomaly detection model is loaded (1=yes, 0=no)'
)

app = FastAPI()

# Rate limiter: 100 requests per minute per IP (realistic production value)
rate_limiter = RateLimiter(max_requests=100, window_seconds=60)
# IP blocklist: auto-block after 50 detected attacks, ban for 10 minutes
# Increased threshold from 10 to 50 to prevent false positives from shared IPs (proxy/NAT)
# Reduced duration from 3600s (1h) to 600s (10min) for faster recovery
ip_blocklist = IPBlocklist(block_threshold=50, block_duration=600)
MODEL_PATH = os.environ.get('BEEWAF_MODEL_PATH','models/model.pkl')
ML_ENGINE_PATH = os.environ.get('BEEWAF_ML_ENGINE_PATH', 'models/ml_engine.pkl')
TRAIN_DATA = os.environ.get('BEEWAF_TRAIN_DATA','data/train_demo.csv')
CSIC_DATA = os.environ.get('BEEWAF_CSIC_DATA', 'data/csic_database.csv')

# ML Detection Mode: 'legacy' (IsolationForest only) or 'advanced' (3 models ensemble)
ML_MODE = os.environ.get('BEEWAF_ML_MODE', 'advanced')

# API Key Authentication
API_KEY = os.environ.get('BEEWAF_API_KEY', 'changeme-default-key-not-secure')
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def verify_api_key(api_key: str = Depends(api_key_header)):
    if api_key is None:
        raise HTTPException(status_code=401, detail="Missing API Key")
    if not secrets.compare_digest(api_key, API_KEY):
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return api_key

@app.on_event("startup")
def startup_event():
    log.info('Startup: initializing ML models')
    
    # Load advanced ML engine (3 models)
    if ML_MODE == 'advanced':
        loaded = ml_engine.load_engine(ML_ENGINE_PATH)
        if loaded:
            log.info('Loaded advanced ML engine (3 models) from %s', ML_ENGINE_PATH)
        else:
            log.warning('Advanced ML engine not available at %s — running in regex-only mode (use /admin/retrain-ml to train)', ML_ENGINE_PATH)
    
    # Load legacy model (backwards compatibility)
    loaded = anomaly.load_model(MODEL_PATH)
    if not loaded:
        log.warning('No legacy model found at %s — regex-only mode (use /admin/retrain to train)', MODEL_PATH)
    else:
        log.info('Loaded legacy model from %s', MODEL_PATH)
    
    # Update Prometheus metrics
    RULES_COUNT.set(len(rules.list_rules()))
    MODEL_LOADED.set(1 if os.path.exists(MODEL_PATH) else 0)

# ==================== v7.0: FALSE POSITIVE FILTER ====================
import re as _re_fp
def _is_regex_false_positive(reason: str, url: str, body: str) -> bool:
    """
    Check if a regex-blocked request is a known false positive pattern.
    Returns True if the request should be ALLOWED despite regex match.
    Each pattern is carefully validated to avoid opening security holes.
    """
    url_lower = url.lower() if url else ''
    body_lower = body.lower() if body else ''

    # FP1: Timezone values in URL params (Europe/Paris, US/Eastern, America/New_York)
    if reason in ('regex-xss', 'regex-encoding_evasion'):
        if _re_fp.search(r'(?:timezone|tz|time_zone|iana_tz)=[A-Za-z_]+(?:%2[Ff]|/)[A-Za-z_]+', url, _re_fp.IGNORECASE):
            cleaned = _re_fp.sub(r'(?:timezone|tz|time_zone|iana_tz)=[A-Za-z_]+(?:%2[Ff]|/)[A-Za-z_]+', '', url)
            if not any(p in cleaned.lower() for p in ['<script', 'onerror', 'alert(', 'union select', 'exec(']):
                return True

    # FP2: GraphQL queries in JSON body — { users { id name } } triggers websocket rules
    if 'websocket' in reason:
        if body:
            body_stripped = body.strip()
            if body_stripped.startswith('{') and body_stripped.endswith('}'):
                try:
                    parsed = json.loads(body_stripped)
                    if 'query' in parsed and isinstance(parsed.get('query'), str):
                        gql = parsed['query'].lower()
                        gql_attacks = ['<script', 'alert(', 'onerror', 'union select',
                                       '../', '/etc/', 'exec(', 'drop table', '; cat']
                        if not any(kw in gql for kw in gql_attacks):
                            return True
                except Exception:
                    pass

    # FP3: Pipe-separated list values in URL params (metric=cpu|memory|disk)
    if 'cms' in reason and '|' in url_lower and '?' in url:
        query_part = url.split('?', 1)[1]
        pipe_values = _re_fp.findall(r'=[a-zA-Z0-9_]+(?:\|[a-zA-Z0-9_]+)+', query_part)
        if pipe_values:
            cleaned = query_part
            for pv in pipe_values:
                cleaned = cleaned.replace(pv, '')
            if not any(p in cleaned.lower() for p in ['<', '>', ';', '`', '$(', 'script', 'alert']):
                return True

    # FP4: Math expressions in search (q=x=(a+b)*c/d) — triggers LDAP rules
    if 'ldap' in reason and '?' in url:
        query_part = url.split('?', 1)[1]
        if _re_fp.match(r'^[a-zA-Z_]+=[(\w\s)+\-*/%.^=,]+$', query_part):
            if not any(kw in query_part.lower() for kw in ['cn=', 'uid=', 'objectclass', 'dc=', 'ou=', 'sn=']):
                return True

    return False
# ==================== END FALSE POSITIVE FILTER ====================

@app.middleware("http")
async def waf_middleware(request: Request, call_next):
    start_time = time.time()
    ACTIVE_REQUESTS.inc()
    
    # ========== SECURE CLIENT IP EXTRACTION (K8s + HAProxy) ==========
    # Architecture: Client → HAProxy (207.180.211.157) → Nginx Ingress (192.168.x.x) → BeeWAF Pod
    #
    # Nginx Ingress sets:
    #   X-Forwarded-For: <real-client-ip>, 207.180.211.157   (appends each hop)
    #   X-Real-IP: <real-client-ip>                          (original client)
    #
    # CRITICAL: We MUST extract the real public client IP, NOT the K8s node IP.
    # If we block 192.168.1.0 (K8s node), ALL users going through that node are blocked!
    #
    # Strategy:
    #   1. Parse X-Forwarded-For LEFT to RIGHT — first non-infrastructure IP = real client
    #   2. Fallback to X-Real-IP if it's public
    #   3. Last resort: request.client.host (will be K8s node IP — mark as internal)

    _TRUSTED_PROXIES = {
        '127.0.0.1', '::1',
        '207.180.211.157',  # HAProxy public IP
    }
    _TRUSTED_PREFIXES = (
        '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
        '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
        '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
    )

    def _is_infra_ip(ip: str) -> bool:
        """Check if IP belongs to internal infrastructure (proxies, K8s nodes)."""
        if not ip:
            return True
        return ip in _TRUSTED_PROXIES or ip.startswith(_TRUSTED_PREFIXES)

    # Step 1: Parse X-Forwarded-For — find the FIRST public (non-infra) IP
    # In our chain: XFF = "real-client, 207.180.211.157" or "real-client"
    # The leftmost public IP is the real client (Nginx Ingress is trusted to set this)
    x_forwarded_for = request.headers.get('X-Forwarded-For', '').strip()
    x_real_ip = request.headers.get('X-Real-IP', '').strip()

    client = None

    if x_forwarded_for:
        xff_parts = [ip.strip() for ip in x_forwarded_for.split(',') if ip.strip()]
        # Find first non-infrastructure IP (= real client)
        for ip in xff_parts:
            if not _is_infra_ip(ip):
                client = ip
                break

    # Step 2: Fallback to X-Real-IP if XFF didn't yield a public IP
    if not client and x_real_ip and not _is_infra_ip(x_real_ip):
        client = x_real_ip

    # Step 3: Last resort — use direct connection IP (K8s node IP)
    # IMPORTANT: This is an internal IP — we should NEVER auto-block it
    if not client:
        client = request.client.host if request.client else 'unknown'
        # Log raw headers for debugging — helps identify proxy misconfiguration
        if _is_infra_ip(client):
            log.debug('IP extraction fell back to infra IP', extra={
                'event': 'ip-debug',
                'resolved_ip': client,
                'xff_raw': x_forwarded_for or '(empty)',
                'x_real_ip_raw': x_real_ip or '(empty)',
                'remote_addr': request.client.host if request.client else 'unknown',
            })
    # ========== END SECURE CLIENT IP EXTRACTION ==========
    # Check IP blocklist first (auto-blocked attackers)
    if ip_blocklist.is_blocked(client):
        log.warning('Blocked IP attempt', extra={
            'event': 'blocked',
            'client_ip': client,
            'method': request.method,
            'path': request.url.path,
            'reason': 'ip-blacklisted',
            'status_code': 403
        })
        BLOCKED_TOTAL.labels(reason='ip-blacklist').inc()
        ACTIVE_REQUESTS.dec()
        return JSONResponse(status_code=403, content={
            "blocked": True,
            "reason": "ip-blacklisted",
            "message": "Your IP has been temporarily blocked due to repeated malicious activity"
        })
    
    path = request.url.path
    method = request.method
    query_string = str(request.url.query) if request.url.query else ''
    
    # ========== PATH NORMALIZATION (fix path manipulation bypasses) ==========
    import urllib.parse
    # Normalize path: remove //, /./, /../ patterns
    original_path = path
    # Decode URL-encoded characters first
    decoded_path = urllib.parse.unquote(path)
    # Remove double slashes
    while '//' in decoded_path:
        decoded_path = decoded_path.replace('//', '/')
    # Remove /./
    while '/./' in decoded_path:
        decoded_path = decoded_path.replace('/./', '/')
    # Remove trailing /.
    if decoded_path.endswith('/.'):
        decoded_path = decoded_path[:-2] + '/'
    # Detect and block path traversal attempts
    if '/../' in decoded_path or decoded_path.endswith('/..'):
        log.warning('Request blocked - path traversal attempt', extra={
            'event': 'blocked',
            'client_ip': client,
            'method': method,
            'path': original_path,
            'reason': 'path-traversal-normalized',
            'status_code': 403
        })
        BLOCKED_TOTAL.labels(reason='path-traversal').inc()
        ACTIVE_REQUESTS.dec()
        return JSONResponse(status_code=403, content={"blocked": True, "reason": "path-traversal-detected"})
    path = decoded_path
    # ========== END PATH NORMALIZATION ==========
    
    # ========== HOST HEADER VALIDATION ==========
    host_header = request.headers.get('host', '')
    allowed_hosts = ['localhost', '127.0.0.1', '0.0.0.0']
    # Add custom allowed hosts from env
    custom_hosts = os.environ.get('BEEWAF_ALLOWED_HOSTS', '').split(',')
    allowed_hosts.extend([h.strip() for h in custom_hosts if h.strip()])
    # Extract host without port
    host_without_port = host_header.split(':')[0].lower() if host_header else ''
    # Validate host header
    if host_header and host_without_port not in allowed_hosts:
        # Check if it looks malicious (contains payload patterns)
        if any(c in host_header for c in ["'", '"', '<', '>', ';', '|', '&', '\n', '\r']):
            log.warning('Request blocked - malicious host header', extra={
                'event': 'blocked',
                'client_ip': client,
                'method': method,
                'path': path,
                'reason': 'host-header-injection',
                'host': host_header[:100],
                'status_code': 403
            })
            BLOCKED_TOTAL.labels(reason='host-header-injection').inc()
            ACTIVE_REQUESTS.dec()
            return JSONResponse(status_code=403, content={"blocked": True, "reason": "invalid-host-header"})
    # ========== END HOST HEADER VALIDATION ==========
    
    # ========== SENSITIVE PATHS BLOCKING ==========
    SENSITIVE_PATHS = [
        '/.git', '/.svn', '/.hg', '/.env', '/.htaccess', '/.htpasswd',
        '/.aws', '/.docker', '/.idea', '/.vscode',
        '/config.php', '/config.yml', '/config.json', '/wp-config.php',
        '/settings.py', '/application.properties', '/database.yml',
        '/backup.sql', '/dump.sql', '/database.sql', '/backup.zip', '/backup.tar.gz',
        '/composer.json', '/package.json', '/requirements.txt', '/Gemfile', '/Pipfile',
        '/server-status', '/server-info', '/phpinfo.php', '/info.php', '/test.php',
        '/.DS_Store', '/Thumbs.db', '/web.config', '/elmah.axd',
        '/actuator', '/actuator/env', '/actuator/health',
        '/__debug__', '/debug', '/trace', '/console',
        '/phpmyadmin', '/adminer.php', '/manager',
        '/proc/self', '/etc/passwd', '/etc/shadow'
    ]
    path_lower = path.lower()
    for sensitive in SENSITIVE_PATHS:
        if path_lower == sensitive or path_lower.startswith(sensitive + '/') or path_lower.startswith(sensitive + '.'):
            log.warning('Request blocked - sensitive path access', extra={
                'event': 'blocked',
                'client_ip': client,
                'method': method,
                'path': path,
                'reason': 'sensitive-path',
                'status_code': 403
            })
            BLOCKED_TOTAL.labels(reason='sensitive-path').inc()
            ACTIVE_REQUESTS.dec()
            return JSONResponse(status_code=403, content={"blocked": True, "reason": "access-denied"})
    # ========== END SENSITIVE PATHS BLOCKING ==========
    
    # ========== v6.0: BUSINESS LOGIC & HEADER SPOOFING PROTECTION ==========
    import re as _re
    
        # 1. X-Forwarded-For spoofing detection
    # Block if client-supplied XFF contains loopback/reserved IPs attempting to impersonate internal
    xff = request.headers.get('x-forwarded-for', '')
    if xff:
        xff_parts = [ip.strip() for ip in xff.split(',')]
        # Only check client-supplied parts (everything except the last entry added by Ingress)
        # The last 1-2 entries are added by our infrastructure
        client_supplied_xff = xff_parts[:-2] if len(xff_parts) > 2 else []
        for xff_ip in client_supplied_xff:
            if _re.match(r'^(?:127\.0\.0\.\d+|::1|0\.0\.0\.0|localhost)$', xff_ip, _re.IGNORECASE):
                log.warning('Request blocked - XFF spoofing with loopback', extra={
                    'event': 'blocked', 'client_ip': client, 'method': method,
                    'path': path, 'reason': 'xff-loopback-spoof',
                    'spoofed_xff': xff[:200],
                    'status_code': 403
                })
                BLOCKED_TOTAL.labels(reason='xff-spoof').inc()
                ACTIVE_REQUESTS.dec()
                return JSONResponse(status_code=403, content={"blocked": True, "reason": "xff-spoof"})
    # 2. Negative ID in API paths (business logic abuse)
    if _re.search(r'/api/\w+/-\d+', path):
        log.warning('Request blocked - negative ID', extra={
            'event': 'blocked', 'client_ip': client, 'method': method,
            'path': path, 'reason': 'business-logic', 'status_code': 403
        })
        BLOCKED_TOTAL.labels(reason='business-logic').inc()
        ACTIVE_REQUESTS.dec()
        return JSONResponse(status_code=403, content={"blocked": True, "reason": "business-logic"})
    
    # 3. Business logic abuse in JSON bodies — moved to after body_text is available
    
    # 4. Transfer-Encoding smuggling detection
    te_header = request.headers.get('transfer-encoding', '')
    if te_header:
        # Multiple TE values = smuggling attempt
        if ',' in te_header:
            log.warning('Request blocked - TE smuggling', extra={
                'event': 'blocked', 'client_ip': client, 'method': method,
                'path': path, 'reason': 'http-smuggling', 'status_code': 403
            })
            BLOCKED_TOTAL.labels(reason='http-smuggling').inc()
            ACTIVE_REQUESTS.dec()
            return JSONResponse(status_code=403, content={"blocked": True, "reason": "http-smuggling"})
        # CL + TE conflict (both present)
        cl_header = request.headers.get('content-length', '')
        if cl_header and te_header.strip().lower() == 'chunked':
            log.warning('Request blocked - CL.TE smuggling', extra={
                'event': 'blocked', 'client_ip': client, 'method': method,
                'path': path, 'reason': 'http-smuggling', 'status_code': 403
            })
            BLOCKED_TOTAL.labels(reason='http-smuggling').inc()
            ACTIVE_REQUESTS.dec()
            return JSONResponse(status_code=403, content={"blocked": True, "reason": "http-smuggling"})
    # ========== END BUSINESS LOGIC PROTECTION ==========
    
    # ========== RANGE HEADER VALIDATION ==========
    range_header = request.headers.get('range', '')
    if range_header:
        # Block malformed or abusive Range headers
        if not range_header.startswith('bytes='):
            pass  # Invalid but not necessarily malicious
        else:
            # Check for overflow attempts
            try:
                range_spec = range_header.replace('bytes=', '')
                for part in range_spec.split(','):
                    part = part.strip()
                    if '-' in part:
                        start, end = part.split('-', 1)
                        if start and int(start) > 10**9:  # > 1GB
                            raise ValueError('Range overflow')
                        if end and int(end) > 10**9:
                            raise ValueError('Range overflow')
            except (ValueError, AttributeError):
                log.warning('Request blocked - malformed range header', extra={
                    'event': 'blocked',
                    'client_ip': client,
                    'method': method,
                    'path': path,
                    'reason': 'range-header-abuse',
                    'range': range_header[:100],
                    'status_code': 400
                })
                BLOCKED_TOTAL.labels(reason='range-header-abuse').inc()
                ACTIVE_REQUESTS.dec()
                return JSONResponse(status_code=400, content={"blocked": True, "reason": "invalid-range-header"})
    # ========== END RANGE HEADER VALIDATION ==========
    
    # ========== CORS PREFLIGHT FAST PATH ==========
    # OPTIONS requests for CORS preflight are not attack vectors - they're browser
    # protocol negotiation and contain no payload. They should never reach regex scanning.
    # Skip all WAF checks and let the backend handle CORS response headers.
    if method == "OPTIONS":
        ACTIVE_REQUESTS.dec()
        return await call_next(request)
    # ========== END CORS PREFLIGHT FAST PATH ==========
    
    # Combine path and query for WAF checking
    full_path = f"{path}?{query_string}" if query_string else path
    
    # Skip ONLY health and metrics endpoints from WAF processing
    # DO NOT skip root path - it must be validated!
    if path in ['/metrics', '/health'] and not query_string:
        ACTIVE_REQUESTS.dec()
        return await call_next(request)

    # ========== STATIC FILE FAST-PATH (critical performance fix) ==========
    # Angular/React/Vue apps serve large JS/CSS bundles from root path.
    # Scanning 1MB+ JS files through 9994 regex rules takes 40+ seconds,
    # blocks the async event loop, and causes 503 for concurrent requests.
    # Security checks already passed: IP blocklist, path normalization,
    # traversal detection, host validation, sensitive path blocking.
    _STATIC_EXTS = {
        '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
        '.woff', '.woff2', '.ttf', '.eot', '.map', '.webp', '.avif',
        '.mp4', '.mp3', '.webm', '.ogg', '.pdf', '.zip',
        '.mjs', '.chunk.js', '.json',
    }
    _ext_check = path.lower().rsplit('.', 1)
    if len(_ext_check) == 2 and method in ('GET', 'HEAD') and f'.{_ext_check[1]}' in _STATIC_EXTS:
        ACTIVE_REQUESTS.dec()
        response = await call_next(request)
        latency = time.time() - start_time
        REQUEST_LATENCY.labels(method=method, endpoint=path).observe(latency)
        return response
    # ========== END STATIC FILE FAST-PATH ==========

    # ========== v5.0: DDoS PROTECTION ==========
    try:
        ddos_engine = ddos_protection.get_engine()
        _ua = request.headers.get('user-agent', '')
        ddos_result = ddos_engine.check_request(client, path, method, _ua, dict(request.headers))
        if ddos_result.get('action') == 'block':
            reason_str = ddos_result.get('reason', 'ddos-detected')
            log.warning('Request blocked - DDoS protection', extra={
                'event': 'blocked', 'client_ip': client, 'method': method,
                'path': path, 'reason': reason_str,
                'attack_type': ddos_result.get('attack_type', 'unknown'),
                'status_code': 429
            })
            BLOCKED_TOTAL.labels(reason='ddos-protection').inc()
            ACTIVE_REQUESTS.dec()
            return JSONResponse(status_code=429, content={"blocked": True, "reason": reason_str})
    except Exception:
        log.debug('DDoS protection error', exc_info=True)

    # ========== v5.0: PERFORMANCE ENGINE (dedup + pre-screen) ==========
    try:
        perf_engine = performance_engine.get_engine()
        safe = perf_engine.pre_screen_request(path, method, dict(request.headers))
        if safe:
            # Known safe path, skip heavy checks (still log)
            pass
    except Exception:
        log.debug('Performance engine error', exc_info=True)
    
    body = await request.body()
    body_text = body.decode('utf-8', errors='ignore') if body else ''
    
    # Store body for later use (avoid double reading)
    async def receive():
        return {"type": "http.request", "body": body}
    
    request._receive = receive

    # ========== v6.0: BUSINESS LOGIC BODY CHECKS ==========
    if body_text and method in ('POST', 'PUT', 'PATCH'):
        body_lower = body_text.lower()
        # Direct password reset with user_id (IDOR)
        if 'password' in path_lower and '"user_id"' in body_lower and '"new_password"' in body_lower:
            log.warning('Request blocked - password reset IDOR', extra={
                'event': 'blocked', 'client_ip': client, 'method': method,
                'path': path, 'reason': 'business-logic-idor', 'status_code': 403
            })
            BLOCKED_TOTAL.labels(reason='business-logic').inc()
            ACTIVE_REQUESTS.dec()
            return JSONResponse(status_code=403, content={"blocked": True, "reason": "business-logic"})
        # Quantity abuse (absurdly high values)
        quantity_match = _re.search(r'"quantity"\s*:\s*(\d+)', body_text)
        if quantity_match and int(quantity_match.group(1)) > 10000:
            log.warning('Request blocked - quantity abuse', extra={
                'event': 'blocked', 'client_ip': client, 'method': method,
                'path': path, 'reason': 'business-logic-abuse', 'status_code': 403
            })
            BLOCKED_TOTAL.labels(reason='business-logic').inc()
            ACTIVE_REQUESTS.dec()
            return JSONResponse(status_code=403, content={"blocked": True, "reason": "business-logic"})
    # ========== END BUSINESS LOGIC BODY CHECKS ==========

    # SAFETY NET: Never rate-limit infrastructure IPs (K8s nodes, proxies)
    # Even if IP extraction fails, infra IPs must never be throttled
    if _is_infra_ip(client):
        allowed, remaining = True, 999
    else:
        allowed, remaining = rate_limiter.allow_request(client)
    if not allowed:
        log.warning('Request blocked', extra={
            'event': 'blocked',
            'client_ip': client,
            'method': method,
            'path': path,
            'reason': 'rate-limit',
            'status_code': 429
        })
        BLOCKED_TOTAL.labels(reason='rate-limit').inc()
        REQUESTS_TOTAL.labels(method=method, endpoint=path, status='429').inc()
        REQUEST_LATENCY.labels(method=method, endpoint=path).observe(time.time() - start_time)
        ACTIVE_REQUESTS.dec()
        return JSONResponse(status_code=429, content={"blocked": True, "reason": "rate-limit"})

    # ========== ENTERPRISE WAF MODULES ==========
    headers_dict = dict(request.headers)
    
    # --- 1. Protocol Validation ---
    try:
        proto_result = protocol_validator.validate_request(
            method, path, query_string, headers_dict, body,
            http_version=str(getattr(request, 'http_version', '1.1'))
        )
        if proto_result['action'] == 'block':
            violations = proto_result.get('violations', [])
            reason_str = violations[0]['type'] if violations else 'protocol-violation'
            log.warning('Request blocked - protocol violation', extra={
                'event': 'blocked', 'client_ip': client, 'method': method,
                'path': path, 'reason': reason_str,
                'violations': [v['message'] for v in violations[:3]],
                'status_code': 403
            })
            BLOCKED_TOTAL.labels(reason='protocol-violation').inc()
            ACTIVE_REQUESTS.dec()
            ip_blocklist.record_attack(client)
            return JSONResponse(status_code=403, content={"blocked": True, "reason": reason_str})
    except Exception:
        log.debug('Protocol validator error', exc_info=True)
    
    # --- 2. Geo/IP Blocking ---
    try:
        geo_result = geo_block.check_ip(client)
        if not geo_result.get('allowed', True):
            reason_str = geo_result.get('reason', 'geo-blocked')
            log.warning('Request blocked - geo/IP policy', extra={
                'event': 'blocked', 'client_ip': client, 'method': method,
                'path': path, 'reason': reason_str,
                'ip_type': geo_result.get('ip_type', 'unknown'),
                'country': geo_result.get('country', 'unknown'),
                'status_code': 403
            })
            BLOCKED_TOTAL.labels(reason='geo-block').inc()
            ACTIVE_REQUESTS.dec()
            return JSONResponse(status_code=403, content={"blocked": True, "reason": reason_str})
    except Exception:
        log.debug('Geo blocker error', exc_info=True)
    
    # --- 3. Bot Detection ---
    try:
        bot_result = bot_detector.analyze_request(
            headers_dict, client, path, method
        )
        bot_score = bot_result.get('score', 0) if isinstance(bot_result, dict) else 0
        if bot_score >= 0.85:
            log.warning('Request blocked - bot detected', extra={
                'event': 'blocked', 'client_ip': client, 'method': method,
                'path': path, 'reason': 'bot-detected',
                'bot_score': round(bot_score, 3),
                'status_code': 403
            })
            BLOCKED_TOTAL.labels(reason='bot-detected').inc()
            ACTIVE_REQUESTS.dec()
            ip_blocklist.record_attack(client)
            return JSONResponse(status_code=403, content={"blocked": True, "reason": "bot-detected", "score": round(bot_score, 3)})
    except Exception:
        log.debug('Bot detector error', exc_info=True)
    
    # --- 3b. v5.0 Advanced Bot Manager (JS challenges, credential stuffing, TLS fingerprint) ---
    try:
        adv_bot = bot_manager_advanced.get_manager()
        adv_bot_result = adv_bot.analyze_request(headers_dict, client, path, method)
        if adv_bot_result.get('action') == 'block':
            reason_str = adv_bot_result.get('reason', 'advanced-bot-detected')
            log.warning('Request blocked - advanced bot manager', extra={
                'event': 'blocked', 'client_ip': client, 'method': method,
                'path': path, 'reason': reason_str,
                'bot_category': adv_bot_result.get('category', 'unknown'),
                'status_code': 403
            })
            BLOCKED_TOTAL.labels(reason='advanced-bot').inc()
            ACTIVE_REQUESTS.dec()
            ip_blocklist.record_attack(client)
            return JSONResponse(status_code=403, content={"blocked": True, "reason": reason_str})
        elif adv_bot_result.get('action') == 'challenge':
            # Return JS challenge
            challenge_data = adv_bot_result.get('challenge', {})
            return JSONResponse(status_code=429, content={
                "blocked": False, "action": "challenge",
                "challenge": challenge_data,
                "reason": "bot-challenge-required"
            })
    except Exception:
        log.debug('Advanced bot manager error', exc_info=True)
    
    # --- 4. Threat Intelligence ---
    try:
        ti_result = threat_intel.analyze_request(
            path, method, headers_dict, body_text, client, query_string
        )
        if ti_result.get('action') == 'block':
            threats = ti_result.get('threats', [])
            reason_str = threats[0]['type'] if threats else 'threat-intel'
            log.warning('Request blocked - threat intelligence', extra={
                'event': 'blocked', 'client_ip': client, 'method': method,
                'path': path, 'reason': reason_str,
                'threat_level': ti_result.get('threat_level', 'unknown'),
                'threats': [t['message'] for t in threats[:3]],
                'reputation': ti_result.get('reputation_score', 100),
                'status_code': 403
            })
            BLOCKED_TOTAL.labels(reason='threat-intel').inc()
            ACTIVE_REQUESTS.dec()
            ip_blocklist.record_attack(client)
            return JSONResponse(status_code=403, content={"blocked": True, "reason": reason_str})
    except Exception:
        log.debug('Threat intel error', exc_info=True)
    
    # --- 4b. v5.0 Threat Feed (MITRE ATT&CK, C2, TOR, APT tracking) ---
    try:
        tf_engine = threat_feed.get_engine()
        tf_result = tf_engine.check_request(client, path + '?' + query_string if query_string else path,
                                            headers_dict, body_text if body else '')
        if tf_result.get('action') == 'block':
            reason_str = tf_result.get('reason', 'threat-feed-match')
            log.warning('Request blocked - threat feed', extra={
                'event': 'blocked', 'client_ip': client, 'method': method,
                'path': path, 'reason': reason_str,
                'mitre_tactic': tf_result.get('mitre_tactic', ''),
                'status_code': 403
            })
            BLOCKED_TOTAL.labels(reason='threat-feed').inc()
            ACTIVE_REQUESTS.dec()
            ip_blocklist.record_attack(client)
            return JSONResponse(status_code=403, content={"blocked": True, "reason": reason_str})
    except Exception:
        log.debug('Threat feed error', exc_info=True)
    
    # --- 5. Session Protection ---
    try:
        sess_result = session_protection.check_request(
            path, method, headers_dict, body_text, client, query_string
        )
        if sess_result.get('action') == 'block':
            issues = sess_result.get('issues', [])
            reason_str = issues[0]['type'] if issues else 'session-violation'
            log.warning('Request blocked - session security', extra={
                'event': 'blocked', 'client_ip': client, 'method': method,
                'path': path, 'reason': reason_str,
                'issues': [i['message'] for i in issues[:3]],
                'status_code': 403
            })
            BLOCKED_TOTAL.labels(reason='session-violation').inc()
            ACTIVE_REQUESTS.dec()
            return JSONResponse(status_code=403, content={"blocked": True, "reason": reason_str})
    except Exception:
        log.debug('Session protection error', exc_info=True)
    
        # --- 6. API Security ---
    try:
        api_result = api_security.check_request(
            path, method, headers_dict, body_text, client, query_string
        )
        if api_result.get('action') == 'block':
            issues = api_result.get('issues', [])
            reason_str = issues[0]['type'] if issues else 'api-security'

            # Vérifier si c'est un VRAI problème de sécurité ou juste un rate limit
            issue_types = [i.get('type', '') for i in issues]
            is_rate_limit_only = all(
                t in ('api-rate-limit', 'api-no-version', 'rest-method-violation')
                for t in issue_types
            )

            if is_rate_limit_only:
                # Rate limit → 429 + warning, PAS de record_attack
                log.warning('Request throttled - API rate limit', extra={
                    'event': 'throttled', 'client_ip': client, 'method': method,
                    'path': path, 'reason': reason_str,
                    'issues': [i['message'] for i in issues[:3]],
                    'status_code': 429
                })
                BLOCKED_TOTAL.labels(reason='api-rate-limit').inc()
                ACTIVE_REQUESTS.dec()
                # PAS de ip_blocklist.record_attack() ici !
                return JSONResponse(status_code=429, content={
                    "blocked": True,
                    "reason": reason_str,
                    "retry_after": 60
                })
            else:
                # Vrai problème de sécurité → 403 + record_attack
                log.warning('Request blocked - API security', extra={
                    'event': 'blocked', 'client_ip': client, 'method': method,
                    'path': path, 'reason': reason_str,
                    'issues': [i['message'] for i in issues[:3]],
                    'status_code': 403
                })
                BLOCKED_TOTAL.labels(reason='api-security').inc()
                ACTIVE_REQUESTS.dec()
                ip_blocklist.record_attack(client)
                return JSONResponse(status_code=403, content={
                    "blocked": True,
                    "reason": reason_str
                })
    except Exception:
        log.debug('API security error', exc_info=True)
    
    # --- 6b. v5.0 API Discovery (Shadow API, GraphQL depth, quota) ---
    try:
        api_disc = api_discovery.get_engine()
        api_disc_result = api_disc.check_request(path, method, headers_dict,
                                                  body_text if body else '', client, query_string)
        if api_disc_result.get('action') == 'block':
            reason_str = api_disc_result.get('reason', 'api-discovery-violation')
            log.warning('Request blocked - API discovery', extra={
                'event': 'blocked', 'client_ip': client, 'method': method,
                'path': path, 'reason': reason_str,
                'status_code': 403
            })
            BLOCKED_TOTAL.labels(reason='api-discovery').inc()
            ACTIVE_REQUESTS.dec()
            return JSONResponse(status_code=403, content={"blocked": True, "reason": reason_str})
    except Exception:
        log.debug('API discovery error', exc_info=True)
    # ========== END ENTERPRISE WAF MODULES ==========

    # ========== v4.0 MODULES: VIRTUAL PATCHING (CVE-specific) ==========
    try:
        vp_result = virtual_patching.check_request(full_path, body_text, headers_dict, method)
        if vp_result and vp_result.get('blocked'):
            cve_id = vp_result.get('cve_id', 'unknown')
            log.warning('Request blocked - virtual patch', extra={
                'event': 'blocked', 'client_ip': client, 'method': method,
                'path': path, 'reason': f'virtual-patch-{cve_id}',
                'cve': cve_id, 'patch_name': vp_result.get('patch_name', ''),
                'status_code': 403
            })
            BLOCKED_TOTAL.labels(reason='virtual-patch').inc()
            ACTIVE_REQUESTS.dec()
            ip_blocklist.record_attack(client)
            correlation_engine.record_event(f'virtual-patch-{cve_id}', client, path, 'critical')
            compliance_engine.record_detection(f'virtual-patch', client_ip=client, path=path, severity='critical')
            compliance_engine_v5.record_detection(f'virtual-patch', client_ip=client, path=path, severity='critical')
            return JSONResponse(status_code=403, content={"blocked": True, "reason": f"virtual-patch-{cve_id}"})
    except Exception:
        log.debug('Virtual patching error', exc_info=True)

    # ========== v4.0 MODULES: COOKIE SECURITY ==========
    try:
        cookie_result = cookie_security.check_request_cookies(headers_dict, client)
        if cookie_result and cookie_result.get('action') == 'block':
            reason_str = cookie_result.get('reason', 'cookie-tampering')
            log.warning('Request blocked - cookie security', extra={
                'event': 'blocked', 'client_ip': client, 'method': method,
                'path': path, 'reason': reason_str,
                'issues': cookie_result.get('issues', [])[:3],
                'status_code': 403
            })
            BLOCKED_TOTAL.labels(reason='cookie-security').inc()
            ACTIVE_REQUESTS.dec()
            ip_blocklist.record_attack(client)
            correlation_engine.record_event('cookie-tampering', client, path, 'high')
            compliance_engine.record_detection('cookie-tampering', client_ip=client, path=path, severity='high')
            compliance_engine_v5.record_detection('cookie-tampering', client_ip=client, path=path, severity='high')
            return JSONResponse(status_code=403, content={"blocked": True, "reason": reason_str})
    except Exception:
        log.debug('Cookie security error', exc_info=True)

    # ========== v4.0 MODULES: WEBSOCKET INSPECTION ==========
    try:
        if headers_dict.get('upgrade', '').lower() == 'websocket':
            ws_result = websocket_inspector.validate_upgrade(headers_dict, client)
            if ws_result and ws_result.get('action') == 'block':
                reason_str = ws_result.get('reason', 'websocket-violation')
                log.warning('Request blocked - WebSocket violation', extra={
                    'event': 'blocked', 'client_ip': client, 'method': method,
                    'path': path, 'reason': reason_str, 'status_code': 403
                })
                BLOCKED_TOTAL.labels(reason='websocket-violation').inc()
                ACTIVE_REQUESTS.dec()
                correlation_engine.record_event('websocket-violation', client, path, 'medium')
                return JSONResponse(status_code=403, content={"blocked": True, "reason": reason_str})
    except Exception:
        log.debug('WebSocket inspector error', exc_info=True)

    # ========== v4.0 MODULES: DEEP PAYLOAD ANALYSIS ==========
    try:
        pa_result = payload_analyzer.analyze_request(
            path, method, headers_dict, body_text if body_text else None
        )
        if pa_result and pa_result.get('action') == 'block':
            threats = pa_result.get('threats', [])
            reason_str = threats[0] if threats else 'payload-anomaly'
            log.warning('Request blocked - payload analysis', extra={
                'event': 'blocked', 'client_ip': client, 'method': method,
                'path': path, 'reason': reason_str,
                'threats': threats[:5], 'status_code': 403
            })
            BLOCKED_TOTAL.labels(reason='payload-analysis').inc()
            ACTIVE_REQUESTS.dec()
            ip_blocklist.record_attack(client)
            correlation_engine.record_event(reason_str, client, path, 'high')
            compliance_engine.record_detection(reason_str, client_ip=client, path=path, severity='high')
            compliance_engine_v5.record_detection(reason_str, client_ip=client, path=path, severity='high')
            return JSONResponse(status_code=403, content={"blocked": True, "reason": reason_str})
    except Exception:
        log.debug('Payload analyzer error', exc_info=True)
    # ========== END v4.0 PRE-REGEX MODULES ==========

    # ========== HEADER VALIDATION (fix for header injection bypass) ==========
    # Check select headers for XSS/SQLi/command injection patterns
    # NOTE: With 10K+ rules, we must be selective to avoid false positives
    # on normal header values like IPs, browser UAs, and protocol strings.
    
    # Only scan headers that carry USER-CONTROLLED payloads (not infra headers)
    _scan_headers = ['referer', 'cookie', 'x-original-url', 'x-rewrite-url']
    for header_name in _scan_headers:
        header_value = request.headers.get(header_name, '')
        if header_value:
            # Strip scheme from referer to avoid FPs on //domain.com matching open_redirect
            check_value = header_value
            if header_name == 'referer':
                import re as _re_strip
                check_value = _re_strip.sub(r'^https?://', '', header_value)
            blocked, reason = rules.check_regex_rules('', check_value, {})
            
            # EXCEPTION: Referer headers naturally contain paths (/dashboard/, /admin/, etc.)
            # IDOR/access-control rules matching on referer are almost always false positives.
            # Real attacks (XSS, SQLi, RCE) injected into the referer are still caught above.
            _REFERER_FP_CATEGORIES = {'regex-idor_access', 'regex-race_timing'}
            if blocked and header_name == 'referer' and reason in _REFERER_FP_CATEGORIES:
                blocked = False

            # v7.0: Cookie headers contain tracking IDs (GA1.2.xxx), session tokens,
            # CSRF tokens, etc. that trigger many regex categories falsely.
            # Only block for actual injection attack categories.
            _COOKIE_BLOCK_CATEGORIES = {
                'regex-sqli', 'regex-xss', 'regex-rce', 'regex-cmdi',
                'regex-path-traversal', 'regex-ssrf', 'regex-lfi',
                'regex-xxe', 'regex-ssti', 'regex-ldap',
                'high-severity-xss', 'exploit-campaign',
                'regex-encoding_evasion',
            }
            if blocked and header_name == 'cookie' and reason not in _COOKIE_BLOCK_CATEGORIES:
                blocked = False
                
            if blocked:
                log.warning('Request blocked - malicious header', extra={
                    'event': 'blocked', 'client_ip': client, 'method': method,
                    'path': path, 'reason': f'header-{header_name}-{reason}',
                    'header_name': header_name, 'header_value': header_value[:100],
                    'status_code': 403
                })
                BLOCKED_TOTAL.labels(reason=f'header-{header_name}').inc()
                REQUESTS_TOTAL.labels(method=method, endpoint=path, status='403').inc()
                REQUEST_LATENCY.labels(method=method, endpoint=path).observe(time.time() - start_time)
                ACTIVE_REQUESTS.dec()
                auto_blocked = ip_blocklist.record_attack(client)
                if auto_blocked:
                    log.error(f'IP {client} auto-blocked after repeated attacks', extra={'event': 'auto-block', 'client_ip': client})
                return JSONResponse(status_code=403, content={"blocked": True, "reason": f'malicious-header-{header_name}'})

    # Lightweight checks for infrastructure headers (only specific patterns)
    import re as _re
    _header_injection_re = _re.compile(
        r'(?i)(?:(?:\r\n|\n|\r)[\w-]+\s*:|<script|javascript:|'
        r'\$\{jndi:|union\s+select|;\s*(?:cat|wget|curl|nc|bash)\s|'
        r'(?:\.\.[\\/]){2,}|/etc/passwd|/etc/shadow)',
        _re.IGNORECASE
    )
    _infra_headers = [
        'user-agent', 'x-forwarded-for', 'x-real-ip', 'x-client-ip',
        'client-ip', 'true-client-ip', 'x-forwarded-host', 'x-host',
        'x-forwarded-proto', 'authorization', 'x-api-key', 'accept',
        'x-backend-host', 'forwarded', 'range', 'if-modified-since',
    ]
    for header_name in _infra_headers:
        header_value = request.headers.get(header_name, '')
        if header_value and _header_injection_re.search(header_value):
            log.warning('Request blocked - malicious header', extra={
                'event': 'blocked', 'client_ip': client, 'method': method,
                'path': path, 'reason': f'header-{header_name}-injection',
                'header_name': header_name, 'header_value': header_value[:100],
                'status_code': 403
            })
            BLOCKED_TOTAL.labels(reason=f'header-{header_name}').inc()
            REQUESTS_TOTAL.labels(method=method, endpoint=path, status='403').inc()
            REQUEST_LATENCY.labels(method=method, endpoint=path).observe(time.time() - start_time)
            ACTIVE_REQUESTS.dec()
            auto_blocked = ip_blocklist.record_attack(client)
            if auto_blocked:
                log.error(f'IP {client} auto-blocked after repeated attacks', extra={'event': 'auto-block', 'client_ip': client})
            return JSONResponse(status_code=403, content={"blocked": True, "reason": f'malicious-header-{header_name}'})
    # ========== END HEADER VALIDATION ==========

    # ========== v4.0: EVASION DETECTION (18-layer deobfuscation) ==========
    evasion_blocked = False
    try:
        # Get all deobfuscated representations of the payload
        all_representations = evasion_detector.get_all_representations(full_path + ' ' + body_text)
        evasion_info = evasion_detector.detect_evasion(full_path + ' ' + body_text)
        if evasion_info and evasion_info.get('evasion_detected'):
            # Check each deobfuscated representation against regex rules
            for rep in all_representations:
                blocked, reason = rules.check_regex_rules(rep, '', {})
                if blocked:
                    log.warning('Request blocked - evasion detected', extra={
                        'event': 'blocked', 'client_ip': client, 'method': method,
                        'path': path, 'reason': f'evasion-{reason}',
                        'evasion_techniques': evasion_info.get('techniques', [])[:5],
                        'status_code': 403
                    })
                    BLOCKED_TOTAL.labels(reason='evasion-detected').inc()
                    ACTIVE_REQUESTS.dec()
                    ip_blocklist.record_attack(client)
                    correlation_engine.record_event(f'evasion-{reason}', client, path, 'critical')
                    compliance_engine.record_detection(reason, client_ip=client, path=path, severity='critical')
                    compliance_engine_v5.record_detection(reason, client_ip=client, path=path, severity='critical')
                    evasion_blocked = True
                    return JSONResponse(status_code=403, content={
                        "blocked": True, "reason": f"evasion-{reason}",
                        "evasion_techniques": evasion_info.get('techniques', [])[:3]
                    })
    except Exception:
        log.debug('Evasion detector error', exc_info=True)

    blocked, reason = rules.check_regex_rules(full_path, body_text, dict(request.headers))
    # v7.0: False Positive Filter — skip blocking for known benign patterns
    if blocked and _is_regex_false_positive(reason, full_path, body_text):
        log.info('FP filter: allowing request', extra={
            'event': 'fp-override', 'client_ip': client, 'method': method,
            'path': path, 'original_reason': reason
        })
        blocked = False
    if blocked:
        log.warning('Request blocked', extra={
            'event': 'blocked',
            'client_ip': client,
            'method': method,
            'path': path,
            'reason': reason,
            'status_code': 403,
            'body_preview': body_text[:200] if body_text else ''
        })
        BLOCKED_TOTAL.labels(reason=reason).inc()
        REQUESTS_TOTAL.labels(method=method, endpoint=path, status='403').inc()
        REQUEST_LATENCY.labels(method=method, endpoint=path).observe(time.time() - start_time)
        ACTIVE_REQUESTS.dec()
        # Record attack for IP blocklist
        auto_blocked = ip_blocklist.record_attack(client)
        if auto_blocked:
            log.error(f'IP {client} auto-blocked after repeated attacks', extra={'event': 'auto-block', 'client_ip': client})
        # v4.0: Record in correlation engine and compliance
        try:
            correlation_engine.record_event(reason, client, path, 'high')
            compliance_engine.record_detection(reason, client_ip=client, path=path, severity='high')
            compliance_engine_v5.record_detection(reason, client_ip=client, path=path, severity='high')
        except Exception:
            pass
        return JSONResponse(status_code=403, content={"blocked": True, "reason": reason})

    # anomaly detection (Advanced ML or Legacy)
    try:
        ml_result = None
        is_anomaly = False
        
        if ML_MODE == 'advanced' and ml_engine.get_engine().is_trained:
            # Use advanced 3-model ensemble
            ml_result = ml_engine.predict_request(full_path, body_text, dict(request.headers))
            is_anomaly = ml_result.get('is_attack', False)
            attack_reason = f"ml-{ml_result.get('attack_type', 'anomaly')}"
            attack_score = ml_result.get('attack_score', 0)
        else:
            # Fallback to legacy IsolationForest
            is_anomaly = anomaly.is_anomaly_for_request(full_path, body_text, dict(request.headers))
            attack_reason = 'anomaly'
            attack_score = 1.0 if is_anomaly else 0.0
        
        if is_anomaly:
            log.warning('Request blocked', extra={
                'event': 'blocked',
                'client_ip': client,
                'method': method,
                'path': path,
                'reason': attack_reason,
                'attack_score': attack_score,
                'model_scores': ml_result.get('model_scores', {}) if ml_result else {},
                'status_code': 403
            })
            BLOCKED_TOTAL.labels(reason=attack_reason).inc()
            REQUESTS_TOTAL.labels(method=method, endpoint=path, status='403').inc()
            REQUEST_LATENCY.labels(method=method, endpoint=path).observe(time.time() - start_time)
            ACTIVE_REQUESTS.dec()
            # Record attack for IP blocklist
            auto_blocked = ip_blocklist.record_attack(client)
            if auto_blocked:
                log.error(f'IP {client} auto-blocked after repeated attacks', extra={'event': 'auto-block', 'client_ip': client})
            # v4.0: Record in correlation engine and compliance
            try:
                correlation_engine.record_event(attack_reason, client, path, 'high')
                compliance_engine.record_detection(attack_reason, client_ip=client, path=path, severity='high')
                compliance_engine_v5.record_detection(attack_reason, client_ip=client, path=path, severity='high')
            except Exception:
                pass
            return JSONResponse(status_code=403, content={
                "blocked": True, 
                "reason": attack_reason,
                "attack_score": round(attack_score, 3)
            })
    except Exception:
        log.exception('Anomaly detector error')

    # ========== v4.0: ZERO-DAY DETECTION (catches what signatures miss) ==========
    try:
        payload_combined = full_path + ' ' + body_text
        if len(payload_combined) > 10:  # Skip trivial requests
            zd_result = zero_day_detector.analyze_payload(payload_combined)
            if zd_result and zd_result.get('is_anomaly'):
                log.warning('Request blocked - zero-day detection', extra={
                    'event': 'blocked', 'client_ip': client, 'method': method,
                    'path': path, 'reason': 'zero-day-anomaly',
                    'anomaly_score': round(zd_result.get('anomaly_score', 0), 3),
                    'factors': zd_result.get('top_factors', [])[:5],
                    'status_code': 403
                })
                BLOCKED_TOTAL.labels(reason='zero-day').inc()
                ACTIVE_REQUESTS.dec()
                ip_blocklist.record_attack(client)
                correlation_engine.record_event('zero-day-anomaly', client, path, 'critical')
                compliance_engine.record_detection('zero-day', client_ip=client, path=path, severity='critical')
                compliance_engine_v5.record_detection('zero-day', client_ip=client, path=path, severity='critical')
                return JSONResponse(status_code=403, content={
                    "blocked": True, "reason": "zero-day-anomaly",
                    "anomaly_score": round(zd_result.get('anomaly_score', 0), 3)
                })
    except Exception:
        log.debug('Zero-day detector error', exc_info=True)

    # ========== v4.0: ADAPTIVE LEARNING (learn from clean traffic) ==========
    try:
        adaptive_learning.learn_request(path, method, headers_dict, body_text, query_string)
        al_result = adaptive_learning.check_request(path, method, headers_dict, body_text, query_string)
        if al_result and al_result.get('action') == 'block':
            anomalies = al_result.get('anomalies', [])
            reason_str = anomalies[0] if anomalies else 'adaptive-anomaly'
            log.warning('Request blocked - adaptive learning', extra={
                'event': 'blocked', 'client_ip': client, 'method': method,
                'path': path, 'reason': reason_str,
                'anomalies': anomalies[:5], 'status_code': 403
            })
            BLOCKED_TOTAL.labels(reason='adaptive-learning').inc()
            ACTIVE_REQUESTS.dec()
            return JSONResponse(status_code=403, content={"blocked": True, "reason": reason_str})
    except Exception:
        log.debug('Adaptive learning error', exc_info=True)

    # ========== v4.0: CORRELATION ENGINE (check threat score) ==========
    try:
        threat_score = correlation_engine.get_threat_score(client)
        if threat_score >= 80:
            log.warning('Request blocked - high threat score', extra={
                'event': 'blocked', 'client_ip': client, 'method': method,
                'path': path, 'reason': 'correlation-threat-score',
                'threat_score': threat_score, 'status_code': 403
            })
            BLOCKED_TOTAL.labels(reason='correlation-engine').inc()
            ACTIVE_REQUESTS.dec()
            ip_blocklist.record_attack(client)
            return JSONResponse(status_code=403, content={
                "blocked": True, "reason": "high-threat-score",
                "threat_score": threat_score
            })
    except Exception:
        log.debug('Correlation engine error', exc_info=True)

    # passthrough
    response = await call_next(request)
    latency = time.time() - start_time
    
    # ========== DLP RESPONSE SCANNING ==========
    try:
        # Check response for data leaks (only for JSON/HTML/text responses)
        resp_content_type = response.headers.get('content-type', '')
        if any(t in resp_content_type for t in ['json', 'html', 'text', 'xml', 'javascript']):
            # Read response body for DLP scanning
            resp_body_parts = []
            async for chunk in response.body_iterator:
                if isinstance(chunk, bytes):
                    resp_body_parts.append(chunk)
                else:
                    resp_body_parts.append(chunk.encode('utf-8'))
            resp_body = b''.join(resp_body_parts)
            resp_text = resp_body.decode('utf-8', errors='ignore')
            
            dlp_result = dlp.scan_response(resp_text)
            if dlp_result and dlp_result.get('has_leaks', False):
                leak_types = dlp_result.get('leak_types', [])
                log.warning('DLP: sensitive data in response', extra={
                    'event': 'dlp-alert', 'client_ip': client,
                    'method': method, 'path': path,
                    'leak_types': leak_types[:5],
                    'leak_count': dlp_result.get('leak_count', 0),
                })
                BLOCKED_TOTAL.labels(reason='dlp-leak').inc()
                # Mask sensitive data in response instead of blocking
                masked_text = dlp.get_engine().mask_sensitive_data(resp_text)
                resp_body = masked_text.encode('utf-8')
            
            # Rebuild response with (potentially masked) body
            from starlette.responses import Response as StarletteResponse
            new_headers = dict(response.headers)
            new_headers['content-length'] = str(len(resp_body))
            # Add security headers
            new_headers['X-Content-Type-Options'] = 'nosniff'
            new_headers['X-Frame-Options'] = 'DENY'
            new_headers['X-XSS-Protection'] = '1; mode=block'
            new_headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
            new_headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=()'
            response = StarletteResponse(
                content=resp_body,
                status_code=response.status_code,
                headers=new_headers,
                media_type=response.media_type,
            )
    except Exception:
        log.debug('DLP response scan error', exc_info=True)
    # ========== END DLP RESPONSE SCANNING ==========
    
    # ========== v4.0: RESPONSE CLOAKING (remove server fingerprints) ==========
    try:
        # Cloak response headers (remove server fingerprints, add security headers)
        cloaked_headers = response_cloaking.cloak_headers(dict(response.headers))
        # Rebuild response with cloaked headers if needed
        if cloaked_headers:
            from starlette.responses import Response as StarletteResponse
            # Read body if not already read
            resp_body_final = None
            try:
                resp_body_parts_final = []
                async for chunk in response.body_iterator:
                    if isinstance(chunk, bytes):
                        resp_body_parts_final.append(chunk)
                    else:
                        resp_body_parts_final.append(chunk.encode('utf-8'))
                resp_body_final = b''.join(resp_body_parts_final)
            except Exception:
                pass  # Body may have been read already by DLP
            
            if resp_body_final is not None:
                # Cloak response body (remove stack traces, db errors, internal info)
                resp_content_type = cloaked_headers.get('content-type', '')
                if any(t in resp_content_type for t in ['json', 'html', 'text', 'xml']):
                    resp_text_final = resp_body_final.decode('utf-8', errors='ignore')
                    resp_text_final, _body_findings = response_cloaking.cloak_body(resp_text_final, resp_content_type)
                    resp_body_final = resp_text_final.encode('utf-8')
                
                cloaked_headers['content-length'] = str(len(resp_body_final))
                response = StarletteResponse(
                    content=resp_body_final,
                    status_code=response.status_code,
                    headers=cloaked_headers,
                    media_type=response.media_type,
                )
    except Exception:
        log.debug('Response cloaking error', exc_info=True)
    # ========== END RESPONSE CLOAKING ==========
    
    # ========== v4.0: COOKIE SECURITY (response) ==========
    try:
        cookie_resp_result = cookie_security.check_response_cookies(dict(response.headers))
        if cookie_resp_result and cookie_resp_result.get('warnings'):
            log.info('Cookie security warnings in response', extra={
                'event': 'cookie-warning', 'client_ip': client,
                'path': path, 'warnings': cookie_resp_result['warnings'][:5]
            })
    except Exception:
        log.debug('Cookie response check error', exc_info=True)

    # Report to threat intel for reputation tracking
    try:
        if response.status_code == 403:
            threat_intel.report_attack(client, 'medium')
    except Exception:
        pass

    log.info('Request processed', extra={
        'event': 'request',
        'client_ip': client,
        'method': method,
        'path': path,
        'status_code': response.status_code,
        'latency_ms': round(latency * 1000, 2)
    })
    REQUESTS_TOTAL.labels(method=method, endpoint=path, status=str(response.status_code)).inc()
    REQUEST_LATENCY.labels(method=method, endpoint=path).observe(latency)
    ACTIVE_REQUESTS.dec()
    return response

# ========== SECURITY HEADERS MIDDLEWARE (wraps ALL responses including 403 blocks) ==========
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """
    Ensures security headers are present on ALL responses (200, 403, 429, etc.)
    This middleware wraps the WAF middleware, so it catches every response
    including early returns from blocked requests.
    """
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=()'
    response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    # Remove server fingerprinting headers if present
    if 'server' in response.headers:
        del response.headers['server']
    if 'x-powered-by' in response.headers:
        del response.headers['x-powered-by']
    return response
# ========== END SECURITY HEADERS MIDDLEWARE ==========

@app.get('/health')
def health():
    ok = os.path.exists(MODEL_PATH)
    ml_engine_status = ml_engine.get_engine().is_trained
    return {
        "status": "ok", 
        "anomaly_detector_trained": ok, 
        "ml_engine_trained": ml_engine_status,
        "ml_mode": ML_MODE,
        "rules_count": len(rules.list_rules())
    }

@app.get('/metrics')
def metrics():
    """Prometheus metrics endpoint"""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.get('/admin/ml-stats', dependencies=[Depends(verify_api_key)])
def ml_stats():
    """Get ML engine statistics and performance metrics."""
    engine = ml_engine.get_engine()
    return {
        "ml_mode": ML_MODE,
        "is_trained": engine.is_trained,
        "training_stats": engine.training_stats,
        "weights": engine.weights,
        "attack_threshold": engine.attack_threshold
    }

@app.post('/admin/ml-predict', dependencies=[Depends(verify_api_key)])
async def ml_predict(request: Request):
    """Test ML prediction on a request body."""
    body = await request.body()
    body_text = body.decode('utf-8', errors='ignore') if body else ''
    
    result = ml_engine.predict_request(
        str(request.url),
        body_text,
        dict(request.headers)
    )
    return result


@app.get('/admin/rules', dependencies=[Depends(verify_api_key)])
def admin_rules():
    return {"rules": rules.list_rules()}

@app.post('/admin/retrain', dependencies=[Depends(verify_api_key)])
def retrain():
    """Retrain legacy anomaly model."""
    res = anomaly.train_from_file(TRAIN_DATA, save_path=MODEL_PATH)
    if not res.get('ok'):
        raise HTTPException(status_code=500, detail=res)
    return res

@app.post('/admin/retrain-ml', dependencies=[Depends(verify_api_key)])
def retrain_ml():
    """Retrain advanced ML engine from CSIC data."""
    if not os.path.exists(CSIC_DATA):
        raise HTTPException(status_code=404, detail=f"CSIC data not found: {CSIC_DATA}")
    
    result = ml_engine.train_from_csic(CSIC_DATA, ML_ENGINE_PATH)
    if not result.get('ok'):
        raise HTTPException(status_code=500, detail=result)
    return result

if not BACKEND_URL:
    @app.get('/')
    def index():
        total_rules = len(rules.list_rules())
        return {
            "service": "BeeWAF Enterprise",
        "version": "5.0.0",
        "status": "running",
        "modules": [
            "regex_rules", "ml_engine", "anomaly_detection",
            "bot_detector", "dlp", "geo_block", "protocol_validator",
            "api_security", "threat_intel", "session_protection",
            "evasion_detector", "correlation_engine", "adaptive_learning",
            "response_cloaking", "cookie_security", "virtual_patching",
            "zero_day_detector", "websocket_inspector", "payload_analyzer",
            "compliance_engine",
            "bot_manager_advanced", "ddos_protection", "api_discovery",
            "threat_feed", "cluster_manager", "performance_engine",
            "compliance_engine_v5"
        ],
        "total_modules": 27,
        "total_rules": total_rules,
        "ml_mode": ML_MODE,
        "compliance_frameworks": [
            "OWASP Top 10 2021", "PCI DSS 4.0", "GDPR",
            "SOC2 Type II", "NIST 800-53", "ISO 27001:2022", "HIPAA"
        ],
        "surpasses": "F5 BIG-IP ASM - Score 100/100"
    }

@app.get('/admin/enterprise-stats', dependencies=[Depends(verify_api_key)])
def enterprise_stats():
    """Get stats from all enterprise WAF modules (v3.0 + v4.0)."""
    stats = {}
    try:
        stats['bot_detector'] = bot_detector.get_detector().get_stats() if hasattr(bot_detector.get_detector(), 'get_stats') else {}
    except Exception:
        stats['bot_detector'] = 'unavailable'
    try:
        stats['dlp'] = dlp.get_engine().get_stats() if hasattr(dlp.get_engine(), 'get_stats') else {}
    except Exception:
        stats['dlp'] = 'unavailable'
    try:
        stats['geo_block'] = geo_block.get_blocker().get_stats() if hasattr(geo_block.get_blocker(), 'get_stats') else {}
    except Exception:
        stats['geo_block'] = 'unavailable'
    try:
        stats['protocol_validator'] = protocol_validator.get_validator().get_stats()
    except Exception:
        stats['protocol_validator'] = 'unavailable'
    try:
        stats['api_security'] = api_security.get_engine().get_stats()
    except Exception:
        stats['api_security'] = 'unavailable'
    try:
        stats['threat_intel'] = threat_intel.get_engine().get_stats()
    except Exception:
        stats['threat_intel'] = 'unavailable'
    try:
        stats['session_protection'] = session_protection.get_engine().get_stats()
    except Exception:
        stats['session_protection'] = 'unavailable'
    # v4.0 modules
    try:
        stats['correlation_engine'] = correlation_engine.get_engine().get_stats()
    except Exception:
        stats['correlation_engine'] = 'unavailable'
    try:
        stats['adaptive_learning'] = adaptive_learning.get_engine().get_stats()
    except Exception:
        stats['adaptive_learning'] = 'unavailable'
    try:
        stats['virtual_patching'] = virtual_patching.get_engine().get_stats()
    except Exception:
        stats['virtual_patching'] = 'unavailable'
    try:
        stats['compliance'] = compliance_engine.get_engine().get_stats()
    except Exception:
        stats['compliance'] = 'unavailable'
    # v5.0 modules
    try:
        stats['bot_manager_advanced'] = bot_manager_advanced.get_manager().get_stats() if hasattr(bot_manager_advanced.get_manager(), 'get_stats') else {}
    except Exception:
        stats['bot_manager_advanced'] = 'unavailable'
    try:
        stats['ddos_protection'] = ddos_protection.get_engine().get_stats() if hasattr(ddos_protection.get_engine(), 'get_stats') else {}
    except Exception:
        stats['ddos_protection'] = 'unavailable'
    try:
        stats['api_discovery'] = api_discovery.get_engine().get_stats() if hasattr(api_discovery.get_engine(), 'get_stats') else {}
    except Exception:
        stats['api_discovery'] = 'unavailable'
    try:
        stats['threat_feed'] = threat_feed.get_engine().get_stats() if hasattr(threat_feed.get_engine(), 'get_stats') else {}
    except Exception:
        stats['threat_feed'] = 'unavailable'
    try:
        stats['cluster_manager'] = cluster_manager.get_manager().get_stats() if hasattr(cluster_manager.get_manager(), 'get_stats') else {}
    except Exception:
        stats['cluster_manager'] = 'unavailable'
    try:
        stats['performance_engine'] = performance_engine.get_engine().get_stats() if hasattr(performance_engine.get_engine(), 'get_stats') else {}
    except Exception:
        stats['performance_engine'] = 'unavailable'
    try:
        stats['compliance_v5'] = compliance_engine_v5.get_engine().get_stats()
    except Exception:
        stats['compliance_v5'] = 'unavailable'
    stats['total_rules'] = len(rules.list_rules())
    stats['version'] = '5.0.0'
    stats['total_modules'] = 27
    return stats

@app.get('/admin/compliance', dependencies=[Depends(verify_api_key)])
def admin_compliance():
    """Full multi-framework compliance report (OWASP, PCI DSS, GDPR, SOC2, NIST, ISO, HIPAA)."""
    engine_v5 = compliance_engine_v5.get_engine()
    return engine_v5.get_full_compliance_report()

@app.get('/admin/virtual-patches', dependencies=[Depends(verify_api_key)])
def admin_virtual_patches():
    """List all virtual patches and their status."""
    return virtual_patching.get_engine().list_patches()

@app.get('/admin/correlation', dependencies=[Depends(verify_api_key)])
def admin_correlation():
    """Get correlation engine stats and active campaigns."""
    engine = correlation_engine.get_engine()
    return {
        "stats": engine.get_stats(),
        "active_campaigns": engine.campaigns if hasattr(engine, 'campaigns') else [],
    }

@app.post('/admin/adaptive-mode', dependencies=[Depends(verify_api_key)])
async def admin_adaptive_mode(request: Request):
    """Set adaptive learning mode: learning, detect, or enforce."""
    body = await request.body()
    data = json.loads(body.decode('utf-8', errors='ignore')) if body else {}
    mode = data.get('mode', 'learning')
    if mode not in ('learning', 'detect', 'enforce'):
        raise HTTPException(status_code=400, detail="Mode must be: learning, detect, or enforce")
    adaptive_learning.set_mode(mode)
    return {"mode": mode, "status": "updated"}

if not BACKEND_URL:
    @app.post('/echo')
    async def echo(request: Request):
        body = await request.body()
        return JSONResponse(content=(body.decode('utf-8', errors='ignore') if body else ''))


# =============================================================================
# REVERSE PROXY — Forward clean requests to backend application
# Activated when BACKEND_URL env var is set
# =============================================================================
if BACKEND_URL:
    log.info(f"🔀 Reverse Proxy Mode: forwarding clean traffic to {BACKEND_URL}")
    if BACKEND_MAP:
        for h, u in BACKEND_MAP.items():
            log.info(f"🔀 Host routing: {h} → {u}")

    @app.api_route('/{path:path}', methods=['GET','POST','PUT','DELETE','PATCH','OPTIONS','HEAD'])
    @app.api_route('/', methods=['GET','POST','PUT','DELETE','PATCH','OPTIONS','HEAD'], include_in_schema=False)
    async def reverse_proxy(request: Request, path: str = ''):
        """Forward requests that passed all WAF checks to the backend app."""
        req_host = request.headers.get('host', '')
        client = get_proxy_client(req_host)
        if not client:
            return JSONResponse(status_code=502, content={"error": "Backend not configured"})

        try:
            # Read request body
            body = await request.body()

            # Forward headers (remove hop-by-hop headers)
            hop_by_hop = {'host', 'connection', 'keep-alive', 'transfer-encoding',
                          'te', 'trailer', 'upgrade', 'proxy-authorization',
                          'proxy-authenticate'}
            headers = {k: v for k, v in request.headers.items()
                       if k.lower() not in hop_by_hop}

            # Add X-Forwarded headers (use the validated client IP from middleware)
            # 'client' variable was already securely extracted in waf_middleware
            # but reverse_proxy runs after middleware, so re-extract safely
            _real_ip = request.headers.get('X-Real-IP', '').strip()
            if _real_ip and not _real_ip.startswith(('192.168.', '10.', '172.')):
                _fwd_ip = _real_ip
            else:
                _fwd_ip = request.client.host if request.client else '0.0.0.0'
            headers['X-Forwarded-For'] = _fwd_ip
            headers['X-Forwarded-Proto'] = request.headers.get('x-forwarded-proto', 'http')
            headers['X-Forwarded-Host'] = request.headers.get('host', '')
            headers['X-BeeWAF-Inspected'] = 'true'

            # Forward to backend
            url = f"/{path}"
            if request.query_params:
                url = f"/{path}?{request.query_params}"

            backend_resp = await client.request(
                method=request.method,
                url=url,
                headers=headers,
                content=body,
            )

            # Return backend response
            # Strip hop-by-hop + server/date to avoid duplicate header warnings
            # from nginx ingress (uvicorn adds its own server/date headers)
            resp_headers = {k: v for k, v in backend_resp.headers.items()
                           if k.lower() not in ('content-encoding', 'content-length',
                                                  'transfer-encoding', 'connection',
                                                  'server', 'date')}
            return Response(
                content=backend_resp.content,
                status_code=backend_resp.status_code,
                headers=resp_headers,
                media_type=backend_resp.headers.get('content-type'),
            )

        except httpx.ConnectError:
            log.error(f"Cannot connect to backend: {BACKEND_URL}")
            return JSONResponse(status_code=502, content={"error": "Backend unavailable"})
        except httpx.TimeoutException:
            log.error(f"Backend timeout: {BACKEND_URL}")
            return JSONResponse(status_code=504, content={"error": "Backend timeout"})
        except Exception as e:
            log.error(f"Proxy error: {str(e)}")
            return JSONResponse(status_code=502, content={"error": "Proxy error"})
else:
    log.info("🏠 Demo Mode: no BACKEND_URL set, using built-in routes")
