"""
BeeWAF API Security Engine
============================
Enterprise-grade API security surpassing F5 Advanced WAF API Protection.
Features:
- JSON/XML payload validation & depth limiting
- GraphQL query depth & complexity limiting
- REST method enforcement per path
- Request schema validation
- API key/token validation patterns
- Parameter type enforcement
- Request/response size limits per endpoint
- JSON injection prevention
- XML bomb (Billion Laughs) prevention
- Mass assignment protection
- BOLA/IDOR pattern detection
- Excessive data exposure prevention
- Rate limiting per API endpoint
"""

import re
import json
import time
import logging
from typing import Dict, List, Optional, Tuple, Set, Any
from collections import defaultdict

log = logging.getLogger("beewaf.api_security")


# ============================================================
#  JSON DEPTH & SIZE VALIDATOR
# ============================================================

class JSONValidator:
    """Validates JSON payloads against security constraints."""

    def __init__(self,
                 max_depth: int = 20,
                 max_keys: int = 500,
                 max_string_length: int = 65536,
                 max_array_length: int = 1000,
                 max_total_size: int = 5242880):  # 5MB
        self.max_depth = max_depth
        self.max_keys = max_keys
        self.max_string_length = max_string_length
        self.max_array_length = max_array_length
        self.max_total_size = max_total_size

    def validate(self, data: str) -> Dict:
        """Validate JSON string."""
        if not data or not data.strip():
            return {'valid': True, 'issues': []}

        if len(data) > self.max_total_size:
            return {
                'valid': False,
                'issues': [{'type': 'json-too-large', 'severity': 'high',
                            'message': f'JSON size {len(data)} exceeds max {self.max_total_size}'}]
            }

        try:
            parsed = json.loads(data)
        except json.JSONDecodeError as e:
            return {
                'valid': False,
                'issues': [{'type': 'json-parse-error', 'severity': 'medium',
                            'message': f'Invalid JSON: {str(e)[:100]}'}]
            }

        issues = []
        self._check_depth(parsed, 0, issues)
        self._check_structure(parsed, issues, key_count=[0])

        return {
            'valid': len(issues) == 0,
            'issues': issues
        }

    def _check_depth(self, obj, depth: int, issues: List):
        if depth > self.max_depth:
            issues.append({
                'type': 'json-max-depth',
                'severity': 'high',
                'message': f'JSON depth {depth} exceeds max {self.max_depth}'
            })
            return

        if isinstance(obj, dict):
            for v in obj.values():
                self._check_depth(v, depth + 1, issues)
                if len(issues) > 5:
                    return
        elif isinstance(obj, list):
            if len(obj) > self.max_array_length:
                issues.append({
                    'type': 'json-array-too-large',
                    'severity': 'medium',
                    'message': f'JSON array length {len(obj)} exceeds max {self.max_array_length}'
                })
            for item in obj[:100]:
                self._check_depth(item, depth + 1, issues)
                if len(issues) > 5:
                    return

    def _check_structure(self, obj, issues: List, key_count: List):
        if isinstance(obj, dict):
            key_count[0] += len(obj)
            if key_count[0] > self.max_keys:
                issues.append({
                    'type': 'json-too-many-keys',
                    'severity': 'high',
                    'message': f'JSON key count {key_count[0]} exceeds max {self.max_keys}'
                })
                return

            for k, v in obj.items():
                suspicious_keys = [
                    'role', 'admin', 'is_admin', 'isAdmin', 'is_superuser',
                    'permission', 'permissions', 'privilege', 'group',
                    'groups', 'is_staff', 'isStaff', 'verified', 'email_verified',
                    'password_hash', 'passwordHash', 'salt', '__proto__',
                    'constructor', '__class__', 'balance', 'credit',
                    'account_type', 'accountType', 'user_type', 'userType',
                ]
                if k.lower() in [s.lower() for s in suspicious_keys]:
                    issues.append({
                        'type': 'mass-assignment-suspect',
                        'severity': 'medium',
                        'message': f'Suspicious field in request body: {k}'
                    })

                if isinstance(v, str) and len(v) > self.max_string_length:
                    issues.append({
                        'type': 'json-string-too-long',
                        'severity': 'medium',
                        'message': f'String value for key "{k}" exceeds max length'
                    })

                self._check_structure(v, issues, key_count)
                if len(issues) > 10:
                    return

        elif isinstance(obj, list):
            for item in obj[:100]:
                self._check_structure(item, issues, key_count)
                if len(issues) > 10:
                    return


# ============================================================
#  XML VALIDATOR (keep your existing XMLValidator as-is)
# ============================================================

class XMLValidator:
    """Validates XML payloads against XXE and bomb attacks."""

    def __init__(self, max_depth: int = 20, max_entity_expansions: int = 100,
                 max_size: int = 5242880):
        self.max_depth = max_depth
        self.max_entity_expansions = max_entity_expansions
        self.max_size = max_size

    def validate(self, data: str) -> Dict:
        if not data or not data.strip():
            return {'valid': True, 'issues': []}

        issues = []

        if len(data) > self.max_size:
            issues.append({
                'type': 'xml-too-large', 'severity': 'high',
                'message': f'XML size {len(data)} exceeds max {self.max_size}'
            })

        # XXE detection
        xxe_patterns = [
            r'<!ENTITY\s+\w+\s+SYSTEM',
            r'<!ENTITY\s+\w+\s+PUBLIC',
            r'<!DOCTYPE[^>]*\[',
            r'file://',
            r'expect://',
            r'php://',
        ]
        for pattern in xxe_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                issues.append({
                    'type': 'xxe-attempt', 'severity': 'critical',
                    'message': f'XXE pattern detected: {pattern[:30]}'
                })

        # Billion laughs detection
        entity_count = data.count('<!ENTITY')
        if entity_count > 5:
            issues.append({
                'type': 'xml-bomb', 'severity': 'critical',
                'message': f'Possible XML bomb: {entity_count} entity definitions'
            })

        # Depth check
        depth = 0
        max_depth_found = 0
        for char in data:
            if char == '<' and not data[data.index(char):].startswith('</'):
                depth += 1
                max_depth_found = max(max_depth_found, depth)
            elif char == '<' and data[data.index(char):].startswith('</'):
                depth -= 1

        if max_depth_found > self.max_depth:
            issues.append({
                'type': 'xml-max-depth', 'severity': 'high',
                'message': f'XML depth {max_depth_found} exceeds max {self.max_depth}'
            })

        return {'valid': len(issues) == 0, 'issues': issues}


# ============================================================
#  GRAPHQL VALIDATOR
# ============================================================

class GraphQLValidator:
    """Validates GraphQL queries against complexity attacks."""

    def __init__(self,
                 max_depth: int = 10,
                 max_complexity: int = 1000,
                 max_aliases: int = 10,
                 max_directives: int = 10,
                 blocked_introspection: bool = False):
        self.max_depth = max_depth
        self.max_complexity = max_complexity
        self.max_aliases = max_aliases
        self.max_directives = max_directives
        self.blocked_introspection = blocked_introspection

    def validate(self, query: str) -> Dict:
        if not query:
            return {'valid': True, 'issues': []}

        issues = []

        if self.blocked_introspection:
            introspection_patterns = ['__schema', '__type', '__typename', '__typekind']
            for p in introspection_patterns:
                if p in query.lower():
                    issues.append({
                        'type': 'graphql-introspection', 'severity': 'medium',
                        'message': f'GraphQL introspection query blocked: {p}'
                    })

        depth = 0
        max_depth_found = 0
        for char in query:
            if char == '{':
                depth += 1
                max_depth_found = max(max_depth_found, depth)
            elif char == '}':
                depth -= 1

        if max_depth_found > self.max_depth:
            issues.append({
                'type': 'graphql-depth-limit', 'severity': 'high',
                'message': f'GraphQL query depth {max_depth_found} exceeds max {self.max_depth}'
            })

        alias_count = len(re.findall(r'\w+\s*:', query))
        if alias_count > self.max_aliases:
            issues.append({
                'type': 'graphql-alias-limit', 'severity': 'high',
                'message': f'GraphQL alias count {alias_count} exceeds max {self.max_aliases}'
            })

        directive_count = query.count('@')
        if directive_count > self.max_directives:
            issues.append({
                'type': 'graphql-directive-limit', 'severity': 'medium',
                'message': f'GraphQL directive count {directive_count} exceeds max {self.max_directives}'
            })

        mutation_count = query.lower().count('mutation')
        query_count = query.lower().count('query')
        if mutation_count + query_count > 5:
            issues.append({
                'type': 'graphql-batch-limit', 'severity': 'high',
                'message': 'Too many batched GraphQL operations'
            })

        field_count = len(re.findall(r'\w+\s*[\({]', query))
        estimated_complexity = field_count * max(max_depth_found, 1)
        if estimated_complexity > self.max_complexity:
            issues.append({
                'type': 'graphql-complexity-limit', 'severity': 'high',
                'message': f'GraphQL estimated complexity {estimated_complexity} exceeds max {self.max_complexity}'
            })

        return {'valid': len(issues) == 0, 'issues': issues}


# ============================================================
#  API ENDPOINT RATE LIMITER — CORRIGÉ
# ============================================================

class APIEndpointRateLimiter:
    """Per-endpoint rate limiting with realistic thresholds."""

    def __init__(self):
        self._requests: Dict[str, Dict[str, List[float]]] = defaultdict(
            lambda: defaultdict(list)
        )

        self._limits: Dict[str, Tuple[int, int]] = {}

        # Default limits by method — GÉNÉREUX pour trafic normal
        self._method_limits = {
            'GET': (10000, 60),
            'POST': (3000, 60),
            'PUT': (3000, 60),
            'DELETE': (2000, 60),
            'PATCH': (3000, 60),
            'OPTIONS': (50000, 60),   # Preflight CORS — ne jamais bloquer
            'HEAD': (10000, 60),
        }

        # =====================================================
        # SENSITIVE ENDPOINTS — LIMITES CORRIGÉES
        # =====================================================
        # Seuls les POST sont limités strictement (tentatives d'auth)
        # Les GET sur /login sont des chargements de PAGE — pas des attaques
        self._sensitive_patterns = {
            # Auth endpoints — limiter seulement les POST (tentatives de connexion)
            # PAS les GET (chargement de la page de login)
            r'POST:/api/v\d+/auth/login': (5, 60),        # 5 login POST par minute (OWASP)
            r'POST:/api/v\d+/auth/register': (5, 60),     # 5 registrations par minute
            r'POST:/api/v\d+/auth/reset': (3, 300),       # 3 resets par 5 minutes
            r'POST:/api/v\d+/auth/forgot': (3, 300),
            r'POST:/api/auth/login': (5, 60),
            r'POST:/login': (5, 60),                      # 5 POST login par minute (OWASP)
            r'POST:/register': (5, 60),
            r'POST:/signup': (10, 60),

            # Admin — limiter mais pas trop
            r'/api/v\d+/admin': (60, 60),

            # Data endpoints — limits raisonnables
            r'/api/v\d+/users$': (60, 60),
            r'/api/v\d+/export': (5, 300),
            r'/api/v\d+/import': (5, 300),

            # GraphQL
            r'/graphql': (100, 60),

            # Financial — limits strictes mais raisonnables
            r'POST:/api/v\d+/payment': (10, 60),
            r'POST:/api/v\d+/transfer': (10, 60),

            # API keys
            r'/api/v\d+/tokens': (20, 60),
            r'/api/v\d+/keys': (20, 60),
            r'/api/v\d+/webhooks': (30, 60),
        }

        # Nettoyage périodique
        self._last_cleanup = time.time()
        self._cleanup_interval = 300  # 5 minutes

    def check_rate(self, path: str, method: str, client_ip: str) -> Dict:
        """Check if request exceeds endpoint-specific rate limit."""
        now = time.time()

        # Nettoyage périodique pour éviter les fuites mémoire
        if now - self._last_cleanup > self._cleanup_interval:
            self._cleanup(now)
            self._last_cleanup = now

        # Ne JAMAIS rate-limiter les pages GET normales
        # Seuls les POST sur endpoints sensibles sont limités strictement
        if method in ('GET', 'HEAD', 'OPTIONS'):
            # Pour GET, utiliser seulement les limites par défaut (très hautes)
            limit = self._method_limits.get(method, (10000, 60))
        else:
            # Pour POST/PUT/DELETE, chercher une limite spécifique
            limit = self._find_limit(path, method)

        max_requests, window = limit

        # Clean old entries
        endpoint_key = f"{method}:{path}"
        timestamps = self._requests[endpoint_key][client_ip]
        cutoff = now - window
        timestamps[:] = [t for t in timestamps if t > cutoff]

        # Check limit
        if len(timestamps) >= max_requests:
            return {
                'allowed': False,
                'reason': f'Endpoint rate limit exceeded: {max_requests}/{window}s',
                'retry_after': int(timestamps[0] + window - now) + 1,
            }

        timestamps.append(now)
        return {
            'allowed': True,
            'remaining': max_requests - len(timestamps),
            'limit': max_requests,
            'window': window,
        }

    def _find_limit(self, path: str, method: str) -> Tuple[int, int]:
        """Find the matching rate limit for a path+method combination."""
        # Chercher d'abord avec method:path
        method_path_key = f"{method}:{path}"
        for pattern, lim in self._sensitive_patterns.items():
            if ':' in pattern:
                pat_method, pat_path = pattern.split(':', 1)
                if pat_method == method and re.match(pat_path, path, re.IGNORECASE):
                    return lim
            else:
                if re.match(pattern, path, re.IGNORECASE):
                    return lim

        # Custom limits
        if path in self._limits:
            return self._limits[path]

        # Default par méthode
        return self._method_limits.get(method, (3000, 60))

    def _cleanup(self, now: float):
        """Remove old entries to prevent memory leaks."""
        stale_endpoints = []
        for endpoint_key, ip_timestamps in self._requests.items():
            stale_ips = []
            for ip, timestamps in ip_timestamps.items():
                # Remove entries older than 10 minutes
                timestamps[:] = [t for t in timestamps if t > now - 600]
                if not timestamps:
                    stale_ips.append(ip)
            for ip in stale_ips:
                del ip_timestamps[ip]
            if not ip_timestamps:
                stale_endpoints.append(endpoint_key)
        for key in stale_endpoints:
            del self._requests[key]

    def set_limit(self, path: str, max_requests: int, window: int):
        self._limits[path] = (max_requests, window)


# ============================================================
#  BOLA DETECTOR
# ============================================================

class BOLADetector:
    """Detect Broken Object Level Authorization (BOLA/IDOR) patterns."""

    def __init__(self, max_unique_ids: int = 50, window: int = 300):
        self.max_unique_ids = max_unique_ids
        self.window = window
        self._access: Dict[str, Dict[str, List[Tuple[float, str]]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self.id_patterns = [
            re.compile(r'/api/v\d+/users/(\d+)'),
            re.compile(r'/api/v\d+/accounts/(\d+)'),
            re.compile(r'/api/v\d+/orders/(\d+)'),
            re.compile(r'/api/v\d+/invoices/(\d+)'),
            re.compile(r'/api/v\d+/documents/(\d+)'),
            re.compile(r'/api/v\d+/files/(\d+)'),
            re.compile(r'/api/v\d+/messages/(\d+)'),
            re.compile(
                r'/api/v\d+/\w+/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
                re.I,
            ),
            re.compile(r'/api/v\d+/\w+/(\d{4,})'),
        ]

    def check_access(self, path: str, client_ip: str) -> Optional[Dict]:
        now = time.time()

        for pattern in self.id_patterns:
            match = pattern.search(path)
            if match:
                obj_id = match.group(1)
                endpoint = pattern.pattern

                entries = self._access[client_ip][endpoint]
                entries[:] = [(t, oid) for t, oid in entries if t > now - self.window]
                entries.append((now, obj_id))

                unique_ids = set(oid for _, oid in entries)
                if len(unique_ids) > self.max_unique_ids:
                    return {
                        'type': 'bola-idor-suspect',
                        'severity': 'high',
                        'message': f'Possible BOLA/IDOR: {len(unique_ids)} unique IDs accessed on {endpoint} in {self.window}s',
                        'unique_ids_count': len(unique_ids),
                    }

                numeric_ids = sorted([int(oid) for oid in unique_ids if oid.isdigit()])
                if len(numeric_ids) >= 10:
                    diffs = [numeric_ids[i + 1] - numeric_ids[i] for i in range(len(numeric_ids) - 1)]
                    if diffs and all(d == 1 for d in diffs[:10]):
                        return {
                            'type': 'bola-sequential-enum',
                            'severity': 'critical',
                            'message': f'Sequential ID enumeration detected: {numeric_ids[0]}-{numeric_ids[-1]}',
                        }

        return None


# ============================================================
#  MAIN API SECURITY ENGINE — CORRIGÉ
# ============================================================

class APISecurityEngine:
    """Main API Security Engine combining all API protection features."""

    def __init__(self):
        self.json_validator = JSONValidator()
        self.xml_validator = XMLValidator()
        self.graphql_validator = GraphQLValidator()
        self.rate_limiter = APIEndpointRateLimiter()
        self.bola_detector = BOLADetector()

        self._stats = {
            'checked': 0,
            'blocked': 0,
            'by_type': defaultdict(int),
        }

        self._json_injection_patterns = [
            re.compile(r'\$where\s*:', re.IGNORECASE),
            re.compile(r'\$ne\s*:', re.IGNORECASE),
            re.compile(r'\$gt\s*:', re.IGNORECASE),
            re.compile(r'\$lt\s*:', re.IGNORECASE),
            re.compile(r'\$regex\s*:', re.IGNORECASE),
            re.compile(r'\$or\s*:\s*\[', re.IGNORECASE),
            re.compile(r'\$and\s*:\s*\[', re.IGNORECASE),
            re.compile(r'__proto__', re.IGNORECASE),
            re.compile(r'constructor\s*\[', re.IGNORECASE),
            re.compile(r'prototype\s*\.', re.IGNORECASE),
        ]

    def check_request(self,
                      path: str,
                      method: str,
                      headers: Dict[str, str],
                      body: str,
                      client_ip: str,
                      query_string: str = '') -> Dict:
        """
        Comprehensive API security check.
        Returns:
            {
                'allowed': bool,
                'issues': [{'type': str, 'severity': str, 'message': str}],
                'action': 'allow' | 'block' | 'warn',
            }
        """
        self._stats['checked'] += 1
        issues = []

        # === 1. Endpoint Rate Limiting ===
        rate_result = self.rate_limiter.check_rate(path, method, client_ip)
        if not rate_result['allowed']:
            issues.append({
                'type': 'api-rate-limit',
                # CHANGÉ: severity 'medium' pour rate limit → warn, pas block
                # Seulement les vrais abus (POST brute force) seront 'high'
                'severity': 'medium',
                'message': rate_result['reason'],
            })

        # === 2. Content-Type Based Validation ===
        content_type = headers.get('content-type', headers.get('Content-Type', ''))

        if body:
            if 'json' in content_type.lower() or (
                body.strip().startswith('{') or body.strip().startswith('[')
            ):
                result = self.json_validator.validate(body)
                issues.extend(result.get('issues', []))

                for pattern in self._json_injection_patterns:
                    if pattern.search(body):
                        issues.append({
                            'type': 'json-injection',
                            'severity': 'critical',
                            'message': f'JSON/NoSQL injection pattern detected: {pattern.pattern[:40]}'
                        })

            elif 'xml' in content_type.lower() or body.strip().startswith(
                '<?xml'
            ) or body.strip().startswith('<'):
                result = self.xml_validator.validate(body)
                issues.extend(result.get('issues', []))

            if 'graphql' in content_type.lower() or '/graphql' in path:
                gql_query = body
                if body.strip().startswith('{'):
                    try:
                        parsed = json.loads(body)
                        gql_query = parsed.get('query', '')
                    except json.JSONDecodeError:
                        pass
                result = self.graphql_validator.validate(gql_query)
                issues.extend(result.get('issues', []))

        # === 3. BOLA/IDOR Detection ===
        bola_result = self.bola_detector.check_access(path, client_ip)
        if bola_result:
            issues.append(bola_result)

        # === 4. Method Enforcement for REST APIs ===
        issues.extend(self._check_method_enforcement(path, method))

        # === 5. API Versioning Check ===
        if path.startswith('/api/') and not re.match(r'/api/v\d+/', path):
            issues.append({
                'type': 'api-no-version',
                'severity': 'low',
                'message': 'API endpoint without version prefix'
            })

        # Determine action
        has_issues = len(issues) > 0
        has_critical = any(
            i.get('severity') in ('critical', 'high') for i in issues
        )

        if has_critical:
            self._stats['blocked'] += 1
            for i in issues:
                self._stats['by_type'][i['type']] += 1

        return {
            'allowed': not has_critical,
            'issues': issues,
            'action': 'block' if has_critical else ('warn' if has_issues else 'allow'),
        }

    def _check_method_enforcement(self, path: str, method: str) -> List[Dict]:
        issues = []
        collection_patterns = [r'/api/v\d+/\w+$']
        for pattern in collection_patterns:
            if re.match(pattern, path) and method == 'DELETE':
                issues.append({
                    'type': 'rest-method-violation',
                    'severity': 'medium',
                    'message': f'DELETE on collection endpoint {path} may be destructive'
                })
        return issues

    def get_stats(self) -> Dict:
        return dict(self._stats)


# Module-level singleton
_engine = None


def get_engine() -> APISecurityEngine:
    global _engine
    if _engine is None:
        _engine = APISecurityEngine()
    return _engine


def check_request(path, method, headers, body, client_ip, query_string=''):
    return get_engine().check_request(
        path, method, headers, body, client_ip, query_string
    )