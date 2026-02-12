"""
BeeWAF Enterprise - Adaptive Learning / Positive Security Engine
================================================================
F5 ASM uses "learning suggestions" and manual policy building.
BeeWAF goes beyond with fully automatic positive security model:

- Learns normal traffic patterns automatically (endpoints, params, values)
- Builds baseline profiles per endpoint (method, params, content-type, size)
- Detects anomalous requests that deviate from learned behavior
- Auto-adjusts sensitivity based on traffic volume
- Supports learning mode (observe only) and enforce mode (block)
- Generates automatic policy suggestions

This creates a "positive security model" - allowing only known-good patterns
instead of just blocking known-bad patterns (negative security).
"""

import time
import re
import math
import threading
import json
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple


class EndpointProfile:
    """Profile of normal behavior for a specific endpoint."""

    def __init__(self, path: str, method: str):
        self.path = path
        self.method = method
        self.created_at = time.time()
        self.last_updated = time.time()
        self.request_count = 0

        # Learned parameters
        self.known_params: Set[str] = set()
        self.param_value_patterns: Dict[str, Dict] = {}  # param -> {min_len, max_len, pattern_type}
        self.known_content_types: Set[str] = set()
        self.body_size_stats = {'min': float('inf'), 'max': 0, 'sum': 0, 'count': 0}
        self.response_codes: Dict[int, int] = defaultdict(int)
        self.avg_latency_ms = 0.0

        # Value type tracking
        self.param_types: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

    def update(self, params: Dict[str, str], content_type: str = '', body_size: int = 0):
        """Update profile with a new request observation."""
        self.request_count += 1
        self.last_updated = time.time()

        # Track parameters
        for name, value in params.items():
            self.known_params.add(name)
            value_str = str(value)

            # Track value characteristics
            if name not in self.param_value_patterns:
                self.param_value_patterns[name] = {
                    'min_len': len(value_str),
                    'max_len': len(value_str),
                    'total_len': len(value_str),
                    'count': 1,
                }
            else:
                p = self.param_value_patterns[name]
                p['min_len'] = min(p['min_len'], len(value_str))
                p['max_len'] = max(p['max_len'], len(value_str))
                p['total_len'] += len(value_str)
                p['count'] += 1

            # Detect value type
            vtype = self._detect_value_type(value_str)
            self.param_types[name][vtype] += 1

        # Track content type
        if content_type:
            self.known_content_types.add(content_type.split(';')[0].strip().lower())

        # Track body size
        if body_size > 0:
            self.body_size_stats['min'] = min(self.body_size_stats['min'], body_size)
            self.body_size_stats['max'] = max(self.body_size_stats['max'], body_size)
            self.body_size_stats['sum'] += body_size
            self.body_size_stats['count'] += 1

    def _detect_value_type(self, value: str) -> str:
        """Classify parameter value type."""
        if not value:
            return 'empty'
        if value.isdigit():
            return 'integer'
        if re.match(r'^-?\d+\.?\d*$', value):
            return 'numeric'
        if re.match(r'^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$', value):
            return 'uuid'
        if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
            return 'email'
        if re.match(r'^[a-zA-Z0-9_-]+$', value):
            return 'alphanumeric'
        if re.match(r'^[a-zA-Z ]+$', value):
            return 'alpha'
        if len(value) > 100:
            return 'text_long'
        return 'text'

    def check_anomaly(self, params: Dict[str, str], content_type: str = '',
                      body_size: int = 0) -> Dict:
        """Check if a request is anomalous compared to the learned profile."""
        anomalies = []
        score = 0.0

        # Need minimum observations to make judgments
        if self.request_count < 20:
            return {'is_anomaly': False, 'score': 0, 'anomalies': [], 'reason': 'insufficient-data'}

        # Check for unknown parameters
        for name in params:
            if name not in self.known_params:
                anomalies.append({
                    'type': 'unknown-parameter',
                    'detail': f'Parameter "{name}" not seen in {self.request_count} previous requests',
                    'severity': 'medium',
                })
                score += 15

        # Check parameter value anomalies
        for name, value in params.items():
            if name in self.param_value_patterns:
                pattern = self.param_value_patterns[name]
                value_len = len(str(value))
                avg_len = pattern['total_len'] / max(pattern['count'], 1)

                # Length anomaly (3x standard deviation approximation)
                if value_len > pattern['max_len'] * 3:
                    anomalies.append({
                        'type': 'param-length-anomaly',
                        'detail': f'Parameter "{name}" length {value_len} vs max learned {pattern["max_len"]}',
                        'severity': 'high',
                    })
                    score += 25

                # Value type anomaly
                if name in self.param_types:
                    current_type = self._detect_value_type(str(value))
                    type_counts = self.param_types[name]
                    total = sum(type_counts.values())
                    if total > 10 and current_type not in type_counts:
                        anomalies.append({
                            'type': 'param-type-anomaly',
                            'detail': f'Parameter "{name}" type "{current_type}" never seen (known types: {list(type_counts.keys())})',
                            'severity': 'high',
                        })
                        score += 20

        # Check content type anomaly
        if content_type:
            ct = content_type.split(';')[0].strip().lower()
            if self.known_content_types and ct not in self.known_content_types:
                anomalies.append({
                    'type': 'content-type-anomaly',
                    'detail': f'Content-Type "{ct}" not in learned set {self.known_content_types}',
                    'severity': 'medium',
                })
                score += 15

        # Check body size anomaly
        if body_size > 0 and self.body_size_stats['count'] > 10:
            avg_size = self.body_size_stats['sum'] / self.body_size_stats['count']
            max_expected = max(self.body_size_stats['max'] * 3, avg_size * 5)
            if body_size > max_expected:
                anomalies.append({
                    'type': 'body-size-anomaly',
                    'detail': f'Body size {body_size} vs max expected {max_expected:.0f}',
                    'severity': 'medium',
                })
                score += 15

        # Check excess parameters
        if len(params) > len(self.known_params) * 2 + 5:
            anomalies.append({
                'type': 'excess-parameters',
                'detail': f'{len(params)} params vs learned max {len(self.known_params)}',
                'severity': 'medium',
            })
            score += 10

        return {
            'is_anomaly': score >= 40,
            'score': min(score, 100),
            'anomalies': anomalies,
            'endpoint_observations': self.request_count,
        }


class AdaptiveLearningEngine:
    """
    Automatic positive security model engine.
    Learns normal traffic patterns and detects deviations.
    """

    def __init__(self, mode: str = 'learning', learning_threshold: int = 100):
        self._lock = threading.Lock()
        self.mode = mode  # 'learning', 'detect', 'enforce'
        self.learning_threshold = learning_threshold

        # Endpoint profiles
        self._profiles: Dict[str, EndpointProfile] = {}

        # Global traffic patterns
        self._global_stats = {
            'total_requests': 0,
            'unique_endpoints': 0,
            'unique_ips': set(),
            'start_time': time.time(),
            'methods_seen': defaultdict(int),
            'content_types_seen': defaultdict(int),
        }

        # Path pattern learning (normalize dynamic segments)
        self._path_patterns: Dict[str, str] = {}

        # Stats
        self.stats = {
            'total_learned': 0,
            'anomalies_detected': 0,
            'requests_blocked': 0,
            'profiles_count': 0,
        }

    def _get_profile_key(self, path: str, method: str) -> str:
        """Create a normalized key for endpoint profiling."""
        normalized = self._normalize_path(path)
        return f"{method.upper()}:{normalized}"

    def _normalize_path(self, path: str) -> str:
        """Normalize dynamic path segments (IDs, UUIDs) to patterns."""
        # Replace UUIDs
        normalized = re.sub(
            r'[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}',
            '{uuid}', path
        )
        # Replace numeric IDs
        normalized = re.sub(r'/\d+(?=/|$)', '/{id}', normalized)
        # Replace hex tokens
        normalized = re.sub(r'/[a-fA-F0-9]{24,}(?=/|$)', '/{token}', normalized)
        return normalized

    def _parse_query_params(self, query_string: str) -> Dict[str, str]:
        """Parse query string into dict."""
        params = {}
        if not query_string:
            return params
        for pair in query_string.split('&'):
            if '=' in pair:
                key, value = pair.split('=', 1)
                params[key] = value
            elif pair:
                params[pair] = ''
        return params

    def learn_request(self, path: str, method: str, query_string: str = '',
                      headers: Dict = None, body: str = '', client_ip: str = '') -> Dict:
        """
        Learn from a normal (allowed) request.
        Called after WAF decides a request is clean.
        """
        self.stats['total_learned'] += 1
        self._global_stats['total_requests'] += 1
        self._global_stats['methods_seen'][method.upper()] += 1
        if client_ip:
            self._global_stats['unique_ips'].add(client_ip)

        profile_key = self._get_profile_key(path, method)
        params = self._parse_query_params(query_string)
        content_type = (headers or {}).get('content-type', '')
        body_size = len(body) if body else 0

        if content_type:
            self._global_stats['content_types_seen'][content_type.split(';')[0].strip()] += 1

        with self._lock:
            if profile_key not in self._profiles:
                self._profiles[profile_key] = EndpointProfile(path, method)
                self.stats['profiles_count'] += 1
                self._global_stats['unique_endpoints'] += 1

            profile = self._profiles[profile_key]
            profile.update(params, content_type, body_size)

        return {'learned': True, 'profile_key': profile_key, 'observations': profile.request_count}

    def check_request(self, path: str, method: str, query_string: str = '',
                      headers: Dict = None, body: str = '', client_ip: str = '') -> Dict:
        """
        Check a request against learned profiles.
        Returns anomaly detection results.
        """
        if self.mode == 'learning':
            return {'action': 'allow', 'reason': 'learning-mode'}

        profile_key = self._get_profile_key(path, method)
        params = self._parse_query_params(query_string)
        content_type = (headers or {}).get('content-type', '')
        body_size = len(body) if body else 0

        profile = self._profiles.get(profile_key)

        if not profile:
            # Unknown endpoint
            if self._global_stats['total_requests'] > self.learning_threshold:
                self.stats['anomalies_detected'] += 1
                return {
                    'action': 'flag' if self.mode == 'detect' else 'allow',
                    'reason': 'unknown-endpoint',
                    'detail': f'Endpoint {method} {path} not seen during learning ({self.stats["profiles_count"]} known endpoints)',
                    'confidence': 'low',
                }
            return {'action': 'allow', 'reason': 'insufficient-data'}

        # Check against learned profile
        result = profile.check_anomaly(params, content_type, body_size)

        if result['is_anomaly']:
            self.stats['anomalies_detected'] += 1
            action = 'block' if self.mode == 'enforce' else 'flag'
            if action == 'block':
                self.stats['requests_blocked'] += 1
            return {
                'action': action,
                'reason': 'positive-security-anomaly',
                'anomaly_score': result['score'],
                'anomalies': result['anomalies'],
                'profile_observations': result['endpoint_observations'],
            }

        return {'action': 'allow', 'reason': 'matches-profile'}

    def get_policy_suggestions(self) -> List[Dict]:
        """Generate security policy suggestions from learned patterns."""
        suggestions = []

        for key, profile in self._profiles.items():
            if profile.request_count < 20:
                continue

            method, path = key.split(':', 1)
            suggestion = {
                'endpoint': path,
                'method': method,
                'observations': profile.request_count,
                'rules': [],
            }

            # Suggest parameter whitelist
            if profile.known_params:
                suggestion['rules'].append({
                    'type': 'param-whitelist',
                    'params': list(profile.known_params),
                    'description': f'Only allow parameters: {", ".join(profile.known_params)}',
                })

            # Suggest parameter type constraints
            for param, types in profile.param_types.items():
                dominant_type = max(types, key=types.get)
                if types[dominant_type] / sum(types.values()) > 0.9:
                    suggestion['rules'].append({
                        'type': 'param-type',
                        'param': param,
                        'expected_type': dominant_type,
                        'description': f'Parameter "{param}" should be type {dominant_type}',
                    })

            # Suggest body size limits
            if profile.body_size_stats['count'] > 10:
                max_size = int(profile.body_size_stats['max'] * 2)
                suggestion['rules'].append({
                    'type': 'body-size-limit',
                    'max_bytes': max_size,
                    'description': f'Body size should not exceed {max_size} bytes',
                })

            if suggestion['rules']:
                suggestions.append(suggestion)

        return suggestions

    def set_mode(self, mode: str) -> Dict:
        """Change engine mode: learning, detect, enforce."""
        old_mode = self.mode
        self.mode = mode
        return {'old_mode': old_mode, 'new_mode': mode, 'profiles': self.stats['profiles_count']}

    def export_profiles(self) -> Dict:
        """Export learned profiles as JSON-serializable dict."""
        export = {}
        for key, profile in self._profiles.items():
            export[key] = {
                'path': profile.path,
                'method': profile.method,
                'request_count': profile.request_count,
                'known_params': list(profile.known_params),
                'known_content_types': list(profile.known_content_types),
                'body_size_stats': profile.body_size_stats,
                'param_types': {k: dict(v) for k, v in profile.param_types.items()},
            }
        return export

    def get_stats(self) -> Dict:
        stats = dict(self.stats)
        stats['mode'] = self.mode
        stats['global_requests'] = self._global_stats['total_requests']
        stats['unique_endpoints'] = self._global_stats['unique_endpoints']
        stats['unique_ips'] = len(self._global_stats['unique_ips'])
        stats['methods'] = dict(self._global_stats['methods_seen'])
        return stats


# ==================== SINGLETON ====================
_engine = None

def get_engine() -> AdaptiveLearningEngine:
    global _engine
    if _engine is None:
        _engine = AdaptiveLearningEngine(mode='learning')
    return _engine

def learn_request(path: str, method: str, **kwargs) -> Dict:
    return get_engine().learn_request(path, method, **kwargs)

def check_request(path: str, method: str, **kwargs) -> Dict:
    return get_engine().check_request(path, method, **kwargs)

def set_mode(mode: str) -> Dict:
    return get_engine().set_mode(mode)
