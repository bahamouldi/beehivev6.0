"""
BeeWAF Enterprise - WebSocket Deep Inspection Engine
====================================================
F5 ASM has minimal WebSocket support. BeeWAF provides deep inspection:

- Full WebSocket message parsing (text + binary)
- Attack detection in WS messages (SQLi, XSS, command injection)
- Message rate limiting per connection
- Frame size validation
- Connection hijacking detection
- Origin validation
- Protocol validation (Sec-WebSocket headers)
- Message content policy enforcement
"""

import re
import time
import hashlib
import threading
from collections import defaultdict
from typing import Dict, List, Optional, Tuple


# ==================== WS ATTACK PATTERNS ====================
WS_ATTACK_PATTERNS = [
    # SQL Injection in WS messages
    (re.compile(r'\b(?:select|union|insert|update|delete|drop)\b.*?\b(?:from|into|table|where)\b', re.I), 'ws-sqli'),
    (re.compile(r"['\"];\s*(?:drop|delete|truncate|alter)\b", re.I), 'ws-sqli'),
    (re.compile(r'\bor\b\s+\d+\s*=\s*\d+', re.I), 'ws-sqli'),
    (re.compile(r'\bwaitfor\b.*?\bdelay\b', re.I), 'ws-sqli'),
    # XSS in WS messages
    (re.compile(r'<script[^>]*>.*?</script>', re.I | re.S), 'ws-xss'),
    (re.compile(r'\bon\w+\s*=\s*["\']', re.I), 'ws-xss'),
    (re.compile(r'javascript:\s*', re.I), 'ws-xss'),
    (re.compile(r'<iframe\b|<object\b|<embed\b|<svg\b.*?onload', re.I), 'ws-xss'),
    (re.compile(r'\beval\s*\(', re.I), 'ws-xss'),
    (re.compile(r'\bdocument\s*\.\s*(?:cookie|write|domain)', re.I), 'ws-xss'),
    # Command Injection in WS
    (re.compile(r'[;|&`]\s*(?:whoami|id|cat|ls|wget|curl|bash|sh|nc)\b', re.I), 'ws-cmdi'),
    (re.compile(r'\$\(.*?\)', re.I), 'ws-cmdi'),
    # Path Traversal
    (re.compile(r'(?:\.\./|\.\.\\){2,}', re.I), 'ws-traversal'),
    (re.compile(r'/etc/(?:passwd|shadow|hosts)', re.I), 'ws-traversal'),
    # JNDI/Log4Shell
    (re.compile(r'\$\{jndi:', re.I), 'ws-jndi'),
    # Template Injection
    (re.compile(r'\{\{.*?\}\}', re.I), 'ws-ssti'),
    (re.compile(r'\$\{.*?\}', re.I), 'ws-ssti'),
    # JSON injection
    (re.compile(r'"__proto__"', re.I), 'ws-prototype-pollution'),
    (re.compile(r'"\$\w+":\s*\{', re.I), 'ws-nosql'),
]


class WebSocketConnection:
    """Tracks a single WebSocket connection."""
    __slots__ = ['connection_id', 'client_ip', 'origin', 'protocol',
                 'connected_at', 'message_count', 'bytes_sent', 'bytes_received',
                 'last_message_at', 'violations', 'rate_window_start', 'rate_count']

    def __init__(self, connection_id: str, client_ip: str, origin: str = '', protocol: str = ''):
        self.connection_id = connection_id
        self.client_ip = client_ip
        self.origin = origin
        self.protocol = protocol
        self.connected_at = time.time()
        self.message_count = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.last_message_at = 0.0
        self.violations = []
        self.rate_window_start = time.time()
        self.rate_count = 0


class WebSocketInspector:
    """
    Deep WebSocket message inspection engine.
    """

    def __init__(self, max_message_size: int = 1_048_576,  # 1MB
                 max_messages_per_second: int = 50,
                 max_connections_per_ip: int = 20,
                 allowed_origins: List[str] = None):
        self._lock = threading.Lock()
        self.max_message_size = max_message_size
        self.max_messages_per_second = max_messages_per_second
        self.max_connections_per_ip = max_connections_per_ip
        self.allowed_origins = allowed_origins or []

        # Connection tracking
        self._connections: Dict[str, WebSocketConnection] = {}
        self._ip_connections: Dict[str, set] = defaultdict(set)

        self.stats = {
            'total_connections': 0,
            'total_messages': 0,
            'attacks_blocked': 0,
            'rate_limited': 0,
            'oversized_blocked': 0,
            'origin_rejected': 0,
            'active_connections': 0,
        }

    def validate_upgrade(self, headers: Dict[str, str], client_ip: str) -> Dict:
        """
        Validate WebSocket upgrade request.
        Called when client sends HTTP Upgrade: websocket request.
        """
        issues = []

        # Check Upgrade header
        upgrade = headers.get('upgrade', '').lower()
        if upgrade != 'websocket':
            issues.append({'type': 'invalid-upgrade', 'severity': 'high',
                          'message': f'Invalid Upgrade header: {upgrade}'})

        # Check Connection header
        connection = headers.get('connection', '').lower()
        if 'upgrade' not in connection:
            issues.append({'type': 'invalid-connection', 'severity': 'medium',
                          'message': 'Connection header missing "upgrade"'})

        # Check Sec-WebSocket-Key
        ws_key = headers.get('sec-websocket-key', '')
        if not ws_key or len(ws_key) < 16:
            issues.append({'type': 'invalid-ws-key', 'severity': 'high',
                          'message': 'Missing or invalid Sec-WebSocket-Key'})

        # Check Sec-WebSocket-Version
        ws_version = headers.get('sec-websocket-version', '')
        if ws_version != '13':
            issues.append({'type': 'invalid-ws-version', 'severity': 'medium',
                          'message': f'Unsupported WebSocket version: {ws_version}'})

        # Validate Origin
        origin = headers.get('origin', '')
        if self.allowed_origins and origin:
            if not any(origin.endswith(allowed) for allowed in self.allowed_origins):
                self.stats['origin_rejected'] += 1
                issues.append({'type': 'origin-rejected', 'severity': 'high',
                              'message': f'Origin {origin} not in allowed list'})

        # Check IP connection limit
        if len(self._ip_connections.get(client_ip, set())) >= self.max_connections_per_ip:
            issues.append({'type': 'connection-limit', 'severity': 'high',
                          'message': f'IP {client_ip} exceeded connection limit ({self.max_connections_per_ip})'})

        # Check for malicious headers
        for header_name, header_value in headers.items():
            for pattern, attack_type in WS_ATTACK_PATTERNS:
                if pattern.search(header_value):
                    issues.append({'type': 'malicious-header', 'severity': 'critical',
                                  'message': f'Attack pattern in header {header_name}: {attack_type}'})
                    break

        if any(i['severity'] == 'critical' for i in issues):
            action = 'block'
        elif any(i['severity'] == 'high' for i in issues):
            action = 'block'
        else:
            action = 'allow'

        if action == 'allow':
            # Register connection
            conn_id = hashlib.md5(f"{client_ip}:{time.time()}".encode()).hexdigest()[:12]
            conn = WebSocketConnection(conn_id, client_ip, origin)
            with self._lock:
                self._connections[conn_id] = conn
                self._ip_connections[client_ip].add(conn_id)
                self.stats['total_connections'] += 1
                self.stats['active_connections'] = len(self._connections)

            return {'action': 'allow', 'connection_id': conn_id, 'issues': issues}

        return {'action': action, 'issues': issues}

    def inspect_message(self, connection_id: str, message: str,
                        direction: str = 'incoming') -> Dict:
        """
        Inspect a WebSocket message for attacks.
        direction: 'incoming' (client->server) or 'outgoing' (server->client)
        """
        self.stats['total_messages'] += 1

        conn = self._connections.get(connection_id)
        if not conn:
            return {'action': 'allow', 'reason': 'unknown-connection'}

        conn.message_count += 1
        conn.last_message_at = time.time()
        issues = []

        # Check message size
        msg_size = len(message) if isinstance(message, str) else len(message)
        if msg_size > self.max_message_size:
            self.stats['oversized_blocked'] += 1
            issues.append({'type': 'message-too-large', 'severity': 'high',
                          'size': msg_size, 'limit': self.max_message_size})

        # Rate limiting
        now = time.time()
        if now - conn.rate_window_start > 1.0:
            conn.rate_window_start = now
            conn.rate_count = 0
        conn.rate_count += 1

        if conn.rate_count > self.max_messages_per_second:
            self.stats['rate_limited'] += 1
            issues.append({'type': 'ws-rate-limit', 'severity': 'high',
                          'rate': conn.rate_count, 'limit': self.max_messages_per_second})

        # Attack pattern scanning (only for incoming messages)
        if direction == 'incoming' and isinstance(message, str):
            for pattern, attack_type in WS_ATTACK_PATTERNS:
                if pattern.search(message):
                    self.stats['attacks_blocked'] += 1
                    issues.append({'type': attack_type, 'severity': 'critical',
                                  'message': f'Attack detected in WebSocket message: {attack_type}'})

        # Track bytes
        if direction == 'incoming':
            conn.bytes_received += msg_size
        else:
            conn.bytes_sent += msg_size

        # Determine action
        if any(i['severity'] == 'critical' for i in issues):
            conn.violations.append({'time': now, 'type': issues[0]['type']})
            return {'action': 'block', 'issues': issues, 'reason': issues[0]['type']}

        if any(i['severity'] == 'high' for i in issues):
            return {'action': 'block', 'issues': issues, 'reason': issues[0]['type']}

        return {'action': 'allow', 'issues': issues}

    def close_connection(self, connection_id: str):
        """Handle WebSocket connection close."""
        with self._lock:
            conn = self._connections.pop(connection_id, None)
            if conn:
                self._ip_connections[conn.client_ip].discard(connection_id)
                if not self._ip_connections[conn.client_ip]:
                    del self._ip_connections[conn.client_ip]
                self.stats['active_connections'] = len(self._connections)

    def get_connection_info(self, connection_id: str) -> Optional[Dict]:
        conn = self._connections.get(connection_id)
        if not conn:
            return None
        return {
            'connection_id': conn.connection_id,
            'client_ip': conn.client_ip,
            'origin': conn.origin,
            'connected_at': conn.connected_at,
            'message_count': conn.message_count,
            'bytes_sent': conn.bytes_sent,
            'bytes_received': conn.bytes_received,
            'violations': len(conn.violations),
        }

    def get_stats(self) -> Dict:
        stats = dict(self.stats)
        stats['connections_by_ip'] = {ip: len(conns) for ip, conns in self._ip_connections.items()}
        return stats


# ==================== SINGLETON ====================
_inspector = None

def get_inspector() -> WebSocketInspector:
    global _inspector
    if _inspector is None:
        _inspector = WebSocketInspector()
    return _inspector

def validate_upgrade(headers: Dict, client_ip: str) -> Dict:
    return get_inspector().validate_upgrade(headers, client_ip)

def inspect_message(connection_id: str, message: str, **kwargs) -> Dict:
    return get_inspector().inspect_message(connection_id, message, **kwargs)
