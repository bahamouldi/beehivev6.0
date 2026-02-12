"""
BeeWAF Enterprise - Response Cloaking Engine
=============================================
Removes server fingerprints, error details, and sensitive information
from HTTP responses to prevent information disclosure.

F5 ASM has basic response scrubbing. This goes far beyond:
- Server header removal/rewriting (30+ server signatures)
- Stack trace removal (Python, Java, PHP, .NET, Node.js, Ruby, Go)
- Database error message masking (MySQL, PostgreSQL, MSSQL, Oracle, MongoDB, Redis)
- Internal IP/hostname stripping
- Version information removal
- Debug information cleanup
- Custom error page injection
- Technology fingerprint elimination
- Source code leak prevention
"""

import re
from typing import Dict, List, Optional, Tuple


# ==================== SERVER SIGNATURES TO REMOVE ====================
SERVER_SIGNATURES = [
    # Web servers
    re.compile(r'Apache/[\d.]+', re.I),
    re.compile(r'nginx/[\d.]+', re.I),
    re.compile(r'Microsoft-IIS/[\d.]+', re.I),
    re.compile(r'LiteSpeed', re.I),
    re.compile(r'Caddy', re.I),
    re.compile(r'Tomcat/[\d.]+', re.I),
    re.compile(r'Jetty\([\d.]+\)', re.I),
    re.compile(r'Undertow', re.I),
    re.compile(r'WildFly/[\d.]+', re.I),
    re.compile(r'GlassFish[\s/][\d.]+', re.I),
    re.compile(r'WebLogic[\s/][\d.]+', re.I),
    re.compile(r'WebSphere[\s/][\d.]+', re.I),
    re.compile(r'Kestrel', re.I),
    re.compile(r'Gunicorn/[\d.]+', re.I),
    re.compile(r'uvicorn', re.I),
    re.compile(r'Werkzeug/[\d.]+', re.I),
    re.compile(r'CherryPy/[\d.]+', re.I),
    re.compile(r'Tornado/[\d.]+', re.I),
    re.compile(r'Express', re.I),
    re.compile(r'Puma/[\d.]+', re.I),
    re.compile(r'Unicorn', re.I),
    # Frameworks
    re.compile(r'PHP/[\d.]+', re.I),
    re.compile(r'ASP\.NET', re.I),
    re.compile(r'X-Powered-By:\s*\S+', re.I),
    re.compile(r'Django/[\d.]+', re.I),
    re.compile(r'Flask', re.I),
    re.compile(r'FastAPI', re.I),
    re.compile(r'Laravel', re.I),
    re.compile(r'Symfony', re.I),
    re.compile(r'Rails/[\d.]+', re.I),
    re.compile(r'Spring[\s/][\d.]+', re.I),
]

# ==================== STACK TRACE PATTERNS ====================
STACK_TRACE_PATTERNS = {
    'python': [
        re.compile(r'Traceback \(most recent call last\):[\s\S]*?(?:\w+Error|\w+Exception):.*', re.M),
        re.compile(r'File ".*?", line \d+, in \w+', re.M),
        re.compile(r'^\s+raise \w+', re.M),
    ],
    'java': [
        re.compile(r'(?:java|javax|org\.)\w+(?:\.\w+)+Exception:.*?(?:\n\s+at .*)+', re.M),
        re.compile(r'^\s+at [\w.$]+\([\w.]+:\d+\)', re.M),
        re.compile(r'Caused by:.*?(?:\n\s+at .*)+', re.M),
        re.compile(r'java\.lang\.\w+Error:.*', re.M),
    ],
    'php': [
        re.compile(r'Fatal error:.*?in .*? on line \d+', re.I),
        re.compile(r'Warning:.*?in .*? on line \d+', re.I),
        re.compile(r'Notice:.*?in .*? on line \d+', re.I),
        re.compile(r'Parse error:.*?in .*? on line \d+', re.I),
        re.compile(r'Stack trace:[\s\S]*?#\d+ .*', re.M),
    ],
    'dotnet': [
        re.compile(r'System\.\w+Exception:.*?(?:\n\s+at .*)+', re.M),
        re.compile(r'Server Error in \'.*?\' Application', re.I),
        re.compile(r'Unhandled Exception:.*', re.I),
        re.compile(r'\[NullReferenceException\]', re.I),
        re.compile(r'YSOD', re.I),  # Yellow Screen of Death
    ],
    'nodejs': [
        re.compile(r'(?:TypeError|ReferenceError|SyntaxError|RangeError):.*?\n\s+at .*', re.M),
        re.compile(r'Error: .*?\n\s+at .*?\(.*?:\d+:\d+\)', re.M),
        re.compile(r'UnhandledPromiseRejection', re.I),
    ],
    'ruby': [
        re.compile(r'\w+Error \(.*?\)[\s\S]*?(?:from .*?:\d+:in .*)+', re.M),
        re.compile(r'ActionController::\w+Error', re.I),
        re.compile(r'ActiveRecord::\w+Error', re.I),
    ],
    'go': [
        re.compile(r'goroutine \d+ \[running\]:[\s\S]*?(?:\w+\.go:\d+)', re.M),
        re.compile(r'panic: .*?\n\ngoroutine', re.M),
    ],
}

# ==================== DATABASE ERROR PATTERNS ====================
DB_ERROR_PATTERNS = [
    # MySQL
    re.compile(r'You have an error in your SQL syntax.*?near \'.*?\'', re.I | re.S),
    re.compile(r'mysql_fetch_\w+\(\)', re.I),
    re.compile(r'MySQL server version for the right syntax', re.I),
    re.compile(r'Warning: mysql_\w+\(\)', re.I),
    re.compile(r'MySQLSyntaxErrorException', re.I),
    re.compile(r'com\.mysql\.jdbc\.\w+Exception', re.I),
    # PostgreSQL
    re.compile(r'ERROR:\s+syntax error at or near', re.I),
    re.compile(r'pg_query\(\).*?ERROR', re.I),
    re.compile(r'PSQLException', re.I),
    re.compile(r'org\.postgresql\.\w+Exception', re.I),
    # MSSQL
    re.compile(r'Microsoft OLE DB Provider for SQL Server', re.I),
    re.compile(r'\[Microsoft\]\[ODBC SQL Server Driver\]', re.I),
    re.compile(r'Unclosed quotation mark after the character string', re.I),
    re.compile(r'SqlException', re.I),
    # Oracle
    re.compile(r'ORA-\d{5}:.*', re.I),
    re.compile(r'oracle\.jdbc\.\w+', re.I),
    re.compile(r'PLS-\d+:', re.I),
    # SQLite
    re.compile(r'SQLite3?::.*?Error', re.I),
    re.compile(r'SQLITE_ERROR', re.I),
    # MongoDB
    re.compile(r'MongoError:', re.I),
    re.compile(r'MongoServerError:', re.I),
    re.compile(r'E11000 duplicate key error', re.I),
    # Redis
    re.compile(r'WRONGTYPE Operation against a key', re.I),
    re.compile(r'ERR wrong number of arguments', re.I),
    re.compile(r'redis\.exceptions\.\w+Error', re.I),
]

# ==================== INTERNAL INFO PATTERNS ====================
INTERNAL_INFO_PATTERNS = [
    # Internal IPs
    re.compile(r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'),
    re.compile(r'\b(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b'),
    re.compile(r'\b(?:192\.168\.\d{1,3}\.\d{1,3})\b'),
    # Internal hostnames
    re.compile(r'\b(?:ip-10-\d+-\d+-\d+)\b', re.I),  # AWS internal
    re.compile(r'\b(?:i-[a-f0-9]{8,17})\b', re.I),  # AWS instance ID
    re.compile(r'\b(?:localhost|127\.0\.0\.1|::1)\b'),
    # File paths (revealing server structure)
    re.compile(r'(?:/home/\w+/|/var/www/|/opt/|/srv/|/usr/local/)', re.I),
    re.compile(r'(?:C:\\\\(?:Users|Windows|Program Files|inetpub)\\\\)', re.I),
    re.compile(r'(?:/app/|/data/|/config/|/src/)', re.I),
    # Version info
    re.compile(r'(?:Python|Ruby|Java|Node\.js|Go)\s+\d+\.\d+', re.I),
    re.compile(r'(?:OpenSSL|LibreSSL)\s+\d+\.\d+', re.I),
    re.compile(r'(?:Linux|Ubuntu|Debian|CentOS|Alpine)\s+\d+\.\d+', re.I),
]

# ==================== HEADERS TO REMOVE/MODIFY ====================
HEADERS_TO_REMOVE = [
    'server',
    'x-powered-by',
    'x-aspnet-version',
    'x-aspnetmvc-version',
    'x-runtime',
    'x-version',
    'x-generator',
    'x-drupal-cache',
    'x-drupal-dynamic-cache',
    'x-varnish',
    'via',
    'x-cache',
    'x-cache-hits',
    'x-served-by',
    'x-timer',
    'x-backend-server',
    'x-debug-token',
    'x-debug-token-link',
    'x-litespeed-cache',
    'x-turbo-charged-by',
]

# Headers to add for security
SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), camera=(), microphone=(), payment=()',
    'X-Permitted-Cross-Domain-Policies': 'none',
    'Cross-Origin-Embedder-Policy': 'require-corp',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Cache-Control': 'no-store, no-cache, must-revalidate, private',
    'Pragma': 'no-cache',
}


class ResponseCloakingEngine:
    """
    Enterprise response cloaking/sanitization engine.
    Removes all server fingerprints and sensitive information from responses.
    """

    def __init__(self):
        self.stats = {
            'total_processed': 0,
            'headers_stripped': 0,
            'traces_removed': 0,
            'db_errors_masked': 0,
            'internal_info_masked': 0,
            'server_signatures_removed': 0,
        }
        self.enabled = True
        self.custom_server_header = 'BeeWAF'
        self.mask_text = '[REDACTED]'
        self.error_page = None

    def cloak_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Remove/modify response headers that leak server info."""
        if not self.enabled:
            return headers

        cloaked = {}
        for key, value in headers.items():
            key_lower = key.lower()

            # Remove fingerprinting headers
            if key_lower in HEADERS_TO_REMOVE:
                self.stats['headers_stripped'] += 1
                continue

            # Replace Server header
            if key_lower == 'server':
                cloaked[key] = self.custom_server_header
                self.stats['server_signatures_removed'] += 1
                continue

            # Strip version info from header values
            new_value = value
            for sig_pattern in SERVER_SIGNATURES:
                new_value = sig_pattern.sub('', new_value)
            cloaked[key] = new_value.strip() if new_value != value else value

        # Add security headers
        for sec_key, sec_value in SECURITY_HEADERS.items():
            if sec_key.lower() not in {k.lower() for k in cloaked}:
                cloaked[sec_key] = sec_value

        return cloaked

    def cloak_body(self, body: str, content_type: str = '') -> Tuple[str, List[Dict]]:
        """
        Remove sensitive information from response body.
        Returns (cloaked_body, list_of_findings).
        """
        if not self.enabled or not body:
            return body, []

        self.stats['total_processed'] += 1
        findings = []
        cloaked = body

        # Only process text-based responses
        if content_type and not any(t in content_type.lower() for t in
                                    ['text', 'html', 'json', 'xml', 'javascript', 'css']):
            return body, []

        # Remove stack traces
        for lang, patterns in STACK_TRACE_PATTERNS.items():
            for pattern in patterns:
                matches = pattern.findall(cloaked)
                if matches:
                    self.stats['traces_removed'] += len(matches)
                    findings.append({
                        'type': 'stack-trace',
                        'language': lang,
                        'count': len(matches),
                    })
                    cloaked = pattern.sub(self.mask_text, cloaked)

        # Mask database errors
        for pattern in DB_ERROR_PATTERNS:
            matches = pattern.findall(cloaked)
            if matches:
                self.stats['db_errors_masked'] += len(matches)
                findings.append({
                    'type': 'database-error',
                    'count': len(matches),
                })
                cloaked = pattern.sub('An error occurred processing your request.', cloaked)

        # Mask internal information
        for pattern in INTERNAL_INFO_PATTERNS:
            matches = pattern.findall(cloaked)
            if matches:
                self.stats['internal_info_masked'] += len(matches)
                findings.append({
                    'type': 'internal-info',
                    'count': len(matches),
                })
                cloaked = pattern.sub(self.mask_text, cloaked)

        # Remove HTML comments (often contain debug info)
        html_comments = re.findall(r'<!--[\s\S]*?-->', cloaked)
        suspicious_comments = [c for c in html_comments if any(
            kw in c.lower() for kw in ['debug', 'todo', 'fixme', 'hack', 'password',
                                        'secret', 'key', 'token', 'admin', 'config',
                                        'version', 'build', 'internal']
        )]
        if suspicious_comments:
            findings.append({
                'type': 'suspicious-comment',
                'count': len(suspicious_comments),
            })
            for comment in suspicious_comments:
                cloaked = cloaked.replace(comment, '')

        # Remove server version strings from body
        for pattern in SERVER_SIGNATURES:
            matches = pattern.findall(cloaked)
            if matches:
                self.stats['server_signatures_removed'] += len(matches)
                cloaked = pattern.sub('', cloaked)

        return cloaked, findings

    def get_custom_error_page(self, status_code: int) -> Optional[str]:
        """Return a custom error page that doesn't leak information."""
        error_pages = {
            400: '{"error": "Bad Request", "message": "The request could not be understood."}',
            401: '{"error": "Unauthorized", "message": "Authentication is required."}',
            403: '{"error": "Forbidden", "message": "Access denied."}',
            404: '{"error": "Not Found", "message": "The requested resource was not found."}',
            405: '{"error": "Method Not Allowed", "message": "The request method is not supported."}',
            500: '{"error": "Internal Server Error", "message": "An unexpected error occurred."}',
            502: '{"error": "Bad Gateway", "message": "The server received an invalid response."}',
            503: '{"error": "Service Unavailable", "message": "The server is temporarily unavailable."}',
        }
        return error_pages.get(status_code)

    def get_stats(self) -> Dict:
        return dict(self.stats)


# ==================== SINGLETON ====================
_engine = None

def get_engine() -> ResponseCloakingEngine:
    global _engine
    if _engine is None:
        _engine = ResponseCloakingEngine()
    return _engine

def cloak_headers(headers: Dict[str, str]) -> Dict[str, str]:
    return get_engine().cloak_headers(headers)

def cloak_body(body: str, content_type: str = '') -> Tuple[str, List[Dict]]:
    return get_engine().cloak_body(body, content_type)
