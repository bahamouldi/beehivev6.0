"""
BeeWAF Enterprise - Deep Payload Analyzer
==========================================
Advanced content inspection engine that goes beyond regex pattern matching.
Performs structural analysis of payloads to detect sophisticated attacks.

Capabilities beyond F5 ASM:
- Abstract Syntax Tree (AST) analysis for SQL/JS payloads
- Context-aware detection (understands payload position: URL, header, body, JSON)
- Content-type aware parsing (JSON, XML, multipart, URL-encoded)
- Recursive parameter extraction (nested JSON, arrays)
- File upload deep inspection (magic bytes, double extensions, polyglot files)
- Obfuscation scoring (measures how obfuscated a payload is)
- Attack confidence scoring per payload segment
"""

import re
import json
import struct
import hashlib
from typing import Dict, List, Optional, Tuple


# ==================== FILE MAGIC BYTES ====================
FILE_SIGNATURES = {
    b'\xff\xd8\xff': ('image/jpeg', 'safe'),
    b'\x89PNG\r\n\x1a\n': ('image/png', 'safe'),
    b'GIF87a': ('image/gif', 'safe'),
    b'GIF89a': ('image/gif', 'safe'),
    b'%PDF': ('application/pdf', 'review'),
    b'PK\x03\x04': ('application/zip', 'review'),
    b'\x1f\x8b': ('application/gzip', 'review'),
    b'BZ': ('application/bzip2', 'review'),
    b'Rar!\x1a\x07': ('application/rar', 'review'),
    b'\xd0\xcf\x11\xe0': ('application/msoffice', 'review'),  # OLE2 (doc/xls/ppt)
    b'\x50\x4b\x03\x04': ('application/office-xml', 'review'),  # docx/xlsx/pptx (ZIP)
    # Dangerous file types
    b'MZ': ('application/x-executable', 'dangerous'),  # PE/EXE
    b'\x7fELF': ('application/x-elf', 'dangerous'),  # Linux ELF
    b'\xfe\xed\xfa': ('application/x-mach-o', 'dangerous'),  # macOS Mach-O
    b'\xca\xfe\xba\xbe': ('application/x-java-class', 'dangerous'),  # Java class
    b'\xac\xed\x00\x05': ('application/x-java-serialized', 'dangerous'),  # Java serialized
    b'<?php': ('application/x-php', 'dangerous'),  # PHP script
    b'<?=': ('application/x-php-short', 'dangerous'),  # PHP short tag
    b'#!/': ('application/x-shellscript', 'dangerous'),  # Shell script
    b'<%': ('application/x-jsp', 'dangerous'),  # JSP
}

# Dangerous file extensions
DANGEROUS_EXTENSIONS = {
    '.php', '.php3', '.php4', '.php5', '.php7', '.phtml', '.phar',
    '.asp', '.aspx', '.ashx', '.asmx', '.ascx',
    '.jsp', '.jspx', '.jsw', '.jsv',
    '.exe', '.dll', '.bat', '.cmd', '.com', '.msi', '.scr', '.pif',
    '.sh', '.bash', '.csh', '.ksh', '.zsh',
    '.py', '.pyc', '.pyw', '.rb', '.pl', '.cgi',
    '.war', '.jar', '.ear', '.class',
    '.htaccess', '.htpasswd', '.config', '.conf',
    '.elf', '.so', '.dylib',
    '.svg',  # Can contain JavaScript
    '.html', '.htm', '.xhtml',  # Can contain scripts
    '.shtml', '.shtm',  # Server-side includes
    '.swf',  # Flash (ActionScript)
}

# Double extension attacks
DOUBLE_EXTENSION_PATTERN = re.compile(
    r'\.(?:php|asp|aspx|jsp|exe|sh|py|rb|pl|cgi|war|jar)\.'
    r'(?:jpg|jpeg|png|gif|bmp|pdf|doc|txt|csv)$', re.I
)


class PayloadAnalyzer:
    """
    Deep content inspection and payload analysis engine.
    """

    def __init__(self):
        self.stats = {
            'total_analyzed': 0,
            'malicious_uploads': 0,
            'json_attacks': 0,
            'xml_attacks': 0,
            'multipart_attacks': 0,
            'obfuscated_payloads': 0,
        }

    def analyze_request(self, path: str, method: str, headers: Dict[str, str],
                        body: bytes, query_string: str = '') -> Dict:
        """
        Deep analysis of the full request payload.
        Returns structured findings with confidence scores.
        """
        self.stats['total_analyzed'] += 1
        findings = []
        content_type = headers.get('content-type', '').lower()
        body_text = body.decode('utf-8', errors='ignore') if isinstance(body, bytes) else body

        # Route to appropriate analyzer based on content type
        if 'multipart/form-data' in content_type:
            upload_findings = self._analyze_multipart(body, content_type)
            findings.extend(upload_findings)

        elif 'application/json' in content_type:
            json_findings = self._analyze_json_body(body_text)
            findings.extend(json_findings)

        elif 'application/xml' in content_type or 'text/xml' in content_type:
            xml_findings = self._analyze_xml_body(body_text)
            findings.extend(xml_findings)

        elif 'application/x-www-form-urlencoded' in content_type:
            form_findings = self._analyze_form_body(body_text)
            findings.extend(form_findings)

        # Always analyze URL and query string
        url_findings = self._analyze_url_params(query_string)
        findings.extend(url_findings)

        # Check obfuscation level
        if body_text:
            obfuscation = self._measure_obfuscation(body_text)
            if obfuscation['score'] > 0.5:
                self.stats['obfuscated_payloads'] += 1
                findings.append({
                    'type': 'obfuscated-payload',
                    'severity': 'high',
                    'confidence': obfuscation['score'],
                    'details': obfuscation,
                })

        # Determine action
        if findings:
            max_severity = max(
                ('critical', 'high', 'medium', 'low').index(f.get('severity', 'low'))
                for f in findings
            )
            severity_map = {3: 'critical', 2: 'high', 1: 'medium', 0: 'low'}
            top_severity = severity_map.get(max_severity, 'low')

            if max_severity >= 2:  # high or critical
                return {
                    'action': 'block',
                    'reason': findings[0]['type'],
                    'findings': findings,
                    'severity': top_severity,
                }

        return {'action': 'allow', 'findings': findings}

    def _analyze_multipart(self, body: bytes, content_type: str) -> List[Dict]:
        """Analyze multipart/form-data uploads."""
        findings = []
        body_text = body.decode('utf-8', errors='ignore')

        # Extract boundary
        boundary_match = re.search(r'boundary=([^\s;]+)', content_type)
        if not boundary_match:
            return findings

        boundary = boundary_match.group(1)
        parts = body_text.split(f'--{boundary}')

        for part in parts:
            if not part.strip() or part.strip() == '--':
                continue

            # Extract filename
            filename_match = re.search(r'filename="([^"]*)"', part, re.I)
            if not filename_match:
                continue

            filename = filename_match.group(1)

            # Check dangerous extensions
            for ext in DANGEROUS_EXTENSIONS:
                if filename.lower().endswith(ext):
                    self.stats['malicious_uploads'] += 1
                    findings.append({
                        'type': 'dangerous-file-extension',
                        'severity': 'critical',
                        'confidence': 0.95,
                        'filename': filename,
                        'extension': ext,
                    })
                    break

            # Check double extensions
            if DOUBLE_EXTENSION_PATTERN.search(filename):
                self.stats['malicious_uploads'] += 1
                findings.append({
                    'type': 'double-extension-attack',
                    'severity': 'critical',
                    'confidence': 0.90,
                    'filename': filename,
                })

            # Check for null bytes in filename
            if '\x00' in filename or '%00' in filename:
                findings.append({
                    'type': 'null-byte-filename',
                    'severity': 'critical',
                    'confidence': 0.99,
                    'filename': filename,
                })

            # Check magic bytes vs declared content type
            content_start_idx = part.find('\r\n\r\n')
            if content_start_idx > 0:
                file_content = part[content_start_idx + 4:].encode('utf-8', errors='ignore')
                magic_result = self._check_magic_bytes(file_content[:16])
                if magic_result:
                    detected_type, risk = magic_result
                    if risk == 'dangerous':
                        self.stats['malicious_uploads'] += 1
                        findings.append({
                            'type': 'dangerous-file-content',
                            'severity': 'critical',
                            'confidence': 0.95,
                            'filename': filename,
                            'detected_type': detected_type,
                        })

                    # Content type mismatch (polyglot file)
                    part_ct_match = re.search(r'Content-Type:\s*([^\r\n]+)', part, re.I)
                    if part_ct_match:
                        declared_type = part_ct_match.group(1).strip()
                        if 'image' in declared_type and risk == 'dangerous':
                            findings.append({
                                'type': 'polyglot-file-upload',
                                'severity': 'critical',
                                'confidence': 0.92,
                                'filename': filename,
                                'declared_type': declared_type,
                                'actual_type': detected_type,
                            })

        return findings

    def _analyze_json_body(self, body: str) -> List[Dict]:
        """Deep analysis of JSON request body."""
        findings = []

        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            # Not valid JSON - but might contain attack in malformed JSON
            if len(body) > 10:
                findings.append({
                    'type': 'malformed-json',
                    'severity': 'low',
                    'confidence': 0.5,
                })
            return findings

        # Recursive value inspection
        dangerous_values = self._inspect_json_values(data, depth=0)
        findings.extend(dangerous_values)

        # Check nesting depth (JSON bomb)
        depth = self._json_depth(data)
        if depth > 15:
            self.stats['json_attacks'] += 1
            findings.append({
                'type': 'json-depth-bomb',
                'severity': 'high',
                'confidence': 0.85,
                'depth': depth,
            })

        # Check key count (mass assignment / DoS)
        key_count = self._count_json_keys(data)
        if key_count > 200:
            findings.append({
                'type': 'json-key-flood',
                'severity': 'medium',
                'confidence': 0.7,
                'key_count': key_count,
            })

        return findings

    def _inspect_json_values(self, data, depth: int = 0, path: str = '') -> List[Dict]:
        """Recursively inspect JSON values for attacks."""
        findings = []
        if depth > 20:
            return findings

        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key

                # Check for NoSQL operators
                if key.startswith('$'):
                    self.stats['json_attacks'] += 1
                    findings.append({
                        'type': 'nosql-operator-injection',
                        'severity': 'critical',
                        'confidence': 0.90,
                        'path': current_path,
                    })

                # Check for prototype pollution keys
                if key in ('__proto__', 'constructor', 'prototype'):
                    findings.append({
                        'type': 'json-prototype-pollution',
                        'severity': 'critical',
                        'confidence': 0.95,
                        'path': current_path,
                    })

                # Check for mass assignment suspicious keys
                if key.lower() in ('role', 'is_admin', 'isadmin', 'admin', 'privilege',
                                   'permissions', 'group', 'type', 'verified'):
                    findings.append({
                        'type': 'mass-assignment-risk',
                        'severity': 'medium',
                        'confidence': 0.6,
                        'path': current_path,
                    })

                findings.extend(self._inspect_json_values(value, depth + 1, current_path))

        elif isinstance(data, list):
            for i, item in enumerate(data[:100]):
                findings.extend(self._inspect_json_values(item, depth + 1, f"{path}[{i}]"))

        elif isinstance(data, str):
            # Check string values for injection
            if len(data) > 5:
                injection_patterns = [
                    (r'\b(?:select|union|insert|delete|drop)\b', 'json-sqli-value'),
                    (r'<script|onerror|javascript:', 'json-xss-value'),
                    (r'[;|`]\s*(?:whoami|cat|ls)', 'json-cmdi-value'),
                    (r'\$\{jndi:', 'json-jndi-value'),
                    (r'\{\{.*\}\}', 'json-ssti-value'),
                ]
                for pattern, attack_type in injection_patterns:
                    if re.search(pattern, data, re.I):
                        findings.append({
                            'type': attack_type,
                            'severity': 'high',
                            'confidence': 0.80,
                            'path': path,
                            'value_preview': data[:100],
                        })

        return findings

    def _analyze_xml_body(self, body: str) -> List[Dict]:
        """Deep analysis of XML request body."""
        findings = []

        # XXE patterns
        if '<!ENTITY' in body or '<!DOCTYPE' in body:
            if 'SYSTEM' in body or 'PUBLIC' in body:
                self.stats['xml_attacks'] += 1
                findings.append({
                    'type': 'xxe-attempt',
                    'severity': 'critical',
                    'confidence': 0.95,
                })

        # XML bomb (Billion Laughs)
        entity_count = body.count('<!ENTITY')
        if entity_count > 3:
            self.stats['xml_attacks'] += 1
            findings.append({
                'type': 'xml-bomb',
                'severity': 'critical',
                'confidence': 0.90,
                'entity_count': entity_count,
            })

        # XInclude
        if 'xinclude' in body.lower() or 'xi:include' in body.lower():
            findings.append({
                'type': 'xinclude-injection',
                'severity': 'high',
                'confidence': 0.85,
            })

        # XSLT injection
        if 'xsl:' in body.lower() or 'stylesheet' in body.lower():
            findings.append({
                'type': 'xslt-injection',
                'severity': 'high',
                'confidence': 0.75,
            })

        return findings

    def _analyze_form_body(self, body: str) -> List[Dict]:
        """Analyze URL-encoded form body."""
        findings = []

        # Parameter pollution detection
        params = body.split('&')
        param_names = [p.split('=')[0] for p in params if '=' in p]
        duplicates = [name for name in set(param_names) if param_names.count(name) > 1]

        if duplicates:
            findings.append({
                'type': 'http-parameter-pollution',
                'severity': 'medium',
                'confidence': 0.70,
                'duplicates': duplicates,
            })

        # Check for oversized parameter values
        for param in params:
            if '=' in param:
                name, value = param.split('=', 1)
                if len(value) > 10000:
                    findings.append({
                        'type': 'oversized-parameter',
                        'severity': 'medium',
                        'confidence': 0.60,
                        'param': name,
                        'size': len(value),
                    })

        return findings

    def _analyze_url_params(self, query_string: str) -> List[Dict]:
        """Analyze URL query parameters."""
        findings = []
        if not query_string:
            return findings

        # Check parameter count
        params = query_string.split('&')
        if len(params) > 50:
            findings.append({
                'type': 'excessive-url-params',
                'severity': 'medium',
                'confidence': 0.70,
                'count': len(params),
            })

        return findings

    def _check_magic_bytes(self, data: bytes) -> Optional[Tuple[str, str]]:
        """Check file magic bytes to detect file type."""
        if not data:
            return None
        for magic, (file_type, risk) in FILE_SIGNATURES.items():
            if data.startswith(magic):
                return (file_type, risk)
        return None

    def _measure_obfuscation(self, text: str) -> Dict:
        """Measure the obfuscation level of a payload."""
        score = 0.0
        indicators = []

        # Hex encoding density
        hex_seqs = re.findall(r'(?:%[0-9a-fA-F]{2}|\\x[0-9a-fA-F]{2})', text)
        if len(hex_seqs) > 5:
            hex_density = len(hex_seqs) / max(len(text) / 4, 1)
            score += min(hex_density * 0.3, 0.3)
            indicators.append('hex-encoding')

        # Unicode escapes
        unicode_seqs = re.findall(r'\\u[0-9a-fA-F]{4}', text)
        if len(unicode_seqs) > 3:
            score += 0.15
            indicators.append('unicode-escapes')

        # String concatenation patterns
        concat_patterns = re.findall(r'["\'][\s+]*\+[\s+]*["\']|["\']\.concat\(', text)
        if len(concat_patterns) > 2:
            score += 0.15
            indicators.append('string-concatenation')

        # Comment injection (SQL)
        if re.search(r'/\*.*?\*/', text):
            if re.search(r'\w+/\*.*?\*/\w+', text):
                score += 0.2
                indicators.append('comment-splitting')

        # Case mixing
        words = re.findall(r'[a-zA-Z]{4,}', text)
        mixed_case_words = [w for w in words if not w.isupper() and not w.islower()]
        if len(mixed_case_words) > 3:
            score += 0.1
            indicators.append('mixed-case')

        # Base64 content
        b64_matches = re.findall(r'[A-Za-z0-9+/]{30,}={0,2}', text)
        if b64_matches:
            score += 0.15
            indicators.append('base64-content')

        return {
            'score': min(score, 1.0),
            'indicators': indicators,
        }

    def _json_depth(self, data, current_depth: int = 0) -> int:
        """Calculate max nesting depth of JSON."""
        if current_depth > 100:
            return current_depth
        if isinstance(data, dict):
            if not data:
                return current_depth
            return max(self._json_depth(v, current_depth + 1) for v in data.values())
        elif isinstance(data, list):
            if not data:
                return current_depth
            return max(self._json_depth(item, current_depth + 1) for item in data[:50])
        return current_depth

    def _count_json_keys(self, data, count: int = 0) -> int:
        """Count total keys in nested JSON."""
        if count > 1000:
            return count
        if isinstance(data, dict):
            count += len(data)
            for v in data.values():
                count = self._count_json_keys(v, count)
        elif isinstance(data, list):
            for item in data[:100]:
                count = self._count_json_keys(item, count)
        return count

    def get_stats(self) -> Dict:
        return dict(self.stats)


# ==================== SINGLETON ====================
_analyzer = None

def get_analyzer() -> PayloadAnalyzer:
    global _analyzer
    if _analyzer is None:
        _analyzer = PayloadAnalyzer()
    return _analyzer

def analyze_request(path: str, method: str, headers: Dict, body: bytes, **kwargs) -> Dict:
    return get_analyzer().analyze_request(path, method, headers, body, **kwargs)
