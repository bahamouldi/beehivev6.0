"""
BeeWAF Enterprise - Zero-Day Detection Engine
==============================================
Advanced anomaly-based detection for unknown (zero-day) attacks
that bypass signature-based rules. Uses statistical analysis and
behavioral heuristics rather than known signatures.

Beyond F5 ASM which relies on signatures + basic anomaly scoring:
- Entropy analysis (high-entropy payloads indicate encoded/encrypted attacks)
- Payload structure analysis (nested encoding depth, special char density)
- N-gram frequency analysis (detects unusual character sequences)
- Request fingerprinting (deviation from normal HTTP patterns)
- Shellcode heuristic detection (NOP sleds, syscall patterns)
- Polyglot payload detection (payloads valid in multiple contexts)
"""

import re
import math
import time
import threading
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Tuple


class ZeroDayDetector:
    """
    Statistical and heuristic zero-day attack detector.
    Detects novel attacks through anomaly analysis rather than signatures.
    """

    def __init__(self, anomaly_threshold: float = 0.75):
        self._lock = threading.Lock()
        self.anomaly_threshold = anomaly_threshold
        self.stats = {
            'total_analyzed': 0,
            'anomalies_detected': 0,
            'high_entropy_payloads': 0,
            'shellcode_detected': 0,
            'polyglot_detected': 0,
        }

        # Baseline character frequency for normal HTTP traffic
        self._baseline_char_freq = self._build_baseline_freq()

        # Common n-grams in normal web traffic
        self._normal_bigrams = set([
            'th', 'he', 'in', 'er', 'an', 'on', 'en', 'at', 'is', 'or',
            'es', 'st', 'te', 'ar', 'al', 'nt', 'ng', 'it', 'ed', 'nd',
            'se', 'ha', 'to', 're', 'le', 'ou', 'io', 'co', 'de', 'ne',
            'id', 'pa', 'us', 'na', 'am', 'ge', 'ra', 'el', 'lo', 'ti',
            # URL common
            'ht', 'tp', '//', 'ww', '.c', 'om', '.h', 'tm', 'ml', '://',
            # Parameter common
            '=t', '=f', '&a', '&s', 'id', 'na', 'me', 'va', 'lu',
        ])

        # Shellcode patterns (x86/x64/ARM)
        self._shellcode_patterns = [
            re.compile(rb'(\x90{4,})'),  # NOP sled (x86)
            re.compile(rb'(\xcc{3,})'),  # INT3 sled
            re.compile(rb'\x31\xc0.*\x50.*\x89\xe3.*\xcd\x80'),  # Linux execve shellcode
            re.compile(rb'\x48\x31\xc0.*\x48\x89.*\x0f\x05'),  # x64 syscall
            re.compile(rb'\xeb[\x00-\x7f]\x5[8-9a-f]'),  # JMP-CALL-POP pattern
            re.compile(rb'(?:\\x[0-9a-f]{2}){20,}'),  # Hex-encoded shellcode in text
        ]

        # Polyglot patterns (valid in multiple contexts)
        self._polyglot_patterns = [
            # XSS + SQL
            re.compile(r"'.*?<script|<script.*?'", re.I),
            # SQL + XSS
            re.compile(r"union.*?<|<.*?union", re.I),
            # JavaScript + HTML
            re.compile(r"javascript:.*?<|<.*?javascript:", re.I),
            # Command + SQL
            re.compile(r";.*?(?:select|union)|(?:select|union).*?;", re.I),
            # SSTI + XSS
            re.compile(r"\{\{.*?<script|<script.*?\{\{", re.I),
            # File inclusion + SSRF
            re.compile(r"(?:file|http|ftp)://.*?(?:etc/passwd|localhost|127\.0\.0\.1)", re.I),
            # Multiple injection contexts
            re.compile(r"(?:<|%3c).*?(?:;|\||`|%0a|%0d).*?(?:select|union|exec)", re.I),
        ]

    def _build_baseline_freq(self) -> Dict[str, float]:
        """Build expected character frequency for normal HTTP traffic."""
        # Based on English text + URL encoded characters
        normal = "the quick brown fox jumps over the lazy dog /api/users?name=john&age=30&city=new+york HTTP/1.1 Host: example.com Accept: text/html Content-Type: application/json"
        counter = Counter(normal.lower())
        total = sum(counter.values())
        return {char: count / total for char, count in counter.items()}

    def calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string (bits per character)."""
        if not data:
            return 0.0
        counter = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in counter.values():
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy

    def analyze_payload(self, path: str, body: str, headers: Dict = None,
                        query_string: str = '') -> Dict:
        """
        Comprehensive zero-day payload analysis.
        Returns anomaly score and detection details.
        """
        self.stats['total_analyzed'] += 1
        headers = headers or {}
        full_payload = f"{path} {query_string} {body}"
        scores = {}
        details = []

        # ====== Analysis 1: Entropy Analysis ======
        entropy = self.calculate_entropy(full_payload)
        # Normal web traffic: 3.5-5.0 bits/char
        # Encoded/encrypted payloads: 5.5-8.0 bits/char
        # Random/binary: 7.0-8.0 bits/char
        if entropy > 6.0 and len(full_payload) > 30:
            entropy_score = min((entropy - 5.0) / 3.0, 1.0)
            scores['entropy'] = entropy_score
            self.stats['high_entropy_payloads'] += 1
            details.append({
                'type': 'high-entropy',
                'entropy': round(entropy, 3),
                'description': f'Payload entropy {entropy:.2f} bits/char (normal: 3.5-5.0)',
            })
        else:
            scores['entropy'] = 0.0

        # ====== Analysis 2: Special Character Density ======
        if len(full_payload) > 10:
            special_chars = sum(1 for c in full_payload if c in r"<>\"'`{}[]|;$()%\\&=+!@#^*~")
            density = special_chars / len(full_payload)
            # Normal: 0.02-0.08, Attacks: >0.15
            if density > 0.15:
                scores['special_char'] = min((density - 0.10) / 0.30, 1.0)
                details.append({
                    'type': 'high-special-char-density',
                    'density': round(density, 3),
                    'description': f'Special character density {density:.1%} (normal: <10%)',
                })
            else:
                scores['special_char'] = 0.0
        else:
            scores['special_char'] = 0.0

        # ====== Analysis 3: Encoding Depth ======
        encoding_depth = self._measure_encoding_depth(full_payload)
        if encoding_depth >= 2:
            scores['encoding_depth'] = min(encoding_depth / 4.0, 1.0)
            details.append({
                'type': 'deep-encoding',
                'depth': encoding_depth,
                'description': f'Payload has {encoding_depth} layers of encoding',
            })
        else:
            scores['encoding_depth'] = 0.0

        # ====== Analysis 4: N-gram Anomaly ======
        if len(full_payload) > 20:
            ngram_score = self._ngram_anomaly_score(full_payload)
            if ngram_score > 0.3:
                scores['ngram'] = ngram_score
                details.append({
                    'type': 'unusual-ngrams',
                    'score': round(ngram_score, 3),
                    'description': 'Character sequences unusual for normal web traffic',
                })
            else:
                scores['ngram'] = 0.0
        else:
            scores['ngram'] = 0.0

        # ====== Analysis 5: Control Character Detection ======
        control_chars = sum(1 for c in full_payload if ord(c) < 32 and c not in '\r\n\t')
        if control_chars > 0:
            scores['control_chars'] = min(control_chars / 5.0, 1.0)
            details.append({
                'type': 'control-characters',
                'count': control_chars,
                'description': f'{control_chars} non-printable control characters detected',
            })
        else:
            scores['control_chars'] = 0.0

        # ====== Analysis 6: Shellcode Heuristics ======
        shellcode_score = self._detect_shellcode(full_payload)
        if shellcode_score > 0:
            scores['shellcode'] = shellcode_score
            self.stats['shellcode_detected'] += 1
            details.append({
                'type': 'shellcode-heuristic',
                'score': round(shellcode_score, 3),
                'description': 'Binary/shellcode patterns detected in payload',
            })
        else:
            scores['shellcode'] = 0.0

        # ====== Analysis 7: Polyglot Detection ======
        polyglot_score = self._detect_polyglot(full_payload)
        if polyglot_score > 0:
            scores['polyglot'] = polyglot_score
            self.stats['polyglot_detected'] += 1
            details.append({
                'type': 'polyglot-payload',
                'score': round(polyglot_score, 3),
                'description': 'Payload appears valid in multiple injection contexts',
            })
        else:
            scores['polyglot'] = 0.0

        # ====== Analysis 8: Payload Length Anomaly ======
        length_anomaly = 0.0
        if len(query_string) > 2000:
            length_anomaly = min((len(query_string) - 1000) / 5000.0, 1.0)
            details.append({
                'type': 'excessive-query-length',
                'length': len(query_string),
                'description': f'Query string length {len(query_string)} is excessive',
            })
        if len(body) > 100000:
            length_anomaly = max(length_anomaly, min((len(body) - 50000) / 200000.0, 1.0))
            details.append({
                'type': 'excessive-body-length',
                'length': len(body),
            })
        scores['length'] = length_anomaly

        # ====== Analysis 9: Repetition Analysis ======
        repetition_score = self._analyze_repetition(full_payload)
        if repetition_score > 0.3:
            scores['repetition'] = repetition_score
            details.append({
                'type': 'payload-repetition',
                'score': round(repetition_score, 3),
                'description': 'Suspicious repetitive patterns (possible fuzzing/DoS)',
            })
        else:
            scores['repetition'] = 0.0

        # ====== Weighted Final Score ======
        weights = {
            'entropy': 0.15,
            'special_char': 0.15,
            'encoding_depth': 0.15,
            'ngram': 0.10,
            'control_chars': 0.10,
            'shellcode': 0.15,
            'polyglot': 0.10,
            'length': 0.05,
            'repetition': 0.05,
        }

        final_score = sum(scores.get(k, 0) * w for k, w in weights.items())

        is_anomaly = final_score >= self.anomaly_threshold
        if is_anomaly:
            self.stats['anomalies_detected'] += 1

        return {
            'is_anomaly': is_anomaly,
            'score': round(final_score, 4),
            'scores': {k: round(v, 4) for k, v in scores.items()},
            'details': details,
            'action': 'block' if is_anomaly else 'allow',
            'reason': 'zero-day-anomaly' if is_anomaly else None,
        }

    def _measure_encoding_depth(self, text: str) -> int:
        """Measure how many layers of encoding are present."""
        depth = 0
        # URL encoding layers
        if '%25' in text:  # Double encoded
            depth += 1
        if '%2525' in text:  # Triple encoded
            depth += 1
        if re.search(r'%[0-9a-fA-F]{2}', text):
            depth += 1
        # HTML entity
        if re.search(r'&#?[a-z0-9]+;', text, re.I):
            depth += 1
        # Base64
        if re.search(r'[A-Za-z0-9+/]{30,}={0,2}', text):
            depth += 1
        # Unicode escapes
        if re.search(r'\\u[0-9a-fA-F]{4}', text):
            depth += 1
        # Hex escapes
        if re.search(r'\\x[0-9a-fA-F]{2}', text):
            depth += 1
        return depth

    def _ngram_anomaly_score(self, text: str) -> float:
        """Score how unusual the character bi-grams are compared to normal traffic."""
        text_lower = text.lower()
        bigrams = [text_lower[i:i+2] for i in range(len(text_lower) - 1)]
        if not bigrams:
            return 0.0

        unusual_count = sum(1 for bg in bigrams if bg not in self._normal_bigrams)
        return unusual_count / len(bigrams)

    def _detect_shellcode(self, text: str) -> float:
        """Heuristic shellcode detection in payload."""
        score = 0.0
        text_bytes = text.encode('utf-8', errors='ignore')

        for pattern in self._shellcode_patterns:
            if pattern.search(text_bytes):
                score += 0.3

        # Check for high density of \x escape sequences
        hex_seqs = re.findall(r'\\x[0-9a-fA-F]{2}', text)
        if len(hex_seqs) > 10:
            score += min(len(hex_seqs) / 30.0, 0.5)

        # Check for NOP-like patterns in hex
        if re.search(r'(?:90|41|42|43){10,}', text):
            score += 0.4

        return min(score, 1.0)

    def _detect_polyglot(self, text: str) -> float:
        """Detect multi-context polyglot payloads."""
        matches = 0
        for pattern in self._polyglot_patterns:
            if pattern.search(text):
                matches += 1
        return min(matches / 3.0, 1.0)

    def _analyze_repetition(self, text: str) -> float:
        """Detect suspicious repetitive patterns (fuzzing, buffer overflow, DoS)."""
        if len(text) < 50:
            return 0.0

        # Check for repeated substrings
        for chunk_size in [3, 5, 8, 12]:
            if len(text) < chunk_size * 5:
                continue
            chunks = [text[i:i+chunk_size] for i in range(0, len(text) - chunk_size, chunk_size)]
            if not chunks:
                continue
            most_common = Counter(chunks).most_common(1)
            if most_common and most_common[0][1] / len(chunks) > 0.5:
                return min(most_common[0][1] / len(chunks), 1.0)

        # Check for single character repetition (buffer overflow attempt)
        if len(text) > 100:
            most_common_char = Counter(text).most_common(1)
            if most_common_char and most_common_char[0][1] / len(text) > 0.7:
                return 0.8

        return 0.0

    def get_stats(self) -> Dict:
        return dict(self.stats)


# ==================== SINGLETON ====================
_detector = None

def get_detector() -> ZeroDayDetector:
    global _detector
    if _detector is None:
        _detector = ZeroDayDetector()
    return _detector

def analyze_payload(path: str, body: str, **kwargs) -> Dict:
    return get_detector().analyze_payload(path, body, **kwargs)
