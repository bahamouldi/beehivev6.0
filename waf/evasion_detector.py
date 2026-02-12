"""
BeeWAF Enterprise - Advanced Evasion Detection Engine
=====================================================
Multi-layer payload deobfuscation with 18+ decoding passes.
Surpasses F5 BIG-IP ASM evasion handling capabilities.

Decoding layers:
 1. URL decoding (single)
 2. Double URL decoding
 3. Triple URL decoding
 4. HTML entity decoding (named + numeric + hex)
 5. Unicode normalization (NFC, NFD, NFKC, NFKD)
 6. UTF-8 overlong encoding
 7. Base64 decoding
 8. Hex decoding (backslash-xNN, 0xNN, %NN)
 9. Octal decoding (backslash-NNN)
10. JavaScript Unicode escape (backslash-uNNNN)
11. CSS escape sequences (backslash-NN)
12. Mixed encoding (combinations)
13. Null byte removal
14. Whitespace normalization
15. Comment stripping (SQL, JS, HTML)
16. Case normalization with homoglyph detection
17. Path canonicalization
18. JSON/XML entity decoding
"""

import re
import html
import base64
import unicodedata
import urllib.parse
from typing import Dict, List, Tuple, Optional


# ==================== UNICODE HOMOGLYPH MAP ====================
HOMOGLYPH_MAP = {
    # Latin homoglyphs (Cyrillic -> Latin)
    '\u0410': 'A', '\u0412': 'B', '\u0421': 'C', '\u0415': 'E',
    '\u041d': 'H', '\u0406': 'I', '\u041a': 'K', '\u041c': 'M',
    '\u041e': 'O', '\u0420': 'P', '\u0422': 'T', '\u0425': 'X',
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
    '\u0441': 'c', '\u0443': 'u', '\u0445': 'x', '\u0455': 's',
    '\u0456': 'i',
    # Greek -> Latin
    '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0397': 'H',
    '\u0399': 'I', '\u039a': 'K', '\u039c': 'M', '\u039d': 'N',
    '\u039f': 'O', '\u03a1': 'P', '\u03a4': 'T', '\u03a7': 'X',
    '\u03b1': 'a', '\u03b5': 'e', '\u03bf': 'o', '\u03c1': 'p',
    # Fullwidth -> ASCII
    '\uff21': 'A', '\uff22': 'B', '\uff23': 'C', '\uff24': 'D',
    '\uff25': 'E', '\uff26': 'F', '\uff27': 'G', '\uff28': 'H',
    '\uff29': 'I', '\uff2a': 'J', '\uff2b': 'K', '\uff2c': 'L',
    '\uff2d': 'M', '\uff2e': 'N', '\uff2f': 'O', '\uff30': 'P',
    '\uff31': 'Q', '\uff32': 'R', '\uff33': 'S', '\uff34': 'T',
    '\uff35': 'U', '\uff36': 'V', '\uff37': 'W', '\uff38': 'X',
    '\uff39': 'Y', '\uff3a': 'Z',
    '\uff41': 'a', '\uff42': 'b', '\uff43': 'c', '\uff44': 'd',
    '\uff45': 'e', '\uff46': 'f', '\uff47': 'g', '\uff48': 'h',
    '\uff49': 'i', '\uff4a': 'j', '\uff4b': 'k', '\uff4c': 'l',
    '\uff4d': 'm', '\uff4e': 'n', '\uff4f': 'o', '\uff50': 'p',
    '\uff51': 'q', '\uff52': 'r', '\uff53': 's', '\uff54': 't',
    '\uff55': 'u', '\uff56': 'v', '\uff57': 'w', '\uff58': 'x',
    '\uff59': 'y', '\uff5a': 'z',
    # Fullwidth digits
    '\uff10': '0', '\uff11': '1', '\uff12': '2', '\uff13': '3',
    '\uff14': '4', '\uff15': '5', '\uff16': '6', '\uff17': '7',
    '\uff18': '8', '\uff19': '9',
    # Fullwidth symbols
    '\uff08': '(', '\uff09': ')', '\uff1c': '<', '\uff1e': '>',
    '\uff1b': ';', '\uff07': "'", '\uff02': '"', '\uff0f': '/',
    '\uff3c': '\\', '\uff0e': '.', '\uff1a': ':',
    # Mathematical/superscript/subscript
    '\u00b2': '2', '\u00b3': '3', '\u00b9': '1',
    '\u2070': '0', '\u2071': 'i', '\u2074': '4', '\u2075': '5',
    '\u2076': '6', '\u2077': '7', '\u2078': '8', '\u2079': '9',
    # Small caps (Latin Extended)
    '\u1d00': 'A', '\u0299': 'B', '\u1d04': 'C', '\u1d05': 'D',
    '\u1d07': 'E', '\ua730': 'F', '\u0262': 'G', '\u029c': 'H',
    '\u026a': 'I', '\u1d0a': 'J', '\u1d0b': 'K', '\u029f': 'L',
    '\u1d0d': 'M', '\u0274': 'N', '\u1d0f': 'O', '\u1d18': 'P',
    '\u0280': 'R', '\ua731': 'S', '\u1d1b': 'T', '\u1d1c': 'U',
    '\u1d20': 'V', '\u1d21': 'W',
}

# Build reverse lookup for fast detection
_HOMOGLYPH_CHARS = set(HOMOGLYPH_MAP.keys())


class EvasionDetector:
    """
    Multi-layer payload deobfuscation engine.
    Applies 18+ decoding techniques to normalize payloads before WAF analysis.
    """

    def __init__(self):
        self.stats = {
            'total_analyzed': 0,
            'evasions_detected': 0,
            'layer_hits': {},
        }
        # Precompile patterns
        self._hex_pattern = re.compile(r'\\x([0-9a-fA-F]{2})')
        self._unicode_pattern = re.compile(r'\\u([0-9a-fA-F]{4})')
        self._octal_pattern = re.compile(r'\\([0-7]{1,3})')
        self._html_hex_entity = re.compile(r'&#x([0-9a-fA-F]+);?')
        self._html_dec_entity = re.compile(r'&#(\d+);?')
        self._css_escape = re.compile(r'\\([0-9a-fA-F]{1,6})\s?')
        self._js_octal = re.compile(r'\\([0-3][0-7]{2})')
        self._sql_comment = re.compile(r'/\*.*?\*/', re.DOTALL)
        self._js_comment_line = re.compile(r'//[^\n]*')
        self._js_comment_block = re.compile(r'/\*.*?\*/', re.DOTALL)
        self._html_comment = re.compile(r'<!--.*?-->', re.DOTALL)
        self._whitespace_multi = re.compile(r'\s+')
        self._null_bytes = re.compile(r'[\x00\x0b\x0c\x1c\x1d\x1e\x1f]')
        self._overlong_2byte = re.compile(r'%c0%([0-9a-fA-F]{2})')
        self._overlong_3byte = re.compile(r'%e0%80%([0-9a-fA-F]{2})')
        self._double_encode = re.compile(r'%25([0-9a-fA-F]{2})')
        self._triple_encode = re.compile(r'%2525([0-9a-fA-F]{2})')
        self._base64_pattern = re.compile(
            r'(?:^|[^a-zA-Z0-9+/])([A-Za-z0-9+/]{20,}={0,2})(?:[^a-zA-Z0-9+/=]|$)'
        )
        self._json_unicode = re.compile(r'\\u([0-9a-fA-F]{4})')

    # ========== LAYER 1: URL Decoding (single) ==========
    def _decode_url(self, text: str) -> str:
        try:
            return urllib.parse.unquote(text)
        except Exception:
            return text

    # ========== LAYER 2: Double URL Decoding ==========
    def _decode_url_double(self, text: str) -> str:
        try:
            decoded = urllib.parse.unquote(text)
            return urllib.parse.unquote(decoded)
        except Exception:
            return text

    # ========== LAYER 3: Triple URL Decoding ==========
    def _decode_url_triple(self, text: str) -> str:
        try:
            decoded = urllib.parse.unquote(text)
            decoded = urllib.parse.unquote(decoded)
            return urllib.parse.unquote(decoded)
        except Exception:
            return text

    # ========== LAYER 4: HTML Entity Decoding ==========
    def _decode_html_entities(self, text: str) -> str:
        try:
            # First handle named entities (&lt; &gt; &amp; &quot; etc.)
            decoded = html.unescape(text)
            # Handle hex entities &#x41; -> A
            decoded = self._html_hex_entity.sub(
                lambda m: chr(int(m.group(1), 16)) if int(m.group(1), 16) < 0x110000 else m.group(0),
                decoded
            )
            # Handle decimal entities &#65; -> A
            decoded = self._html_dec_entity.sub(
                lambda m: chr(int(m.group(1))) if int(m.group(1)) < 0x110000 else m.group(0),
                decoded
            )
            return decoded
        except Exception:
            return text

    # ========== LAYER 5: Unicode Normalization ==========
    def _normalize_unicode(self, text: str) -> str:
        try:
            # NFKC is the most aggressive normalization
            # Converts fullwidth chars, compatibility chars, etc.
            normalized = unicodedata.normalize('NFKC', text)
            # Also apply homoglyph replacement
            result = []
            for ch in normalized:
                if ch in HOMOGLYPH_MAP:
                    result.append(HOMOGLYPH_MAP[ch])
                else:
                    result.append(ch)
            return ''.join(result)
        except Exception:
            return text

    # ========== LAYER 6: UTF-8 Overlong Encoding ==========
    def _decode_overlong_utf8(self, text: str) -> str:
        try:
            # 2-byte overlong: %c0%ae -> . (%c0%af -> /)
            decoded = self._overlong_2byte.sub(
                lambda m: chr(int(m.group(1), 16)) if int(m.group(1), 16) < 128 else m.group(0),
                text
            )
            # 3-byte overlong: %e0%80%ae -> .
            decoded = self._overlong_3byte.sub(
                lambda m: chr(int(m.group(1), 16)) if int(m.group(1), 16) < 128 else m.group(0),
                decoded
            )
            # Double encoding: %252e -> %2e -> .
            decoded = self._double_encode.sub(
                lambda m: chr(int(m.group(1), 16)) if int(m.group(1), 16) < 128 else m.group(0),
                decoded
            )
            # Triple encoding
            decoded = self._triple_encode.sub(
                lambda m: chr(int(m.group(1), 16)) if int(m.group(1), 16) < 128 else m.group(0),
                decoded
            )
            return decoded
        except Exception:
            return text

    # ========== LAYER 7: Base64 Decoding ==========
    def _decode_base64(self, text: str) -> str:
        try:
            matches = self._base64_pattern.findall(text)
            result = text
            for match in matches:
                if len(match) >= 20:  # Only decode substantial base64 strings
                    try:
                        decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                        # Only replace if decoded looks like text (not random binary)
                        if decoded and all(c.isprintable() or c in '\r\n\t' for c in decoded[:50]):
                            result = result.replace(match, decoded, 1)
                    except Exception:
                        continue
            return result
        except Exception:
            return text

    # ========== LAYER 8: Hex Decoding ==========
    def _decode_hex(self, text: str) -> str:
        try:
            # \x41 -> A
            decoded = self._hex_pattern.sub(
                lambda m: chr(int(m.group(1), 16)) if int(m.group(1), 16) < 128 else m.group(0),
                text
            )
            # Also handle 0x41 format in certain contexts
            decoded = re.sub(
                r'0x([0-9a-fA-F]{2})(?=[,\s\)\]\}]|$)',
                lambda m: chr(int(m.group(1), 16)) if 32 <= int(m.group(1), 16) < 127 else m.group(0),
                decoded
            )
            return decoded
        except Exception:
            return text

    # ========== LAYER 9: Octal Decoding ==========
    def _decode_octal(self, text: str) -> str:
        try:
            return self._octal_pattern.sub(
                lambda m: chr(int(m.group(1), 8)) if int(m.group(1), 8) < 128 else m.group(0),
                text
            )
        except Exception:
            return text

    # ========== LAYER 10: JavaScript Unicode Escape ==========
    def _decode_js_unicode(self, text: str) -> str:
        try:
            return self._unicode_pattern.sub(
                lambda m: chr(int(m.group(1), 16)) if int(m.group(1), 16) < 0x110000 else m.group(0),
                text
            )
        except Exception:
            return text

    # ========== LAYER 11: CSS Escape Sequences ==========
    def _decode_css_escapes(self, text: str) -> str:
        try:
            return self._css_escape.sub(
                lambda m: chr(int(m.group(1), 16)) if int(m.group(1), 16) < 0x110000 else m.group(0),
                text
            )
        except Exception:
            return text

    # ========== LAYER 12: Mixed Encoding Detection ==========
    def _decode_mixed(self, text: str) -> str:
        """Apply all decoders in sequence for mixed encoding attacks."""
        try:
            decoded = text
            decoded = self._decode_url(decoded)
            decoded = self._decode_html_entities(decoded)
            decoded = self._decode_hex(decoded)
            decoded = self._decode_js_unicode(decoded)
            decoded = self._decode_overlong_utf8(decoded)
            return decoded
        except Exception:
            return text

    # ========== LAYER 13: Null Byte Removal ==========
    def _remove_null_bytes(self, text: str) -> str:
        try:
            # Remove null bytes and other control characters used for evasion
            return self._null_bytes.sub('', text)
        except Exception:
            return text

    # ========== LAYER 14: Whitespace Normalization ==========
    def _normalize_whitespace(self, text: str) -> str:
        try:
            # Replace tab, vertical tab, form feed, non-breaking space with regular space
            normalized = text.replace('\t', ' ').replace('\x0b', ' ').replace('\x0c', ' ')
            normalized = normalized.replace('\xa0', ' ')  # NBSP
            normalized = normalized.replace('\u2000', ' ')  # EN QUAD
            normalized = normalized.replace('\u2001', ' ')  # EM QUAD
            normalized = normalized.replace('\u2002', ' ')  # EN SPACE
            normalized = normalized.replace('\u2003', ' ')  # EM SPACE
            normalized = normalized.replace('\u200b', '')  # Zero-width space (REMOVE)
            normalized = normalized.replace('\u200c', '')  # Zero-width non-joiner
            normalized = normalized.replace('\u200d', '')  # Zero-width joiner
            normalized = normalized.replace('\u200e', '')  # LTR mark
            normalized = normalized.replace('\u200f', '')  # RTL mark
            normalized = normalized.replace('\ufeff', '')  # BOM / Zero-width no-break space
            # Collapse multiple spaces
            normalized = self._whitespace_multi.sub(' ', normalized)
            return normalized
        except Exception:
            return text

    # ========== LAYER 15: Comment Stripping ==========
    def _strip_comments(self, text: str) -> str:
        try:
            # SQL inline comments: SELECT/**/FROM -> SELECT FROM
            stripped = self._sql_comment.sub(' ', text)
            # HTML comments
            stripped = self._html_comment.sub('', stripped)
            # JavaScript line comments (be careful not to break URLs with //)
            # Only strip if preceded by whitespace or start of line
            stripped = re.sub(r'(?<=\s)//[^\n]*', '', stripped)
            return stripped
        except Exception:
            return text

    # ========== LAYER 16: Case + Homoglyph Normalization ==========
    def _normalize_case_homoglyphs(self, text: str) -> str:
        try:
            result = []
            for ch in text:
                mapped = HOMOGLYPH_MAP.get(ch)
                if mapped:
                    result.append(mapped)
                else:
                    result.append(ch)
            return ''.join(result).lower()
        except Exception:
            return text.lower()

    # ========== LAYER 17: Path Canonicalization ==========
    def _canonicalize_path(self, text: str) -> str:
        try:
            # Remove dot segments
            result = text
            while '//' in result:
                result = result.replace('//', '/')
            while '/./' in result:
                result = result.replace('/./', '/')
            # Resolve /../
            parts = result.split('/')
            resolved = []
            for part in parts:
                if part == '..':
                    if resolved and resolved[-1] != '':
                        resolved.pop()
                elif part != '.':
                    resolved.append(part)
            result = '/'.join(resolved) or '/'
            # Remove trailing /. and /..
            if result.endswith('/.'):
                result = result[:-2] + '/'
            return result
        except Exception:
            return text

    # ========== LAYER 18: JSON/XML Entity Decoding ==========
    def _decode_json_xml(self, text: str) -> str:
        try:
            # JSON unicode escapes: \u003c -> <
            decoded = self._json_unicode.sub(
                lambda m: chr(int(m.group(1), 16)) if int(m.group(1), 16) < 0x110000 else m.group(0),
                text
            )
            # XML entities
            xml_entities = {
                '&lt;': '<', '&gt;': '>', '&amp;': '&',
                '&quot;': '"', '&apos;': "'",
            }
            for entity, char in xml_entities.items():
                decoded = decoded.replace(entity, char)
            return decoded
        except Exception:
            return text

    # ========== MAIN ANALYSIS ==========
    def normalize_payload(self, text: str) -> Dict:
        """
        Apply all 18 decoding layers and return all normalized variants.
        Returns dict with decoded variants and evasion detection info.
        """
        if not text:
            return {'original': '', 'normalized': '', 'variants': [], 'evasion_detected': False, 'layers_triggered': []}

        self.stats['total_analyzed'] += 1
        variants = set()
        layers_triggered = []
        original = text

        # Apply each layer and track which ones produce different output
        decoders = [
            ('url_decode', self._decode_url),
            ('double_url_decode', self._decode_url_double),
            ('triple_url_decode', self._decode_url_triple),
            ('html_entity', self._decode_html_entities),
            ('unicode_normalize', self._normalize_unicode),
            ('overlong_utf8', self._decode_overlong_utf8),
            ('base64', self._decode_base64),
            ('hex', self._decode_hex),
            ('octal', self._decode_octal),
            ('js_unicode', self._decode_js_unicode),
            ('css_escape', self._decode_css_escapes),
            ('mixed_encoding', self._decode_mixed),
            ('null_byte', self._remove_null_bytes),
            ('whitespace', self._normalize_whitespace),
            ('comment_strip', self._strip_comments),
            ('homoglyph', self._normalize_case_homoglyphs),
            ('path_canonical', self._canonicalize_path),
            ('json_xml', self._decode_json_xml),
        ]

        for layer_name, decoder in decoders:
            try:
                decoded = decoder(text)
                if decoded != text and decoded != original:
                    layers_triggered.append(layer_name)
                    variants.add(decoded)
                    self.stats['layer_hits'][layer_name] = self.stats['layer_hits'].get(layer_name, 0) + 1
            except Exception:
                continue

        # Also do recursive deep decode (apply all layers to each variant)
        deep_variants = set()
        for variant in list(variants):
            for _, decoder in decoders[:6]:  # Apply first 6 decoders to variants
                try:
                    deep = decoder(variant)
                    if deep != variant and deep != original:
                        deep_variants.add(deep)
                except Exception:
                    continue
        variants.update(deep_variants)

        # Final normalized version: apply all decoders sequentially
        normalized = text
        for _, decoder in decoders:
            try:
                normalized = decoder(normalized)
            except Exception:
                continue

        evasion_detected = len(layers_triggered) > 0
        if evasion_detected:
            self.stats['evasions_detected'] += 1

        return {
            'original': original,
            'normalized': normalized,
            'variants': list(variants)[:20],  # Cap at 20 variants
            'evasion_detected': evasion_detected,
            'layers_triggered': layers_triggered,
        }

    def get_all_representations(self, text: str) -> List[str]:
        """
        Get all decoded representations of a payload for WAF rule matching.
        This is the main function called by the WAF middleware.
        """
        result = self.normalize_payload(text)
        representations = [result['original'], result['normalized']]
        representations.extend(result['variants'])
        # Deduplicate while preserving order
        seen = set()
        unique = []
        for r in representations:
            if r not in seen:
                seen.add(r)
                unique.append(r)
        return unique

    def detect_evasion_techniques(self, text: str) -> Dict:
        """
        Specifically detect known evasion techniques.
        Returns details about detected techniques.
        """
        techniques = []

        # Double/Triple URL encoding
        if '%25' in text:
            techniques.append({'type': 'double-url-encoding', 'severity': 'high'})
        if '%2525' in text:
            techniques.append({'type': 'triple-url-encoding', 'severity': 'critical'})

        # UTF-8 overlong
        if re.search(r'%c0%[0-9a-f]{2}', text, re.I):
            techniques.append({'type': 'utf8-overlong-2byte', 'severity': 'critical'})
        if re.search(r'%e0%80%[0-9a-f]{2}', text, re.I):
            techniques.append({'type': 'utf8-overlong-3byte', 'severity': 'critical'})

        # Null byte injection
        if '\x00' in text or '%00' in text:
            techniques.append({'type': 'null-byte-injection', 'severity': 'high'})

        # Unicode homoglyphs
        if any(ch in _HOMOGLYPH_CHARS for ch in text):
            techniques.append({'type': 'unicode-homoglyph', 'severity': 'high'})

        # Fullwidth characters
        if any('\uff00' <= ch <= '\uffef' for ch in text):
            techniques.append({'type': 'fullwidth-chars', 'severity': 'high'})

        # SQL comment splitting: SEL/**/ECT
        if re.search(r'\w+/\*.*?\*/\w+', text):
            techniques.append({'type': 'sql-comment-splitting', 'severity': 'high'})

        # Hex encoding in payload
        if re.search(r'(?:\\x[0-9a-f]{2}){3,}', text, re.I):
            techniques.append({'type': 'hex-encoding', 'severity': 'medium'})

        # JavaScript Unicode escapes
        if re.search(r'(?:\\u[0-9a-f]{4}){2,}', text, re.I):
            techniques.append({'type': 'js-unicode-escape', 'severity': 'medium'})

        # Base64 encoded payloads
        if re.search(r'[A-Za-z0-9+/]{40,}={0,2}', text):
            techniques.append({'type': 'base64-encoding', 'severity': 'medium'})

        # Mixed case SQL keywords (SeLeCt)
        if re.search(r'(?:[sS][eE][lL][eE][cC][tT]|[uU][nN][iI][oO][nN])', text):
            if not text.isupper() and not text.islower():
                techniques.append({'type': 'mixed-case-keyword', 'severity': 'low'})

        # Zero-width characters
        if any(ch in text for ch in ['\u200b', '\u200c', '\u200d', '\ufeff']):
            techniques.append({'type': 'zero-width-chars', 'severity': 'high'})

        # Tab/newline splitting: SEL\tECT, SEL\nECT
        if re.search(r'(?:select|union|insert|delete|drop|exec)\s*[\t\n\r]+\s*(?:from|all|into|table)', text, re.I):
            techniques.append({'type': 'whitespace-splitting', 'severity': 'medium'})

        # Backslash obfuscation
        if re.search(r'\\[a-z]', text) and not text.startswith('{'):
            techniques.append({'type': 'backslash-obfuscation', 'severity': 'medium'})

        # HTTP Parameter Pollution indicators
        if text.count('&') > 15:
            techniques.append({'type': 'parameter-pollution', 'severity': 'medium'})

        return {
            'evasion_detected': len(techniques) > 0,
            'techniques': techniques,
            'risk_level': 'critical' if any(t['severity'] == 'critical' for t in techniques)
                else 'high' if any(t['severity'] == 'high' for t in techniques)
                else 'medium' if techniques
                else 'none',
        }

    def get_stats(self) -> Dict:
        return dict(self.stats)


# ==================== SINGLETON ====================
_detector = None

def get_detector() -> EvasionDetector:
    global _detector
    if _detector is None:
        _detector = EvasionDetector()
    return _detector

def normalize_payload(text: str) -> Dict:
    return get_detector().normalize_payload(text)

def get_all_representations(text: str) -> List[str]:
    return get_detector().get_all_representations(text)

def detect_evasion(text: str) -> Dict:
    return get_detector().detect_evasion_techniques(text)
