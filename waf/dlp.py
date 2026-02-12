"""
BeeWAF Data Leak Prevention (DLP) Engine
==========================================
Surpasses F5 DataGuard with:
- Credit card number detection (Luhn validation)
- Social Security Number detection
- API key/secret leak detection (AWS, GCP, Azure, GitHub, etc.)
- Private key detection (RSA, SSH, PGP)
- Email address enumeration prevention
- Phone number leak detection
- Password hash leak detection
- Database connection string detection
- JWT token leak detection
- Internal IP address leak prevention
- Custom PII pattern matching
- Response body masking/redaction
"""

import re
import hashlib
from typing import Dict, List, Tuple, Optional, Set
import logging

log = logging.getLogger("beewaf.dlp")


# ==================== CREDIT CARD PATTERNS ====================
CREDIT_CARD_PATTERNS = [
    # Visa
    (re.compile(r'\b4[0-9]{12}(?:[0-9]{3})?\b'), 'visa'),
    # MasterCard
    (re.compile(r'\b5[1-5][0-9]{14}\b'), 'mastercard'),
    (re.compile(r'\b2(?:2[2-9][1-9]|2[3-9][0-9]|[3-6][0-9]{2}|7[0-1][0-9]|720)[0-9]{12}\b'), 'mastercard-2series'),
    # American Express
    (re.compile(r'\b3[47][0-9]{13}\b'), 'amex'),
    # Discover
    (re.compile(r'\b6(?:011|5[0-9]{2})[0-9]{12}\b'), 'discover'),
    # Diners Club
    (re.compile(r'\b3(?:0[0-5]|[68][0-9])[0-9]{11}\b'), 'diners'),
    # JCB
    (re.compile(r'\b(?:2131|1800|35\d{3})\d{11}\b'), 'jcb'),
    # UnionPay
    (re.compile(r'\b62[0-9]{14,17}\b'), 'unionpay'),
    # With separators
    (re.compile(r'\b4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b'), 'visa-formatted'),
    (re.compile(r'\b5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b'), 'mastercard-formatted'),
]

# ==================== PII PATTERNS ====================
PII_PATTERNS = {
    'ssn': re.compile(r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b'),
    'ssn_french': re.compile(r'\b[12]\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\s?\d{3}\s?\d{2}\b'),  # French SSN (NIR)
    'email_bulk': re.compile(r'(?:[\w.+-]+@[\w-]+\.[\w.-]+[,;\s]){3,}'),  # 3+ emails = bulk leak
    'phone_us': re.compile(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
    'phone_intl': re.compile(r'\b\+\d{1,3}[-.\s]?\d{4,14}\b'),
    'iban': re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b'),
    'passport': re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'),
    'date_of_birth': re.compile(r'\b(?:dob|date.?of.?birth|birthday)\s*[:=]\s*\d{1,4}[-/]\d{1,2}[-/]\d{1,4}\b', re.IGNORECASE),
}

# ==================== API KEY / SECRET PATTERNS ====================
SECRET_PATTERNS = {
    # Cloud Provider Keys
    'aws_access_key': re.compile(r'(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}'),
    'aws_secret_key': re.compile(r'(?:aws)?_?(?:secret)?_?(?:access)?_?key\s*[:=]\s*[A-Za-z0-9/+=]{40}', re.IGNORECASE),
    'aws_session_token': re.compile(r'FwoGZXIvYXdzE[A-Za-z0-9/+=]{100,}'),
    'gcp_api_key': re.compile(r'AIza[0-9A-Za-z_-]{35}'),
    'gcp_service_account': re.compile(r'"type"\s*:\s*"service_account"'),
    'azure_subscription': re.compile(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', re.IGNORECASE),
    'azure_storage_key': re.compile(r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}'),
    
    # Version Control
    'github_token': re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,255}'),
    'github_oauth': re.compile(r'gho_[A-Za-z0-9]{36}'),
    'github_pat': re.compile(r'github_pat_[A-Za-z0-9_]{22,255}'),
    'gitlab_token': re.compile(r'glpat-[A-Za-z0-9\-]{20,}'),
    'bitbucket_token': re.compile(r'ATBB[A-Za-z0-9]{32,}'),
    
    # Communication
    'slack_token': re.compile(r'xox[boaprs]-[0-9]+-[A-Za-z0-9-]+'),
    'slack_webhook': re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'),
    'discord_token': re.compile(r'[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9-_]{6}\.[A-Za-z0-9-_]{27,}'),
    'discord_webhook': re.compile(r'https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+'),
    'telegram_token': re.compile(r'\d{8,10}:[A-Za-z0-9_-]{35}'),
    
    # Payment
    'stripe_secret': re.compile(r'sk_(?:live|test)_[A-Za-z0-9]{24,}'),
    'stripe_publishable': re.compile(r'pk_(?:live|test)_[A-Za-z0-9]{24,}'),
    'paypal_braintree': re.compile(r'access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}'),
    'square_token': re.compile(r'sq0[a-z]{3}-[A-Za-z0-9-_]{22,}'),
    
    # SaaS
    'twilio_sid': re.compile(r'AC[a-f0-9]{32}'),
    'twilio_auth': re.compile(r'SK[a-f0-9]{32}'),
    'sendgrid_key': re.compile(r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'),
    'mailgun_key': re.compile(r'key-[A-Za-z0-9]{32}'),
    'mailchimp_key': re.compile(r'[a-f0-9]{32}-us\d{1,2}'),
    
    # Database
    'mongodb_uri': re.compile(r'mongodb(?:\+srv)?://[^:]+:[^@]+@[^/]+'),
    'postgres_uri': re.compile(r'postgres(?:ql)?://[^:]+:[^@]+@[^/]+'),
    'mysql_uri': re.compile(r'mysql://[^:]+:[^@]+@[^/]+'),
    'redis_uri': re.compile(r'redis://[^:]*:[^@]+@[^/]+'),
    
    # JWT and Auth
    'jwt_token': re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'),
    'bearer_token': re.compile(r'[Bb]earer\s+[A-Za-z0-9_-]{20,}'),
    'basic_auth': re.compile(r'[Bb]asic\s+[A-Za-z0-9+/]{20,}={0,2}'),
    
    # Generic
    'generic_api_key': re.compile(r'(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[:=]\s*["\']?[A-Za-z0-9_-]{16,}["\']?', re.IGNORECASE),
    'generic_secret': re.compile(r'(?:secret|password|passwd|pwd|token|auth)\s*[:=]\s*["\'][^"\']{8,}["\']', re.IGNORECASE),
    'generic_private_key': re.compile(r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'),
    'ssh_private_key': re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'),
    'pgp_private_key': re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
    'certificate': re.compile(r'-----BEGIN CERTIFICATE-----'),
}

# ==================== INTERNAL INFO LEAK PATTERNS ====================
INTERNAL_LEAK_PATTERNS = {
    'internal_ip': re.compile(r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b'),
    'stack_trace_java': re.compile(r'(?:java\.lang\.|javax\.|org\.springframework\.|com\.sun\.)\w+(?:Exception|Error)'),
    'stack_trace_python': re.compile(r'Traceback \(most recent call last\)'),
    'stack_trace_php': re.compile(r'(?:Fatal error|Parse error|Warning):\s.*in\s/.+\.php\s+on\sline\s\d+'),
    'stack_trace_dotnet': re.compile(r'(?:System\.|Microsoft\.)\w+\.\w+Exception'),
    'stack_trace_node': re.compile(r'at\s+\w+\s+\((?:/|[A-Z]:\\)[\w/\\.-]+:\d+:\d+\)'),
    'server_path': re.compile(r'(?:/var/www/|/home/\w+/|/opt/|/srv/|C:\\inetpub\\|C:\\Users\\)\S+'),
    'sql_error': re.compile(r'(?:SQL syntax|ORA-\d{5}|PG::\w+|mysql_fetch|sqlite3?\.|SQLSTATE\[)', re.IGNORECASE),
    'debug_info': re.compile(r'(?:DEBUG|TRACE)\s*[:=]\s*(?:true|1|on|enabled)', re.IGNORECASE),
    'version_disclosure': re.compile(r'(?:X-Powered-By|Server|X-AspNet-Version|X-AspNetMvc-Version)\s*:\s*\S+'),
    'database_name': re.compile(r'(?:database|db_name|schema)\s*[:=]\s*["\']?\w+["\']?', re.IGNORECASE),
}

# ==================== PASSWORD HASH PATTERNS ====================
PASSWORD_HASH_PATTERNS = {
    'bcrypt': re.compile(r'\$2[ayb]\$\d{2}\$[./A-Za-z0-9]{53}'),
    'md5_crypt': re.compile(r'\$1\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{22}'),
    'sha256_crypt': re.compile(r'\$5\$(?:rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}'),
    'sha512_crypt': re.compile(r'\$6\$(?:rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}'),
    'argon2': re.compile(r'\$argon2(?:i|d|id)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+'),
    'ntlm': re.compile(r'\b[a-f0-9]{32}\b'),  # Careful: needs context
    'md5_hash': re.compile(r'\b[a-f0-9]{32}\b'),
    'sha1_hash': re.compile(r'\b[a-f0-9]{40}\b'),
    'sha256_hash': re.compile(r'\b[a-f0-9]{64}\b'),
}


def luhn_check(card_number: str) -> bool:
    """Validate credit card number using Luhn algorithm."""
    digits = [int(d) for d in card_number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def mask_sensitive_data(text: str, mask_char: str = '*') -> str:
    """Mask sensitive data in response text."""
    masked = text
    
    # Mask credit cards
    for pattern, _ in CREDIT_CARD_PATTERNS:
        def cc_replacer(match):
            cc = match.group(0)
            digits = ''.join(c for c in cc if c.isdigit())
            if luhn_check(digits):
                return cc[:4] + mask_char * (len(cc) - 8) + cc[-4:]
            return cc
        masked = pattern.sub(cc_replacer, masked)
    
    # Mask SSNs
    masked = PII_PATTERNS['ssn'].sub(
        lambda m: f"***-**-{m.group(0)[-4:]}", masked)
    
    # Mask API keys
    for name, pattern in SECRET_PATTERNS.items():
        def secret_replacer(match):
            s = match.group(0)
            if len(s) > 8:
                return s[:4] + mask_char * (len(s) - 8) + s[-4:]
            return mask_char * len(s)
        masked = pattern.sub(secret_replacer, masked)
    
    return masked


class DLPEngine:
    """
    Data Leak Prevention Engine.
    Scans responses for sensitive data leaks.
    """
    
    def __init__(self, 
                 enabled: bool = True,
                 mask_responses: bool = True,
                 block_on_leak: bool = False,
                 max_scan_size: int = 1048576,  # 1MB max response scan
                 sensitivity: str = 'high'):  # low, medium, high
        
        self.enabled = enabled
        self.mask_responses = mask_responses
        self.block_on_leak = block_on_leak
        self.max_scan_size = max_scan_size
        self.sensitivity = sensitivity
        self._stats = {
            'scanned': 0,
            'leaks_detected': 0,
            'leaks_blocked': 0,
            'leaks_masked': 0,
            'by_type': {},
        }
    
    def scan_response(self, response_body: str, content_type: str = '') -> Dict:
        """
        Scan response body for sensitive data leaks.
        
        Returns:
            {
                'has_leak': bool,
                'leaks': [{'type': str, 'category': str, 'count': int, 'severity': str}],
                'action': 'allow' | 'mask' | 'block',
                'masked_body': str (if masking enabled)
            }
        """
        if not self.enabled:
            return {'has_leak': False, 'leaks': [], 'action': 'allow'}
        
        # Skip binary content types
        if content_type and any(t in content_type.lower() for t in 
                               ['image/', 'audio/', 'video/', 'application/octet']):
            return {'has_leak': False, 'leaks': [], 'action': 'allow'}
        
        # Truncate very large responses
        scan_text = response_body[:self.max_scan_size]
        self._stats['scanned'] += 1
        
        leaks = []
        
        # === 1. Credit Card Detection ===
        for pattern, card_type in CREDIT_CARD_PATTERNS:
            matches = pattern.findall(scan_text)
            for match in matches:
                digits = ''.join(c for c in match if c.isdigit())
                if luhn_check(digits):
                    leaks.append({
                        'type': f'credit_card_{card_type}',
                        'category': 'financial',
                        'severity': 'critical',
                        'count': 1,
                    })
        
        # === 2. PII Detection ===
        for pii_type, pattern in PII_PATTERNS.items():
            matches = pattern.findall(scan_text)
            if matches:
                leaks.append({
                    'type': pii_type,
                    'category': 'pii',
                    'severity': 'high',
                    'count': len(matches),
                })
        
        # === 3. Secret/API Key Detection ===
        for secret_type, pattern in SECRET_PATTERNS.items():
            matches = pattern.findall(scan_text)
            if matches:
                leaks.append({
                    'type': secret_type,
                    'category': 'secret',
                    'severity': 'critical',
                    'count': len(matches),
                })
        
        # === 4. Internal Information Leak Detection ===
        if self.sensitivity in ('medium', 'high'):
            for leak_type, pattern in INTERNAL_LEAK_PATTERNS.items():
                matches = pattern.findall(scan_text)
                if matches:
                    leaks.append({
                        'type': leak_type,
                        'category': 'internal',
                        'severity': 'medium' if 'debug' in leak_type else 'high',
                        'count': len(matches),
                    })
        
        # === 5. Password Hash Detection ===
        if self.sensitivity == 'high':
            for hash_type, pattern in PASSWORD_HASH_PATTERNS.items():
                if hash_type in ('md5_hash', 'ntlm'):
                    continue  # Too many false positives for standalone hashes
                matches = pattern.findall(scan_text)
                if matches:
                    leaks.append({
                        'type': f'password_hash_{hash_type}',
                        'category': 'credential',
                        'severity': 'critical',
                        'count': len(matches),
                    })
        
        has_leak = len(leaks) > 0
        
        if has_leak:
            self._stats['leaks_detected'] += 1
            for leak in leaks:
                self._stats['by_type'][leak['type']] = \
                    self._stats['by_type'].get(leak['type'], 0) + leak['count']
        
        # Determine action
        action = 'allow'
        masked_body = None
        
        if has_leak:
            critical_leaks = [l for l in leaks if l['severity'] == 'critical']
            
            if self.block_on_leak and critical_leaks:
                action = 'block'
                self._stats['leaks_blocked'] += 1
            elif self.mask_responses:
                action = 'mask'
                masked_body = mask_sensitive_data(response_body)
                self._stats['leaks_masked'] += 1
            else:
                action = 'alert'
        
        return {
            'has_leak': has_leak,
            'leaks': leaks,
            'action': action,
            'masked_body': masked_body,
        }
    
    def scan_request(self, path: str, body: str, headers: Dict[str, str]) -> Dict:
        """
        Scan request for sensitive data being sent (e.g., accidental secret in URL).
        """
        leaks = []
        
        # Check URL for secrets (very bad practice)
        for secret_type, pattern in SECRET_PATTERNS.items():
            if pattern.search(path):
                leaks.append({
                    'type': f'secret_in_url_{secret_type}',
                    'category': 'secret_exposure',
                    'severity': 'critical',
                })
        
        # Check for credit cards in request body
        if body:
            for cc_pattern, card_type in CREDIT_CARD_PATTERNS:
                matches = cc_pattern.findall(body)
                for match in matches:
                    digits = ''.join(c for c in match if c.isdigit())
                    if luhn_check(digits):
                        # Only flag if not going to a known payment endpoint
                        if not any(p in path.lower() for p in ['/pay', '/checkout', '/charge', '/stripe', '/payment']):
                            leaks.append({
                                'type': f'credit_card_in_body_{card_type}',
                                'category': 'financial_exposure',
                                'severity': 'high',
                            })
        
        return {
            'has_leak': len(leaks) > 0,
            'leaks': leaks,
        }
    
    def get_stats(self) -> Dict:
        return dict(self._stats)


# Module-level singleton
_engine = None

def get_engine(**kwargs) -> DLPEngine:
    global _engine
    if _engine is None:
        _engine = DLPEngine(**kwargs)
    return _engine

def scan_response(body: str, content_type: str = '') -> Dict:
    return get_engine().scan_response(body, content_type)

def scan_request(path: str, body: str, headers: Dict) -> Dict:
    return get_engine().scan_request(path, body, headers)
