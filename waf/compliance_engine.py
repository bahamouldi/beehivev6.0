"""
BeeWAF Enterprise - OWASP Compliance Engine
============================================
Real-time compliance scoring against OWASP Top 10 (2021) and
CWE/SANS Top 25 most dangerous software weaknesses.

F5 ASM provides basic OWASP reporting. BeeWAF provides:
- Live OWASP Top 10 (2021) compliance scoring
- Per-category detection coverage metrics
- Automated gap analysis
- CWE mapping for each detection
- PCI DSS 6.6 compliance tracking
- Remediation recommendations
- Real-time compliance dashboard data
"""

import time
from typing import Dict, List
from collections import defaultdict


# ==================== OWASP TOP 10 (2021) ====================
OWASP_TOP_10 = {
    'A01:2021': {
        'name': 'Broken Access Control',
        'description': 'Restrictions on authenticated users are not properly enforced',
        'cwe_ids': ['CWE-200', 'CWE-201', 'CWE-352', 'CWE-566', 'CWE-639',
                    'CWE-862', 'CWE-863', 'CWE-913'],
        'detection_categories': [
            'path-traversal', 'lfi', 'auth_bypass', 'jwt-bypass',
            'access-denied', 'sensitive-path', 'session-violation',
            'api-security', 'privilege-escalation',
        ],
        'waf_modules': ['rules', 'session_protection', 'api_security', 'cookie_security'],
        'pci_dss': ['6.5.8', '6.5.10'],
    },
    'A02:2021': {
        'name': 'Cryptographic Failures',
        'description': 'Failures related to cryptography leading to sensitive data exposure',
        'cwe_ids': ['CWE-259', 'CWE-327', 'CWE-331', 'CWE-798'],
        'detection_categories': [
            'dlp-leak', 'weak-session-id', 'jwt-none-algorithm',
            'missing-secure-flag', 'missing-httponly-flag',
        ],
        'waf_modules': ['dlp', 'session_protection', 'cookie_security', 'response_cloaking'],
        'pci_dss': ['6.5.3', '6.5.4'],
    },
    'A03:2021': {
        'name': 'Injection',
        'description': 'SQL, NoSQL, OS, LDAP injection attacks',
        'cwe_ids': ['CWE-20', 'CWE-74', 'CWE-75', 'CWE-77', 'CWE-78',
                    'CWE-79', 'CWE-89', 'CWE-90', 'CWE-564', 'CWE-917'],
        'detection_categories': [
            'sqli', 'xss', 'cmdi', 'ldap', 'nosql', 'ssti',
            'python-injection', 'xpath', 'csv_injection',
            'el_injection', 'log_injection', 'email_injection',
            'jndi', 'deserialization',
        ],
        'waf_modules': ['rules', 'rules_extended', 'evasion_detector', 'ml_engine'],
        'pci_dss': ['6.5.1', '6.5.7'],
    },
    'A04:2021': {
        'name': 'Insecure Design',
        'description': 'Missing or ineffective control design',
        'cwe_ids': ['CWE-209', 'CWE-256', 'CWE-501', 'CWE-522'],
        'detection_categories': [
            'info_disclosure', 'rate-limit', 'brute',
        ],
        'waf_modules': ['ratelimit', 'adaptive_learning', 'response_cloaking'],
        'pci_dss': ['6.5.6'],
    },
    'A05:2021': {
        'name': 'Security Misconfiguration',
        'description': 'Missing hardening, default configs, verbose errors',
        'cwe_ids': ['CWE-2', 'CWE-11', 'CWE-13', 'CWE-15', 'CWE-16',
                    'CWE-260', 'CWE-315', 'CWE-520', 'CWE-526'],
        'detection_categories': [
            'sensitive-path', 'scanner_probe', 'server-fingerprint',
            'stack-trace', 'database-error', 'internal-info',
            'debug-info', 'host-header-injection',
        ],
        'waf_modules': ['response_cloaking', 'protocol_validator', 'threat_intel'],
        'pci_dss': ['6.5.5', '6.5.6'],
    },
    'A06:2021': {
        'name': 'Vulnerable and Outdated Components',
        'description': 'Using components with known vulnerabilities',
        'cwe_ids': ['CWE-937', 'CWE-1035', 'CWE-1104'],
        'detection_categories': [
            'exploit-campaign', 'known-attack-tool', 'cve',
            'virtual-patch',
        ],
        'waf_modules': ['threat_intel', 'virtual_patching'],
        'pci_dss': ['6.2', '6.5.6'],
    },
    'A07:2021': {
        'name': 'Identification and Authentication Failures',
        'description': 'Confirmation of identity, authentication, session management',
        'cwe_ids': ['CWE-255', 'CWE-259', 'CWE-287', 'CWE-288', 'CWE-307',
                    'CWE-384', 'CWE-613', 'CWE-640', 'CWE-798'],
        'detection_categories': [
            'brute', 'jwt-bypass', 'session-violation', 'credential-stuffing',
            'session-fixation', 'cookie-tampering', 'auth_bypass',
        ],
        'waf_modules': ['session_protection', 'cookie_security', 'bot_detector', 'ratelimit'],
        'pci_dss': ['6.5.10', '8.1', '8.2'],
    },
    'A08:2021': {
        'name': 'Software and Data Integrity Failures',
        'description': 'Code/infrastructure without integrity verification',
        'cwe_ids': ['CWE-345', 'CWE-353', 'CWE-426', 'CWE-494',
                    'CWE-502', 'CWE-565', 'CWE-784', 'CWE-829', 'CWE-830'],
        'detection_categories': [
            'deserialization', 'prototype-pollution', 'supply-chain',
            'cookie-tampering', 'csrf',
        ],
        'waf_modules': ['rules', 'cookie_security', 'session_protection', 'payload_analyzer'],
        'pci_dss': ['6.5.6'],
    },
    'A09:2021': {
        'name': 'Security Logging and Monitoring Failures',
        'description': 'Insufficient logging, detection, monitoring, response',
        'cwe_ids': ['CWE-117', 'CWE-223', 'CWE-532', 'CWE-778'],
        'detection_categories': [
            'log_injection',
        ],
        'waf_modules': ['correlation_engine'],
        'pci_dss': ['10.1', '10.2', '10.3'],
    },
    'A10:2021': {
        'name': 'Server-Side Request Forgery (SSRF)',
        'description': 'Web application fetches a remote resource without validating URL',
        'cwe_ids': ['CWE-918'],
        'detection_categories': [
            'ssrf', 'c2-callback', 'dns-exfil',
        ],
        'waf_modules': ['rules', 'threat_intel', 'geo_block'],
        'pci_dss': ['6.5.9'],
    },
}

# ==================== CWE MAPPING ====================
CWE_TO_ATTACK = {
    'CWE-89': 'sqli',
    'CWE-79': 'xss',
    'CWE-78': 'cmdi',
    'CWE-77': 'cmdi',
    'CWE-90': 'ldap',
    'CWE-22': 'path-traversal',
    'CWE-918': 'ssrf',
    'CWE-611': 'xxe',
    'CWE-917': 'ssti',
    'CWE-502': 'deserialization',
    'CWE-94': 'rce',
    'CWE-352': 'csrf',
    'CWE-307': 'brute',
    'CWE-384': 'session-fixation',
}


class ComplianceEngine:
    """
    OWASP Top 10 and PCI DSS compliance scoring engine.
    Tracks WAF detections and maps them to compliance categories.
    """

    def __init__(self):
        self._detection_counts: Dict[str, int] = defaultdict(int)
        self._category_events: Dict[str, List[Dict]] = defaultdict(list)
        self.stats = {
            'total_events': 0,
            'owasp_categories_triggered': set(),
        }

    def record_detection(self, attack_type: str, client_ip: str = '',
                         path: str = '', severity: str = 'medium') -> Dict:
        """
        Record a WAF detection and map it to OWASP/CWE categories.
        """
        self.stats['total_events'] += 1

        # Normalize attack type
        normalized = attack_type.replace('regex-', '').lower()
        self._detection_counts[normalized] += 1

        # Find which OWASP categories this maps to
        mapped_categories = []
        for owasp_id, config in OWASP_TOP_10.items():
            if normalized in config['detection_categories']:
                mapped_categories.append(owasp_id)
                self.stats['owasp_categories_triggered'].add(owasp_id)

                # Record event
                event = {
                    'timestamp': time.time(),
                    'attack_type': normalized,
                    'client_ip': client_ip,
                    'path': path,
                    'severity': severity,
                }
                self._category_events[owasp_id].append(event)
                # Keep only last 100 events per category
                if len(self._category_events[owasp_id]) > 100:
                    self._category_events[owasp_id] = self._category_events[owasp_id][-100:]

        return {
            'attack_type': normalized,
            'owasp_categories': mapped_categories,
            'cwe_ids': [cwe for cwe, at in CWE_TO_ATTACK.items() if at == normalized],
        }

    def get_owasp_score(self) -> Dict:
        """
        Calculate OWASP Top 10 compliance score.
        Returns per-category coverage and overall score.
        """
        results = {}
        total_score = 0
        max_score = 0

        for owasp_id, config in OWASP_TOP_10.items():
            # Calculate coverage: what % of detection categories are active
            active_detections = sum(
                1 for cat in config['detection_categories']
                if self._detection_counts.get(cat, 0) > 0 or cat in self._get_all_active_categories()
            )
            total_categories = len(config['detection_categories'])
            coverage = active_detections / max(total_categories, 1)

            # Count detections for this category
            category_detections = sum(
                self._detection_counts.get(cat, 0)
                for cat in config['detection_categories']
            )

            # Category score (1-10)
            category_score = min(int(coverage * 8) + (2 if len(config['waf_modules']) >= 2 else 0), 10)
            total_score += category_score
            max_score += 10

            results[owasp_id] = {
                'name': config['name'],
                'score': category_score,
                'max_score': 10,
                'coverage': round(coverage * 100, 1),
                'detections': category_detections,
                'active_modules': config['waf_modules'],
                'pci_dss_mapping': config['pci_dss'],
                'status': 'protected' if coverage >= 0.5 else 'partial' if coverage > 0 else 'unprotected',
            }

        overall_score = round((total_score / max(max_score, 1)) * 100, 1)

        return {
            'overall_score': overall_score,
            'grade': self._score_to_grade(overall_score),
            'categories': results,
            'total_detections': self.stats['total_events'],
            'categories_triggered': len(self.stats['owasp_categories_triggered']),
        }

    def _get_all_active_categories(self) -> set:
        """Get all detection categories that the WAF has rules for."""
        # These are all the categories our WAF modules cover
        return {
            'sqli', 'xss', 'cmdi', 'path-traversal', 'ssrf', 'xxe',
            'ldap', 'nosql', 'jndi', 'php-filter', 'ssti', 'jsp',
            'lfi', 'python-injection', 'jar-protocol', 'graphql',
            'deserialization', 'prototype-pollution', 'jwt-bypass',
            'hex-encoding', 'brute', 'rce', 'info_disclosure',
            'auth_bypass', 'scanner_probe', 'encoding_evasion',
            'waf_bypass', 'log_injection', 'email_injection',
            'xpath', 'csv_injection', 'el_injection',
            'crlf', 'open_redirect', 'request_smuggling',
            'cache_poisoning', 'websocket', 'cors_bypass',
            'dlp-leak', 'bot-detected', 'rate-limit', 'geo-blocked',
            'protocol-violation', 'threat-intel', 'session-violation',
            'exploit-campaign', 'known-attack-tool', 'c2-callback',
            'cookie-tampering', 'virtual-patch',
            'access-denied', 'sensitive-path', 'host-header-injection',
        }

    def _score_to_grade(self, score: float) -> str:
        if score >= 90:
            return 'A+'
        elif score >= 85:
            return 'A'
        elif score >= 80:
            return 'A-'
        elif score >= 75:
            return 'B+'
        elif score >= 70:
            return 'B'
        elif score >= 65:
            return 'B-'
        elif score >= 60:
            return 'C+'
        elif score >= 50:
            return 'C'
        elif score >= 40:
            return 'D'
        else:
            return 'F'

    def get_gap_analysis(self) -> List[Dict]:
        """Identify gaps in OWASP Top 10 coverage."""
        gaps = []
        score_data = self.get_owasp_score()

        for owasp_id, data in score_data['categories'].items():
            if data['status'] != 'protected':
                config = OWASP_TOP_10[owasp_id]
                uncovered = [
                    cat for cat in config['detection_categories']
                    if cat not in self._get_all_active_categories()
                ]
                gaps.append({
                    'owasp_id': owasp_id,
                    'name': data['name'],
                    'current_score': data['score'],
                    'coverage': data['coverage'],
                    'uncovered_categories': uncovered,
                    'recommendation': f'Enable/enhance modules: {", ".join(config["waf_modules"])}',
                })

        return gaps

    def get_pci_dss_status(self) -> Dict:
        """Get PCI DSS 6.6 compliance status."""
        pci_requirements = defaultdict(list)
        for owasp_id, config in OWASP_TOP_10.items():
            for req in config['pci_dss']:
                pci_requirements[req].append(owasp_id)

        status = {}
        score_data = self.get_owasp_score()
        for req, owasp_ids in pci_requirements.items():
            covered = all(
                score_data['categories'][oid]['status'] in ('protected', 'partial')
                for oid in owasp_ids
            )
            status[req] = {
                'compliant': covered,
                'related_owasp': owasp_ids,
            }

        return {
            'pci_dss_6_6': all(s['compliant'] for s in status.values()),
            'requirements': status,
        }

    def get_stats(self) -> Dict:
        stats = {
            'total_events': self.stats['total_events'],
            'categories_triggered': len(self.stats['owasp_categories_triggered']),
            'detection_counts': dict(self._detection_counts),
        }
        score = self.get_owasp_score()
        stats['overall_score'] = score['overall_score']
        stats['grade'] = score['grade']
        return stats


# ==================== SINGLETON ====================
_engine = None

def get_engine() -> ComplianceEngine:
    global _engine
    if _engine is None:
        _engine = ComplianceEngine()
    return _engine

def record_detection(attack_type: str, **kwargs) -> Dict:
    return get_engine().record_detection(attack_type, **kwargs)

def get_owasp_score() -> Dict:
    return get_engine().get_owasp_score()

def get_pci_status() -> Dict:
    return get_engine().get_pci_dss_status()
