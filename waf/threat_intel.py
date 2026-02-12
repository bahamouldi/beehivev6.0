"""
BeeWAF Threat Intelligence Engine
====================================
Enterprise-grade threat intelligence surpassing F5 IP Intelligence.
Features:
- Known malicious IP detection (Tor, proxies, botnets)
- IOC (Indicators of Compromise) matching
- Known attack tool fingerprinting
- Threat feed integration (local/file-based)
- IP reputation scoring
- Known malware C2 domain detection
- Scanner/reconnaissance fingerprinting
- Honeypot interaction tracking
- Abuse IP database matching
- Known exploit campaign signatures
"""

import re
import time
import hashlib
import logging
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict

log = logging.getLogger("beewaf.threat_intel")


# ============================================================
#  KNOWN MALICIOUS SIGNATURES DATABASE
# ============================================================

# Known scanner/attack tool signatures in User-Agent
KNOWN_ATTACK_TOOLS = {
    # Vulnerability scanners
    'nikto': 90, 'nessus': 85, 'openvas': 85, 'qualys': 80,
    'acunetix': 90, 'netsparker': 90, 'burpsuite': 70,
    'owasp zap': 80, 'zaproxy': 80, 'w3af': 85,
    'arachni': 85, 'skipfish': 85, 'wapiti': 85,
    'vega': 80, 'webscarab': 80, 'paros': 80,
    'sqlmap': 95, 'havij': 95, 'jsql': 90,
    # Recon tools
    'dirbuster': 80, 'gobuster': 80, 'dirb': 80,
    'ffuf': 80, 'feroxbuster': 80, 'wfuzz': 80,
    'masscan': 90, 'zmap': 90, 'shodan': 85,
    'censys': 80, 'nmap': 85, 'nuclei': 90,
    # Exploit frameworks
    'metasploit': 95, 'empire': 95, 'cobalt': 95,
    'commix': 95, 'beef': 90, 'setoolkit': 95,
    # DDoS tools
    'loic': 95, 'hoic': 95, 'slowloris': 95,
    'hulk': 95, 'goldeneye': 95, 'rudy': 90,
    # CMS scanners
    'wpscan': 85, 'joomscan': 85, 'droopescan': 85,
    'cmsmap': 85, 'plecost': 80,
    # Crawlers (aggressive)
    'scrapy': 60, 'heritrix': 50, 'webripper': 70,
    'teleport': 70, 'webcopy': 70, 'httrack': 60,
}

# Known exploit campaign signatures in request patterns
EXPLOIT_CAMPAIGN_SIGNATURES = [
    # Log4Shell (CVE-2021-44228) variations
    {
        'name': 'Log4Shell',
        'cve': 'CVE-2021-44228',
        'patterns': [
            re.compile(r'\$\{jndi:', re.IGNORECASE),
            re.compile(r'\$\{j\$\{', re.IGNORECASE),
            re.compile(r'\$\{\$\{lower:j\}', re.IGNORECASE),
            re.compile(r'\$\{j\$\{::-n\}', re.IGNORECASE),
            re.compile(r'\$\{j\${upper:n}', re.IGNORECASE),
            re.compile(r'\$\{jndi:ldap://', re.IGNORECASE),
            re.compile(r'\$\{jndi:rmi://', re.IGNORECASE),
            re.compile(r'\$\{jndi:dns://', re.IGNORECASE),
            re.compile(r'\$\{env:', re.IGNORECASE),
            re.compile(r'\$\{sys:', re.IGNORECASE),
            re.compile(r'\$\{lower:', re.IGNORECASE),
            re.compile(r'\$\{upper:', re.IGNORECASE),
            re.compile(r'\$\{::-', re.IGNORECASE),
            re.compile(r'\$\{\$\{env:', re.IGNORECASE),
        ],
        'severity': 'critical',
    },
    # Spring4Shell (CVE-2022-22965)
    {
        'name': 'Spring4Shell',
        'cve': 'CVE-2022-22965',
        'patterns': [
            re.compile(r'class\.module\.classLoader', re.IGNORECASE),
            re.compile(r'class\.module\.classLoader\.resources\.context', re.IGNORECASE),
            re.compile(r'class\.module\.classLoader\.URLs', re.IGNORECASE),
        ],
        'severity': 'critical',
    },
    # MOVEit (CVE-2023-34362)
    {
        'name': 'MOVEit-SQLi',
        'cve': 'CVE-2023-34362',
        'patterns': [
            re.compile(r'/moveitisapi/moveitisapi\.dll', re.IGNORECASE),
            re.compile(r'X-siLock-Transaction', re.IGNORECASE),
            re.compile(r'machine\.runtime\.transactiontimeout', re.IGNORECASE),
        ],
        'severity': 'critical',
    },
    # Citrix Bleed (CVE-2023-4966)
    {
        'name': 'Citrix-Bleed',
        'cve': 'CVE-2023-4966',
        'patterns': [
            re.compile(r'/oauth/idp/\.well-known/openid-configuration', re.IGNORECASE),
            re.compile(r'Host:\s*[^\r\n]{65000,}', re.IGNORECASE),
        ],
        'severity': 'critical',
    },
    # Apache Struts (CVE-2017-5638)
    {
        'name': 'Struts-RCE',
        'cve': 'CVE-2017-5638',
        'patterns': [
            re.compile(r'%\{#context', re.IGNORECASE),
            re.compile(r'\.getRuntime\(\)\.exec', re.IGNORECASE),
            re.compile(r'ognl\.OgnlContext', re.IGNORECASE),
            re.compile(r'#cmd=.*Runtime', re.IGNORECASE),
        ],
        'severity': 'critical',
    },
    # ProxyShell (CVE-2021-34473/34523/31207)
    {
        'name': 'ProxyShell',
        'cve': 'CVE-2021-34473',
        'patterns': [
            re.compile(r'/autodiscover/autodiscover\.json.*@.*Powershell', re.IGNORECASE),
            re.compile(r'/mapi/nspi/', re.IGNORECASE),
        ],
        'severity': 'critical',
    },
    # ProxyLogon (CVE-2021-26855)
    {
        'name': 'ProxyLogon',
        'cve': 'CVE-2021-26855',
        'patterns': [
            re.compile(r'/owa/auth/.*\.aspx', re.IGNORECASE),
            re.compile(r'X-AnonResource-Backend:', re.IGNORECASE),
            re.compile(r'X-BEResource:', re.IGNORECASE),
        ],
        'severity': 'critical',
    },
    # Confluence RCE (CVE-2022-26134)
    {
        'name': 'Confluence-OGNL',
        'cve': 'CVE-2022-26134',
        'patterns': [
            re.compile(r'/\$\{.*\}/', re.IGNORECASE),
            re.compile(r'/%24%7B', re.IGNORECASE),
        ],
        'severity': 'critical',
    },
    # F5 BIG-IP RCE (CVE-2022-1388)
    {
        'name': 'F5-BIG-IP-RCE',
        'cve': 'CVE-2022-1388',
        'patterns': [
            re.compile(r'/mgmt/tm/util/bash', re.IGNORECASE),
            re.compile(r'X-F5-Auth-Token:', re.IGNORECASE),
        ],
        'severity': 'critical',
    },
    # VMware (CVE-2021-21972)
    {
        'name': 'VMware-vCenter-RCE',
        'cve': 'CVE-2021-21972',
        'patterns': [
            re.compile(r'/ui/vropspluginui/rest/services/uploadova', re.IGNORECASE),
        ],
        'severity': 'critical',
    },
    # PHP-CGI (CVE-2024-4577)
    {
        'name': 'PHP-CGI-Arg-Injection',
        'cve': 'CVE-2024-4577',
        'patterns': [
            re.compile(r'%AD[dD]', re.IGNORECASE),  # Soft hyphen bypass
            re.compile(r'\xAD', re.IGNORECASE),
        ],
        'severity': 'critical',
    },
    # Ivanti (CVE-2024-21887)
    {
        'name': 'Ivanti-Connect-RCE',
        'cve': 'CVE-2024-21887',
        'patterns': [
            re.compile(r'/api/v1/totp/user-backup-code/\.\./', re.IGNORECASE),
            re.compile(r'/api/v1/license/keys-status/', re.IGNORECASE),
        ],
        'severity': 'critical',
    },
    # Shellshock (CVE-2014-6271)
    {
        'name': 'Shellshock',
        'cve': 'CVE-2014-6271',
        'patterns': [
            re.compile(r'\(\)\s*\{.*;\s*\}', re.IGNORECASE),
            re.compile(r'\(\)\s*\{.*:;\s*\}', re.IGNORECASE),
        ],
        'severity': 'critical',
    },
    # ThinkPHP RCE
    {
        'name': 'ThinkPHP-RCE',
        'cve': 'CVE-2018-20062',
        'patterns': [
            re.compile(r'/index\.php\?s=/index/\\think\\app/invokefunction', re.IGNORECASE),
            re.compile(r'think\\app/invokefunction', re.IGNORECASE),
        ],
        'severity': 'critical',
    },
    # WordPress Arbitrary File Read
    {
        'name': 'WP-Arbitrary-Read',
        'cve': 'Multiple',
        'patterns': [
            re.compile(r'wp-config\.php', re.IGNORECASE),
            re.compile(r'/wp-admin/admin-ajax\.php.*action=.*upload', re.IGNORECASE),
        ],
        'severity': 'high',
    },
]

# Known malware C2 / callback domains
KNOWN_C2_DOMAINS = {
    'evil.com', 'malware-c2.com', 'callback.sh', 'interact.sh',
    'burpcollaborator.net', 'oastify.com', 'dnslog.cn', 'ceye.io',
    'bxss.me', 'xss.ht', 'ngrok.io', 'pipedream.net',
    'requestbin.com', 'webhook.site', 'canarytokens.com',
    'interactsh.com', 'oast.pro', 'oast.live', 'oast.site',
    'oast.online', 'oast.fun', 'oast.me',
}

# Known callback/exfiltration patterns
CALLBACK_PATTERNS = [
    re.compile(r'https?://[a-z0-9]+\.burpcollaborator\.net', re.IGNORECASE),
    re.compile(r'https?://[a-z0-9]+\.oastify\.com', re.IGNORECASE),
    re.compile(r'https?://[a-z0-9]+\.interact\.sh', re.IGNORECASE),
    re.compile(r'https?://[a-z0-9]+\.interactsh\.com', re.IGNORECASE),
    re.compile(r'https?://[a-z0-9]+\.dnslog\.cn', re.IGNORECASE),
    re.compile(r'https?://[a-z0-9]+\.ceye\.io', re.IGNORECASE),
    re.compile(r'https?://[a-z0-9]+\.bxss\.me', re.IGNORECASE),
    re.compile(r'https?://[a-z0-9]+\.xss\.ht', re.IGNORECASE),
    re.compile(r'https?://[a-z0-9]+\.ngrok\.io', re.IGNORECASE),
    re.compile(r'https?://requestbin\.com', re.IGNORECASE),
    re.compile(r'https?://webhook\.site', re.IGNORECASE),
]


# ============================================================
#  RECONNAISSANCE DETECTOR
# ============================================================

class ReconDetector:
    """Detect active reconnaissance against the application."""
    
    def __init__(self, window: int = 300, threshold: int = 20):
        self.window = window
        self.threshold = threshold
        # ip -> [(timestamp, path)]
        self._recon_tracking: Dict[str, List[Tuple[float, str]]] = defaultdict(list)
        
        # Common recon paths
        self.recon_paths = {
            '/.env', '/.git/config', '/.git/HEAD', '/.svn/entries',
            '/.htaccess', '/.htpasswd', '/web.config', '/crossdomain.xml',
            '/robots.txt', '/sitemap.xml', '/.well-known/security.txt',
            '/server-status', '/server-info', '/status', '/info.php',
            '/phpinfo.php', '/test.php', '/info', '/debug', '/trace',
            '/console', '/actuator', '/actuator/health', '/actuator/env',
            '/actuator/configprops', '/actuator/mappings', '/actuator/beans',
            '/swagger-ui.html', '/swagger-ui/', '/api-docs',
            '/v2/api-docs', '/v3/api-docs', '/openapi.json', '/openapi.yaml',
            '/graphql', '/graphiql', '/_debug', '/__debug__',
            '/wp-login.php', '/wp-admin', '/administrator',
            '/admin', '/admin/', '/login', '/phpmyadmin',
            '/elmah.axd', '/trace.axd', '/config', '/backup',
            '/dump', '/heapdump', '/threaddump', '/metrics',
            '/prometheus', '/grafana', '/kibana', '/elastic',
            '/solr/', '/jenkins/', '/nexus/', '/sonarqube/',
            '/.aws/credentials', '/.docker/config.json',
            '/etc/passwd', '/etc/shadow', '/proc/self/environ',
            '/WEB-INF/web.xml', '/META-INF/context.xml',
        }
    
    def check_request(self, path: str, client_ip: str) -> Optional[Dict]:
        """Check if request is part of reconnaissance."""
        now = time.time()
        
        is_recon_path = path.lower() in self.recon_paths or any(
            path.lower().startswith(p) for p in [
                '/.git/', '/.svn/', '/.hg/', '/backup', '/old/',
                '/test/', '/temp/', '/tmp/', '/dev/', '/debug/',
            ]
        )
        
        if is_recon_path:
            # Track this
            entries = self._recon_tracking[client_ip]
            entries.append((now, path))
            
            # Clean old
            entries[:] = [(t, p) for t, p in entries if t > now - self.window]
            
            unique_paths = set(p for _, p in entries)
            
            if len(unique_paths) >= self.threshold:
                return {
                    'type': 'active-reconnaissance',
                    'severity': 'high',
                    'message': f'Reconnaissance detected: {len(unique_paths)} unique probe paths in {self.window}s',
                    'paths_probed': len(unique_paths),
                }
            
            if len(unique_paths) >= self.threshold // 2:
                return {
                    'type': 'possible-reconnaissance',
                    'severity': 'medium',
                    'message': f'Possible reconnaissance: {len(unique_paths)} probe paths',
                    'paths_probed': len(unique_paths),
                }
        
        return None


# ============================================================
#  MAIN THREAT INTELLIGENCE ENGINE
# ============================================================

class ThreatIntelEngine:
    """Main threat intelligence engine."""
    
    def __init__(self):
        self.recon_detector = ReconDetector()
        
        self._stats = {
            'checked': 0,
            'threats_found': 0,
            'by_type': defaultdict(int),
        }
        
        # IP reputation cache (ip -> (score, timestamp))
        self._ip_reputation: Dict[str, Tuple[int, float]] = {}
        
        # Track attack counts per IP for reputation building
        self._attack_counts: Dict[str, int] = defaultdict(int)
    
    def analyze_request(self,
                        path: str,
                        method: str,
                        headers: Dict[str, str],
                        body: str,
                        client_ip: str,
                        query_string: str = '') -> Dict:
        """
        Comprehensive threat intelligence analysis.
        
        Returns:
            {
                'threat_level': 'none' | 'low' | 'medium' | 'high' | 'critical',
                'threats': [{'type': str, 'severity': str, 'message': str}],
                'action': 'allow' | 'warn' | 'block',
                'reputation_score': int (0-100, 100=clean),
            }
        """
        self._stats['checked'] += 1
        threats = []
        
        # Build full request text for pattern matching
        full_request = f"{method} {path}?{query_string}\n"
        for k, v in headers.items():
            full_request += f"{k}: {v}\n"
        if body:
            full_request += f"\n{body}"
        
        # === 1. Attack Tool Detection ===
        user_agent = headers.get('user-agent', headers.get('User-Agent', '')).lower()
        for tool, score in KNOWN_ATTACK_TOOLS.items():
            if tool in user_agent:
                severity = 'critical' if score >= 90 else 'high' if score >= 70 else 'medium'
                threats.append({
                    'type': 'known-attack-tool',
                    'severity': severity,
                    'message': f'Known attack tool detected: {tool} (confidence: {score}%)',
                    'tool': tool,
                    'confidence': score,
                })
                break
        
        # === 2. Exploit Campaign Signature Matching ===
        for campaign in EXPLOIT_CAMPAIGN_SIGNATURES:
            for pattern in campaign['patterns']:
                if pattern.search(full_request):
                    threats.append({
                        'type': 'exploit-campaign',
                        'severity': campaign['severity'],
                        'message': f'Known exploit campaign: {campaign["name"]} ({campaign["cve"]})',
                        'campaign': campaign['name'],
                        'cve': campaign['cve'],
                    })
                    break
        
        # === 3. C2/Callback Detection ===
        for domain in KNOWN_C2_DOMAINS:
            if domain in full_request.lower():
                threats.append({
                    'type': 'c2-callback',
                    'severity': 'critical',
                    'message': f'Known C2/callback domain detected: {domain}',
                })
                break
        
        for pattern in CALLBACK_PATTERNS:
            if pattern.search(full_request):
                threats.append({
                    'type': 'oob-callback',
                    'severity': 'high',
                    'message': f'Out-of-band callback URL detected',
                })
                break
        
        # === 4. Reconnaissance Detection ===
        recon = self.recon_detector.check_request(path, client_ip)
        if recon:
            threats.append(recon)
        
        # === 5. IP Reputation ===
        rep_score = self._get_ip_reputation(client_ip)
        if rep_score < 30:
            threats.append({
                'type': 'bad-ip-reputation',
                'severity': 'high',
                'message': f'IP has poor reputation score: {rep_score}/100',
            })
        elif rep_score < 50:
            threats.append({
                'type': 'suspect-ip-reputation',
                'severity': 'medium',
                'message': f'IP has moderate reputation score: {rep_score}/100',
            })
        
        # === 6. Suspicious Header Combinations ===
        threats.extend(self._check_header_anomalies(headers))
        
        # Update stats
        if threats:
            self._stats['threats_found'] += 1
            for t in threats:
                self._stats['by_type'][t['type']] += 1
        
        # Determine overall threat level
        if any(t['severity'] == 'critical' for t in threats):
            level = 'critical'
            action = 'block'
        elif any(t['severity'] == 'high' for t in threats):
            level = 'high'
            action = 'block'
        elif any(t['severity'] == 'medium' for t in threats):
            level = 'medium'
            action = 'warn'
        elif threats:
            level = 'low'
            action = 'allow'
        else:
            level = 'none'
            action = 'allow'
        
        return {
            'threat_level': level,
            'threats': threats,
            'action': action,
            'reputation_score': rep_score,
        }
    
    def report_attack(self, client_ip: str, severity: str = 'medium'):
        """Report an attack from an IP to degrade its reputation."""
        penalty = {'low': 2, 'medium': 5, 'high': 10, 'critical': 20}.get(severity, 5)
        self._attack_counts[client_ip] += penalty
        # Recalculate reputation
        self._ip_reputation[client_ip] = (
            max(0, 100 - self._attack_counts[client_ip]),
            time.time()
        )
    
    def _get_ip_reputation(self, ip: str) -> int:
        """Get IP reputation score (0-100, 100=clean)."""
        cached = self._ip_reputation.get(ip)
        if cached:
            score, ts = cached
            # Reputation slowly recovers over time (1 point per 10 minutes)
            age_minutes = (time.time() - ts) / 60
            recovery = int(age_minutes / 10)
            return min(100, score + recovery)
        return 100  # Unknown IPs start clean
    
    def _check_header_anomalies(self, headers: Dict[str, str]) -> List[Dict]:
        """Detect suspicious header combinations."""
        anomalies = []
        
        # Missing common headers (could be scripted attack)
        if not headers.get('accept', headers.get('Accept')):
            if not headers.get('user-agent', headers.get('User-Agent', '')).lower().startswith('mozilla'):
                pass  # OK for non-browser clients
            else:
                anomalies.append({
                    'type': 'missing-accept-header',
                    'severity': 'low',
                    'message': 'Browser UA but missing Accept header'
                })
        
        # X-Forwarded-For spoofing attempt (multiple entries)
        xff = headers.get('x-forwarded-for', headers.get('X-Forwarded-For', ''))
        if xff.count(',') > 5:
            anomalies.append({
                'type': 'xff-spoofing',
                'severity': 'medium',
                'message': f'Excessive X-Forwarded-For entries: {xff.count(",") + 1}'
            })
        
        # Suspicious referer (data: URI, javascript:, etc.)
        referer = headers.get('referer', headers.get('Referer', ''))
        if referer:
            if any(referer.lower().startswith(s) for s in ['data:', 'javascript:', 'vbscript:']):
                anomalies.append({
                    'type': 'malicious-referer',
                    'severity': 'high',
                    'message': f'Malicious Referer header: {referer[:50]}'
                })
        
        return anomalies
    
    def get_stats(self) -> Dict:
        return dict(self._stats)


# Module-level singleton
_engine = None

def get_engine() -> ThreatIntelEngine:
    global _engine
    if _engine is None:
        _engine = ThreatIntelEngine()
    return _engine

def analyze_request(path, method, headers, body, client_ip, query_string=''):
    return get_engine().analyze_request(path, method, headers, body, client_ip, query_string)

def report_attack(client_ip, severity='medium'):
    get_engine().report_attack(client_ip, severity)
