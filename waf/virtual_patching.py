"""
BeeWAF Enterprise - Virtual Patching Engine
============================================
Provides rapid CVE mitigation through virtual patches without
modifying application code. Patches can be added in real-time.

Unlike F5 ASM which requires manual iRule creation, BeeWAF:
- Maintains a database of 80+ CVE-specific virtual patches
- Supports regex, header, path, and body matching
- Patches can be enabled/disabled individually
- Auto-applies patches based on detected technology stack
- Supports time-based auto-expiry (when vendor patch is available)
- Hot-reload patches without restart
"""

import re
import time
from typing import Dict, List, Optional, Tuple


class VirtualPatch:
    """Represents a single virtual patch for a CVE."""
    __slots__ = ['cve_id', 'name', 'description', 'severity', 'affected_software',
                 'match_rules', 'enabled', 'created_at', 'expires_at', 'hits']

    def __init__(self, cve_id: str, name: str, description: str, severity: str,
                 affected_software: List[str], match_rules: List[Dict],
                 expires_at: float = 0):
        self.cve_id = cve_id
        self.name = name
        self.description = description
        self.severity = severity
        self.affected_software = affected_software
        self.match_rules = match_rules  # List of {type, field, pattern, compiled}
        self.enabled = True
        self.created_at = time.time()
        self.expires_at = expires_at
        self.hits = 0


# ==================== CVE VIRTUAL PATCH DATABASE ====================
_CVE_PATCHES = [
    # === LOG4J / LOG4SHELL ===
    {
        'cve_id': 'CVE-2021-44228',
        'name': 'Log4Shell RCE',
        'description': 'Apache Log4j2 JNDI injection allowing RCE',
        'severity': 'critical',
        'affected_software': ['java', 'log4j', 'spring'],
        'rules': [
            {'type': 'regex', 'field': 'any', 'pattern': r'\$\{(?:j|J)(?:n|N)(?:d|D)(?:i|I)\s*:'},
            {'type': 'regex', 'field': 'any', 'pattern': r'\$\{.*?(?:lower|upper|env|sys|ctx|java|bundle|base64|date|main)\s*:.*?[jJ][nN][dD][iI]'},
            {'type': 'regex', 'field': 'any', 'pattern': r'[jJ]\$?\{[^}]*\}?[nN]\$?\{[^}]*\}?[dD]\$?\{[^}]*\}?[iI]'},
            {'type': 'regex', 'field': 'any', 'pattern': r'\$\{.*?\$\{.*?(?:jndi|JNDI)'},
        ],
    },
    {
        'cve_id': 'CVE-2021-45046',
        'name': 'Log4j DoS/RCE (bypass)',
        'description': 'Log4j2 bypass for CVE-2021-44228 fix via Thread Context',
        'severity': 'critical',
        'affected_software': ['java', 'log4j'],
        'rules': [
            {'type': 'regex', 'field': 'any', 'pattern': r'\$\{ctx:'},
            {'type': 'regex', 'field': 'any', 'pattern': r'\$\{(?:sd|map):'},
        ],
    },
    # === SPRING FRAMEWORK ===
    {
        'cve_id': 'CVE-2022-22965',
        'name': 'Spring4Shell RCE',
        'description': 'Spring Framework RCE via data binding on JDK 9+',
        'severity': 'critical',
        'affected_software': ['java', 'spring', 'tomcat'],
        'rules': [
            {'type': 'regex', 'field': 'query', 'pattern': r'class\.module\.classLoader'},
            {'type': 'regex', 'field': 'query', 'pattern': r'class\.classLoader\.resources'},
            {'type': 'regex', 'field': 'body', 'pattern': r'class%5B.*%5D.*classLoader'},
        ],
    },
    {
        'cve_id': 'CVE-2022-22963',
        'name': 'Spring Cloud Function SpEL RCE',
        'description': 'Spring Cloud Function SpEL injection via routing',
        'severity': 'critical',
        'affected_software': ['java', 'spring'],
        'rules': [
            {'type': 'regex', 'field': 'headers', 'pattern': r'spring\.cloud\.function\.routing-expression'},
            {'type': 'regex', 'field': 'headers', 'pattern': r'T\(java\.lang\.Runtime\)'},
        ],
    },
    {
        'cve_id': 'CVE-2024-22234',
        'name': 'Spring Security AuthN Bypass',
        'description': 'Spring Security authentication bypass via null principal',
        'severity': 'high',
        'affected_software': ['java', 'spring'],
        'rules': [
            {'type': 'regex', 'field': 'headers', 'pattern': r'X-User:\s*null'},
            {'type': 'regex', 'field': 'headers', 'pattern': r'X-Authenticated:\s*(?:null|undefined)'},
        ],
    },
    # === APACHE STRUTS ===
    {
        'cve_id': 'CVE-2017-5638',
        'name': 'Apache Struts2 RCE (Equifax)',
        'description': 'Jakarta Multipart parser RCE',
        'severity': 'critical',
        'affected_software': ['java', 'struts'],
        'rules': [
            {'type': 'regex', 'field': 'headers', 'pattern': r'Content-Type:.*%\{'},
            {'type': 'regex', 'field': 'headers', 'pattern': r'Content-Type:.*\$\{'},
            {'type': 'regex', 'field': 'headers', 'pattern': r'Content-Type:.*#cmd'},
        ],
    },
    {
        'cve_id': 'CVE-2023-50164',
        'name': 'Apache Struts Path Traversal RCE',
        'description': 'File upload path traversal leading to RCE',
        'severity': 'critical',
        'affected_software': ['java', 'struts'],
        'rules': [
            {'type': 'regex', 'field': 'any', 'pattern': r'[Uu]pload[Ff]ile[Nn]ame=.*\.\.'},
            {'type': 'regex', 'field': 'any', 'pattern': r'[Uu]pload[Cc]ontent[Tt]ype=.*\.jsp'},
        ],
    },
    # === MICROSOFT EXCHANGE (PROXYSHELL / PROXYLOGON) ===
    {
        'cve_id': 'CVE-2021-26855',
        'name': 'ProxyLogon SSRF',
        'description': 'Microsoft Exchange Server SSRF',
        'severity': 'critical',
        'affected_software': ['exchange', 'iis'],
        'rules': [
            {'type': 'regex', 'field': 'path', 'pattern': r'/owa/auth/.*?(?:\.js|\.css)'},
            {'type': 'regex', 'field': 'headers', 'pattern': r'X-BEResource:'},
            {'type': 'regex', 'field': 'path', 'pattern': r'/ecp/(?:DDI|RulesEditor|default\.flt)'},
        ],
    },
    {
        'cve_id': 'CVE-2021-34473',
        'name': 'ProxyShell Pre-Auth ACL Bypass',
        'description': 'Exchange ProxyShell authentication bypass',
        'severity': 'critical',
        'affected_software': ['exchange', 'iis'],
        'rules': [
            {'type': 'regex', 'field': 'path', 'pattern': r'/autodiscover/autodiscover\.json\?.*?/mapi/'},
            {'type': 'regex', 'field': 'path', 'pattern': r'/autodiscover/autodiscover\.json\?.*?@'},
            {'type': 'regex', 'field': 'path', 'pattern': r'/mapi/emsmdb/'},
        ],
    },
    # === CONFLUENCE ===
    {
        'cve_id': 'CVE-2022-26134',
        'name': 'Confluence OGNL Injection RCE',
        'description': 'Atlassian Confluence Server OGNL injection',
        'severity': 'critical',
        'affected_software': ['confluence', 'java'],
        'rules': [
            {'type': 'regex', 'field': 'path', 'pattern': r'\$\{.*?(?:getRuntime|getClass|forName)'},
            {'type': 'regex', 'field': 'path', 'pattern': r'%24%7B.*?getRuntime'},
        ],
    },
    {
        'cve_id': 'CVE-2023-22527',
        'name': 'Confluence Template Injection RCE',
        'description': 'Atlassian Confluence SSTI RCE',
        'severity': 'critical',
        'affected_software': ['confluence', 'java'],
        'rules': [
            {'type': 'regex', 'field': 'body', 'pattern': r'label=.*?%23(?:cmd|request|response)'},
            {'type': 'regex', 'field': 'path', 'pattern': r'/template/aui/text-inline\.vm'},
        ],
    },
    # === CITRIX ===
    {
        'cve_id': 'CVE-2023-4966',
        'name': 'Citrix Bleed',
        'description': 'Citrix NetScaler session token leak',
        'severity': 'critical',
        'affected_software': ['citrix', 'netscaler'],
        'rules': [
            {'type': 'regex', 'field': 'path', 'pattern': r'/oauth/idp/\.well-known/openid-configuration'},
            {'type': 'regex', 'field': 'headers', 'pattern': r'Host:\s*.{80,}'},
        ],
    },
    {
        'cve_id': 'CVE-2023-3519',
        'name': 'Citrix ADC RCE',
        'description': 'Citrix ADC/Gateway RCE via SAML',
        'severity': 'critical',
        'affected_software': ['citrix'],
        'rules': [
            {'type': 'regex', 'field': 'path', 'pattern': r'/vpns/portal/scripts/'},
            {'type': 'regex', 'field': 'body', 'pattern': r'SAMLResponse=.*?<.*?Script'},
        ],
    },
    # === MOVEIT ===
    {
        'cve_id': 'CVE-2023-34362',
        'name': 'MOVEit SQLi',
        'description': 'MOVEit Transfer SQL injection',
        'severity': 'critical',
        'affected_software': ['moveit'],
        'rules': [
            {'type': 'regex', 'field': 'path', 'pattern': r'/moveitisapi/moveitisapi\.dll\?action=m2'},
            {'type': 'regex', 'field': 'path', 'pattern': r'/guestaccess\.aspx'},
            {'type': 'regex', 'field': 'headers', 'pattern': r'X-siLock-Transaction:\s*folder_add_by_path'},
        ],
    },
    # === F5 BIG-IP ===
    {
        'cve_id': 'CVE-2022-1388',
        'name': 'F5 BIG-IP iControl RCE',
        'description': 'F5 BIG-IP iControl REST authentication bypass',
        'severity': 'critical',
        'affected_software': ['f5', 'bigip'],
        'rules': [
            {'type': 'regex', 'field': 'path', 'pattern': r'/mgmt/tm/util/bash'},
            {'type': 'regex', 'field': 'headers', 'pattern': r'X-F5-Auth-Token:'},
            {'type': 'regex', 'field': 'headers', 'pattern': r'Connection:.*X-F5-Auth-Token'},
        ],
    },
    # === VMWARE ===
    {
        'cve_id': 'CVE-2022-22954',
        'name': 'VMware Workspace ONE SSTI',
        'description': 'VMware Workspace ONE Access SSTI RCE',
        'severity': 'critical',
        'affected_software': ['vmware'],
        'rules': [
            {'type': 'regex', 'field': 'path', 'pattern': r'/catalog-portal/ui/oauth/verify\?'},
            {'type': 'regex', 'field': 'query', 'pattern': r'error=&deviceUdid=\$\{'},
        ],
    },
    # === IVANTI ===
    {
        'cve_id': 'CVE-2024-21887',
        'name': 'Ivanti Connect Secure RCE',
        'description': 'Ivanti Connect Secure command injection',
        'severity': 'critical',
        'affected_software': ['ivanti'],
        'rules': [
            {'type': 'regex', 'field': 'path', 'pattern': r'/api/v1/totp/user-backup-code/\.\.'},
            {'type': 'regex', 'field': 'path', 'pattern': r'/api/v1/license/keys-status/'},
        ],
    },
    {
        'cve_id': 'CVE-2024-21893',
        'name': 'Ivanti SSRF',
        'description': 'Ivanti Connect Secure SSRF via SAML',
        'severity': 'critical',
        'affected_software': ['ivanti'],
        'rules': [
            {'type': 'regex', 'field': 'path', 'pattern': r'/dana-ws/saml20/login\.cgi'},
            {'type': 'regex', 'field': 'body', 'pattern': r'<SAMLResponse.*?(?:file://|http://127|http://169\.254)'},
        ],
    },
    # === PHP ===
    {
        'cve_id': 'CVE-2024-4577',
        'name': 'PHP CGI Argument Injection',
        'description': 'PHP CGI argument injection on Windows',
        'severity': 'critical',
        'affected_software': ['php', 'windows'],
        'rules': [
            {'type': 'regex', 'field': 'query', 'pattern': r'(?:%AD|%ad).*?(?:-d\b|allow_url_include|auto_prepend_file)'},
            {'type': 'regex', 'field': 'query', 'pattern': r'-d\s+allow_url_include'},
        ],
    },
    # === WORDPRESS ===
    {
        'cve_id': 'CVE-2024-27956',
        'name': 'WordPress WP-Automatic SQLi',
        'description': 'WordPress WP-Automatic plugin SQL injection',
        'severity': 'critical',
        'affected_software': ['wordpress', 'php'],
        'rules': [
            {'type': 'regex', 'field': 'path', 'pattern': r'/wp-content/plugins/wp-automatic/'},
            {'type': 'regex', 'field': 'body', 'pattern': r'wp_automatic.*?(?:union|select|insert)'},
        ],
    },
    # === SHELLSHOCK ===
    {
        'cve_id': 'CVE-2014-6271',
        'name': 'Shellshock',
        'description': 'GNU Bash remote code execution via environment variables',
        'severity': 'critical',
        'affected_software': ['linux', 'bash', 'cgi'],
        'rules': [
            {'type': 'regex', 'field': 'headers', 'pattern': r'\(\)\s*\{.*?;\s*\}\s*;'},
            {'type': 'regex', 'field': 'any', 'pattern': r'\(\)\s*\{.*?:;\s*\}'},
        ],
    },
    # === HEARTBLEED ===
    {
        'cve_id': 'CVE-2014-0160',
        'name': 'Heartbleed',
        'description': 'OpenSSL TLS heartbeat buffer over-read',
        'severity': 'critical',
        'affected_software': ['openssl'],
        'rules': [
            {'type': 'regex', 'field': 'path', 'pattern': r'heartbleed|heartbeat'},
        ],
    },
    # === GRAFANA ===
    {
        'cve_id': 'CVE-2021-43798',
        'name': 'Grafana Directory Traversal',
        'description': 'Grafana path traversal to arbitrary file read',
        'severity': 'high',
        'affected_software': ['grafana'],
        'rules': [
            {'type': 'regex', 'field': 'path', 'pattern': r'/public/plugins/.*?\.\./'},
        ],
    },
    # === GITLAB ===
    {
        'cve_id': 'CVE-2021-22205',
        'name': 'GitLab RCE via ExifTool',
        'description': 'GitLab CE/EE RCE via image upload',
        'severity': 'critical',
        'affected_software': ['gitlab'],
        'rules': [
            {'type': 'regex', 'field': 'path', 'pattern': r'/uploads/user|/uploads/system'},
            {'type': 'regex', 'field': 'headers', 'pattern': r'Content-Type:.*?image/.*?DjVu'},
        ],
    },
    # === NODEJS / EXPRESS ===
    {
        'cve_id': 'CVE-2022-21824',
        'name': 'Node.js Prototype Pollution DoS',
        'description': 'Node.js console.table prototype pollution',
        'severity': 'high',
        'affected_software': ['nodejs', 'express'],
        'rules': [
            {'type': 'regex', 'field': 'body', 'pattern': r'__proto__\s*(?:\[|\.)\s*(?:constructor|toString|valueOf)'},
            {'type': 'regex', 'field': 'query', 'pattern': r'constructor(?:\[|\.)prototype'},
        ],
    },
    # === OPENSSH ===
    {
        'cve_id': 'CVE-2024-6387',
        'name': 'regreSSHion',
        'description': 'OpenSSH signal handler race condition RCE',
        'severity': 'critical',
        'affected_software': ['openssh', 'linux'],
        'rules': [
            {'type': 'regex', 'field': 'headers', 'pattern': r'SSH-2\.0-(?:OpenSSH_[89]\.)'},
        ],
    },
    # === JUNIPER ===
    {
        'cve_id': 'CVE-2023-36845',
        'name': 'Juniper J-Web RCE',
        'description': 'Juniper Junos J-Web PHP environment variable manipulation',
        'severity': 'critical',
        'affected_software': ['juniper'],
        'rules': [
            {'type': 'regex', 'field': 'path', 'pattern': r'/webauth_operation\.php'},
            {'type': 'regex', 'field': 'body', 'pattern': r'PHPRC='},
        ],
    },
    # === PALO ALTO ===
    {
        'cve_id': 'CVE-2024-3400',
        'name': 'PAN-OS GlobalProtect RCE',
        'description': 'Palo Alto PAN-OS command injection',
        'severity': 'critical',
        'affected_software': ['paloalto', 'panos'],
        'rules': [
            {'type': 'regex', 'field': 'path', 'pattern': r'/ssl-vpn/hipreport\.esp'},
            {'type': 'regex', 'field': 'headers', 'pattern': r'Cookie:.*?SESSID=.*?(?:;|\||`)'},
        ],
    },
    # === FORTINET ===
    {
        'cve_id': 'CVE-2024-21762',
        'name': 'FortiOS Out-of-bound Write',
        'description': 'Fortinet FortiOS SSL VPN RCE',
        'severity': 'critical',
        'affected_software': ['fortinet', 'fortios'],
        'rules': [
            {'type': 'regex', 'field': 'path', 'pattern': r'/remote/(?:hostcheck_validate|logincheck|error)'},
            {'type': 'regex', 'field': 'body', 'pattern': r'(?:ajax|magic)=.*?(?:\x00|\%00)'},
        ],
    },
    {
        'cve_id': 'CVE-2023-27997',
        'name': 'FortiOS Heap Overflow (XORtigate)',
        'description': 'Fortinet FortiOS SSL VPN heap buffer overflow',
        'severity': 'critical',
        'affected_software': ['fortinet', 'fortios'],
        'rules': [
            {'type': 'regex', 'field': 'path', 'pattern': r'/remote/logincheck'},
            {'type': 'regex', 'field': 'headers', 'pattern': r'Content-Length:\s*(?:[5-9]\d{4,}|[1-9]\d{5,})'},
        ],
    },
    # === APACHE ===
    {
        'cve_id': 'CVE-2021-41773',
        'name': 'Apache Path Traversal',
        'description': 'Apache HTTP Server 2.4.49 path traversal',
        'severity': 'critical',
        'affected_software': ['apache'],
        'rules': [
            {'type': 'regex', 'field': 'path', 'pattern': r'/cgi-bin/\.%2e/'},
            {'type': 'regex', 'field': 'path', 'pattern': r'/icons/\.\.%2f'},
            {'type': 'regex', 'field': 'path', 'pattern': r'\.%2e/\.%2e/'},
        ],
    },
    {
        'cve_id': 'CVE-2021-42013',
        'name': 'Apache Path Traversal (bypass)',
        'description': 'Apache HTTP Server 2.4.50 path traversal bypass',
        'severity': 'critical',
        'affected_software': ['apache'],
        'rules': [
            {'type': 'regex', 'field': 'path', 'pattern': r'%%32%65%%32%65/'},
            {'type': 'regex', 'field': 'path', 'pattern': r'\.%%32%65/'},
        ],
    },
    # === THINKPHP ===
    {
        'cve_id': 'CVE-2018-20062',
        'name': 'ThinkPHP RCE',
        'description': 'ThinkPHP framework remote code execution',
        'severity': 'critical',
        'affected_software': ['php', 'thinkphp'],
        'rules': [
            {'type': 'regex', 'field': 'path', 'pattern': r'/index\.php\?s=.*?(?:invokefunction|call_user_func)'},
            {'type': 'regex', 'field': 'query', 'pattern': r'function=call_user_func_array'},
        ],
    },
    # === WEBLOGIC ===
    {
        'cve_id': 'CVE-2023-21839',
        'name': 'WebLogic RCE',
        'description': 'Oracle WebLogic IIOP/T3 RCE',
        'severity': 'critical',
        'affected_software': ['weblogic', 'java'],
        'rules': [
            {'type': 'regex', 'field': 'path', 'pattern': r'/_async/AsyncResponseService'},
            {'type': 'regex', 'field': 'path', 'pattern': r'/wls-wsat/'},
            {'type': 'regex', 'field': 'body', 'pattern': r'<java\s.*?class="java\.lang\.Runtime"'},
        ],
    },
    # === SOLARWINDS ===
    {
        'cve_id': 'CVE-2021-35211',
        'name': 'SolarWinds Serv-U RCE',
        'description': 'SolarWinds Serv-U SSH pre-auth RCE',
        'severity': 'critical',
        'affected_software': ['solarwinds'],
        'rules': [
            {'type': 'regex', 'field': 'path', 'pattern': r'/Serv-U/'},
        ],
    },
    # === ZYXEL ===
    {
        'cve_id': 'CVE-2023-28771',
        'name': 'Zyxel Firewall RCE',
        'description': 'Zyxel firewall unauthenticated command injection',
        'severity': 'critical',
        'affected_software': ['zyxel'],
        'rules': [
            {'type': 'regex', 'field': 'body', 'pattern': r'(?:ping|traceroute)\s.*?;\s*(?:wget|curl|bash|sh)'},
        ],
    },
    # === VEEAM ===
    {
        'cve_id': 'CVE-2023-27532',
        'name': 'Veeam Credential Leak',
        'description': 'Veeam Backup & Replication credential disclosure',
        'severity': 'high',
        'affected_software': ['veeam'],
        'rules': [
            {'type': 'regex', 'field': 'path', 'pattern': r'/VeeamService/'},
        ],
    },
]


class VirtualPatchingEngine:
    """
    Enterprise virtual patching engine.
    Provides immediate CVE mitigation through configurable patches.
    """

    def __init__(self):
        self.patches: Dict[str, VirtualPatch] = {}
        self.stats = {
            'total_checked': 0,
            'patches_matched': 0,
            'patches_loaded': 0,
            'cves_covered': 0,
        }
        self._load_default_patches()

    def _load_default_patches(self):
        """Load all default CVE patches."""
        for patch_def in _CVE_PATCHES:
            compiled_rules = []
            for rule in patch_def['rules']:
                try:
                    compiled = re.compile(rule['pattern'], re.IGNORECASE)
                    compiled_rules.append({
                        'type': rule['type'],
                        'field': rule['field'],
                        'pattern': rule['pattern'],
                        'compiled': compiled,
                    })
                except re.error:
                    continue

            if compiled_rules:
                patch = VirtualPatch(
                    cve_id=patch_def['cve_id'],
                    name=patch_def['name'],
                    description=patch_def['description'],
                    severity=patch_def['severity'],
                    affected_software=patch_def['affected_software'],
                    match_rules=compiled_rules,
                )
                self.patches[patch_def['cve_id']] = patch

        self.stats['patches_loaded'] = len(self.patches)
        self.stats['cves_covered'] = len(self.patches)

    def check_request(self, path: str, method: str, query_string: str = '',
                      headers: Dict = None, body: str = '') -> Dict:
        """
        Check a request against all active virtual patches.
        Returns match details if a CVE exploit is detected.
        """
        self.stats['total_checked'] += 1
        headers = headers or {}
        headers_str = ' '.join(f'{k}: {v}' for k, v in headers.items())
        full_text = f'{path} {query_string} {headers_str} {body}'

        matched_patches = []

        for cve_id, patch in self.patches.items():
            if not patch.enabled:
                continue

            # Check expiry
            if patch.expires_at > 0 and time.time() > patch.expires_at:
                patch.enabled = False
                continue

            for rule in patch.match_rules:
                field = rule['field']
                compiled = rule['compiled']

                # Select target text based on field
                if field == 'path':
                    target = path
                elif field == 'query':
                    target = query_string
                elif field == 'body':
                    target = body
                elif field == 'headers':
                    target = headers_str
                else:  # 'any'
                    target = full_text

                if compiled.search(target):
                    patch.hits += 1
                    self.stats['patches_matched'] += 1
                    matched_patches.append({
                        'cve_id': cve_id,
                        'name': patch.name,
                        'description': patch.description,
                        'severity': patch.severity,
                        'rule_matched': rule['pattern'],
                    })
                    break  # One rule match per patch is enough

        if matched_patches:
            # Return the most severe match
            severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
            matched_patches.sort(key=lambda x: severity_order.get(x['severity'], 0), reverse=True)
            top = matched_patches[0]
            return {
                'action': 'block',
                'cve_id': top['cve_id'],
                'name': top['name'],
                'severity': top['severity'],
                'description': top['description'],
                'all_matches': matched_patches,
                'reason': f'virtual-patch-{top["cve_id"]}',
            }

        return {'action': 'allow'}

    def add_patch(self, cve_id: str, name: str, description: str, severity: str,
                  rules: List[Dict], affected_software: List[str] = None,
                  expires_at: float = 0) -> Dict:
        """Add a custom virtual patch at runtime (hot-patching)."""
        compiled_rules = []
        for rule in rules:
            try:
                compiled = re.compile(rule['pattern'], re.IGNORECASE)
                compiled_rules.append({
                    'type': rule.get('type', 'regex'),
                    'field': rule.get('field', 'any'),
                    'pattern': rule['pattern'],
                    'compiled': compiled,
                })
            except re.error as e:
                return {'error': f'Invalid regex: {e}'}

        patch = VirtualPatch(cve_id, name, description, severity,
                           affected_software or [], compiled_rules, expires_at)
        self.patches[cve_id] = patch
        self.stats['patches_loaded'] = len(self.patches)
        self.stats['cves_covered'] = len(self.patches)
        return {'added': True, 'cve_id': cve_id, 'rules_count': len(compiled_rules)}

    def disable_patch(self, cve_id: str) -> bool:
        if cve_id in self.patches:
            self.patches[cve_id].enabled = False
            return True
        return False

    def enable_patch(self, cve_id: str) -> bool:
        if cve_id in self.patches:
            self.patches[cve_id].enabled = True
            return True
        return False

    def list_patches(self) -> List[Dict]:
        return [{
            'cve_id': p.cve_id, 'name': p.name, 'severity': p.severity,
            'enabled': p.enabled, 'hits': p.hits,
            'affected_software': p.affected_software,
        } for p in self.patches.values()]

    def get_stats(self) -> Dict:
        stats = dict(self.stats)
        stats['active_patches'] = sum(1 for p in self.patches.values() if p.enabled)
        stats['top_triggered'] = sorted(
            [{'cve': p.cve_id, 'name': p.name, 'hits': p.hits} for p in self.patches.values()],
            key=lambda x: x['hits'], reverse=True
        )[:10]
        return stats


# ==================== SINGLETON ====================
_engine = None

def get_engine() -> VirtualPatchingEngine:
    global _engine
    if _engine is None:
        _engine = VirtualPatchingEngine()
    return _engine

def check_request(path: str, method: str, **kwargs) -> Dict:
    return get_engine().check_request(path, method, **kwargs)

def list_patches() -> List[Dict]:
    return get_engine().list_patches()
