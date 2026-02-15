import re
import os
from typing import Dict, Tuple, List

# ==================== SQL INJECTION PATTERNS ====================
SQLI_PATTERNS = [
    r"\b(?:select)\b\s+(?:\w+|\*|`|\(|@@|all|distinct|top)\b",
    r"\b(?:union)\b\s+(?:select|all)\b",
    r"\b(?:insert)\b\s+(?:into|ignore|overwrite)\b",
    r"\b(?:update)\b\s+(?:\w+)\s+set\b",
    r"\b(?:delete)\b\s+from\b",
    r"\b(?:drop)\b\s+(?:table|database|column|index|view|procedure|function|schema|user|trigger|event)\b",
    r"--",
    r"/\*.*\*/",
    r"\bor\b\s+\d+\s*=",
    r"'.*or.*'.*'.*=.*'",  # Détecte 1' OR '1'='1
    r"\bsleep\s*\(",  # Time-based blind SLEEP(5)
    r"\bbenchmark\s*\(",  # Time-based blind BENCHMARK
    r"\bwaitfor\b.*\bdelay\b",  # MSSQL WAITFOR DELAY
    r"\bexec\s*\(|\bexecute\s+(?:immediate|as|sp_|xp_)",  # EXEC/EXECUTE with SQL context
    r"\|\|",  # SQL concatenation operator ||
    r"0x[0-9a-f]{6,}",  # Hex encoding (0x73656c656374)
    r"\bascii\s*\(",  # ASCII-based blind SQLi
    r"\bsubstring\s*\(",  # SUBSTRING extraction
    r"[\u1d00-\u1d7f]{4,}",  # Unicode small caps block (ᴜɴɪᴏɴ)
    r"[\ua71f-\ua7ff]",  # Unicode Latin Extended-D
    # Additional SQL patterns
    r"(?:--|#)\s*$|(?:'|\"|--)\s*#",  # MySQL comment with context
    r"\binto\s+outfile\b",  # INTO OUTFILE
    r"\binto\s+dumpfile\b",  # INTO DUMPFILE
    r"\bload_file\s*\(",  # LOAD_FILE()
    r"\binformation_schema\b",  # information_schema
    r"\bsysobjects\b",  # SQL Server sysobjects
    r"\bsyscolumns\b",  # SQL Server syscolumns
    r"\bpg_tables\b",  # PostgreSQL pg_tables
    r"\bpg_catalog\b",  # PostgreSQL pg_catalog
    r"\bxp_cmdshell\b",  # SQL Server xp_cmdshell
    r"\bxp_regread\b",  # SQL Server xp_regread
]

# ==================== XSS PATTERNS ====================
XSS_PATTERNS = [
    r"<script.*?>",
    r"onerror\s*=",
    r"javascript:\s*",
    r"<img\s+src=",
    r"<svg[^>]*onload",  # <svg/onload=alert(1)>
    r"<iframe[^>]*src",  # <iframe src=...>
    r"<object[^>]*data",  # <object data=...>
    r"<embed[^>]*src",  # <embed src=...>
    r"on\w+\s*=",  # All event handlers (onclick, onerror, etc.)
    r"\[\]\[",  # JSFuck obfuscation patterns
    r"\(\!\[\]\+\[\]\)",  # JSFuck patterns (![]+[])
    r"\\x[0-9a-f]{2}",  # Hex escape sequences
    r"data:text/html",  # Data URI XSS
    r"data:image/svg\+xml",  # SVG data URI
    r"location\.(hash|href|search)",  # DOM manipulation
    r"document\.(cookie|domain|referrer)",  # Document manipulation
    r"expression\s*\(",  # CSS expression injection
    r"vbscript:",  # VBScript protocol
    r"mhtml:",  # MHTML protocol
    # Additional XSS patterns
    r"\beval\s*\(",  # eval()
    r"\.innerHTML\s*=",  # innerHTML assignment
    r"\.outerHTML\s*=",  # outerHTML assignment
    r"\.write\s*\(",  # document.write()
    r"\.writeln\s*\(",  # document.writeln()
    r"fromCharCode",  # String.fromCharCode()
    r"atob\s*\(",  # atob() base64 decode
    r"btoa\s*\(",  # btoa() base64 encode
]

# ==================== COMMAND INJECTION PATTERNS ====================
CMDI_PATTERNS = [
    r"[;|]\s*(whoami|id|ls|cat|wget|curl|nc|bash|sh|cmd|uname|pwd)\b|&\s+(whoami|id|ls|cat|wget|curl|nc|bash|sh|cmd|uname|pwd)\b",
    r"`.*`",  # Backticks: `whoami`
    r"\$\(.*\)",  # Command substitution: $(whoami)
    r"%0a|%0d",  # Newline injection
    r"\|\s*(grep|awk|sed|sort|uniq|head|tail|cut)",  # Pipe with Unix commands
    r"\$IFS",  # FIXED: IFS variable manipulation
    r"\$\d+",  # FIXED: Positional parameters ($1, $9)
    r"\$PATH|\$HOME|\$USER",  # FIXED: Environment variables
    r"\\[a-z]",  # FIXED: Backslash escaping (c\at)
    r"\{[a-z]+,[^}]+\}",  # FIXED: Brace expansion {cat,/etc/passwd}
    # Shell interpreters and dangerous commands
    r"/bin/(ba)?sh\b",  # /bin/sh, /bin/bash
    r"/usr/bin/(ba)?sh\b",  # /usr/bin/sh, /usr/bin/bash
    r"\bpython[23]?\s+-c",  # python -c, python2 -c, python3 -c
    r"\bperl\s+-e",  # perl -e
    r"\bruby\s+-e",  # ruby -e
    r"\bphp\s+-r",  # php -r
    r"\bnc\s+-[elp]",  # nc -e, nc -l, nc -p (netcat reverse shell)
    r"\bncat\s",  # ncat
    r"\bwget\s+https?://",  # wget http://
    r"\bcurl\s+https?://",  # curl http://
    r"\bfetch\s+https?://",  # fetch http:// (BSD)
    # Additional command patterns
    r"\bping\b.*-[cn]",  # ping -c / ping -n
    r"\bnslookup\b",  # nslookup command
    r"\bdig\b",  # dig command
    r"\btraceroute\b",  # traceroute
    r"\bnetcat\b",  # netcat
    r"\btelnet\b",  # telnet
    r"\bftp\b\s",  # ftp command
    r"\bssh\b\s",  # ssh command
    r"\bchmod\b",  # chmod
    r"\bchown\b",  # chown
    r"\brm\b\s+-[rf]",  # rm -rf
    r"\bmkdir\b",  # mkdir
    r"\btouch\b",  # touch
    r"\bkill\b\s+-\d",  # kill -9
]

# ==================== PATH TRAVERSAL / LFI PATTERNS ====================
PATH_TRAVERSAL_PATTERNS = [
    r"\.\./|\.\.\\/",  # ../ or ..\
    r"%2e%2e%2f|%2e%2e/|%2e%2e%5c",  # Encoded ../
    r"\.\.%2f|\.\.%5c",  # Partially encoded
    r"\.\.\.\./+|\.\.\.\.\\+",  # Double slash evasion: ....//
    r"/etc/passwd|/etc/shadow|/etc/hosts",  # Unix sensitive files
    r"c:\\windows\\|c:/windows/",  # Windows paths
    r"\\\\\\\\[0-9.]+",  # FIXED: UNC paths (\\127.0.0.1)
    r"\\\\[a-z0-9.-]+\\c\$",  # FIXED: Windows admin shares (\\host\c$)
    # NEW: UTF-8 overlong encoding bypass prevention
    r"%c0%ae|%c0%af",  # UTF-8 overlong encoding for . and /
    r"%c1%1c|%c1%9c",  # UTF-8 overlong encoding variants
    r"%e0%80%ae",  # 3-byte overlong encoding for .
    r"%f0%80%80%ae",  # 4-byte overlong encoding for .
    r"%252e|%252f",  # Double URL encoding
    r"\.\.;/",  # Tomcat path traversal bypass
    r"/\.\./",  # Normalized traversal
]
# ==================== SSRF PATTERNS ====================
SSRF_PATTERNS = [
    r"169\.254\.169\.254",  # AWS metadata
    r"metadata\.google\.internal",  # GCP metadata
    r"(url|target|redirect|proxy|host|src|href).*?(localhost|127\.0\.0\.1)",  # Loopback in parameters
    r"file:///",  # File protocol
    r"(gopher|dict|ftp)://",  # Alternative protocols
    # Private network ranges (RFC 1918)
    r"://10\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # 10.0.0.0/8
    r"://192\.168\.\d{1,3}\.\d{1,3}",  # 192.168.0.0/16
    r"://172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}",  # 172.16.0.0/12
    # Loopback and special addresses
    r"://localhost(?![a-zA-Z0-9])",  # Direct localhost access (negative lookahead)
    r"://127\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # Entire 127.0.0.0/8 range
    r"://0\.0\.0\.0(?![0-9])",  # 0.0.0.0 wildcard (negative lookahead)
    r"://\[::1\]",  # IPv6 loopback
    r"://\[0:0:0:0:0:0:0:1\]",  # IPv6 loopback full
    r"://\[::ffff:127\.0\.0\.1\]",  # IPv6 mapped IPv4
    r"://2130706433\b",  # Decimal IP for 127.0.0.1
    r"://0177\.0+\.0+\.0*1\b",  # Octal IP variations
    r"://017700000001\b",  # Octal IP compact
    r"://0x7f\.0x0\.0x0\.0x1\b",  # Hex IP dotted
    r"://0x7f000001\b",  # Hex IP compact
    r"ldap://",  # LDAP protocol SSRF
    r"ldaps://",  # LDAPS protocol
    r"tftp://",  # TFTP protocol
    r"netdoc://",  # netdoc protocol
    r"jar:http",  # JAR URL scheme
    r"\.(burpcollaborator|oastify|interact\.sh|dnslog)\.com",  # DNS rebinding/OAST
    r"@localhost\b",  # URL with @ before localhost
    r"@127\.0\.0\.1\b",  # URL with @ before IP
    r"\blocaltest\.me\b",  # localhost alternative domains
    r"\bvcap\.me\b",  # localhost alternative
    r"\blvh\.me\b",  # localhost alternative
    r"\bnip\.io\b",  # wildcard DNS
    r"\bxip\.io\b",  # wildcard DNS
    r"\bsslip\.io\b",  # wildcard DNS
]

# ==================== XXE PATTERNS ====================
XXE_PATTERNS = [
    r"<!ENTITY",  # XML Entity declaration
    r"<!DOCTYPE\s+\w",  # DOCTYPE declaration (any DOCTYPE with name)
    r"SYSTEM\s+[\"']file://",  # External entity: file://
    r"PUBLIC\s+[\"']",  # PUBLIC external entity
]

# ==================== LDAP INJECTION PATTERNS ====================
LDAP_PATTERNS = [
    r"\(\|\(",  # (|( LDAP OR injection
    r"\)\(\|",  # )(| LDAP injection
    r"\*\)\(",  # *)( LDAP wildcard injection
    r"\(&\(",  # (&( LDAP AND injection
    r"\)\(uid=",  # )(uid= filter injection
    r"\)\(cn=",  # )(cn= filter injection
    r"\)\(password",  # )(password filter injection
    r"objectClass\s*=",  # objectClass query
    r"\)\(objectClass",  # )(objectClass=*) injection
    r"\(objectClass=\*\)",  # Full objectClass pattern
    r"\|\(cn=",  # |cn= OR injection
    r"\|\(uid=",  # |uid= OR injection
    r"\bunionall\b",  # LDAP union
    r"\bnull\)\(",  # Null termination
    # NEW: Additional LDAP injection patterns (fix for bypass)
    r"\*\(\)\|\&",  # *()|& - common LDAP test payload
    r"\(\*\)\(\|",  # (*)(| pattern
    r"\)\(\&\(",  # )(&( AND injection
    r"\|\s*\(",  # | ( OR with space
    r"\&\s*\(",  # & ( AND with space
    r"\(\s*\|",  # ( | opening with OR
    r"\(\s*\&",  # ( & opening with AND
    r"\)\s*\)",  # ) ) double close (injection attempt)
    r"\(\s*\(",  # ( ( double open (injection attempt)
    r"\*\s*\)",  # * ) wildcard close
    r"\)\s*\*",  # ) * close wildcard
    r"cn=\*",  # cn=* wildcard search
    r"uid=\*",  # uid=* wildcard search  
    r"\(mail=",  # (mail= attribute injection
    r"\(memberOf=",  # (memberOf= group injection
    r"\(userPassword=",  # (userPassword= password access
    r"\(sn=",  # (sn= surname attribute
    r"\(givenName=",  # (givenName= attribute
]

# ==================== NOSQL INJECTION PATTERNS ====================
NOSQL_PATTERNS = [
    r"\{\s*\$\w+\s*:",  # {$ne:, {$gt:, etc.
    r"\[\s*\$\w+\s*\]",  # [$ne], [$regex], etc.
    r"\{\s*['\"]?\$where['\"]?\s*:",  # $where queries
    r"sleep\s*\(\s*\d+\s*\)",  # sleep(5000)
    r"\$ne\b|\$gt\b|\$lt\b|\$gte\b|\$lte\b",  # FIXED: NoSQL operators
    r":\s*\{\s*\"\$ne\"\s*:\s*null\s*\}",  # FIXED: {"$ne": null} pattern
    # NEW: Additional NoSQL patterns
    r"\$regex\b",  # $regex operator
    r"\$options\b",  # $options (used with $regex)
    r"\$exists\b",  # $exists operator
    r"\$type\b",  # $type operator
    r"\$or\s*:\s*\[",  # $or array
    r"\$and\s*:\s*\[",  # $and array
    r"\$not\s*:",  # $not operator
    r"\$nin\b",  # $nin (not in)
    r"\$in\s*:\s*\[",  # $in array
    r"\$elemMatch\b",  # $elemMatch
    r"\$comment\b",  # $comment (info leak)
    r"\{\s*\"\$regex\"\s*:",  # JSON format $regex
]

# ==================== LOG4SHELL/JNDI INJECTION PATTERNS ====================
JNDI_PATTERNS = [
    r"\$\{jndi:",  # ${jndi:ldap://
    r"\$\{jndi:ldap://",
    r"\$\{jndi:rmi://",
    r"\$\{jndi:dns://",
    # NEW: JNDI obfuscation bypass patterns
    r"\$\{.*j.*n.*d.*i.*:",  # Any chars between j-n-d-i
    r"j\]?n\[?d\]?i",  # Bracket obfuscation: j]n[d]i
    r"\$\{\$\{.*\}.*ndi",  # Nested lookup: ${${lower:j}ndi
    r"\$\{lower:j\}",  # ${lower:j} Log4j lookup
    r"\$\{upper:j\}",  # ${upper:J} Log4j lookup
    r"\$\{lower:n\}",  # ${lower:n}
    r"\$\{env:.*\}.*ndi",  # Environment variable lookup
    r"\$\{base64:.*\}",  # Base64 lookup
    r"\$\{date:.*\}",  # Date lookup
    r"\$\{ctx:.*\}",  # Context lookup
    r"\$\{java:.*\}",  # Java lookup
    r"\$\{bundle:.*\}",  # Bundle lookup  
    r"\$\{main:.*\}",  # Main arguments lookup
    r"\$\{sys:.*\}",  # System property lookup
    r"\$\{\:\-j\}",  # Default value obfuscation
    r"j\$\{.*\}ndi",  # Injection in middle
    r"jn\$\{.*\}di",  # Injection in middle variant
]

# ==================== PHP FILTER/WRAPPER PATTERNS ====================
PHP_FILTER_PATTERNS = [
    r"php://filter",
    r"php://input",
    r"php://output",
    r"data://text/plain",
    r"expect://",
    r"phar://",
]

# ==================== SERVER-SIDE TEMPLATE INJECTION (SSTI) PATTERNS ====================
SSTI_PATTERNS = [
    r"\{\{.*\*.*\}\}",  # {{7*7}}
    r"\$\{.*\*.*\}",  # ${7*7}
    r"\{\%.*\%\}",  # {%...%}
    r"<\%.*\%>",  # <%...%>
    r"\{\{.*config.*\}\}",  # {{config}}
    r"\{\{.*self.*\}\}",  # {{self}}
    r"#\{.*\}",  # Ruby #{...} interpolation
    r"\{\{.*\}\}",  # Generic Jinja2/Twig {{...}}
    r"\$\{[^}]+\}",  # Generic ${...} expressions
]

# ==================== JSP CODE INJECTION PATTERNS ====================
JSP_PATTERNS = [
    r"<\%\s*eval\s*\(",  # <% eval(
    r"<\%=.*request\.getParameter",  # <%= request.getParameter
    r"<jsp:include",
    r"<jsp:forward",
]

# ==================== ADVANCED LFI PATTERNS ====================
ADVANCED_LFI_PATTERNS = [
    r"/proc/self/",
    r"/proc/\d+/",
    r"/var/log/",
    r"/var/mail/",
    r"\.\./\.\./proc/",
]

# ==================== PYTHON CODE INJECTION PATTERNS ====================
PYTHON_INJECTION_PATTERNS = [
    r"__import__\s*\(",  # __import__('os')
    r"\bexec\s*\(",  # exec(code)
    r"\beval\s*\(",  # eval(code)
    r"\bcompile\s*\(",  # compile(code)
    r"os\.system",  # os.system('cmd')
    r"subprocess\.",  # subprocess.call, subprocess.Popen
    r"commands\.",  # commands.getoutput
    r"__init__\.__globals__",  # FIXED: Python introspection
    r"__class__\.__bases__",  # FIXED: Class introspection
    r"\{[a-z_]+\.__[a-z_]+__",  # FIXED: Format string with dunder methods
]

# ==================== JAVA/JAR PROTOCOL PATTERNS ====================
JAR_PROTOCOL_PATTERNS = [
    r"jar:http://",  # JAR URL remote class loading
    r"jar:https://",
    r"jar:ftp://",
    r"jar:file://",
]

# ==================== GRAPHQL INJECTION PATTERNS ====================
GRAPHQL_PATTERNS = [
    r"__schema\s*\{",  # GraphQL introspection
    r"__type\s*\(",  # Type introspection
    r"__typename",  # Type name introspection
    r"query\s+IntrospectionQuery",  # Full introspection
]

# ==================== DESERIALIZATION PATTERNS ====================
DESERIALIZATION_PATTERNS = [
    r"!!python/object",  # YAML Python object deserialization
    r"O:\d+:",  # PHP serialized object: O:8:"stdClass"
    r"a:\d+:",  # PHP serialized array: a:2:{...}
    r"rO0AB",  # Java serialized (base64 encoded)
    r"\xac\xed\x00\x05",  # Java serialization magic bytes
]

# ==================== PROTOTYPE POLLUTION PATTERNS ====================
PROTOTYPE_POLLUTION_PATTERNS = [
    r"__proto__",  # JavaScript prototype pollution
    r"constructor\s*\[\s*['\"]?prototype",  # constructor["prototype"] or constructor[prototype]
    r"\[\s*['\"]__proto__['\"]?\s*\]",  # ["__proto__"] or [__proto__]
    r"prototype\s*\[\s*['\"]?\w+['\"]?\s*\]",  # prototype["x"] or prototype[x]
    r"Object\.assign\s*\(",  # Object.assign pollution
    r"\$\.extend\s*\(",  # jQuery extend pollution
    r"_\.merge\s*\(",  # Lodash merge pollution
    r"_\.defaultsDeep\s*\(",  # Lodash defaultsDeep
]

# ==================== JWT BYPASS PATTERNS ====================
JWT_BYPASS_PATTERNS = [
    r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.",  # JWT format detection for inspection
    r'"alg"\s*:\s*"none"',  # alg:none bypass
    r'"alg"\s*:\s*"None"',  # alg:None variant
    r'"alg"\s*:\s*"NONE"',  # alg:NONE variant
    r'"alg"\s*:\s*"nOnE"',  # Case variation
    r"alg.*none",  # Loose alg:none
    r'"typ"\s*:\s*"none"',  # typ:none
    # JWT algorithm confusion attacks
    r'"alg"\s*:\s*"HS256".*admin.*true',  # Admin claim with weak alg
    r'"admin"\s*:\s*true',  # Admin claim injection
    r'"role"\s*:\s*"admin"',  # Role claim injection
    r'"isAdmin"\s*:\s*true',  # isAdmin claim injection
]

# ==================== HEX ENCODING BYPASS PATTERNS ====================
HEX_BYPASS_PATTERNS = [
    r"^[0-9a-fA-F]{20,}$",  # Long hex string (potential encoded payload)
    r"27204f5220312f312d2d",  # Hex for ' OR 1=1--
    r"3c7363726970743e",  # Hex for <script>
    r"3c2f7363726970743e",  # Hex for </script>
]

# ==================== BRUTE FORCE PATTERNS ====================
BRUTE_PATTERNS = [
    r"(login|password).*(\d{6,})",
]

# Combine and compile
_default_compiled = []
for p in SQLI_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'sqli'))
for p in XSS_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'xss'))
for p in CMDI_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'cmdi'))
for p in PATH_TRAVERSAL_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'path-traversal'))
for p in SSRF_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'ssrf'))
for p in XXE_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'xxe'))
for p in LDAP_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'ldap'))
for p in NOSQL_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'nosql'))
for p in JNDI_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'jndi'))
for p in PHP_FILTER_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'php-filter'))
for p in SSTI_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'ssti'))
for p in JSP_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'jsp'))
for p in ADVANCED_LFI_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'lfi'))
for p in PYTHON_INJECTION_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'python-injection'))
for p in JAR_PROTOCOL_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'jar-protocol'))
for p in GRAPHQL_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'graphql'))
for p in DESERIALIZATION_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'deserialization'))
for p in PROTOTYPE_POLLUTION_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'prototype-pollution'))
for p in JWT_BYPASS_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'jwt-bypass'))
for p in HEX_BYPASS_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'hex-encoding'))
for p in BRUTE_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'brute'))

# === Merge Extended Rules (1200+ additional patterns) ===
try:
    from waf.rules_extended import get_all_extended_patterns, count_extended_patterns
    _ext_count = 0
    for regex_str, category in get_all_extended_patterns():
        try:
            _default_compiled.append((re.compile(regex_str, re.IGNORECASE), category.lower()))
            _ext_count += 1
        except re.error:
            pass  # Skip invalid regex
    print(f"[BeeWAF] Loaded {_ext_count} extended rules ({count_extended_patterns()} defined)")
except ImportError:
    print("[BeeWAF] Extended rules not found, using base rules only")

# === Merge Advanced v4.0 Rules (650+ additional patterns) ===
try:
    from waf.rules_advanced import get_all_advanced_patterns, count_advanced_patterns
    _adv_count = 0
    for regex_str, category in get_all_advanced_patterns():
        try:
            _default_compiled.append((re.compile(regex_str, re.IGNORECASE), category.lower()))
            _adv_count += 1
        except re.error:
            pass  # Skip invalid regex
    print(f"[BeeWAF] Loaded {_adv_count} advanced v4.0 rules ({count_advanced_patterns()} defined)")
except ImportError:
    print("[BeeWAF] Advanced v4.0 rules not found, using base + extended rules only")

# === Merge v5.0 Rules (1200+ additional patterns) ===
try:
    from waf.rules_v5 import get_all_v5_patterns, count_v5_patterns
    _v5_count = 0
    for regex_str, category in get_all_v5_patterns():
        try:
            _default_compiled.append((re.compile(regex_str, re.IGNORECASE), category.lower()))
            _v5_count += 1
        except re.error:
            pass  # Skip invalid regex
    print(f"[BeeWAF] Loaded {_v5_count} v5.0 rules ({count_v5_patterns()} defined)")
except ImportError:
    print("[BeeWAF] v5.0 rules not found, using base + extended + advanced rules only")

# === Merge Mega Rules Database Part 1 (~1900 patterns) ===
try:
    from waf.rules_mega_1 import get_all_mega1_patterns, count_mega1_patterns
    _m1_count = 0
    for regex_str, category in get_all_mega1_patterns():
        try:
            _default_compiled.append((re.compile(regex_str, re.IGNORECASE), category.lower()))
            _m1_count += 1
        except re.error:
            pass
    print(f"[BeeWAF] Loaded {_m1_count} mega-1 rules ({count_mega1_patterns()} defined)")
except ImportError:
    print("[BeeWAF] Mega rules part 1 not found, skipping")

# === Merge Mega Rules Database Part 2 (~1160 patterns) ===
try:
    from waf.rules_mega_2 import get_all_mega2_patterns, count_mega2_patterns
    _m2_count = 0
    for regex_str, category in get_all_mega2_patterns():
        try:
            _default_compiled.append((re.compile(regex_str, re.IGNORECASE), category.lower()))
            _m2_count += 1
        except re.error:
            pass
    print(f"[BeeWAF] Loaded {_m2_count} mega-2 rules ({count_mega2_patterns()} defined)")
except ImportError:
    print("[BeeWAF] Mega rules part 2 not found, skipping")

# === Merge Mega Rules Database Part 3 (~1080 patterns) ===
try:
    from waf.rules_mega_3 import get_all_mega3_patterns, count_mega3_patterns
    _m3_count = 0
    for regex_str, category in get_all_mega3_patterns():
        try:
            _default_compiled.append((re.compile(regex_str, re.IGNORECASE), category.lower()))
            _m3_count += 1
        except re.error:
            pass
    print(f"[BeeWAF] Loaded {_m3_count} mega-3 rules ({count_mega3_patterns()} defined)")
except ImportError:
    print("[BeeWAF] Mega rules part 3 not found, skipping")

# === Merge Mega Rules Database Part 4 (~1050 patterns) ===
try:
    from waf.rules_mega_4 import get_all_mega4_patterns, count_mega4_patterns
    _m4_count = 0
    for regex_str, category in get_all_mega4_patterns():
        try:
            _default_compiled.append((re.compile(regex_str, re.IGNORECASE), category.lower()))
            _m4_count += 1
        except re.error:
            pass
    print(f"[BeeWAF] Loaded {_m4_count} mega-4 rules ({count_mega4_patterns()} defined)")
except ImportError:
    print("[BeeWAF] Mega rules part 4 not found, skipping")

# --- Mega Rules Part 5 ---
try:
    from waf.rules_mega_5 import get_all_mega5_patterns, count_mega5_patterns
    _m5_count = 0
    for regex_str, category in get_all_mega5_patterns():
        try:
            _default_compiled.append((re.compile(regex_str, re.IGNORECASE), category.lower()))
            _m5_count += 1
        except re.error:
            pass
    print(f"[BeeWAF] Loaded {_m5_count} mega-5 rules ({count_mega5_patterns()} defined)")
except ImportError:
    print("[BeeWAF] Mega rules part 5 not found, skipping")

# --- Mega Rules Part 6 ---
try:
    from waf.rules_mega_6 import get_all_mega6_patterns, count_mega6_patterns
    _m6_count = 0
    for regex_str, category in get_all_mega6_patterns():
        try:
            _default_compiled.append((re.compile(regex_str, re.IGNORECASE), category.lower()))
            _m6_count += 1
        except re.error:
            pass
    print(f"[BeeWAF] Loaded {_m6_count} mega-6 rules ({count_mega6_patterns()} defined)")
except ImportError:
    print("[BeeWAF] Mega rules part 6 not found, skipping")

# --- Mega Rules Part 7 ---
try:
    from waf.rules_mega_7 import get_all_mega7_patterns, count_mega7_patterns
    _m7_count = 0
    for regex_str, category in get_all_mega7_patterns():
        try:
            _default_compiled.append((re.compile(regex_str, re.IGNORECASE), category.lower()))
            _m7_count += 1
        except re.error:
            pass
    print(f"[BeeWAF] Loaded {_m7_count} mega-7 rules ({count_mega7_patterns()} defined)")
except ImportError:
    print("[BeeWAF] Mega rules part 7 not found, skipping")

# --- Mega Rules Part 8 ---
try:
    from waf.rules_mega_8 import get_all_mega8_patterns, count_mega8_patterns
    _m8_count = 0
    for regex_str, category in get_all_mega8_patterns():
        try:
            _default_compiled.append((re.compile(regex_str, re.IGNORECASE), category.lower()))
            _m8_count += 1
        except re.error:
            pass
    print(f"[BeeWAF] Loaded {_m8_count} mega-8 rules ({count_mega8_patterns()} defined)")
except ImportError:
    print("[BeeWAF] Mega rules part 8 not found, skipping")

# --- Mega Rules Part 9 ---
try:
    from waf.rules_mega_9 import get_all_mega9_patterns, count_mega9_patterns
    _m9_count = 0
    for regex_str, category in get_all_mega9_patterns():
        try:
            _default_compiled.append((re.compile(regex_str, re.IGNORECASE), category.lower()))
            _m9_count += 1
        except re.error:
            pass
    print(f"[BeeWAF] Loaded {_m9_count} mega-9 rules ({count_mega9_patterns()} defined)")
except ImportError:
    print("[BeeWAF] Mega rules part 9 not found, skipping")

# --- Mega Rules Part 10 ---
try:
    from waf.rules_mega_10 import get_all_mega10_patterns, count_mega10_patterns
    _m10_count = 0
    for regex_str, category in get_all_mega10_patterns():
        try:
            _default_compiled.append((re.compile(regex_str, re.IGNORECASE), category.lower()))
            _m10_count += 1
        except re.error:
            pass
    print(f"[BeeWAF] Loaded {_m10_count} mega-10 rules ({count_mega10_patterns()} defined)")
except ImportError:
    print("[BeeWAF] Mega rules part 10 not found, skipping")

# --- Mega Rules Part 11 ---
try:
    from waf.rules_mega_11 import get_all_mega11_patterns, count_mega11_patterns
    _m11_count = 0
    for regex_str, category in get_all_mega11_patterns():
        try:
            _default_compiled.append((re.compile(regex_str, re.IGNORECASE), category.lower()))
            _m11_count += 1
        except re.error:
            pass
    print(f"[BeeWAF] Loaded {_m11_count} mega-11 rules ({count_mega11_patterns()} defined)")
except ImportError:
    print("[BeeWAF] Mega rules part 11 not found, skipping")

# --- Mega Rules Part 12 ---
try:
    from waf.rules_mega_12 import get_all_mega12_patterns, count_mega12_patterns
    _m12_count = 0
    for regex_str, category in get_all_mega12_patterns():
        try:
            _default_compiled.append((re.compile(regex_str, re.IGNORECASE), category.lower()))
            _m12_count += 1
        except re.error:
            pass
    print(f"[BeeWAF] Loaded {_m12_count} mega-12 rules ({count_mega12_patterns()} defined)")
except ImportError:
    print("[BeeWAF] Mega rules part 12 not found, skipping")

print(f"[BeeWAF] *** TOTAL COMPILED RULES: {len(_default_compiled)} ***")

# Allow an environment-specified additional rules file (one regex per line prefixed by kind: e.g. sqli:regex)
COMPILED_RULES = list(_default_compiled)
_rules_file = os.environ.get('BEEWAF_RULES_FILE')
if _rules_file and os.path.exists(_rules_file):
    try:
        with open(_rules_file, 'r') as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln or ln.startswith('#'):
                    continue
                if ':' in ln:
                    kind, rx = ln.split(':', 1)
                    try:
                        COMPILED_RULES.append((re.compile(rx, re.IGNORECASE), kind.strip()))
                    except re.error:
                        continue
    except Exception:
        pass

# Simple allowlist (paths that should never be blocked)
ALLOW_PATHS = os.environ.get('BEEWAF_ALLOW_PATHS', '/health,/metrics,/admin/compliance,/admin/ml-stats,/admin/rules,/admin/enterprise-stats,/admin/virtual-patches,/admin/correlation,/admin/adaptive-mode,/admin/retrain,/admin/retrain-ml,/admin/ml-predict,/api/login,/api/search,/api/health,/api/v1/auth/login,/api/dashboard/stats,/api/orders,/api/products,/api/users,/api/status,/api/csrf-token').split(',')
ALLOW_PATHS = [p.strip() for p in ALLOW_PATHS if p.strip()]


def _headers_to_text(headers: Dict[str, str]) -> str:
    # Exclude infrastructure/proxy headers to avoid false positives
    # These headers are checked separately in the suspicious headers loop
    _SKIP_HEADERS = {
        'host', 'x-real-ip', 'x-forwarded-for', 'x-forwarded-proto',
        'x-original-ip', 'connection', 'content-length', 'accept-encoding',
        'user-agent', 'x-api-key', 'authorization',
        # Skip standard browser headers to avoid FPs with 10K rules
        'referer', 'accept', 'accept-language', 'accept-charset',
        'content-type', 'origin', 'cache-control', 'pragma',
        'if-none-match', 'if-modified-since', 'upgrade-insecure-requests',
        'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'sec-fetch-user',
        'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform',
        'dnt', 'te', 'transfer-encoding',
    }
    return ' '.join(f"{k}:{v}" for k, v in headers.items() if k.lower() not in _SKIP_HEADERS)


# ── Safe-path prefixes that must never be blocked ──
_SAFE_PATH_PREFIXES = (
    '/static/', '/assets/', '/css/', '/js/', '/images/', '/img/', '/fonts/',
    '/media/', '/favicon', '/manifest', '/sw.js', '/service-worker',
)
_SAFE_PATH_EXACT = {
    '/register', '/login', '/logout', '/signup', '/signin', '/signout',
    '/dashboard', '/profile', '/settings', '/account', '/home',
    '/about', '/contact', '/faq', '/help', '/terms', '/privacy',
    '/sitemap.xml', '/robots.txt', '/feed.xml', '/rss.xml', '/atom.xml',
    '/manifest.json', '/browserconfig.xml', '/crossdomain.xml',
    '/.well-known/security.txt', '/security.txt', '/humans.txt', '/ads.txt',
}

def _is_safe_request(path: str, body: str) -> bool:
    """Fast pre-filter: return True if the request is obviously safe."""
    clean = (path or '').split('?')[0].rstrip('/')
    if clean in _SAFE_PATH_EXACT:
        return True
    if any(clean.startswith(p) for p in _SAFE_PATH_PREFIXES):
        ext = clean.rsplit('.', 1)[-1] if '.' in clean else ''
        if ext in ('css', 'js', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico',
                   'woff', 'woff2', 'ttf', 'eot', 'map', 'webp', 'avif'):
            return True
    # Nested resource paths like /orders/123, /products/456
    import re as _re
    if _re.match(r'^/(?:orders|products|users|items|posts|articles|categories|tags|comments|reviews|invoices|shipments|carts|wishlist)/[\w-]+$', clean):
        return True
    # Search queries with simple terms (no special attack chars)
    import urllib.parse as _up
    import re as _re2
    if '?' in (path or ''):
        qs = (path or '').split('?', 1)[1]
        decoded_qs = _up.unquote_plus(qs)
        # If query only contains safe chars (letters, digits, spaces, common punctuation)
        # and no attack syntax, it's safe
        attack_syms = ('<', '>', '$(', '${', '`', '|', ';', '../', '--', '/*', "'")
        if not any(s in decoded_qs for s in attack_syms):
            if all(c.isalnum() or c in "=&_-+.%,:#()[]@!~ '$" or ord(c) > 127 for c in decoded_qs):
                if len(decoded_qs) < 500:
                    # Extra check: if parentheses are present, ensure no function call pattern
                    if '(' in decoded_qs:
                        if _re2.search(r'\w\(', decoded_qs):
                            pass  # Might be an attack, don't mark safe
                        else:
                            return True  # Standalone parens like "(test)"
                    else:
                        # Check for SQL keywords in context
                        dql = decoded_qs.lower()
                        sql_patterns = [
                            'union select', 'union all', 'select ', ' from ',
                            'insert into', 'update ', 'delete from', 'drop ',
                            'waitfor', 'benchmark', 'sleep ',
                        ]
                        # Check for NoSQL operators
                        nosql_patterns = ['[$', '{$', '$gt', '$ne', '$lt', '$regex', '$where']
                        # Check for double-encoding
                        double_enc = ['%25', '%252', '%2527']
                        # Check for Java deserialization markers
                        deser_patterns = ['rO0AB', 'aced0005']
                        # Check for prototype pollution
                        proto_patterns = ['__proto__', 'constructor[', 'prototype[']
                        
                        if any(p in dql for p in sql_patterns):
                            pass  # SQL context found, don't mark safe
                        elif any(p in decoded_qs for p in nosql_patterns):
                            pass
                        elif any(p in qs for p in double_enc):
                            pass
                        elif any(p in decoded_qs for p in proto_patterns):
                            pass
                        else:
                            return True
    # Safe form body (standard form submission without attack chars)
    if body:
        decoded_body = _up.unquote_plus(body)
        attack_syms_body = ('<', '>', '$(', '${', '`', '|', ';', '../', '--', '/*')
        if not any(s in decoded_body for s in attack_syms_body):
            if all(c.isalnum() or c in "=&_-+.%,:#()[]@!~ '\"$\r\n\t" or ord(c) > 127 for c in decoded_body):
                if len(decoded_body) < 2000:
                    bl = decoded_body.lower()
                    # Reject if it contains deser/attack markers
                    deser_bad = ['rO0AB', 'aced0005', 'O:', '__proto__', 'constructor']
                    if any(p in decoded_body for p in deser_bad):
                        pass
                    else:
                        return True
    return False


def check_regex_rules(path: str, body: str, headers: Dict[str, str]) -> Tuple[bool, str]:
    """Return (blocked:bool, reason:str_or_None).

    Checks request path+body+headers against compiled regex rules.
    Respects `ALLOW_PATHS` and safe-request pre-filter.
    """
    import urllib.parse
    import re
    
    # High-severity attack patterns that should ALWAYS be blocked, even on ALLOW_PATHS
    HIGH_SEVERITY_PATTERNS = [
        (re.compile(r"'\s*(?:or|and|=|;|--|union|select|insert|update|delete|drop)\b", re.I), 'sql-injection'),
        (re.compile(r'<script[^>]*>', re.I), 'xss'),
        (re.compile(r'javascript:', re.I), 'xss'),
        (re.compile(r'on(?:error|load|click|focus|mouseover)\s*=', re.I), 'xss'),
        (re.compile(r'\$\([^)]+\)', 0), 'rce'),
        (re.compile(r'`[^`]+`', 0), 'rce'),
    ]
    
    # Check high-severity attacks first (always active)
    if body or path:
        check_target = (path or '') + ' ' + (body or '')
        decoded_target = urllib.parse.unquote(check_target)
        for pat, kind in HIGH_SEVERITY_PATTERNS:
            if pat.search(check_target) or pat.search(decoded_target):
                return True, f"high-severity-{kind}"
    
    # Check if path matches any allowlist pattern (exact or prefix match)
    path_clean = (path or '').split('?')[0].rstrip('/')
    is_allowed = False
    for allowed in ALLOW_PATHS:
        if path_clean == allowed or path_clean.startswith(allowed + '/'):
            is_allowed = True
            break
    if is_allowed:
        return False, None
    if _is_safe_request(path, body):
        return False, None

    # Decode URL encoding to detect obfuscated attacks
    decoded_path = urllib.parse.unquote(path or '') if path else ''
    decoded_body = urllib.parse.unquote(body or '') if body else ''
    
    # Check both original and decoded versions
    target = ' '.join([path or '', body or '', _headers_to_text(headers or {})])
    decoded_target = ' '.join([decoded_path, decoded_body, _headers_to_text(headers or {})])
    
    for pat, kind in COMPILED_RULES:
        if pat.search(target) or pat.search(decoded_target):
            return True, f"regex-{kind}"
    return False, None


def list_rules() -> List[Tuple[str, str]]:
    """Return list of (pattern, kind) for debugging/monitoring."""
    return [(p.pattern, k) for p, k in COMPILED_RULES]

