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
    r"(?:'\s*--|\)\s*--|\d\s*--|;\s*--)",  # FIXED: SQL comment with context (not bare --)
    r"/\*[!+].*\*/",  # FIXED: MySQL hint comments /*!...*/ and /*+...*/ only
    r"\bor\b\s+\d+\s*=",
    r"'.*or.*'.*'.*=.*'",  # Détecte 1' OR '1'='1
    r"\bsleep\s*\(",  # Time-based blind SLEEP(5)
    r"\bbenchmark\s*\(",  # Time-based blind BENCHMARK
    r"\bwaitfor\b.*\bdelay\b",  # MSSQL WAITFOR DELAY
    r"\bexec\s*\(|\bexecute\s+(?:immediate|as|sp_|xp_)",  # EXEC/EXECUTE with SQL context
    r"'\s*\|\||\|\|\s*'",  # FIXED: SQL concat || with quote context only
    r"0x[0-9a-f]{8,}",  # FIXED: Hex (min 8 chars to avoid CSS color 0xffffff FP)
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
    # === PostgreSQL RCE patterns (NEW) ===
    r"\bcopy\b.*\bto\b.*\bprogram\b",  # COPY ... TO PROGRAM 'cmd'
    r"\blo_import\s*\(",  # lo_import() large object RCE
    r"\blo_export\s*\(",  # lo_export()
    r"\bpg_read_file\s*\(",  # pg_read_file() file read
    r"\bpg_ls_dir\s*\(",  # pg_ls_dir() directory listing
    r"\bpg_stat_file\s*\(",  # pg_stat_file()
    r"\bquery_to_xml\s*\(",  # query_to_xml() data exfil
    # === MSSQL RCE patterns (NEW) ===
    r"\bsp_oacreate\b",  # sp_OACreate COM object
    r"\bsp_oamethod\b",  # sp_OAMethod
    r"\bxp_dirtree\b",  # xp_dirtree directory listing
    r"\bxp_fileexist\b",  # xp_fileexist file check
    r"\bxp_subdirs\b",  # xp_subdirs
    r"\bxp_availablemedia\b",  # xp_availablemedia
    # === Oracle RCE patterns (NEW) ===
    r"\butl_file\.\w+",  # UTL_FILE.PUT/GET/FOPEN/FCLOSE
    r"\bdbms_utility\.exec_ddl\b",  # DBMS_UTILITY.EXEC_DDL
    # === v7.1 Bypass fix patterns ===
    r"\)\s*(?:AND|OR)\s*\(",                          # Parenthesized blind: 1)AND(1)=(1
    r"\d+(?:[eE]\d*|\.\d*)\s*(?:UNION|SELECT)\b",     # Scientific notation: 1e0UNION SELECT
    r"\bCASE[\s+]+WHEN\b",                               # CASE WHEN blind SQLi (matches + URL-encoding)
    r"\bIF\s*\(\s*\d+\s*[=<>!]+\s*\d+\s*,",           # IF(1=1,id,name) sort injection
    # === v7.2 Bypass fix patterns ===
    r"\bUNION\s*\(",                                     # UNION( spaceless: UNION(SELECT(1))
    r"\(\s*SELECT\b",                                     # (SELECT subquery: (SELECT(1)FROM(users))
    r"\b(?:XOR|DIV|MOD)\b\s+\(?",                        # XOR/DIV/MOD operators with optional subquery
    r"\bRLIKE\b",                                         # RLIKE regex match (MySQL-specific)
    r"\bREGEXP\b\s+\(?",                                  # REGEXP with optional subquery
    r"\bGROUP\s+BY\b.*?\bHAVING\b",                       # GROUP BY...HAVING
    r"\bHAVING\b\s+\w+\s*[><!=]",                         # HAVING col>0 (with comparison)
    r"\bELT\s*\(",                                        # ELT() MySQL function
    r"\bMAKE_SET\s*\(",                                   # MAKE_SET() MySQL function
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
    # FIXED: Explicit event handler whitelist (avoids FP on onion=, once=, ongoing=)
    r"\bon(?:error|load|click|focus|blur|mouseover|mousedown|mouseup|mousemove|mouseout|keydown|keyup|keypress|change|submit|reset|select|abort|resize|scroll|unload|beforeunload|hashchange|popstate|storage|message|copy|cut|paste|drag|dragend|dragenter|dragleave|dragover|dragstart|drop|wheel|contextmenu|pointerdown|pointerup|pointermove|pointerover|pointerout|toggle|input|invalid|animationend|animationstart|transitionend|touchstart|touchend|touchmove)\s*=",
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
    # === DOM Clobbering XSS (NEW) ===
    r"<form\s+[^>]*id\s*=\s*['\"]?(?:document|location|window|self|top|parent|frames)\b",
    r"<a\s+[^>]*id\s*=\s*['\"]?(?:document|location|URL|origin)\b",
    r"<output\s+[^>]*id\s*=\s*['\"]?(?:document|location|URL)\b",
    r"<embed\s+[^>]*name\s*=\s*['\"]?(?:document|location|window)\b",
    # === Import Maps XSS (NEW) ===
    r"<script\s+type\s*=\s*['\"]?importmap",
    r"import\s*\(['\"]data:",
    r"import\s*\(['\"]blob:",
    # === Service Worker XSS (NEW) ===
    r"navigator\.serviceWorker\.register\s*\(",
    r"importScripts\s*\(",
]

# ==================== COMMAND INJECTION PATTERNS ====================
CMDI_PATTERNS = [
    r"[;|]\s*(whoami|id|ls|cat|wget|curl|nc|bash|sh|cmd|uname|pwd)\b|&\s+(whoami|id|ls|cat|wget|curl|nc|bash|sh|cmd|uname|pwd)\b",
    r"`[^`]{1,200}`",  # FIXED: Backticks with length limit (avoids FP on markdown)
    r"\$\([^)]{1,200}\)",  # FIXED: Command substitution with length limit (avoids jQuery FP)
    r"%0a|%0d",  # Newline injection
    r"\|\s*(grep|awk|sed|sort|uniq|head|tail|cut)",  # Pipe with Unix commands
    r"\$IFS",  # IFS variable manipulation
    r"\$\d+",  # Positional parameters ($1, $9)
    r"\$PATH|\$HOME|\$USER",  # Environment variables
    r"\\[a-z]",  # Backslash escaping (c\at)
    r"\{[a-z]+,[^}]+\}",  # Brace expansion {cat,/etc/passwd}
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
    # FIXED: Commands with metachar context (avoid FP on plain English words)
    r"(?:[;|&]|&&|\|\|)\s*(?:ping|nslookup|dig|traceroute|netcat|telnet)\b",
    r"(?:[;|&]|&&|\|\|)\s*(?:ftp|ssh|chmod|chown|mkdir|touch)\b",
    r"\brm\b\s+-[rf]",  # rm -rf
    r"\bkill\b\s+-\d",  # kill -9
    # === Windows Command Injection (NEW) ===
    r"\bcmd\s*/[cCkK]\s",  # cmd /c whoami
    r"\bcmd\.exe\s*/[cCkK]\s",  # cmd.exe /c
    r"\bpowershell\s+-(?:enc|e|encodedcommand|nop|sta|ep\s+bypass|exec\s+bypass)\b",  # PowerShell
    r"\bpowershell\.exe\s+-(?:enc|e|w\s+hidden|nop)\b",  # powershell.exe
    r"\bcertutil\s+-(?:urlcache|decode|encode)\b",  # certutil download/decode
    r"\bbitsadmin\s+/transfer\b",  # bitsadmin download
    r"\bmshta\s+(?:http|javascript|vbscript):",  # mshta execution
    r"\bregsvr32\s+/s\s+/n\b",  # regsvr32 bypass
    r"\brundll32\s+",  # rundll32 execution
    r"\bwmic\s+(?:process|os|service|useraccount)\b",  # WMIC
    r"\bcscript\s+",  # cscript.exe
    r"\bwscript\s+",  # wscript.exe
    r"\bschtasks\s+/create\b",  # Scheduled tasks
    r"\bsc\s+(?:create|config|start|stop|delete)\b",  # Service control
    r"\bnet\s+(?:user|localgroup|group|share|use)\b",  # Net commands
    r"\breg\s+(?:add|delete|query|save|export)\b",  # Registry manipulation
]

# ==================== PATH TRAVERSAL / LFI PATTERNS ====================
PATH_TRAVERSAL_PATTERNS = [
    r"\.\./|\.\.\\/",  # ../ or ..\
    r"%2e%2e%2f|%2e%2e/|%2e%2e%5c",  # Encoded ../
    r"\.\.%2f|\.\.%5c",  # Partially encoded
    r"\.\.\.\./+|\.\.\.\.\\+",  # Double slash evasion: ....//
    r"/etc/passwd|/etc/shadow|/etc/hosts",  # Unix sensitive files
    r"c:\\windows\\|c:/windows/",  # Windows paths
    r"\\\\\\\\[0-9.]+",  # UNC paths (\\127.0.0.1)
    r"\\\\[a-z0-9.-]+\\c\$",  # Windows admin shares (\\host\c$)
    # UTF-8 overlong encoding bypass prevention
    r"%c0%ae|%c0%af",  # UTF-8 overlong encoding for . and /
    r"%c1%1c|%c1%9c",  # UTF-8 overlong encoding variants
    r"%e0%80%ae",  # 3-byte overlong encoding for .
    r"%f0%80%80%ae",  # 4-byte overlong encoding for .
    r"%252e|%252f",  # Double URL encoding
    r"\.\.\.;/",  # Tomcat path traversal bypass
    r"/\.\./",  # Normalized traversal
    # === Windows ADS & IIS bypass (NEW) ===
    r"::\$DATA",  # NTFS Alternate Data Stream
    r"::\$INDEX_ALLOCATION",  # NTFS directory ADS
    r"\.\.\.;\./",  # Tomcat path normalization variant
    r"/%5c\.\.%5c",  # IIS backslash traversal
    r"/%252e%252e/",  # IIS double-encoded traversal
    r"/\.%00\./",  # Null byte directory bypass
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
    # === Base XXE patterns ===
    r"<!ENTITY",  # XML Entity declaration
    r"<!DOCTYPE\s+\w",  # DOCTYPE declaration (any DOCTYPE with name)
    r"SYSTEM\s+[\"'](?:file|http|https|ftp|gopher|expect|jar|netdoc|php|data|dict)://",  # External entity with protocol
    r"PUBLIC\s+[\"']",  # PUBLIC external entity
    # === Parameter Entities (Blind XXE OOB) ===
    r"<!ENTITY\s+%\s+\w+",  # Parameter entity declaration: <!ENTITY % xxe
    r"%\w+;",  # Parameter entity reference: %xxe;
    r"<!ENTITY\s+%\s+\w+\s+SYSTEM",  # External parameter entity
    r"<!ENTITY\s+%\s+\w+\s+\"<!ENTITY",  # Nested entity declaration for OOB
    r"<!ENTITY\s+\w+\s+SYSTEM\s+[\"']https?://",  # External entity HTTP
    r"<!ENTITY\s+\w+\s+SYSTEM\s+[\"']ftp://",  # External entity FTP
    r"<!ENTITY\s+\w+\s+SYSTEM\s+[\"']gopher://",  # External entity Gopher
    r"<!ENTITY\s+\w+\s+SYSTEM\s+[\"']expect://",  # External entity Expect (PHP)
    r"<!ENTITY\s+\w+\s+SYSTEM\s+[\"']jar:",  # External entity JAR
    r"<!ENTITY\s+\w+\s+SYSTEM\s+[\"']netdoc://",  # External entity netdoc
    r"<!ENTITY\s+\w+\s+SYSTEM\s+[\"']php://",  # External entity php://
    r"<!ENTITY\s+\w+\s+SYSTEM\s+[\"']data://",  # External entity data://
    # === XInclude Attacks ===
    r"<xi:include\b",  # XInclude element
    r"xmlns:xi\s*=\s*[\"']http://www\.w3\.org/2001/XInclude",  # XInclude namespace
    r"<xi:include\s+[^>]*href\s*=\s*[\"'](?:file|http|ftp)://",  # XInclude with external href
    r"<xi:include\s+[^>]*parse\s*=\s*[\"']text",  # XInclude text parsing
    # === XSLT Injection ===
    r"<xsl:value-of\s+select\s*=\s*[\"']document\(",  # XSLT document() function
    r"<xsl:include\s+href\s*=",  # XSLT include
    r"<xsl:import\s+href\s*=",  # XSLT import
    r"<xsl:(?:stylesheet|transform)\b",  # XSLT root elements
    r"<xsl:(?:variable|param|template|output|copy-of)\b",  # XSLT directives
    r"xmlns:xsl\s*=\s*[\"']http://www\.w3\.org/1999/XSL/Transform",  # XSLT namespace
    # === SVG/XML-based XXE ===
    r"<!DOCTYPE\s+svg\b",  # SVG DOCTYPE
    r"<!DOCTYPE\s+(?:svg|math|html)\s[^>]*\[",  # DOCTYPE with internal subset
    r"<!DOCTYPE\s+\w+\s*\[",  # Any DOCTYPE with internal subset (DTD)
    # === XML Bomb / Billion Laughs ===
    r"<!ENTITY\s+\w+\s+\"(?:&\w+;){2,}",  # Entity referencing other entities (XML bomb)
    r"<!ENTITY\s+\w+\s+\"(?:.*){100,}",  # Very long entity value
    # === Encoded XXE variants ===
    r"%3C!ENTITY",  # URL-encoded <!ENTITY
    r"%3C!DOCTYPE",  # URL-encoded <!DOCTYPE
    r"&#x3c;!ENTITY",  # HTML entity encoded <!ENTITY
    r"&#x3c;!DOCTYPE",  # HTML entity encoded <!DOCTYPE
    r"&#60;!ENTITY",  # Decimal HTML entity
    r"&#60;!DOCTYPE",  # Decimal HTML entity
    # === Advanced XXE bypass patterns ===
    r"<!\[CDATA\[.*<!ENTITY",  # CDATA-wrapped entity
    r"<!DOCTYPE\s+\w+\s+PUBLIC\s+[\"'][^\"\']*[\"']\s+[\"'](?:http|ftp|file)://",  # PUBLIC with external DTD
    r"<!ENTITY\s+\w+\s+SYSTEM\s+[\"']/etc/",  # Direct file access Unix
    r"<!ENTITY\s+\w+\s+SYSTEM\s+[\"']c:\\",  # Direct file access Windows
    r"<!ENTITY\s+\w+\s+SYSTEM\s+[\"']\\\\\\\\\w+",  # UNC path entity
    r"<!ENTITY\s+\w+\s+SYSTEM\s+[\"']\s*\"\s*>",  # Empty SYSTEM entity (probe)
    # === SOAP/XML-RPC XXE ===
    r"<soap:(?:Envelope|Body|Header).*<!ENTITY",  # SOAP with XXE
    r"<methodCall>.*<!ENTITY",  # XML-RPC with XXE
    r"<methodCall>.*<!DOCTYPE",  # XML-RPC with DOCTYPE
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
    r"\{\{.*\*.*\}\}",  # {{7*7}} — arithmetic probe
    r"\$\{.*\*.*\}",  # ${7*7} — arithmetic probe
    r"\{\%.*\%\}",  # {%...%} — Jinja2/Twig block tags
    r"<\%.*\%>",  # <%...%> — ERB/JSP/ASP
    r"\{\{.*config.*\}\}",  # {{config}} — Jinja2 config access
    r"\{\{.*self.*\}\}",  # {{self}} — Jinja2 self access
    r"#\{.*(?:system|exec|`|IO\.popen|open\s*\|).*\}",  # FIXED: Ruby #{} only with dangerous calls
    # FIXED: Generic {{...}} only with exploit indicators (not every template variable)
    r"\{\{.*(?:__class__|__mro__|__subclasses__|__globals__|__builtins__|__import__|lipsum|cycler|joiner|namespace|url_for|get_flashed|request\.|config\.|popen|subprocess|os\.).*\}\}",
    # FIXED: ${...} only with dangerous Java/Spring EL expressions
    r"\$\{.*(?:Runtime|exec|getClass|ProcessBuilder|Thread|forName|getRuntime|System|classLoader|ScriptEngine|java\.|javax\.).*\}",
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

# === DEDUPLICATION ENGINE ===
# Normalize category labels so SIEM logs are consistent across all rule files
_CATEGORY_NORMALIZE = {
    'sqli_ext': 'sqli', 'sqli_adv_v5': 'sqli',
    'xss_ext': 'xss', 'xss_adv_v5': 'xss',
    'crlf': 'crlf-injection', 'open_redirect': 'open-redirect',
    'request_smuggling': 'request-smuggling', 'cache_poisoning': 'cache-poisoning',
    'websocket': 'websocket-injection', 'cors_bypass': 'cors-bypass',
    'el_injection': 'el-injection', 'rce': 'rce',
    'info_disclosure': 'info-disclosure', 'auth_bypass': 'auth-bypass',
    'scanner_probe': 'scanner-probe', 'encoding_evasion': 'encoding-evasion',
    'waf_bypass': 'waf-bypass', 'log_injection': 'log-injection',
    'email_injection': 'email-injection', 'xpath': 'xpath-injection',
    'csv_injection': 'csv-injection', 'wordpress': 'wordpress',
    'php_ext': 'php-injection', 'java_spring': 'java-spring',
    'dotnet': 'dotnet-injection', 'nodejs': 'nodejs-injection',
    'ruby_rails': 'ruby-rails', 'cve': 'cve',
    'api_security_adv': 'api-security', 'cloud_attacks': 'cloud-attacks',
    'container_k8s': 'container-k8s', 'oauth_saml': 'oauth-saml',
    'file_upload_adv': 'file-upload', 'http2_http3': 'http2-http3',
    'deserialization_adv': 'deserialization', 'ssrf_adv': 'ssrf',
    'race_condition': 'race-condition', 'business_logic': 'business-logic',
    'drupal': 'drupal', 'joomla': 'joomla', 'cve_2024_2025': 'cve',
    'sqli_adv_v5': 'sqli', 'cmd_injection_v5': 'cmdi',
    'path_traversal_v5': 'path-traversal', 'ssrf_v5': 'ssrf',
    'auth_session_v5': 'auth-bypass', 'ssti_v5': 'ssti',
    'xml_xxe_v5': 'xxe', 'webshell_v5': 'webshell',
    'cryptomining_v5': 'cryptomining', 'api_abuse_v5': 'api-security',
    'infrastructure_v5': 'infrastructure', 'mobile_iot_v5': 'mobile-iot',
    'business_logic_v5': 'business-logic', 'crypto_attacks_v5': 'crypto-attacks',
    'wordpress_v5': 'wordpress', 'cache_desync_v5': 'cache-desync',
    'cve_2025_v5': 'cve', 'ai_llm_v5': 'ai-llm',
    'supply_chain_v5': 'supply-chain', 'protocol_v5': 'protocol-attacks',
    'evasion_v5': 'evasion', 'serverless_cloud_v5': 'serverless-cloud',
    'log_evasion_v5': 'log-evasion', 'compliance_v5': 'compliance',
    'deser_ext_v5': 'deserialization', 'framework_v5': 'framework-attacks',
    'data_exfil_v5': 'data-exfil', 'emerging_v5': 'emerging-threats',
    'scanner_detect_v5': 'scanner-probe', 'cms_ext_v5': 'cms-attacks',
}

def _normalize_category(cat: str) -> str:
    """Normalize category label for consistent SIEM logging."""
    return _CATEGORY_NORMALIZE.get(cat, cat)

# Track seen regex strings to deduplicate across rule files
_seen_patterns = set()
_dedup_skipped = 0

def _add_pattern_dedup(regex_str: str, category: str) -> bool:
    """Add pattern if not already seen (deduplication). Returns True if added."""
    global _dedup_skipped
    # Strip (?i) prefix for dedup comparison since we compile with re.IGNORECASE
    clean = regex_str.strip()
    if clean.startswith('(?i)'):
        clean = clean[4:]
    if clean in _seen_patterns:
        _dedup_skipped += 1
        return False
    _seen_patterns.add(clean)
    norm_cat = _normalize_category(category)
    try:
        _default_compiled.append((re.compile(regex_str, re.IGNORECASE), norm_cat))
        return True
    except re.error:
        return False

# Register base patterns in dedup tracker
for pat, kind in _default_compiled:
    clean = pat.pattern.strip()
    if clean.startswith('(?i)'):
        clean = clean[4:]
    _seen_patterns.add(clean)

# === Merge Extended Rules (1200+ additional patterns) ===
try:
    from waf.rules_extended import get_all_extended_patterns, count_extended_patterns
    _ext_count = sum(1 for r, c in get_all_extended_patterns() if _add_pattern_dedup(r, c))
    print(f"[BeeWAF] Loaded {_ext_count} extended rules ({count_extended_patterns()} defined, {_dedup_skipped} deduped)")
except ImportError:
    print("[BeeWAF] Extended rules not found, using base rules only")

# === Merge Advanced v4.0 Rules (650+ additional patterns) ===
try:
    from waf.rules_advanced import get_all_advanced_patterns, count_advanced_patterns
    _adv_count = sum(1 for r, c in get_all_advanced_patterns() if _add_pattern_dedup(r, c))
    print(f"[BeeWAF] Loaded {_adv_count} advanced v4.0 rules ({count_advanced_patterns()} defined, {_dedup_skipped} total deduped)")
except ImportError:
    print("[BeeWAF] Advanced v4.0 rules not found, using base + extended rules only")

# === Merge v5.0 Rules (1200+ additional patterns) ===
try:
    from waf.rules_v5 import get_all_v5_patterns, count_v5_patterns
    _v5_count = sum(1 for r, c in get_all_v5_patterns() if _add_pattern_dedup(r, c))
    print(f"[BeeWAF] Loaded {_v5_count} v5.0 rules ({count_v5_patterns()} defined, {_dedup_skipped} total deduped)")
except ImportError:
    print("[BeeWAF] v5.0 rules not found, using base + extended + advanced rules only")

# === Merge Mega Rules Database Parts 1-12 ===
for _mega_idx in range(1, 13):
    try:
        _mod = __import__(f'waf.rules_mega_{_mega_idx}', fromlist=[f'get_all_mega{_mega_idx}_patterns', f'count_mega{_mega_idx}_patterns'])
        _get_fn = getattr(_mod, f'get_all_mega{_mega_idx}_patterns')
        _cnt_fn = getattr(_mod, f'count_mega{_mega_idx}_patterns')
        _m_count = sum(1 for r, c in _get_fn() if _add_pattern_dedup(r, c))
        print(f"[BeeWAF] Loaded {_m_count} mega-{_mega_idx} rules ({_cnt_fn()} defined)")
    except (ImportError, AttributeError):
        print(f"[BeeWAF] Mega rules part {_mega_idx} not found, skipping")

print(f"[BeeWAF] *** TOTAL COMPILED RULES: {len(_default_compiled)} (deduplicated {_dedup_skipped} redundant patterns) ***")

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
# Includes all IDTS application API endpoints to prevent false positives
# ── Paths communs à tous les domaines (WAF internal + health) ──
_ALLOW_COMMON = [
    '/health', '/metrics', '/admin/compliance', '/admin/ml-stats', '/admin/rules',
    '/admin/enterprise-stats', '/admin/virtual-patches', '/admin/correlation',
    '/admin/adaptive-mode', '/admin/retrain', '/admin/retrain-ml', '/admin/ml-predict',
]

# ── IDTS BACK (idts.back.dpc.com.tn) — context-path=/api ──
_ALLOW_IDTS_BACK = [
    '/api/auth/login', '/api/auth/register', '/api/auth/change-password',
    '/api/auth/reset-password', '/api/auth/validKey',
    '/api/chantiers', '/api/clients', '/api/factures', '/api/fournisseurs',
    '/api/roles', '/api/pointage', '/api/pointages',
    '/api/pointageChefChantierAndConducteur',
    '/api/tache', '/api/taches', '/api/salaire', '/api/salaires',
    '/api/remboursement', '/api/remboursements',
    '/api/notification', '/api/notifications',
    '/api/notification/token', '/api/notification/topic',
    '/api/user-details', '/api/fileFacture', '/api/images', '/api/uploadPhoto',
    '/api/paye', '/api/payes', '/api/chantUser', '/api/chantierUsers',
    '/api/users', '/api/sendNotificationForUserNotPointedToday',
]

# ── IDTS FRONT (dev.idts.dpc.com.tn) — Angular SPA, pas d'API propre ──
_ALLOW_IDTS_FRONT = [
    # Pas d'endpoints API — tout va vers idts.back via le navigateur
    # Les routes Angular sont gérées par _SAFE_PATH_PREFIXES/_SAFE_PATH_EXACT
]

# ── KAIROS BACK (dev.kairos.dpc.com.tn) — context-path=/api ──
_ALLOW_KAIROS_BACK = [
    '/auth', '/contact', '/unite', '/hR', '/gestionnaireprod', '/invoice',
    '/roles', '/users', '/user-details',
    '/api/basic_Material', '/api/PrimaryMatrial', '/api/PackagingAll',
    '/api/lot', '/api/Reposit', '/api/Adress_All', '/api/factoryall',
    '/api/Prefactory', '/api/prefactoryall', '/api/ProductAll', 
    '/api/QuarentineMP', '/api/QuarentinePr', '/api/rejection', 
    '/api/Customer', '/api/Provider', '/api/bcclient', '/api/bcfournisseur',
    '/api/blclient', '/api/blfournisseur', '/api/Invoice_Details', 
    '/api/paymentall', '/api/cotation', '/api/taxation', '/api/currency', 
    '/api/Transaction_All'
]

# ── KAIROS FRONT (front.kairos.dpc.com.tn) — Angular SPA, pas d'API propre ──
_ALLOW_KAIROS_FRONT = [
    # Pas d'endpoints API — tout va vers dev.kairos via le navigateur
]

# ── Table de routage host → liste d'endpoints autorisés ──
_ALLOW_BY_HOST = {
    'idts.back.dpc.com.tn':    _ALLOW_COMMON + _ALLOW_IDTS_BACK,
    'dev.idts.dpc.com.tn':     _ALLOW_COMMON + _ALLOW_IDTS_FRONT,
    'dev.kairos.dpc.com.tn':   _ALLOW_COMMON + _ALLOW_KAIROS_BACK,
    'front.kairos.dpc.com.tn': _ALLOW_COMMON + _ALLOW_KAIROS_FRONT,
}

# ── Fallback global (env var ou default) pour rétro-compatibilité ──
_DEFAULT_ALLOW = ','.join(_ALLOW_COMMON + _ALLOW_IDTS_BACK + _ALLOW_KAIROS_BACK)
ALLOW_PATHS = os.environ.get('BEEWAF_ALLOW_PATHS', _DEFAULT_ALLOW).split(',')
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
        'if-none-match', 'if-modified-since', 'if-range', 'if-match', 'if-unmodified-since',
        'upgrade-insecure-requests',
        'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'sec-fetch-user',
        'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform',
        'dnt', 'te', 'transfer-encoding',
        # Proxy/load-balancer tracing headers (HAProxy, nginx, etc.)
        'x-request-id', 'x-correlation-id', 'x-trace-id', 'idempotency-key',
        'x-forwarded-host', 'x-forwarded-port', 'x-forwarded-server',
        'x-forwarded-prefix', 'x-forwarded-scheme',
    }
    return ' '.join(f"{k}:{v}" for k, v in headers.items() if k.lower() not in _SKIP_HEADERS)


# ── Safe-path prefixes that must never be blocked ──
_SAFE_PATH_PREFIXES = (
    '/static/', '/assets/', '/css/', '/js/', '/images/', '/img/', '/fonts/',
    '/media/', '/favicon', '/manifest', '/sw.js', '/service-worker',
    # IDTS Front Angular SPA
    '/dashboard/',
    '/reset/',
    # Kairos Front Angular (lazy-loading modules)
    '/authentication/',
    '/admin/',
    '/customer/',
    '/Gestionnaire_Production/',
)
_SAFE_PATH_EXACT = {
    '/register', '/login', '/logout', '/signup', '/signin', '/signout',
    '/dashboard', '/profile', '/settings', '/account', '/home',
    '/about', '/contact', '/faq', '/help', '/terms', '/privacy',
    '/sitemap.xml', '/robots.txt', '/feed.xml', '/rss.xml', '/atom.xml',
    '/manifest.json', '/browserconfig.xml', '/crossdomain.xml',
    '/.well-known/security.txt', '/security.txt', '/humans.txt', '/ads.txt',
    # IDTS Front Angular routes
    '/forgetPassword', '/changePassword', '/erreur',
    '/reset/finish',
    # Kairos Front Angular routes
    '/authentication/login', '/authentication/forgetpsw',
    '/customer/bon-de-commande', '/customer/bondelivraisonclient',
    '/customer/add-devis',
}

_SPA_ROUTE_PREFIXES = ('/dashboard/', '/authentication/', '/admin/', '/customer/', '/Gestionnaire_Production/')

def _is_safe_request(path: str, body: str) -> bool:
    """Fast pre-filter: return True if the request is obviously safe."""
    clean = (path or '').split('?')[0].rstrip('/')
    if clean in _SAFE_PATH_EXACT:
        return True
    # SPA routes: Angular frontend handles all /dashboard/* paths internally
    if any(clean.startswith(p.rstrip('/')) for p in _SPA_ROUTE_PREFIXES):
        return True
    if any(clean.startswith(p) for p in _SAFE_PATH_PREFIXES):
        ext = clean.rsplit('.', 1)[-1] if '.' in clean else ''
        if ext in ('css', 'js', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico',
                   'woff', 'woff2', 'ttf', 'eot', 'map', 'webp', 'avif'):
            return True
    # Nested resource paths like /orders/123, /products/456
    import re as _re
    if _re.match(r'^/(?:orders|products|users|items|posts|articles|categories|tags|comments|reviews|invoices|shipments|carts|wishlist|chantiers|clients|factures|fournisseurs|roles|pointages|taches|salaires|remboursements|notifications|payes|chantierUsers)/[\w-]+$', clean):
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
                    # Extra check: if parentheses are present, ensure no function call or SQL pattern
                    if '(' in decoded_qs:
                        dql_paren = decoded_qs.lower()
                        # Check for SQL keywords near parens (subquery patterns)
                        sql_paren_patterns = [
                            'select(', '(select', 'union(', '(union',
                            'from(', '(from', 'where(', '(where',
                            'xor ', 'div ', 'mod ', 'rlike ', 'regexp ',
                            'having ', 'group by', 'elt(', 'make_set(',
                            'union select', 'select ', ' from ',
                            'case when', 'if(', ')and(', ')or(',
                        ]
                        if any(p in dql_paren for p in sql_paren_patterns):
                            pass  # SQL subquery/keyword found
                        elif _re2.search(r'\w\(', decoded_qs):
                            pass  # Function call pattern like func()
                        else:
                            return True  # Standalone parens like "(test)"
                    else:
                        # Check for SQL keywords in context
                        dql = decoded_qs.lower()
                        sql_patterns = [
                            'union select', 'union all', 'select ', ' from ',
                            'insert into', 'update ', 'delete from', 'drop ',
                            'waitfor', 'benchmark', 'sleep ', 'case when',
                            'if(', ')and(', ')or(',
                            ' xor ', ' div ', ' mod ', 'rlike ', 'regexp ',
                            'having ', 'group by', 'elt(', 'make_set(',
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
                    sql_bad = ['union select', 'union all', 'case when', 'select ',
                               'insert into', 'update ', 'delete from', 'drop ',
                               ')and(', ')or(', 'if(', '(select', 'union(',
                               ' xor ', ' div ', ' mod ', 'rlike ', 'regexp ',
                               'having ', 'group by', 'elt(', 'make_set(']
                    if any(p in decoded_body for p in deser_bad):
                        pass
                    elif any(p in bl for p in sql_bad):
                        pass  # SQL keywords in body, don't mark safe
                    elif _re2.search(r'\w\(', decoded_body):
                        pass  # Function call pattern in body
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
    
    # Note: DEBUG header logging removed for production performance
    
    # High-severity attack patterns that should ALWAYS be blocked, even on ALLOW_PATHS
    HIGH_SEVERITY_PATTERNS = [
        (re.compile(r"'\s*(?:or|and|=|;|--|union|select|insert|update|delete|drop)\b", re.I), 'sql-injection'),
        (re.compile(r'<script[^>]*>', re.I), 'xss'),
        (re.compile(r'javascript:', re.I), 'xss'),
        (re.compile(r'on(?:error|load|click|focus|mouseover)\s*=', re.I), 'xss'),
        (re.compile(r'\$\([^)]+\)', 0), 'rce'),
        (re.compile(r'`[^`]+`', 0), 'rce'),
        # === v7.1 Bypass fixes (always block, even on ALLOW_PATHS) ===
        (re.compile(r'\d\)\s*(?:AND|OR)\s*\(\s*(?:\d|SELECT\b)', re.I), 'sql-injection'),
        (re.compile(r'\d+(?:[eE]\d*|\.\d*)\s*(?:UNION|SELECT)\b', re.I), 'sql-injection'),
        (re.compile(r'\bCASE[\s+]+WHEN\b.*?\bTHEN\b', re.I), 'sql-injection'),
        (re.compile(r'\bIF\s*\(\s*\d+\s*[=<>!]+\s*\d+\s*,', re.I), 'sql-injection'),
        # === v7.2 Subquery & operator bypasses ===
        (re.compile(r'\(\s*SELECT\b', re.I), 'sql-injection'),
        (re.compile(r'\bUNION\s*\(\s*SELECT\b', re.I), 'sql-injection'),
    ]
    
    # Malicious header patterns that should ALWAYS be blocked, even on ALLOW_PATHS
    MALICIOUS_HEADER_PATTERNS = [
        # Cache poisoning with malicious domains
        (re.compile(r'X-Forwarded-Host\s*:\s*(?:evil|attacker|hacker|malicious)\b', re.I), 'cache_poisoning'),
        (re.compile(r'X-Forwarded-Host\s*:\s*\w+\.(?:evil|attacker|hacker|malicious|burp|ngrok|interact\.sh|oast)\.\w+', re.I), 'cache_poisoning'),
        (re.compile(r'X-Forwarded-Host\s*:\s*\w+\.interact\.sh\b', re.I), 'cache_poisoning'),
        (re.compile(r'X-Forwarded-Host\s*:\s*\w+\.oast\.\w+', re.I), 'cache_poisoning'),
        (re.compile(r'X-Host\s*:\s*(?:evil|attacker|hacker|malicious)\b', re.I), 'cache_poisoning'),
        # Loopback/localhost in X-Forwarded-For (bypass attempt)
        (re.compile(r'X-Forwarded-For\s*:\s*127\.0\.0\.1\b', re.I), 'cache_poisoning'),
        (re.compile(r'X-Forwarded-For\s*:\s*localhost\b', re.I), 'cache_poisoning'),
        (re.compile(r'X-Forwarded-For\s*:\s*0\.0\.0\.0\b', re.I), 'cache_poisoning'),
        (re.compile(r'X-Forwarded-For\s*:\s*169\.254\.169\.254\b', re.I), 'cache_poisoning'),
        # Admin path injection via headers
        (re.compile(r'X-Original-URL\s*:\s*/(?:admin|internal|debug|console|actuator)\b', re.I), 'cache_poisoning'),
        (re.compile(r'X-Rewrite-URL\s*:\s*/(?:admin|internal|debug|console|actuator)\b', re.I), 'cache_poisoning'),
    ]
    
    # Check high-severity attacks first (always active)
    if body or path:
        check_target = (path or '') + ' ' + (body or '')
        decoded_target = urllib.parse.unquote(check_target)
        decoded_target_plus = urllib.parse.unquote_plus(check_target)
        for pat, kind in HIGH_SEVERITY_PATTERNS:
            if pat.search(check_target) or pat.search(decoded_target) or pat.search(decoded_target_plus):
                return True, f"high-severity-{kind}"
    
    # Check malicious headers (always active, even on allowed paths)
    # Check raw headers directly (not through _headers_to_text which skips some)
    if headers:
        for h_name, h_value in headers.items():
            header_line = f"{h_name}: {h_value}"
            for pat, kind in MALICIOUS_HEADER_PATTERNS:
                if pat.search(header_line):
                    # Debug: log the matching pattern
                    import logging
                    logger = logging.getLogger('beewaf')
                    logger.warning(f"DEBUG HEADER match - header: {header_line}, kind: {kind}, pattern: {pat.pattern}")
                    return True, f"header-{kind}"
    
    # ── Isolation par domaine : sélectionner la bonne liste d'endpoints ──
    host_header = (headers.get('host') or headers.get('Host') or '').split(':')[0].lower().strip()
    if host_header and host_header in _ALLOW_BY_HOST:
        effective_allow = _ALLOW_BY_HOST[host_header]
    else:
        effective_allow = ALLOW_PATHS  # fallback global

    # Check if path matches the domain-specific allowlist
    path_clean = (path or '').split('?')[0].rstrip('/')
    is_allowed = False
    for allowed in effective_allow:
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
    decoded_path_plus = urllib.parse.unquote_plus(path or '') if path else ''
    decoded_body_plus = urllib.parse.unquote_plus(body or '') if body else ''
    
    # Check original, unquote-decoded, and unquote_plus-decoded versions
    target = ' '.join([path or '', body or '', _headers_to_text(headers or {})])
    decoded_target = ' '.join([decoded_path, decoded_body, _headers_to_text(headers or {})])
    decoded_target_plus = ' '.join([decoded_path_plus, decoded_body_plus, _headers_to_text(headers or {})])
    
    for pat, kind in COMPILED_RULES:
        if pat.search(target) or pat.search(decoded_target) or pat.search(decoded_target_plus):
            return True, f"regex-{kind}"
    return False, None


def list_rules() -> List[Tuple[str, str]]:
    """Return list of (pattern, kind) for debugging/monitoring."""
    return [(p.pattern, k) for p, k in COMPILED_RULES]

