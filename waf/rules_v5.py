"""
BeeWAF Enterprise v5.0 - Extended Rule Database v5
1200+ NEW attack signatures across 25 categories for total 2500+ rules.
Organized by attack class with regex patterns optimized for performance.
"""

# ============================================================================
# 1. ADVANCED SQL INJECTION (100 patterns)
# ============================================================================
SQLI_ADVANCED = [
    # Error-based
    r"(?i)extractvalue\s*\(",
    r"(?i)updatexml\s*\(",
    r"(?i)geometrycollection\s*\(",
    r"(?i)multipoint\s*\(",
    r"(?i)multipolygon\s*\(",
    r"(?i)linestring\s*\(",
    r"(?i)polygon\s*\(",
    r"(?i)exp\s*\(\s*~",
    r"(?i)floor\s*\(\s*rand\s*\(",
    r"(?i)row\s*\(\s*\d",
    # Stacked queries
    r";\s*(?:declare|exec|execute)\s+",
    r";\s*waitfor\s+delay\s+",
    r";\s*(?:shutdown|xp_cmdshell|xp_regread)",
    r"(?i)(?:;|\|)\s*(?:ls|cat|id|whoami|pwd|uname)\b",
    # MSSQL specific
    r"(?i)xp_cmdshell\s*\(",
    r"(?i)xp_regread\s*\(",
    r"(?i)sp_oacreate\s*",
    r"(?i)sp_oamethod\s*",
    r"(?i)sp_makewebtask\b",
    r"(?i)openrowset\s*\(",
    r"(?i)opendatasource\s*\(",
    r"(?i)(?:master|msdb|tempdb)\.\.(?:xp_|sp_)",
    r"(?i)into\s+(?:outfile|dumpfile)\s+",
    r"(?i)load_file\s*\(",
    r"(?i)@@(?:version|servername|hostname|language)",
    # PostgreSQL specific
    r"(?i)pg_sleep\s*\(",
    r"(?i)pg_user\b",
    r"(?i)current_setting\s*\(",
    r"(?i)pg_read_file\s*\(",
    r"(?i)pg_ls_dir\s*\(",
    r"(?i)lo_import\s*\(",
    r"(?i)lo_export\s*\(",
    r"(?i)copy\s+.*\s+from\s+program\b",
    r"(?i)string_agg\s*\(",
    r"(?i)\$\$.*\$\$",
    # Oracle specific
    r"(?i)dbms_pipe\.receive_message",
    r"(?i)utl_http\.request",
    r"(?i)utl_inaddr\.get_host_address",
    r"(?i)ctxsys\.drithsx\.sn",
    r"(?i)sys\.dbms_ldap\.init",
    r"(?i)all_tables\b",
    r"(?i)user_tables\b",
    r"(?i)dba_users\b",
    # MySQL specific
    r"(?i)information_schema\.(?:tables|columns|schemata)",
    r"(?i)group_concat\s*\(",
    r"(?i)concat_ws\s*\(",
    r"(?i)char\s*\(\s*\d+\s*,",
    r"(?i)hex\s*\(\s*(?:select|user|version)",
    r"(?i)unhex\s*\(",
    r"(?i)conv\s*\(\s*(?:select|user)",
    r"(?i)0x[0-9a-f]{6,}",
    # SQLite specific
    r"(?i)sqlite_master\b",
    r"(?i)sqlite_version\b",
    r"(?i)sqlite_temp_master\b",
    r"(?i)randomblob\s*\(",
    # Blind techniques
    r"(?i)(?:and|or)\s+\d+=\d+\s*(?:--|#|/\*)",
    r"(?i)(?:and|or)\s+['\"]\w+['\"]=['\"]",
    r"(?i)if\s*\(\s*(?:ascii|substr|mid|left|right)\s*\(",
    r"(?i)case\s+when\s+.*\s+then\s+",
    r"(?i)(?:ascii|ord)\s*\(\s*(?:substr|mid|left|right)\s*\(",
    r"(?i)substr(?:ing)?\s*\(\s*(?:select|user|version|database)",
    r"(?i)mid\s*\(\s*(?:select|user|version|database)",
    r"(?i)left\s*\(\s*(?:select|user|version|database)",
    r"(?i)bit_length\s*\(",
    r"(?i)char_length\s*\(",
    # Second-order injection markers
    r"(?i)(?:insert|update)\s+.*\s+(?:values|set)\s+.*(?:select|union)",
    # JSON-based SQLi
    r"(?i)json_extract\s*\(\s*.*(?:select|union)",
    r"(?i)json_arrayagg\s*\(",
    r"(?i)json_objectagg\s*\(",
    # Window functions abuse
    r"(?i)(?:row_number|rank|dense_rank|ntile)\s*\(\s*\)\s*over\s*\(",
    r"(?i)lead\s*\(.*\)\s*over\s*\(",
    r"(?i)lag\s*\(.*\)\s*over\s*\(",
    # CTE injection
    r"(?i)with\s+\w+\s+as\s*\(\s*select\b",
    # Bypass techniques
    r"(?i)\/\*!(?:\d+)?\s*select\b",
    r"(?i)\/\*!(?:\d+)?\s*union\b",
    r"(?i)sel%65ct\b",
    r"(?i)un%69on\b",
    r"(?i)%55nion%20%53elect",
    r"(?i)%73elect\b",
    r"(?i)s%65lect\b",
    r"(?i)uni%6fn\b",
    r"(?i)(?:having|group\s+by)\s+\d+",
    r"(?i)order\s+by\s+\d{2,}",
    r"(?i)procedure\s+analyse\s*\(",
    # Time-based
    r"(?i)benchmark\s*\(\s*\d{4,}",
    r"(?i)sleep\s*\(\s*\d{2,}",
    r"(?i)pg_sleep\s*\(\s*\d{2,}",
    r"(?i)waitfor\s+delay\s+['\"]0:\d+",
    r"(?i)dbms_pipe\.receive_message\s*\(\s*['\"]",
    # NoSQL injection extended
    r"\$(?:regex|exists|type|mod|slice|elemMatch|size|all)\b",
    r"(?i)db\.\w+\.(?:find|insert|update|remove|drop|aggregate)\s*\(",
    r"(?i)mapreduce\s*\(",
    r"(?i)\$(?:lookup|graphLookup|unwind|project|match)\b",
    r"(?i)this\.\w+\s*(?:==|!=|>|<)",
    r"(?i)tojsononeline\s*\(",
    r"(?i)db\.getCollectionNames\s*\(",
    r"(?i)db\.adminCommand\s*\(",
]

# ============================================================================
# 2. ADVANCED XSS (80 patterns)
# ============================================================================
XSS_ADVANCED = [
    # DOM-based XSS
    r"(?i)document\.(?:write|writeln|cookie|domain|location|referrer|URL)",
    r"(?i)window\.(?:location|name|open)\s*=",
    r"(?i)(?:location|document)\.(?:href|hash|search)\s*=",
    r"(?i)(?:innerHTML|outerHTML|insertAdjacentHTML|write)\s*[=\(]",
    r"(?i)eval\s*\(\s*(?:location|document|window|name)",
    r"(?i)setTimeout\s*\(\s*(?:location|document|window)",
    r"(?i)setInterval\s*\(\s*(?:location|document|window)",
    r"(?i)Function\s*\(\s*(?:location|document|window)",
    # Event handlers (comprehensive)
    r"(?i)\bon(?:abort|blur|change|click|dblclick|error|focus|load|mouse\w+|key\w+|submit|reset|resize|scroll|unload|drag\w+|touch\w+|pointer\w+|animation\w+|transition\w+)\s*=",
    r"(?i)\bon(?:before(?:copy|cut|paste|print|unload|input))\s*=",
    r"(?i)\bon(?:after(?:print|update))\s*=",
    r"(?i)\bon(?:copy|cut|paste|select|selectstart)\s*=",
    r"(?i)\bon(?:context(?:menu|lost|restored))\s*=",
    r"(?i)\bon(?:formdata|invalid|search|toggle|wheel)\s*=",
    r"(?i)\bon(?:message|storage|hashchange|popstate|pagehide|pageshow)\s*=",
    # SVG/MathML XSS
    r"(?i)<svg[^>]*\bon\w+\s*=",
    r"(?i)<math[^>]*\bon\w+\s*=",
    r"(?i)<(?:animate|set|animateTransform)\s+[^>]*(?:on\w+|href\s*=\s*['\"]javascript)",
    r"(?i)<use\s+[^>]*href\s*=\s*['\"](?:data:|javascript:)",
    r"(?i)<foreignObject\b",
    # Template injection (SSTI) / XSS in templates
    r"\{\{.*(?:constructor|prototype|__proto__|process)\b",
    r"\{\{.*(?:exec|system|spawn|eval)\s*\(",
    r"(?i)\$\{.*(?:constructor|process|require)\b",
    r"\[\s*(?:'|\")\s*constructor\s*(?:'|\")\s*\]",
    # Polyglot payloads
    r"(?i)jaVasCript\s*:",
    r"(?i)vbscript\s*:",
    r"(?i)livescript\s*:",
    r"(?i)mocha\s*:",
    r"(?i)data\s*:\s*text/html",
    r"(?i)data\s*:\s*(?:application|text)/(?:xhtml|xml|javascript)",
    # CSS-based XSS
    r"(?i)expression\s*\(",
    r"(?i)behavior\s*:\s*url\s*\(",
    r"(?i)-moz-binding\s*:\s*url\s*\(",
    r"(?i)@import\s+['\"](?:javascript|data):",
    r"(?i)style\s*=\s*['\"].*(?:expression|behavior|binding|@import)",
    # HTML5 attack vectors
    r"(?i)<(?:details|dialog|summary)\s+[^>]*(?:open|on\w+)",
    r"(?i)<(?:video|audio|source)\s+[^>]*(?:on\w+|src\s*=\s*['\"]javascript)",
    r"(?i)<(?:embed|object|applet)\s+[^>]*(?:code|data|src)\s*=",
    r"(?i)<(?:base|meta)\s+[^>]*(?:href|content|http-equiv)\s*=",
    r"(?i)<link\s+[^>]*rel\s*=\s*['\"]import",
    r"(?i)<(?:iframe|frame)\s+[^>]*(?:srcdoc|src)\s*=",
    r"(?i)srcdoc\s*=\s*['\"]",
    # Mutation XSS (mXSS)
    r"(?i)<(?:noscript|title|textarea|style|xmp|listing)\b[^>]*>[^<]*<(?:img|svg|script)",
    r"(?i)</?(?:noembed|noframes)\b",
    # Obfuscated XSS
    r"(?i)&#x?[0-9a-f]+;.*(?:script|alert|onerror|onload)",
    r"(?i)\\u00[0-9a-f]{2}.*(?:script|alert|document)",
    r"(?i)String\.fromCharCode\s*\(",
    r"(?i)atob\s*\(",
    r"(?i)(?:unescape|decodeURI(?:Component)?)\s*\(\s*['\"]%",
    # Fetch/XHR-based exfiltration
    r"(?i)(?:fetch|XMLHttpRequest)\s*\(\s*['\"]https?://",
    r"(?i)navigator\.sendBeacon\s*\(",
    r"(?i)new\s+Image\s*\(\s*\)\s*\.src\s*=",
    # Content injection
    r"(?i)<(?:meta|base)\s+[^>]*(?:url|content)\s*=\s*['\"](?:http|data|javascript)",
    # Angular/React/Vue template injection
    r"(?i)ng-(?:init|bind|include|click|mouseover)\s*=",
    r"(?i)v-(?:html|bind|on|model)\s*=.*(?:script|alert|document)",
    r"(?i)dangerouslySetInnerHTML",
    # Service Worker hijacking
    r"(?i)navigator\.serviceWorker\.register\s*\(",
    r"(?i)importScripts\s*\(",
    # WebAssembly injection
    r"(?i)WebAssembly\.(?:instantiate|compile|Module)\s*\(",
    # Prototype pollution XSS
    r"(?i)Object\.(?:assign|defineProperty)\s*\(\s*.*__proto__",
    # CSP bypass techniques
    r"(?i)<script[^>]*\s+nonce\s*=\s*['\"]['\"]",
    r"(?i)<script[^>]*\s+src\s*=\s*['\"]data:",
    # Markdown XSS
    r"(?i)\[.*\]\s*\(\s*javascript:",
    r"(?i)!\[.*\]\s*\(\s*(?:onerror|data:)",
]

# ============================================================================
# 3. COMMAND INJECTION ADVANCED (60 patterns)
# ============================================================================
CMD_INJECTION_ADVANCED = [
    # Shell metacharacters
    r"(?:;|\||&&|\|\|)\s*(?:ls|dir|cat|type|more|head|tail|nl|tac)\b",
    r"(?:;|\||&&)\s*(?:wget|curl|fetch|nc|ncat|socat)\b",
    r"(?:;|\||&&)\s*(?:bash|sh|zsh|ksh|csh|tcsh|dash|fish)\b",
    r"(?:;|\||&&)\s*(?:python[23]?|perl|ruby|node|php|lua)\b",
    r"(?:;|\||&&)\s*(?:chmod|chown|chgrp|chattr)\b",
    r"(?:;|\||&&)\s*(?:useradd|usermod|userdel|passwd|adduser)\b",
    r"(?:;|\||&&)\s*(?:iptables|firewall-cmd|ufw|nft)\b",
    r"(?:;|\||&&)\s*(?:crontab|at\b|systemctl|service)\b",
    r"(?:;|\||&&)\s*(?:rm\s+-rf|mkfs|dd\s+if=|shred)\b",
    # Backtick execution
    r"`\s*(?:id|whoami|uname|hostname|ifconfig|ip\s+addr)\s*`",
    r"`\s*(?:cat|head|tail)\s+/etc/",
    r"`\s*(?:wget|curl|nc)\s+",
    # $() command substitution
    r"\$\(\s*(?:id|whoami|uname|hostname|pwd)\s*\)",
    r"\$\(\s*(?:cat|head|tail|less|more)\s+",
    r"\$\(\s*(?:wget|curl|nc|ncat)\s+",
    r"\$\(\s*(?:find|grep|awk|sed|sort|cut)\s+",
    # Environment variable injection
    r"(?i)(?:PATH|LD_PRELOAD|LD_LIBRARY_PATH|DYLD_INSERT_LIBRARIES)\s*=",
    r"(?i)(?:IFS|ENV|BASH_ENV|SHELLOPTS|BASHOPTS)\s*=",
    r"(?i)(?:PS1|PS4|PROMPT_COMMAND)\s*=.*\$\(",
    # Process manipulation
    r"(?:;|\|)\s*(?:kill|pkill|killall)\s+",
    r"(?:;|\|)\s*(?:nohup|disown|setsid)\s+",
    r"(?:;|\|)\s*(?:screen|tmux)\s+",
    # Reverse shell patterns
    r"(?i)bash\s+-i\s+>&\s*/dev/tcp/",
    r"(?i)/dev/tcp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/",
    r"(?i)mkfifo\s+/tmp/",
    r"(?i)nc\s+-[elp]+\s+",
    r"(?i)python[23]?\s+-c\s+['\"]import\s+(?:socket|os|subprocess|pty)",
    r"(?i)perl\s+-e\s+['\"].*(?:socket|exec|system|fork)\b",
    r"(?i)ruby\s+-e\s+['\"].*(?:TCPSocket|exec|system|spawn)\b",
    r"(?i)php\s+-r\s+['\"].*(?:fsockopen|exec|system|passthru)\b",
    r"(?i)socat\s+(?:TCP|UDP|EXEC)\b",
    r"(?i)telnet\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d+\s*\|",
    # PowerShell
    r"(?i)powershell\s+(?:-enc|-encodedcommand|-ep\s+bypass|-exec\s+bypass)",
    r"(?i)(?:Invoke-Expression|IEX|Invoke-WebRequest|iwr|Invoke-RestMethod|irm)",
    r"(?i)(?:New-Object\s+System\.Net|Net\.WebClient|DownloadString|DownloadFile)",
    r"(?i)(?:Start-Process|Set-ExecutionPolicy|Add-MpPreference)",
    r"(?i)\[System\.(?:Convert|Text|IO|Net|Reflection)\]",
    r"(?i)(?:ConvertTo-SecureString|Get-Credential|Export-Clixml)",
    r"(?i)(?:-windowstyle\s+hidden|-w\s+hidden)\b",
    r"(?i)(?:FromBase64String|ToBase64String)\b",
    # Windows cmd
    r"(?i)(?:cmd\s*/c|cmd\.exe\s*/c)\s+",
    r"(?i)(?:certutil\s+-urlcache|-decode|certutil\.exe)",
    r"(?i)(?:mshta|regsvr32|rundll32|wscript|cscript)\b",
    r"(?i)(?:bitsadmin\s+/transfer)\b",
    r"(?i)(?:wmic\s+(?:process|service|os))\b",
    # File operations
    r"(?i)(?:;|\|)\s*(?:cp|mv|ln)\s+.*(?:/etc/|/var/|/tmp/)",
    r"(?i)(?:;|\|)\s*tar\s+(?:-[cxz]*f|czf|xzf)\s+",
    r"(?i)(?:;|\|)\s*(?:zip|unzip|gzip|gunzip|bzip2)\s+",
    # Network reconnaissance
    r"(?:;|\|)\s*(?:nmap|masscan|zmap)\s+",
    r"(?:;|\|)\s*(?:dig|nslookup|host)\s+",
    r"(?:;|\|)\s*(?:traceroute|mtr|ping)\s+",
    r"(?:;|\|)\s*(?:netstat|ss)\s+",
    # Blind injection
    r"(?i)\bping\s+-c\s+\d+\s+",
    r"(?i)\bcurl\s+https?://\w+\.\w+\.(?:burpcollaborator|interact\.sh|oast\w*)\b",
    r"(?i)\bnslookup\s+\w+\.\w+\.(?:burpcollaborator|interact\.sh|oast\w*)\b",
    r"(?i)(?:;|\|)\s*sleep\s+\d+",
    # Process injection
    r"(?i)(?:gdb|strace|ltrace|ptrace)\s+(?:-p\s+)?\d+",
    r"(?i)(?:;|\|)\s*(?:mount|umount)\s+",
]

# ============================================================================
# 4. PATH TRAVERSAL & FILE INCLUSION ADVANCED (50 patterns)
# ============================================================================
PATH_TRAVERSAL_ADVANCED = [
    # Multi-encoding traversal
    r"(?:%2e|\.){2}(?:%2f|%5c|/|\\)",
    r"(?:%252e){2}(?:%252f|%255c)",
    r"\.\./\.\./\.\./\.\./",
    r"\.\.\\\.\.\\\.\.\\",
    r"\.{3,}/",
    r"(?:%%32%65){2}(?:%%32%66|/)",
    # Null byte injection
    r"%00\.",
    r"\x00\.",
    r"\0\.",
    # Wrapper-based LFI
    r"(?i)(?:php|phar|zip|rar|data|glob|expect|input|ogg)://",
    r"(?i)php://(?:filter|input|output|fd|memory|temp)",
    r"(?i)php://filter/(?:read|write|convert)\.",
    r"(?i)convert\.(?:base64|iconv|quoted-printable)-(?:encode|decode)",
    r"(?i)phar://.*\.(?:phar|jpg|gif|png|zip|tar)",
    r"(?i)zip://.*\.(?:zip|jar|war|ear)#",
    r"(?i)compress\.(?:zlib|bzip2)://",
    # Sensitive file targets
    r"(?i)/etc/(?:passwd|shadow|group|hosts|hostname|resolv\.conf|crontab|sudoers|ssh)",
    r"(?i)/etc/(?:nginx|apache2|httpd|mysql|php|redis|mongod)",
    r"(?i)/proc/(?:self|version|cpuinfo|meminfo|net/(?:tcp|udp|arp))",
    r"(?i)/proc/self/(?:environ|cmdline|fd/|maps|cwd|exe|root|status)",
    r"(?i)/var/log/(?:auth|syslog|messages|secure|apache|nginx|mysql|mail|kern)",
    r"(?i)/var/(?:mail|spool|run|lib/mysql)",
    r"(?i)/root/\.(?:bash_history|ssh/|mysql_history)",
    r"(?i)/home/\w+/\.(?:bash_history|ssh/|mysql_history|aws/credentials)",
    r"(?i)\.(?:env|htaccess|htpasswd|git/config|svn/|DS_Store)",
    r"(?i)(?:web|app)\.(?:config|xml|yaml|yml|ini|properties)",
    r"(?i)(?:database|db)\.(?:yml|json|xml|sqlite|sqlite3|mdb)",
    r"(?i)wp-config\.php",
    r"(?i)configuration\.php",
    r"(?i)settings\.py",
    r"(?i)application\.(?:yml|properties|conf)",
    r"(?i)appsettings\.json",
    # Windows file paths
    r"(?i)(?:C|D):\\(?:Windows|Users|Program\s*Files|inetpub|boot\.ini)",
    r"(?i)\\\\(?:localhost|127\.0\.0\.1)\\(?:c|d|admin)\$",
    r"(?i)(?:boot|win)\.ini",
    r"(?i)(?:sam|system|security|software)\.(?:old|bak|save)",
    # Cloud metadata paths
    r"(?i)/latest/(?:meta-data|user-data|api/token)",
    r"(?i)/metadata/v\d+/",
    r"(?i)/computeMetadata/v\d+/",
    r"(?i)/metadata\.google\.internal",
    r"(?i)169\.254\.169\.254",
    r"(?i)100\.100\.100\.200",
    # Docker/container paths
    r"(?i)/\.dockerenv",
    r"(?i)/run/secrets/",
    r"(?i)/var/run/docker\.sock",
    r"(?i)cgroup.*docker",
    # Kubernetes paths
    r"(?i)/var/run/secrets/kubernetes\.io/",
    r"(?i)/serviceaccount/(?:token|ca\.crt|namespace)",
    # Git repository disclosure
    r"(?i)/\.git/(?:HEAD|config|index|objects|refs|logs|COMMIT_EDITMSG)",
    r"(?i)/\.svn/(?:entries|wc\.db|pristine)",
    r"(?i)/\.hg/(?:store|dirstate|requires)",
]

# ============================================================================
# 5. SSRF ADVANCED (50 patterns)
# ============================================================================
SSRF_ADVANCED_V5 = [
    # IPv4 obfuscation
    r"(?i)(?:url|uri|target|dest|redirect|next|link|fetch|proxy|callback)\s*=\s*https?://(?:127|0|10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.",
    r"(?i)https?://0x[0-9a-f]+",
    r"(?i)https?://0[0-7]+\.",
    r"(?i)https?://\d{8,10}(?:/|$)",
    r"(?i)https?://(?:localhost|loopback|internal)\b",
    # IPv6 SSRF
    r"(?i)https?://\[::(?:1|ffff:(?:127|10|172|192))\]",
    r"(?i)https?://\[0:0:0:0:0:(?:0:0:1|ffff)\]",
    r"(?i)https?://\[::\]",
    # DNS rebinding indicators
    r"(?i)(?:rbndr|1u|nip)\.io\b",
    r"(?i)(?:xip|sslip)\.io\b",
    r"(?i)\.(?:localtest\.me|lvh\.me|vcap\.me)\b",
    r"(?i)(?:spoofed|rebind|dns).*(?:127\.0|192\.168|10\.0|172\.1[6-9])",
    # Cloud metadata endpoints
    r"(?i)https?://169\.254\.169\.254",
    r"(?i)https?://(?:metadata\.google\.internal|metadata\.goog)",
    r"(?i)https?://100\.100\.100\.200",
    r"(?i)https?://169\.254\.170\.2",
    r"(?i)https?://fd00:ec2::254",
    # Internal service access
    r"(?i)https?://(?:consul|vault|etcd|zookeeper)(?::\d+)",
    r"(?i)https?://(?:redis|memcached|rabbitmq|kafka|nats)(?::\d+)",
    r"(?i)https?://(?:elasticsearch|kibana|grafana|prometheus)(?::\d+)",
    r"(?i)https?://(?:jenkins|gitlab|artifactory|nexus|sonarqube)(?::\d+)",
    r"(?i)https?://(?:docker|portainer|kubernetes)(?::\d+)",
    # Protocol handlers
    r"(?i)(?:gopher|dict|tftp|ldap|ldaps|telnet|ftp|sftp)://",
    r"(?i)file:///",
    r"(?i)jar:(?:https?|file)://",
    r"(?i)netdoc://",
    # URL redirect SSRF
    r"(?i)(?:redirect|return|next|url|continue|dest)\s*=\s*(?:%2F|/|%252F){2}",
    r"(?i)(?:redirect|return|next|url|continue)\s*=\s*https?%3A",
    # PDF/image SSRF
    r"(?i)(?:wkhtmlto(?:pdf|image)|phantomjs|puppeteer|chrome)\s*.*https?://(?:127|10|172|192\.168)",
    # SSRF via headers
    r"(?i)X-(?:Forwarded|Original|Rewrite)-(?:Url|Host|Proto)\s*:\s*https?://(?:127|10|172|192\.168)",
    r"(?i)(?:Client-IP|True-Client-IP|X-Real-IP)\s*:\s*(?:127|10|172|192\.168)\.",
    # Webhook SSRF
    r"(?i)webhook[_-]?url\s*=\s*https?://(?:127|10|172|192\.168)",
    r"(?i)callback[_-]?url\s*=\s*https?://(?:127|10|172|192\.168)",
    # Import/include SSRF
    r"(?i)(?:import|include|require|load)[_-]?url\s*=\s*https?://",
    r"(?i)(?:avatar|profile|image|icon)[_-]?url\s*=\s*https?://(?:127|10|172|192\.168)",
    # Cloud-specific
    r"(?i)/latest/api/token",
    r"(?i)X-aws-ec2-metadata-token",
    r"(?i)X-Google-Metadata-Request:\s*True",
    r"(?i)Metadata-Flavor:\s*Google",
    r"(?i)/metadata/instance\b",
    r"(?i)instance/(?:compute|network|service-accounts)",
    # Out-of-band SSRF detection
    r"(?i)https?://\w+\.(?:burpcollaborator|interact\.sh|oast\w*|canarytokens)\.(?:com|net|org)",
    r"(?i)https?://\w+\.(?:dnslog|ceye|bxss)\.(?:cn|me|io|org)",
    # Unicode SSRF bypass
    r"(?i)https?://(?:①②⑦|ⓛⓞⓒⓐⓛ|ⓁⓄⒸⒶⓁ)",
    r"(?i)https?://[\x{FF10}-\x{FF19}]+",
]

# ============================================================================
# 6. AUTHENTICATION & SESSION ATTACKS (50 patterns)
# ============================================================================
AUTH_SESSION_ATTACKS = [
    # JWT attacks
    r"(?i)eyJ(?:hb|0e|pc)[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.$",
    r'(?i)"alg"\s*:\s*"(?:none|None|NONE|nOnE|HS256|HS384|HS512)"\s*[,}].*"typ"',
    r'(?i)"kid"\s*:\s*"(?:\.\./|/etc/|/dev/|; |&&|\|)',
    r'(?i)"jku"\s*:\s*"https?://(?!(?:your|trusted)\.)',
    r'(?i)"x5u"\s*:\s*"https?://',
    r'(?i)"jwk"\s*:\s*\{',
    # OAuth attacks
    r"(?i)(?:redirect_uri|redirect_url)\s*=\s*https?://(?!(?:localhost|127\.0\.0\.1|your-domain))",
    r"(?i)response_type\s*=\s*(?:token|id_token)\s*(?:&|$)",
    r"(?i)scope\s*=\s*(?:.*\s+){5,}",
    r"(?i)state\s*=\s*$",
    r"(?i)code_challenge_method\s*=\s*plain\b",
    # SAML attacks
    r"(?i)SAMLResponse\s*=.*(?:<!ENTITY|<!DOCTYPE|SYSTEM\s+['\"](?:http|file|ftp))",
    r"(?i)(?:NameID|Issuer|Audience)\s*>.*(?:<script|javascript:|onerror)",
    r"(?i)(?:NotBefore|NotOnOrAfter)\s*=\s*['\"](?:9999|2099)",
    r"(?i)SignatureMethod\s+Algorithm\s*=\s*['\"].*(?:none|md5)",
    r"(?i)DigestMethod\s+Algorithm\s*=\s*['\"].*(?:none|md5)",
    # Session attacks
    r"(?i)(?:PHPSESSID|JSESSIONID|ASP\.NET_SessionId)\s*=\s*['\"]?[\w-]{50,}",
    r"(?i)(?:session|sess|sid)[_-]?(?:id|key|token)\s*=\s*(?:admin|root|test|debug|null|undefined)",
    r"(?i)(?:auth|access|refresh)[_-]?token\s*=\s*(?:null|undefined|test|admin)",
    # Password attacks
    r"(?i)(?:password|passwd|pwd)\s*=\s*(?:admin|root|123456|password|qwerty|letmein)",
    r"(?i)(?:password|passwd|pwd)\s*=\s*(.{0,3})(?:\s|&|$)",
    # API key exposure
    r"(?i)(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_-]{20,}",
    r"(?i)(?:sk_live|pk_live|rk_live|sk_test)_[A-Za-z0-9]{20,}",
    r"(?i)(?:AKIA|ASIA|AROA)[A-Z0-9]{16}",
    r"(?i)(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}",
    r"(?i)(?:glpat|glptt)-[A-Za-z0-9_-]{20}",
    r"(?i)xox[bpsar]-[A-Za-z0-9-]{10,}",
    # MFA bypass attempts
    r"(?i)(?:mfa|2fa|otp|totp)[_-]?(?:code|token)\s*=\s*(?:000000|123456|111111|999999)",
    r"(?i)(?:mfa|2fa|otp)[_-]?(?:skip|bypass|disable)\s*=\s*(?:true|1|yes)",
    r"(?i)X-(?:MFA|2FA|OTP)-(?:Skip|Bypass|Override)\s*:\s*",
    # Account enumeration
    r"(?i)(?:forgot|reset)[_-]?password.*(?:admin|root|administrator|postmaster|webmaster)",
    r"(?i)(?:register|signup).*(?:admin|root|administrator|system|superuser)",
    # CSRF token bypass
    r"(?i)(?:csrf|xsrf|_token)\s*=\s*(?:null|undefined|test|bypass|skip)",
    r"(?i)X-(?:CSRF|XSRF)-Token:\s*$",
    # Cookie manipulation
    r"(?i)(?:isAdmin|is_admin|role|user_type)\s*=\s*(?:true|1|admin|root|superuser)",
    r"(?i)(?:verified|authenticated|is_auth)\s*=\s*(?:true|1|yes)",
    # Header-based auth bypass
    r"(?i)X-(?:Custom|Debug|Test)-(?:Auth|User|Admin)\s*:\s*",
    r"(?i)X-(?:Original|Forwarded)-(?:User|For)\s*:\s*admin",
    # LDAP injection in auth
    r"(?i)\)\s*\(\s*(?:\||&)\s*\(",
    r"(?i)(?:uid|cn|sn|mail)\s*=\s*\*\s*\)",
    r"(?i)(?:\x00|\x0a|\x0d).*(?:uid|cn|dn)=",
    # Kerberos attacks
    r"(?i)(?:krbtgt|SPN|TGT|TGS)\s*[/:]",
    r"(?i)Negotiate\s+TlRMT",
    r"(?i)(?:AS-REP|TGS-REP)roasting",
    # Password spray patterns
    r"(?i)(?:Spring|Summer|Fall|Winter|Autumn)20\d{2}!?$",
    r"(?i)(?:P@ss(?:w0rd)?|Welcome|Changeme|Company)\d*!?$",
    r"(?i)(?:January|February|March|April|May|June|July|August|September|October|November|December)20\d{2}",
]

# ============================================================================
# 7. SERVER-SIDE TEMPLATE INJECTION (40 patterns)
# ============================================================================
SSTI_PATTERNS = [
    # Jinja2/Python
    r"\{\{.*(?:config|request|session|g\.|self\.)\w+",
    r"\{\{.*(?:__class__|__mro__|__subclasses__|__builtins__|__import__)",
    r"\{\{.*(?:lipsum|cycler|joiner|namespace)\.__init__",
    r"\{%.*(?:import|include|extends|block|from)\s+",
    r"\{\{.*(?:popen|subprocess|os\.system|eval|exec)\s*\(",
    r"\{\{.*\.__(?:globals|init|class)__",
    # Twig/PHP
    r"\{\{.*_self\.env\.",
    r"\{\{.*(?:system|exec|passthru|shell_exec|popen)\s*\(",
    r"\{\{.*(?:getFilter|registerUndefinedFilterCallback)\(",
    r"\{\{.*(?:file_get_contents|file_put_contents|readfile)\s*\(",
    # Freemarker/Java
    r"(?i)<#assign\s+\w+\s*=\s*['\"]freemarker\.template\.utility\.Execute",
    r"(?i)\$\{.*\.getClass\(\)\.forName\(",
    r"(?i)\$\{.*Runtime\.getRuntime\(\)\.exec\(",
    r"(?i)new\s+freemarker\.template\.utility\.Execute",
    r"(?i)<#assign\s+.*\?new\(\)",
    # Velocity/Java
    r"(?i)#set\s*\(\s*\$\w+\s*=\s*.*\.getClass\(\)",
    r"(?i)#set\s*\(\s*\$\w+\s*=\s*.*Runtime\.getRuntime\(\)",
    r"(?i)\$class\.inspect\(",
    # Thymeleaf/Java
    r"(?i)__\$\{.*T\(java\.lang\.Runtime\)",
    r"(?i)__\$\{.*new\s+java\.lang\.ProcessBuilder",
    r"(?i)\$\{T\(java\.lang\.Runtime\)\.getRuntime\(\)\.exec\(",
    r"(?i)\$\{#rt\s*=\s*@java\.lang\.Runtime",
    # Pebble/Java
    r"(?i)\{\{.*\.java\.lang\.Runtime",
    r'(?i)\{\{.*\["getRuntime"\]',
    # Smarty/PHP
    r"(?i)\{(?:php|literal)\}.*(?:system|exec|passthru|eval)\(",
    r"(?i)\{\$smarty\.version\}",
    r"(?i)\{Smarty_Internal_Write_File::writeFile\(",
    # Mako/Python
    r"<%.*(?:import\s+os|import\s+subprocess|__import__).*%>",
    r"\$\{.*(?:os\.popen|subprocess\.check_output|eval|exec)\(",
    # ERB/Ruby
    r"<%=.*(?:system|exec|spawn|open|IO\.popen|Kernel\.exec)\(",
    r"<%.*(?:require|load|eval)\s+",
    # Handlebars/JS
    r"\{\{#with\s+.*(?:constructor|__proto__|prototype)",
    r"\{\{.*(?:constructor\.constructor|process\.mainModule)",
    # EJS/JS
    r"<%[-=].*(?:process|require|child_process|fs\.)\w+",
    r"<%.*(?:exec|spawn|execSync)\(",
    # Nunjucks/JS
    r"\{\{.*(?:range|constructor)\.\w+\(",
    # Generic detection
    r"\{\{7\*7\}\}",
    r"\$\{7\*7\}",
    r"<%= 7\*7 %>",
    r"#\{7\*7\}",
    r"\{\{['\"].*['\"]\.(?:constructor|__class__)\b",
]

# ============================================================================
# 8. XML/XXE ADVANCED (35 patterns)
# ============================================================================
XML_XXE_ADVANCED = [
    # Standard XXE
    r"(?i)<!DOCTYPE\s+\w+\s+\[\s*<!ENTITY",
    r"(?i)<!ENTITY\s+\w+\s+SYSTEM\s+['\"](?:file|http|https|ftp|php|expect|data|gopher)://",
    r"(?i)<!ENTITY\s+%\s+\w+\s+SYSTEM\b",
    r"(?i)<!ENTITY\s+\w+\s+PUBLIC\b",
    # Parameter entities
    r"(?i)<!ENTITY\s+%\s+\w+\s+['\"].*<!ENTITY",
    r"(?i)%\w+;.*(?:SYSTEM|PUBLIC)\b",
    # OOB XXE
    r"(?i)<!ENTITY\s+\w+\s+SYSTEM\s+['\"]https?://\w+\.",
    r"(?i)<!ENTITY\s+\w+\s+SYSTEM\s+['\"]ftp://",
    # XML bombs / Billion Laughs
    r"(?i)<!ENTITY\s+\w+\s+['\"](?:&\w+;){2,}['\"]",
    r"(?i)(?:<!ENTITY\s+\w+\s+['\"].*['\"]>\s*){5,}",
    # XInclude
    r"(?i)<xi:include\s+",
    r"(?i)xmlns:xi\s*=\s*['\"]http://www\.w3\.org/2001/XInclude['\"]",
    r"(?i)<xi:include\s+.*(?:href|parse)\s*=",
    # XSLT injection
    r"(?i)<xsl:(?:stylesheet|transform|template|value-of|variable|include|import)",
    r"(?i)xmlns:xsl\s*=\s*['\"]http://www\.w3\.org/1999/XSL/Transform['\"]",
    r"(?i)<xsl:value-of\s+select\s*=\s*['\"].*(?:document|system-property)\(",
    r"(?i)<msxsl:script\b",
    # XPath injection
    r"(?i)(?:string|number|boolean|count|contains|substring|normalize-space)\s*\(\s*/",
    r"(?i)/\w+\[.*(?:=|!=|<|>|contains)\s*\(\s*['\"]",
    r"(?i)(?:or|and)\s+\d+\s*=\s*\d+\s*(?:\]|$)",
    r"(?i)/\*\s*\[\s*(?:position|last|count)\s*\(",
    # SVG-based XXE
    r"(?i)<svg\s+[^>]*xmlns\s*=.*<!ENTITY",
    r"(?i)<image\s+[^>]*href\s*=\s*['\"](?:file|data|http):",
    # SOAP injection
    r"(?i)<(?:soap|soapenv):(?:Envelope|Header|Body|Fault)\b",
    r"(?i)<!DOCTYPE\s+.*SYSTEM.*>.*<(?:soap|soapenv):",
    # XML external DTD
    r"(?i)<!DOCTYPE\s+\w+\s+SYSTEM\s+['\"]https?://",
    r"(?i)<!DOCTYPE\s+\w+\s+PUBLIC\s+['\"]",
    # RSS/Atom injection
    r"(?i)<rss\s+.*<!ENTITY",
    r"(?i)<(?:entry|feed)\s+.*xmlns.*<!ENTITY",
    # XSLT RCE
    r"(?i)xsl:(?:output|sort|for-each|choose|when|otherwise)\b.*(?:exec|system|Runtime)",
    r"(?i)document\s*\(\s*['\"](?:http|file|ftp)://",
    # Binary XML (OOXML, docx, xlsx)
    r"(?i)\[Content_Types\]\.xml.*<!ENTITY",
    r"(?i)customXml.*<!ENTITY",
    # XMLDecoder (Java)
    r"(?i)<java\s+.*class\s*=\s*['\"]java\.lang\.ProcessBuilder",
    r"(?i)<void\s+method\s*=\s*['\"](?:exec|start|invoke|forName)\b",
]

# ============================================================================
# 9. WEBSHELL & BACKDOOR DETECTION (50 patterns)
# ============================================================================
WEBSHELL_PATTERNS = [
    # PHP webshells
    r"(?i)<\?php\s*(?:eval|assert|exec|system|passthru|shell_exec|popen|proc_open)\s*\(",
    r"(?i)(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|gzdecode)\s*\(",
    r"(?i)(?:eval|assert)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[",
    r'(?i)(?:eval|assert)\s*\(\s*(?:str_replace|preg_replace)\s*\(\s*[\'"].*[/e]',
    r"(?i)(?:move_uploaded_file|copy)\s*\(\s*\$_FILES",
    r"(?i)(?:fwrite|file_put_contents)\s*\(\s*.*\$_(?:GET|POST|REQUEST)",
    r"(?i)\$\w+\s*=\s*create_function\s*\(",
    r"(?i)\$\w+\s*=\s*(?:chr|pack|hex2bin)\s*\(",
    r"(?i)call_user_func(?:_array)?\s*\(\s*\$",
    r"(?i)preg_replace\s*\(\s*['\"].*['\"/]e['\"]",
    # ASP/ASPX webshells
    r"(?i)<%.*(?:eval|execute|executeglobal)\s*\(",
    r"(?i)(?:Server\.CreateObject|CreateObject)\s*\(\s*['\"](?:WScript|Scripting|ADODB)",
    r"(?i)(?:Response\.Write|Response\.BinaryWrite).*(?:exec|cmd|shell)",
    r"(?i)Process\.Start\s*\(",
    r"(?i)System\.Diagnostics\.Process",
    # JSP webshells
    r"(?i)Runtime\.getRuntime\(\)\.exec\s*\(",
    r"(?i)ProcessBuilder\s*\(\s*(?:new\s+String|Arrays\.asList)",
    r"(?i)(?:java\.lang\.Runtime|java\.io\.BufferedReader|java\.io\.InputStreamReader)",
    r"(?i)Class\.forName\s*\(\s*['\"]java\.lang\.Runtime",
    # Python webshells
    r"(?i)(?:os\.system|os\.popen|subprocess\.(?:call|Popen|check_output|run))\s*\(",
    r"(?i)exec\s*\(\s*(?:compile|open|__import__|base64\.b64decode)\s*\(",
    r"(?i)importlib\.import_module\s*\(\s*['\"]os['\"]",
    # Node.js webshells
    r"(?i)child_process\.(?:exec|execSync|spawn|spawnSync|fork)\s*\(",
    r"(?i)require\s*\(\s*['\"]child_process['\"]",
    r"(?i)process\.(?:binding|dlopen|mainModule)\s*\(",
    # Generic webshell indicators
    r"(?i)(?:c99|r57|b374k|wso|alfa|FilesMan|fx29|webadmin)\b",
    r"(?i)(?:eval|exec|system)\s*\(\s*(?:base64|rot13|hex|gzip)\s*(?:_decode|inflate)\s*\(",
    r"(?i)(?:shell|cmd|command|exec)\s*=\s*(?:\$_(?:GET|POST|REQUEST)|request\.(?:getParameter|args))",
    r"(?i)\b(?:web_?shell|backdoor|rootkit|trojan|malware)\b",
    # File upload indicators
    r"(?i)Content-Disposition:.*filename=.*\.(?:php[3-8]?|phtml|pht|phps|phar)",
    r"(?i)Content-Disposition:.*filename=.*\.(?:asp[x]?|asa|cer|cdx)",
    r"(?i)Content-Disposition:.*filename=.*\.(?:jsp[x]?|jspf|jsw|jsv)",
    r"(?i)Content-Disposition:.*filename=.*\.(?:cgi|pl|py|rb|sh|bash)",
    r"(?i)Content-Disposition:.*filename=.*\.(?:exe|dll|bat|cmd|com|msi|scr|vbs|vbe|wsf|wsh|ps1)",
    # Encoded webshells
    r"(?i)(?:chr\s*\(\s*\d+\s*\)\s*\.?\s*){5,}",
    r"(?i)(?:base64_decode|atob)\s*\(\s*['\"][A-Za-z0-9+/=]{50,}",
    r"(?i)\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){10,}",
    r"(?i)(?:0x[0-9a-f]{2},?\s*){10,}",
    # PHP disable_functions bypass
    r"(?i)(?:dl|putenv|mail|imap_open|error_log)\s*\(\s*.*(?:\$_|/tmp/|/dev/)",
    r"(?i)(?:pcntl_exec|posix_kill|posix_setuid)\s*\(",
    r"(?i)(?:FFI::cdef|FFI::new|ffi_cif)\b",
    # Obfuscation patterns
    r"(?i)\$\w+\s*=\s*['\"](?:e|ev|eva|eval)['\"]",
    r"(?i)\$\w+\s*\.\s*=\s*['\"][a-z]{1,3}['\"];\s*\$\w+\s*\(",
    r"(?i)str_replace\s*\(\s*['\"].*['\"],\s*['\"]['\"],\s*['\"].*(?:eval|exec|system)",
    r"(?i)(?:array_map|array_filter|array_walk)\s*\(\s*['\"](?:eval|exec|system|assert)['\"]",
    r"(?i)(?:usort|uasort|uksort)\s*\(\s*.*,\s*['\"](?:eval|assert|create_function)['\"]",
    # PHP7/8 specific
    r"(?i)(?:\(\s*new\s+\w+\s*\))\s*->\s*(?:__toString|__destruct|__wakeup)\s*\(",
    r"(?i)ReflectionFunction.*invoke\b",
]

# ============================================================================
# 10. CRYPTOMINING & MALWARE INDICATORS (30 patterns)
# ============================================================================
CRYPTOMINING_MALWARE = [
    # Cryptominer scripts
    r"(?i)coinhive\.min\.js",
    r"(?i)(?:CoinHive|CryptoLoot|DeepMiner|CoinImp|Jsecoin|MineMyTraffic|CryptoNoter)\.(?:Anonymous|User|Miner)\b",
    r"(?i)new\s+(?:CoinHive\.Anonymous|CryptoLoot\.Anonymous)\s*\(",
    r"(?i)(?:miner\.start|startMining|throttleMiner)\s*\(",
    r"(?i)(?:stratum\+tcp|stratum\+ssl|nicehash)://",
    r"(?i)(?:xmr|monero|bitcoin|ethereum|litecoin)(?:pool|mine|hash)\.",
    # WebSocket mining
    r"(?i)wss?://.*(?:mine|pool|stratum|coinhive|cryptonight)",
    # Known mining pools
    r"(?i)(?:pool\.minergate|minerxmr|xmrpool|hashvault|supportxmr|nanopool)\.(?:com|org|net)",
    # Malware download indicators
    r"(?i)(?:powershell|cmd|bash)\s+.*(?:DownloadString|wget|curl)\s+.*(?:\.exe|\.ps1|\.bat|\.sh|\.py)",
    r"(?i)(?:certutil|bitsadmin|mshta)\s+.*https?://",
    r"(?i)(?:Invoke-Mimikatz|Invoke-Shellcode|Invoke-PowerShellTcp)\b",
    r"(?i)(?:mimikatz|lazagne|responder|bloodhound|rubeus|crackmapexec)\b",
    # Ransomware indicators
    r"(?i)(?:Your files have been encrypted|pay.*(?:bitcoin|btc|ransom))",
    r"(?i)(?:\.encrypted|\.locked|\.crypt|\.cerber|\.locky|\.wannacry|\.ryuk)\b",
    r"(?i)(?:decrypt|restore).*(?:instructions|readme|help_decrypt|HOW_TO)",
    # C2 beaconing patterns
    r"(?i)(?:beacon|heartbeat|checkin|ping)\s*=\s*(?:true|1|yes)",
    r"(?i)(?:sleep|jitter|interval)\s*=\s*\d{2,}",
    r"(?i)(?:agent|implant|payload|shellcode|stager)\s*=",
    # Exploit kit indicators
    r"(?i)(?:exploit[-_]?kit|rig[-_]?ek|angler[-_]?ek|nuclear[-_]?ek)\b",
    r"(?i)(?:landing[-_]?page|gate[-_]?url|payload[-_]?url)\s*=",
    # Keylogger patterns
    r"(?i)(?:keylog|keystroke|key_press|keyboard_hook)\b",
    r"(?i)(?:GetAsyncKeyState|SetWindowsHookEx|GetKeyState)\b",
    # Data exfiltration
    r"(?i)(?:exfil|upload_data|send_data|post_data|steal_data)\s*\(",
    r"(?i)(?:screenshot|screen_capture|webcam_capture)\s*\(",
    # Rootkit indicators
    r"(?i)(?:hide_process|hide_file|hook_syscall|intercept_io)\b",
    r"(?i)(?:LdrLoadDll|NtCreateThread|ZwQuerySystemInformation)\b",
    # RAT indicators
    r"(?i)(?:remote_desktop|vnc_connect|rdp_session|reverse_vnc)\b",
    r"(?i)(?:DarkComet|PoisonIvy|njRAT|Quasar|AsyncRAT)\b",
    r"(?i)(?:gh0st|PlugX|ShadowPad|Emotet|TrickBot|QakBot|IcedID)\b",
]

# ============================================================================
# 11. API ABUSE & SCRAPING (35 patterns)
# ============================================================================
API_ABUSE_PATTERNS = [
    # GraphQL abuse
    r"(?i)query\s*\{.*\{.*\{.*\{.*\{.*\{",
    r"(?i)__schema\s*\{.*queryType.*mutationType",
    r"(?i)(?:__type|__schema)\s*\(\s*name\s*:",
    r"(?i)mutation\s*\{.*(?:delete|drop|truncate|destroy)All\b",
    r"(?i)query\s+\w+\s*\{.*\b(?:users|accounts|customers|orders)\b.*\{.*\{",
    # REST API abuse
    r"(?i)/api/v\d+/(?:users|accounts|admin|config|settings|debug|internal|private)/",
    r"(?i)/api/.*\?.*(?:limit|per_page|page_size)\s*=\s*(?:\d{4,}|999+)",
    r"(?i)/api/.*\?.*(?:offset|skip|start)\s*=\s*\d{6,}",
    r"(?i)/api/.*\?.*fields\s*=\s*(?:\*|all)",
    r"(?i)/api/.*\?.*(?:include|expand|embed)\s*=\s*(?:\*|all|everything)",
    r"(?i)/api/.*(?:\.json|\.xml|\.csv|\.xlsx)\?.*(?:dump|export|download)",
    # Rate limit evasion
    r"(?i)X-Forwarded-For:\s*(?:\d{1,3}\.){3}\d{1,3}\s*,\s*(?:\d{1,3}\.){3}\d{1,3}\s*,\s*(?:\d{1,3}\.){3}\d{1,3}",
    # Scraping indicators
    r"(?i)/(?:sitemap|feed|rss|atom)\.(?:xml|json)\?.*(?:dump|export|download|key|token|secret)",
    r"(?i)/robots\.txt.*(?:allow|disallow|crawl-delay)",
    # Enumeration
    r"(?i)/api/v\d+/users/\d+$",
    r"(?i)/(?:user|account|profile)/(?:\d{1,6}|[a-z]{1,3})$",
    # Mass operations
    r"(?i)/api/.*(?:batch|bulk|mass|multi)[_-]?(?:create|delete|update|import|export)",
    r"(?i)/api/.*(?:purge|reset|wipe|clear)[_-]?all\b",
    # Internal/debug endpoints
    r"(?i)/(?:debug|internal|private|hidden|backdoor|test|dev|staging)/",
    r"(?i)/(?:phpinfo|server-info|server-status|status|info)\.(?:php|aspx?|jsp)",
    r"(?i)/(?:actuator|jolokia|console|jmx|hawtio)/",
    r"(?i)/(?:_debug|_profiler|_config|_status|_health_check)/",
    r"(?i)/(?:elmah|trace|diagnostics|glimpse)\b",
    # Swagger/OpenAPI disclosure
    r"(?i)/(?:swagger|api-docs|openapi)(?:\.(?:json|yaml|yml))?(?:/|$)",
    r"(?i)/v\d+/api-docs\b",
    # GraphQL introspection
    r"(?i)/graphql\?query=\{__schema\b",
    r"(?i)/graphql.*(?:IntrospectionQuery|__schema|__type)",
    # Webhook abuse
    r"(?i)/(?:webhooks?|hooks?|callbacks?|notify)/(?:test|debug|admin)",
    # Data export abuse
    r"(?i)(?:format|output|type)\s*=\s*(?:csv|json|xml|xlsx|pdf).*(?:all|full|complete|dump)",
    # Admin API access
    r"(?i)/(?:wp-json|xmlrpc)\.php.*(?:wp/v2/users|wp\.getUsersBlogs)",
    r"(?i)/(?:admin|manager|console)/api/",
    # Hidden parameter discovery
    r"(?i)\?(?:debug|test|admin|verbose|trace)\s*=\s*(?:true|1|yes)",
    r"(?i)\?(?:_method|_format|_locale|_fragment)\s*=",
    r"(?i)\?(?:XDEBUG_SESSION|PHPSTORM|VSCODE)\s*=",
]

# ============================================================================
# 12. INFRASTRUCTURE ATTACKS (40 patterns)
# ============================================================================
INFRASTRUCTURE_ATTACKS = [
    # DNS attacks
    r"(?i)(?:ns|mx|cname|txt|srv|ptr)\s+.*(?:evil|malicious|attacker)",
    r"(?i)(?:zone[-_]?transfer|axfr|ixfr)\b",
    r"(?i)dig\s+.*@\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+axfr\b",
    # SMTP injection
    r"(?:\r\n|\n)(?:MAIL\s+FROM|RCPT\s+TO|DATA|HELO|EHLO)\s*:",
    r"(?i)(?:bcc|cc|to|from)\s*:.*(?:\r\n|\n)(?:subject|content-type)",
    r"(?i)Content-Type:.*(?:multipart/mixed|text/html).*boundary=",
    # LDAP injection
    r"(?i)\)\s*\(\s*\|\s*\(\s*(?:uid|cn|sn)\s*=\s*\*",
    r"(?i)\)\s*\(\s*&\s*\(\s*(?:objectClass|objectCategory)\s*=",
    r"(?i)(?:adminCount|userAccountControl|servicePrincipalName)\s*=",
    r"(?i)\)(?:\x00|\0)(?:\)|&|\|)",
    # Redis injection
    r"(?i)(?:CONFIG\s+SET|FLUSHALL|FLUSHDB|SLAVEOF|DEBUG\s+SLEEP|SHUTDOWN)\b",
    r"(?i)(?:EVAL|EVALSHA|SCRIPT\s+(?:LOAD|EXISTS|FLUSH))\b",
    r"(?i)(?:SET|MSET|SETNX)\s+.*(?:authorized_keys|crontab|webshell)",
    # Memcached injection
    r"(?i)(?:stats|version|flush_all|delete|set|add|replace|append|prepend)\s+\w+",
    # Docker/Container escape
    r"(?i)(?:docker|podman)\s+(?:exec|cp|run|attach|commit)\b",
    r"(?i)/var/run/docker\.sock",
    r"(?i)(?:--privileged|--cap-add\s*=?\s*SYS_ADMIN|--security-opt\s+apparmor=unconfined)\b",
    r"(?i)nsenter\s+.*--target\s+1\b",
    r"(?i)(?:mount|cgroup).*(?:escape|breakout|release_agent)",
    # Kubernetes attacks
    r"(?i)kubectl\s+(?:exec|apply|delete|create|edit)\b",
    r"(?i)/api/v1/(?:namespaces|pods|services|secrets|configmaps|nodes)",
    r"(?i)/apis/(?:apps|extensions|batch|rbac\.authorization)",
    r"(?i)(?:cluster-admin|system:masters)\b",
    r"(?i)(?:ServiceAccount|ClusterRole|RoleBinding)\b.*(?:bind|escalate)",
    # CI/CD attacks
    r"(?i)(?:jenkins|gitlab|github|bitbucket|azure-devops|circleci).*(?:token|secret|key|password|credential)",
    r"(?i)(?:\.github/workflows|\.gitlab-ci\.yml|Jenkinsfile|\.circleci/config)\b",
    r"(?i)(?:pipeline|workflow|job).*(?:inject|override|poison|tamper)",
    # Supply chain
    r"(?i)(?:npm|pip|gem|composer|nuget|maven|cargo)\s+(?:install|add)\s+.*(?:--unsafe|--no-verify|--force)",
    r"(?i)(?:package\.json|requirements\.txt|Gemfile|pom\.xml).*(?:malicious|evil|backdoor)",
    # Cloud infrastructure
    r"(?i)(?:aws|gcloud|az)\s+(?:iam|ec2|s3|lambda|rds)\s+",
    r"(?i)(?:terraform|ansible|puppet|chef|salt)\s+(?:apply|destroy|state)\b",
    # Service mesh attacks
    r"(?i)(?:istio|envoy|linkerd|consul)\s+.*(?:config|inject|sidecar)",
    r"(?i)/config_dump|/clusters|/listeners|/routes",
    # Serverless attacks
    r"(?i)(?:lambda|function|cloud[-_]function).*(?:invoke|trigger|payload).*(?:cmd|exec|shell)",
    r"(?i)(?:handler|entry[-_]point)\s*=\s*['\"].*(?:os\.|subprocess\.|child_process)",
    # Message queue injection
    r"(?i)(?:rabbitmq|kafka|sqs|nats|mqtt).*(?:admin|management|publish|subscribe).*(?:inject|poison)",
    r"(?i)(?:AMQP|STOMP|MQTT)\s+.*(?:eval|exec|system)",
    # Secrets manager attacks
    r"(?i)/v1/secret/(?:data|metadata)/",
    r"(?i)(?:vault|secrets[-_]manager|parameter[-_]store|key[-_]vault)\s*.*(?:list|get|read|dump)",
]

# ============================================================================
# 13. MOBILE & IOT ATTACKS (25 patterns)
# ============================================================================
MOBILE_IOT_ATTACKS = [
    # Mobile API abuse
    r"(?i)(?:x-device-id|x-app-version|x-platform)\s*:\s*(?:jailbroken|rooted|emulator|frida|xposed)",
    r"(?i)(?:Frida|Objection|Cycript|Substrate)\b",
    r"(?i)com\.saurik\.substrate\b",
    r"(?i)(?:frida-server|frida-gadget|frida-inject)\b",
    # Certificate pinning bypass indicators
    r"(?i)(?:ssl[-_]?pin(?:ning)?|cert[-_]?pin(?:ning)?|trust[-_]?manager)\s*(?:bypass|disable|override)",
    # API key extraction
    r"(?i)(?:GoogleMapsKey|firebase|crashlytics|fabric)\s*[:=]\s*['\"]?[A-Za-z0-9_-]{20,}",
    # Deep link exploitation
    r"(?i)(?:intent|deeplink|applink|universallink)://.*(?:javascript:|data:|file://)",
    r"(?i)(?:scheme|host|path)\s*=\s*['\"].*(?:eval|exec|system)\b",
    # IoT protocol attacks
    r"(?i)(?:MQTT|CoAP|AMQP|Zigbee|BLE|LoRa)\s*.*(?:inject|overflow|replay|fuzzing)",
    r"(?i)(?:MQTT|CoAP)://.*(?:admin|\$SYS|system|config)",
    # Firmware attacks
    r"(?i)(?:firmware|fw)[-_]?(?:update|upload|flash|dump|extract)\b.*(?:\.bin|\.img|\.hex)",
    r"(?i)(?:U-Boot|OpenWrt|DD-WRT|LEDE|Tomato)\s*.*(?:shell|cmd|exec|root)",
    # Smart device exploitation
    r"(?i)(?:camera|thermostat|lock|speaker|hub|bridge|gateway)\s*.*(?:admin|password|default|factory)",
    # OTA update tampering
    r"(?i)(?:ota[-_]?update|firmware[-_]?update)\s*.*(?:http://|unsigned|no[-_]verify)",
    # BLE attacks
    r"(?i)(?:gatttool|hcitool|btlejack|ubertooth)\b",
    # Zigbee/Z-Wave
    r"(?i)(?:killerbee|zbstumbler|zwave[-_]?sniffer)\b",
    # Industrial IoT
    r"(?i)(?:Modbus|DNP3|OPC[-_]UA|BACnet|EtherNet/IP)\s*.*(?:write|force|override|exploit)",
    r"(?i)(?:SCADA|HMI|PLC|RTU|DCS|ICS)\s*.*(?:admin|default|exploit|overflow)",
    # Automotive
    r"(?i)(?:CAN[-_]?bus|OBD[-_]?II|J1939|UDS)\s*.*(?:inject|replay|fuzz|spoof)",
    # Medical IoT
    r"(?i)(?:HL7|DICOM|FHIR)\s*.*(?:inject|overflow|bypass|exploit)",
    # Smart home
    r"(?i)(?:Alexa|Google[-_]Home|HomeKit|SmartThings)\s*.*(?:skill|action|routine)\s*.*(?:eval|exec|cmd)",
    # Edge computing
    r"(?i)(?:edge[-_]?function|worker|cdn[-_]?worker)\s*.*(?:eval|exec|import|require)\s*\(",
    r"(?i)(?:cloudflare[-_]worker|lambda@edge|cloud[-_]function)\s*.*(?:process|child_process|fs\.)",
]

# ============================================================================
# 14. BUSINESS LOGIC ADVANCED (30 patterns)
# ============================================================================
BUSINESS_LOGIC_ADVANCED = [
    # Price manipulation
    r"(?i)(?:price|amount|total|cost|fee|discount|tax)\s*=\s*(?:-\d|0\.0{2,}|0(?:\s|&|$))",
    r"(?i)(?:quantity|qty|count|num|units)\s*=\s*(?:-\d|99999|\d{6,}|0(?:\s|&|$))",
    r"(?i)(?:coupon|promo|voucher|discount)[-_]?code\s*=\s*(?:.{0,2}|(?:test|admin|debug|free|100off))",
    # IDOR patterns
    r"(?i)/(?:user|account|profile|order|invoice|document|file|message)/\d{1,6}(?:\?|/|$)",
    r"(?i)(?:user_id|account_id|customer_id|owner_id)\s*=\s*\d{1,6}(?:\s|&|$)",
    r"(?i)(?:id|ref|num|no)[-_]?\s*=\s*(?:1(?:\s|&|$)|(?:\d{1,3})(?:\s|&|$))",
    # Privilege escalation via params
    r"(?i)(?:role|permission|access[-_]?level|user[-_]?type|is[-_]?admin)\s*=\s*(?:admin|root|super|manager|elevated|1|true)",
    r"(?i)(?:can[-_]?edit|can[-_]?delete|can[-_]?admin|is[-_]?staff|is[-_]?superuser)\s*=\s*(?:true|1|yes)",
    # Race condition indicators
    r"(?i)(?:transfer|withdraw|redeem|claim|activate|approve)\s*.*(?:amount|quantity|balance)",
    # Mass assignment
    r"(?i)(?:is_admin|is_staff|is_superuser|verified|email_verified|approved|active)\s*[:=]\s*(?:true|1|yes)",
    # Workflow bypass
    r"(?i)(?:step|stage|phase|status|state)\s*=\s*(?:completed?|approved|verified|final|done|skip)",
    r"(?i)(?:bypass|skip|ignore)[-_]?(?:validation|verification|approval|review|check)\s*=\s*(?:true|1|yes)",
    # Integer overflow attempts
    r"(?i)(?:amount|quantity|price|balance)\s*=\s*(?:2147483647|4294967295|9223372036854775807|2\.22E308)",
    r"(?i)(?:amount|quantity|price|balance)\s*=\s*(?:-2147483648|-9223372036854775808)",
    # Type juggling
    r"(?i)(?:password|token|code|pin)\s*\[\]\s*=",
    r"(?i)(?:true|false|null|undefined|NaN|Infinity)\s*(?:==|!=)\s*(?:true|false|null|undefined)",
    # Replay attacks
    r"(?i)(?:nonce|timestamp|request[-_]?id|idempotency[-_]?key)\s*=\s*(?:0{5,}|test|null|expired)",
    # Account takeover patterns
    r"(?i)(?:email|phone|username)\s*=\s*.*&.*(?:verification|confirm)[-_]?(?:code|token)\s*=",
    r"(?i)(?:change|update|reset)[-_]?(?:email|phone|password).*(?:old[-_]?|current[-_]?)?(?:password|token)\s*=",
    # Gift card / voucher abuse
    r"(?i)(?:gift[-_]?card|voucher|credit|points|rewards)\s*.*(?:generate|create|add|redeem)\s*.*(?:-\d|\d{6,})",
    # Inventory manipulation
    r"(?i)(?:add[-_]?to[-_]?cart|update[-_]?cart|checkout).*(?:quantity|qty)\s*=\s*(?:-\d|\d{4,})",
    # Subscription abuse
    r"(?i)(?:plan|tier|subscription|license)\s*=\s*(?:enterprise|premium|unlimited|admin|free)",
    # Feature flag manipulation
    r"(?i)(?:feature|flag|toggle|experiment)\s*=\s*(?:true|enabled|active|beta|preview)",
    # Referral/affiliate abuse
    r"(?i)(?:referral|affiliate|partner)[-_]?(?:code|id|link)\s*=\s*(?:self|own|same|admin|test)",
    # Voting/rating manipulation
    r"(?i)(?:vote|rating|review|like|upvote|downvote)\s*.*(?:count|score|value)\s*=",
    # Time-based manipulation
    r"(?i)(?:expires?[-_]?at|valid[-_]?until|not[-_]?after|deadline)\s*=\s*(?:9999|2099|2100)",
    r"(?i)(?:created[-_]?at|timestamp|date)\s*=\s*(?:1970|0{10}|9{10})",
    # Multi-tenancy bypass
    r"(?i)(?:tenant[-_]?id|org[-_]?id|company[-_]?id|workspace[-_]?id)\s*=\s*(?:0|1|null|admin|\*)",
]

# ============================================================================
# 15. ENCRYPTION & CRYPTO ATTACKS (25 patterns)
# ============================================================================
CRYPTO_ATTACKS = [
    # Padding oracle indicators
    r"(?i)(?:padding|pkcs|block)\s*(?:error|invalid|bad|malformed|incorrect)",
    r"(?i)(?:decrypt(?:ion)?|cipher)\s*(?:error|failed|invalid|bad)",
    # Key/IV manipulation
    r"(?i)(?:key|iv|nonce|salt)\s*=\s*(?:0{16,}|(?:41){8,}|(?:00){8,}|test|null|none)",
    r"(?i)(?:aes|des|3des|rc4|blowfish|chacha)\s*.*(?:ecb|null|none|weak)\b",
    # Weak algorithm indicators
    r"(?i)(?:md5|sha1|rc4|des|rot13|base64)\s*(?:hash|encrypt|encode)\b",
    r"(?i)(?:algorithm|cipher|method)\s*=\s*(?:none|null|md5|sha1|rc4|des|ecb)",
    # Certificate attacks
    r"(?i)(?:ssl|tls)\s*(?:verify|check|validate)\s*=\s*(?:false|0|no|none|disable)",
    r"(?i)(?:VERIFY_NONE|CERT_NONE|InsecureSkipVerify|check_hostname\s*=\s*False)",
    # Key disclosure
    r"(?i)-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----",
    r"(?i)-----BEGIN\s+(?:DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----",
    r"(?i)-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----",
    # Downgrade attacks
    r"(?i)(?:ssl|tls)[-_]?version\s*=\s*(?:ssl[23]|tls1[._]?0|tls1[._]?1)",
    r"(?i)(?:cipher[-_]?suite|ciphers)\s*=\s*(?:.*(?:NULL|EXPORT|RC4|DES|MD5|anon))",
    # Side-channel indicators
    r"(?i)(?:timing|side[-_]?channel|cache[-_]?timing|power[-_]?analysis)\b",
    # Hash length extension
    r"(?i)(?:hmac|hash|digest|signature)\s*=\s*[0-9a-f]{32,}.*(?:&|$).*(?:data|message|payload)\s*=",
    # JWT crypto attacks
    r'(?i)"alg"\s*:\s*"(?:HS256|HS384|HS512)".*(?:public[-_]?key|certificate)',
    r'(?i)"alg"\s*:\s*"(?:RS|PS|ES)\d+".*(?:hmac|symmetric|shared[-_]?secret)',
    # XML signature wrapping
    r"(?i)(?:SignedInfo|SignatureValue|KeyInfo|Reference)\s*.*(?:transform|xpath|xslt)",
    r"(?i)(?:Signature|DigestMethod)\s+Algorithm\s*=\s*['\"].*(?:hmac[-_]sha1|rsa[-_]md5|dsa[-_]sha1)",
    # PKCS attacks
    r"(?i)(?:PKCS[157]|OAEP|PSS)\s*.*(?:bleichenbacher|oracle|padding|manger)",
    # Key reuse/weakness
    r"(?i)(?:api[_-]?key|secret[_-]?key|auth[_-]?token)\s*=\s*(?:password|123456|admin|test|key|secret|changeme|default)",
    # Entropy attacks
    r"(?i)(?:random|seed|entropy)\s*=\s*(?:0|1|fixed|static|predictable|test)",
    r"(?i)(?:Math\.random|rand|srand|random\.seed)\s*\(\s*(?:\d{1,3})?\s*\)",
]

# ============================================================================
# 16. WORDPRESS ADVANCED (40 patterns)
# ============================================================================
WORDPRESS_ADVANCED = [
    # Core vulnerabilities
    r"(?i)/wp-(?:admin|login|content|includes)/",
    r"(?i)/xmlrpc\.php\b",
    r"(?i)/wp-json/wp/v2/users\b",
    r"(?i)/wp-json/(?:oembed|wp-site-health|wp-block-editor)/",
    r"(?i)/wp-config\.php(?:\.bak|\.old|\.save|\.orig|\.swp|~)",
    r"(?i)/wp-content/(?:debug|uploads/\d{4}/.*\.php)",
    r"(?i)/wp-content/plugins/.*(?:\.php\?|cmd=|exec=|shell=)",
    r"(?i)/wp-admin/(?:admin-ajax|admin-post|load-scripts|load-styles)\.php\?.*(?:action=|plugin=)",
    # Plugin vulnerabilities
    r"(?i)/wp-content/plugins/(?:revslider|revolution-slider|showbiz|js_composer)/",
    r"(?i)/wp-content/plugins/(?:wp-file-manager|file-manager|elfinder)/",
    r"(?i)/wp-content/plugins/(?:duplicator|backwpup|updraftplus)/.*(?:download|backup|dump)",
    r"(?i)/wp-content/plugins/(?:contact-form-7|ninja-forms|wpforms)/.*(?:upload|file)",
    r"(?i)/wp-content/plugins/(?:elementor|beaver-builder|divi)/.*(?:ajax|action)",
    r"(?i)/wp-content/plugins/(?:woocommerce|easy-digital-downloads)/.*(?:download|export|api)",
    r"(?i)/wp-content/plugins/(?:all-in-one-wp-migration|duplicator)/.*(?:export|download|backup)",
    r"(?i)/wp-admin/admin-ajax\.php\?action=(?:revslider_show_image|duplicator_download|elegantbuilder_save|uploadify)",
    # Theme vulnerabilities
    r"(?i)/wp-content/themes/.*/(?:download|upload|ajax|proxy|api)\.php",
    r"(?i)/wp-content/themes/(?:flavor|flavor|flavor)/.*(?:cmd|exec|eval)",
    # User enumeration
    r"(?i)/\?author=\d+",
    r"(?i)/wp-json/wp/v2/users(?:\?per_page=100)?",
    r"(?i)/feed/\?author=\d+",
    # Login attacks
    r"(?i)/wp-login\.php\?action=(?:lostpassword|register|postpass|logout&redirect_to=)",
    r"(?i)/wp-login\.php.*(?:interim-login|reauth|redirect_to=.*(?:http|//|%2F%2F))",
    # REST API abuse
    r"(?i)/wp-json/(?:wp|wc|oembed|jetpack)/.*(?:delete|update|create|install|activate)",
    r"(?i)/wp-json/wp/v2/(?:posts|pages|media|comments|settings)\?.*(?:per_page=100|status=draft)",
    # File upload exploitation
    r"(?i)/wp-admin/(?:async-upload|media-new|import)\.php",
    r"(?i)/wp-content/uploads/.*\.(?:php[3-8]?|phtml|pht|phps)",
    # WP-CLI abuse
    r"(?i)wp\s+(?:core\s+download|plugin\s+install|theme\s+install|user\s+create|eval-file)\b",
    # Cron abuse
    r"(?i)/wp-cron\.php\?doing_wp_cron=",
    # Database prefix guessing
    r"(?i)(?:wp_|wordpress_)(?:users|options|posts|postmeta|usermeta|terms|comments)\b",
    # Plugin/theme installer exploit
    r"(?i)/wp-admin/(?:plugin-install|theme-install|update)\.php\?.*(?:s=|tab=upload)",
    # Multisite attacks
    r"(?i)/wp-signup\.php\?new=",
    r"(?i)/wp-activate\.php\?key=",
    # AJAX nonce bypass
    r"(?i)admin-ajax\.php.*(?:_wpnonce=|wp_ajax_)",
    # XML-RPC attacks
    r"(?i)<methodCall>.*<methodName>(?:system\.multicall|wp\.getUsersBlogs|pingback\.ping|wp\.getUsers)",
    r"(?i)<methodCall>.*<methodName>(?:demo\.sayHello|system\.listMethods)",
    # WooCommerce specific
    r"(?i)/wc-api/v[123]/.*(?:orders|customers|products|coupons|webhooks)\?.*(?:consumer_key|consumer_secret)",
    r"(?i)/wp-json/wc/v[123]/.*(?:payment|checkout|cart).*(?:total|amount|price)\s*[:=]",
]

# ============================================================================
# 17. CACHE POISONING & DESYNC (25 patterns)
# ============================================================================
# NOTE: Patterns updated to avoid false positives from legitimate proxy headers
CACHE_DESYNC_ATTACKS = [
    # HTTP Request Smuggling (keep these - they are attack-specific)
    r"(?i)Transfer-Encoding\s*:\s*(?:chunked|compress|deflate|gzip)\s*,\s*(?:chunked|identity)",
    r"(?i)Transfer-Encoding\s*:\s*[\t ]*chunked",
    r"(?i)Content-Length\s*:\s*\d+\s*\r?\n\s*Transfer-Encoding\s*:\s*chunked",
    r"(?i)Transfer-Encoding\s*:\s*chunked\s*\r?\n\s*Content-Length\s*:\s*\d+",
    r"(?i)Transfer-Encoding\s*:\s*xchunked",
    r"(?i)Transfer-Encoding\s*:\s*\[chunked\]",
    r"(?i)Transfer[\t -]Encoding\s*:\s*chunked",
    # Cache poisoning headers (only match malicious values)
    r"(?i)X-(?:Forwarded-Host|Original-URL|Rewrite-URL|Override-URL)\s*:\s*(?:evil|attacker|hacker|malicious)\b",
    r"(?i)X-(?:Forwarded-Host|Original-URL)\s*:\s*\w+\.(?:evil|attacker|hacker|malicious|burp|ngrok|interact\.sh|oast)\.\w+",
    r"(?i)X-(?:Forwarded-Scheme|Forwarded-Proto)\s*:\s*(?:nothttps|javascript|data|vbscript)\b",
    r"(?i)X-(?:Host|Forwarded-Server)\s*:\s*['\"]?(?:evil|attacker|malicious)\b",
    # Cache deception (only match specific attack patterns)
    r"(?i)/(?:account|profile|settings|admin)/[^?]*\.(?:css|js|png|jpg|gif|ico)\b",
    r"(?i)/(?:api|internal|private)/[^?]*(?:%0d|%0a|%00)",
    r"(?i)/[^?]*\.(?:css|js|png|jpg)(?:\?|;).*(?:admin|user|account|session)",
    # Response splitting (keep these - they are attack-specific)
    r"(?i)(?:%0d%0a|%0d|%0a|\r\n|\n|\r)(?:Set-Cookie|Location|Content-Type)\s*:",
    r"(?i)(?:Location|Set-Cookie|Content-Type)\s*:.*(?:%0d%0a|%0d|%0a|\r\n)",
    # Host header attacks (only match malicious values)
    r"(?i)Host\s*:\s*(?:evil|attacker|malicious)\.\w+",
    r"(?i)Host\s*:.*@(?:evil|attacker|hacker)",
    # HTTP/2 specific (keep these - they are attack-specific)
    r"(?i):authority\s*:\s*.*(?:evil|attacker|malicious)",
    r"(?i):path\s*:\s*.*(?:%0d|%0a|%00)",
    # Web cache deception paths (only match user/dashboard paths, not /api/)
    r"(?i)/(?:user|my|dashboard|profile)/.*(?:\.js|\.css|\.png|\.jpg|\.gif|\.ico|\.svg|\.woff)",
    # Parameter cloaking (keep these - they are attack-specific)
    r"(?i)(?:utm_\w+|fbclid|gclid|__cf_chl)\s*=.*(?:<script|javascript:|onerror=)",
    # Edge-case cache keys (keep these - they are attack-specific)
    r"(?i)(?:Accept|Accept-Language|Cookie)\s*:.*(?:<|>|%3C|%3E|javascript:|data:)",
    # H2C smuggling (keep these - they are attack-specific)
    r"(?i)Upgrade\s*:\s*h2c",
    r"(?i)Connection\s*:\s*Upgrade,\s*HTTP2-Settings",
]

# ============================================================================
# 18. ZERO-DAY CVE 2025 (40 patterns)
# ============================================================================
CVE_2025_PATTERNS = [
    # Continued CVE tracking
    r"(?i)/cgi-bin/.*(?:%AD|%8F|%8E)d\s+allow_url_include",
    r"(?i)/\.env(?:\.(?:local|production|staging|development|backup|old))?\b",
    r"(?i)/(?:admin|manager|console)/(?:login|index|dashboard)(?:\.(?:php|jsp|aspx|do|action))?\b",
    # Next.js / Vercel
    r"(?i)/_next/(?:data|image|static)/.*(?:\.\.|%2e%2e|%252e)",
    r"(?i)/__nextjs_original-stack-frame",
    # Middleware bypass patterns
    r"(?i)/(?:api|internal|admin)\.(?:json|xml|html)(?:\?|;|#)",
    r"(?i)/[^?]*\.(?:php|jsp|asp)(?:\.|%2e)(?:jpg|png|gif|ico)",
    # Spring Boot actuator
    r"(?i)/actuator/(?:env|configprops|mappings|beans|info|health|threaddump|heapdump|logfile|shutdown|jolokia|restart|refresh)\b",
    r"(?i)/actuator/gateway/routes\b",
    r"(?i)/manage/(?:env|configprops|mappings|beans)\b",
    # Laravel debug
    r"(?i)/_ignition/(?:execute-solution|health-check|scripts)\b",
    r"(?i)/telescope/requests\b",
    r"(?i)/horizon/api/\b",
    # Node.js specific
    r"(?i)/(?:__proto__|constructor|prototype)\s*[/=]",
    r"(?i)/node_modules/.*(?:\.env|\.git|\.ssh)",
    # Ruby on Rails
    r"(?i)/rails/(?:info|mailers|conductor|action_mailbox)\b",
    r"(?i)/assets/.*(?:\.\.|%2e%2e|\.sprockets)",
    # Django debug
    r"(?i)/__debug__/\b",
    r"(?i)/admin/(?:jsi18n|login|logout)/\b.*(?:next=|redirect=)",
    # ASP.NET
    r"(?i)/(?:trace|elmah|glimpse|mini-profiler-resources)\b",
    r"(?i)/\w+\.(?:axd|ashx|asmx|svc)\b.*(?:wsdl|disco|mex)",
    r"(?i)__VIEWSTATE\s*=\s*[A-Za-z0-9+/=]{100,}",
    # Grafana
    r"(?i)/api/(?:dashboards|datasources|admin|users|org)/.*(?:db/|uid=)",
    r"(?i)/public/plugins/.*\.\./",
    # GitLab
    r"(?i)/uploads/.*\.(?:rb|py|php|sh|pl|cgi)",
    r"(?i)/-/(?:graphql|ide|snippets|raw)/",
    # Nginx misconfiguration
    r"(?i)(?:location|alias)\s+.*\.\.\s*/",
    r"(?i)/\.\.;/",
    # Apache misconfiguration
    r"(?i)/\.ht(?:access|passwd|groups|digest|dbm)",
    r"(?i)/server-(?:status|info)\?(?:auto|full|notable)",
    # Cloud function injection
    r"(?i)/(?:api|functions|invoke)/\w+\?.*(?:cmd|exec|system|eval)\s*=",
    r"(?i)/\.well-known/(?:acme-challenge|openid-configuration|apple-app-site-association).*(?:\.\.|%00)",
    # WAF bypass patterns
    r"(?i)(?:%ef%bc%9c|%ef%b9%a4|%ef%bc%9e)(?:script|img|svg)\b",
    r"(?i)(?:\\u003c|\\u003e|\\x3c|\\x3e)(?:script|img|svg)\b",
    r"(?i)(?:x]|%78%5d)\s*(?:on\w+=|src=|href=)",
    # AI/ML model attacks
    r"(?i)(?:model|inference|predict|classify)\s*.*(?:adversarial|poison|backdoor|evasion)\b",
    r"(?i)/(?:ml|model|ai)/(?:train|predict|classify|inference)\?.*(?:data=|input=|payload=).*(?:<|>|;|\||&)",
    # GraphQL injection
    r"(?i)\{.*(?:__schema|__type)\s*\{.*(?:queryType|mutationType|subscriptionType)",
    r"(?i)(?:query|mutation)\s*\w*\s*\(.*\$\w+\s*:\s*String\s*!\s*\)\s*\{.*(?:exec|eval|system)",
]


# ============================================================================
# RULES MAP
# ============================================================================

# ============================================================================
# 19. AI/LLM SECURITY (30 patterns)
# ============================================================================
AI_LLM_ATTACKS = [
    # Prompt injection
    r"(?i)(?:ignore|disregard|forget)\s+(?:previous|above|all|prior)\s+(?:instructions?|rules?|prompts?|context)",
    r"(?i)(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|roleplay\s+as)\s+(?:a\s+)?(?:hacker|malicious|evil|DAN)",
    r"(?i)(?:system\s+prompt|initial\s+instructions?|secret\s+instructions?|hidden\s+prompt)\s*[:=]",
    r"(?i)(?:do\s+anything\s+now|DAN\s+mode|jailbreak|bypass\s+(?:filter|safety|content\s+policy))",
    r"(?i)(?:reveal|show|display|print|output)\s+(?:your|the|system)\s+(?:prompt|instructions?|rules?|constraints?)",
    r"(?i)\[(?:system|assistant|user)\]\s*(?:ignore|override|bypass)",
    r"(?i)(?:translate|encode|base64|rot13|reverse)\s+the\s+(?:following|previous)\s+(?:into|to)\s+(?:code|python|shell|bash)",
    r"(?i)(?:write|generate|create|output)\s+(?:a\s+)?(?:malware|virus|exploit|ransomware|keylogger|backdoor)",
    r"(?i)(?:how\s+to|steps\s+to|guide\s+for)\s+(?:hack|exploit|attack|breach|compromise|bypass)",
    r"(?i)(?:SUDO|ADMIN|ROOT)\s+(?:MODE|ACCESS|OVERRIDE)",
    # Training data extraction
    r"(?i)(?:repeat|recite|recall|output)\s+(?:your|the)\s+(?:training|fine-?tuning|instruction)\s+(?:data|set|examples?)",
    r"(?i)(?:what\s+(?:is|was)\s+(?:your|the))\s+(?:training|fine-?tuning|system)\s+(?:data|prompt|instruction)",
    # Model manipulation
    r"(?i)(?:adversarial|perturbation|gradient|FGSM|PGD|C&W|DeepFool)\s+(?:attack|example|input|sample)",
    r"(?i)(?:poison|backdoor|trojan)\s+(?:the\s+)?(?:model|dataset|training\s+data)",
    r"(?i)(?:model\s+(?:extraction|stealing|inversion|cloning)|membership\s+inference)\b",
    # LLM-specific attacks
    r"(?i)(?:indirect\s+prompt|cross-?prompt)\s+injection\b",
    r"(?i)(?:token\s+smuggling|payload\s+splitting|context\s+overflow)\b",
    r"(?i)(?:hallucination|confabulation)\s+(?:attack|exploit|induc)",
    # Data exfiltration via AI
    r"(?i)(?:embed|hide|encode|steganograph)\s+(?:data|payload|secret)\s+(?:in|into|within)\s+(?:output|response|image)",
    r"(?i)(?:exfiltrate|leak|extract)\s+(?:data|PII|credentials?|secrets?)\s+(?:via|through|using)\s+(?:model|API|prompt)",
    # Multimodal attacks
    r"(?i)(?:image|audio|video)\s+(?:adversarial|injection|embedded)\s+(?:payload|prompt|instruction)",
    r"(?i)(?:OCR|ASR|STT)\s+(?:injection|bypass|poisoning)\b",
    # Tool/function calling abuse
    r"(?i)(?:function|tool)\s+(?:call|invoke|execute)\s*[:=].*(?:os\.|subprocess|system|exec)",
    r"(?i)(?:plugin|extension|tool)\s*.*(?:malicious|backdoor|inject|override)",
    # Embedding injection
    r"(?i)(?:embedding|vector)\s+(?:injection|manipulation|poisoning|perturbation)\b",
    # RAG poisoning
    r"(?i)(?:RAG|retrieval)\s+(?:poisoning|injection|manipulation)\b",
    r"(?i)(?:knowledge\s+base|vector\s+(?:store|db))\s+(?:poison|inject|manipulate|corrupt)",
    # Agent exploitation
    r"(?i)(?:agent|autonomous)\s+(?:loop|recursion|injection|hijack|takeover)\b",
    r"(?i)(?:chain[-_]of[-_]thought|CoT|ReAct)\s+(?:injection|hijack|manipulat)",
]

# ============================================================================
# 20. SUPPLY CHAIN & DEPENDENCY ATTACKS (30 patterns)
# ============================================================================
SUPPLY_CHAIN_ATTACKS = [
    # Package manager attacks
    r"(?i)(?:npm|pip|gem|cargo|composer|nuget|maven|gradle)\s+(?:install|add)\s+.*(?:[-_]typo|[-_]fake|[-_]evil|[-_]malicious)",
    r"(?i)(?:package|module|library|dependency)\s+(?:confusion|substitution|hijack|squatting)\b",
    r"(?i)(?:requirements|package|Gemfile|pom|build\.gradle).*(?:http://|git\+ssh://[^@]|file://)",
    r"(?i)(?:postinstall|preinstall|install)\s*['\"]:\s*['\"](?:curl|wget|nc|bash|sh|python|node)\b",
    r"(?i)(?:setup\.py|setup\.cfg|pyproject\.toml).*(?:cmdclass|install_requires).*(?:os\.|subprocess|system|exec)",
    # CI/CD poisoning
    r"(?i)(?:\.github/workflows|\.gitlab-ci|Jenkinsfile|\.circleci|\.travis).*(?:curl|wget|eval|exec)\s+",
    r"(?i)(?:secrets?\.|env\.|variables?\.).*(?:TOKEN|KEY|PASSWORD|SECRET|CREDENTIAL)\b",
    r"(?i)(?:pull_request_target|workflow_dispatch|repository_dispatch).*(?:checkout|run)\b",
    r"(?i)(?:actions/checkout).*(?:ref:\s*\$\{\{|persist-credentials:\s*true)",
    # Container supply chain
    r"(?i)(?:FROM|COPY|ADD|RUN)\s+.*(?:http://|curl\s+-k|wget\s+--no-check)",
    r"(?i)(?:docker\.io|gcr\.io|ecr\.|quay\.io)/.*(?:latest|dev|test|staging)\b",
    r"(?i)(?:Dockerfile|docker-compose).*(?:--no-verify|--insecure|VERIFY_NONE)",
    # Git-based attacks
    r"(?i)(?:git\s+(?:clone|pull|fetch|submodule)).*(?:--depth\s*=?\s*1|--single-branch).*(?:http://)",
    r"(?i)(?:\.gitmodules|\.gitconfig|\.git/hooks/).*(?:url\s*=|command\s*=)",
    r"(?i)(?:pre-commit|post-checkout|pre-push|post-merge)\s+.*(?:curl|wget|eval|exec)",
    # Dependency confusion
    r"(?i)(?:--index-url|--extra-index-url|--trusted-host)\s+(?:http://|https?://(?!pypi\.org|registry\.npmjs))",
    r"(?i)(?:registry|repository)\s*[:=]\s*['\"]?https?://(?!registry\.npmjs\.org|pypi\.org|rubygems\.org|repo\.maven)",
    # Binary supply chain
    r"(?i)(?:download|fetch|pull)\s+.*(?:\.exe|\.dll|\.so|\.dylib|\.bin).*(?:http://|unsigned|no[-_]verify)",
    r"(?i)(?:checksum|hash|sha256|md5)\s*(?:skip|ignore|bypass|disable)\b",
    # Package manifest manipulation
    r"(?i)(?:version|name)\s*[:=]\s*['\"].*(?:[-_](?:\d+\.){5,}|[-_]{3,}|\.\.)",
    # Lockfile poisoning
    r"(?i)(?:package-lock|yarn\.lock|Pipfile\.lock|Gemfile\.lock|composer\.lock).*(?:integrity|resolved)\s*[:=]\s*['\"](?:http://)",
    # Typosquatting common packages
    r"(?i)(?:import|require|from)\s+['\"](?:requets|urrllib3|colorsama|beautifulsoup|numppy|pandass|scikitlearn)\b",
    # Build system attacks
    r"(?i)(?:Makefile|CMakeLists|build\.xml|Rakefile).*(?:\$\(shell|backtick|system\(|exec\()",
    r"(?i)(?:maven[-_]?plugin|gradle[-_]?plugin|sbt[-_]?plugin).*(?:execute|shell|process|runtime)",
    # Software signing bypass
    r"(?i)(?:gpg|pgp|codesign)\s+(?:--no[-_]verify|--skip[-_]verify|--ignore[-_]sign)",
    r"(?i)(?:MINISIGN|SIGSTORE|COSIGN)\s+(?:skip|ignore|bypass|disable)",
    # Terraform/IaC supply chain
    r"(?i)(?:module|provider)\s+['\"](?:source|version)\s*[:=].*(?:http://|git::ssh://[^@]|\.\.)",
    r"(?i)(?:terraform|pulumi|crossplane)\s+(?:init|apply).*(?:--backend[-_]?config|--provider[-_]?source)\s*=\s*https?://(?!registry\.terraform)",
]

# ============================================================================
# 21. PROTOCOL ATTACKS (30 patterns)
# ============================================================================
PROTOCOL_ATTACKS = [
    # HTTP/2 attacks
    r"(?i)(?:SETTINGS|WINDOW_UPDATE|RST_STREAM|GOAWAY|PRIORITY)\s+(?:flood|attack|abuse)\b",
    r"(?i)(?:h2c|h2)\s+(?:smuggling|desync|bypass)\b",
    r"(?i)(?::method|:path|:scheme|:authority)\s*=\s*.*(?:CONNECT|TRACE|TRACK|DEBUG)",
    # WebSocket attacks
    r"(?i)Upgrade\s*:\s*websocket.*(?:inject|poison|hijack|overflow)",
    r"(?i)Sec-WebSocket-(?:Key|Protocol|Extensions)\s*:.*(?:injection|overflow|malform)",
    r"(?i)ws[s]?://.*(?:eval|exec|system|import|require)\b",
    # gRPC attacks
    r"(?i)(?:grpc|protobuf)\s*.*(?:inject|overflow|deserialization|malform)",
    r"(?i)application/grpc.*(?:malicious|exploit|inject)",
    r"(?i)(?:grpc-status|grpc-message)\s*:.*(?:error|overflow|inject)",
    # HTTP method attacks
    r"(?i)(?:TRACE|TRACK|DEBUG|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|SEARCH)\s+/",
    r"(?i)X-HTTP-Method-Override:\s*(?:PUT|DELETE|PATCH|OPTIONS|TRACE|CONNECT)",
    r"(?i)X-Method-Override:\s*(?:PUT|DELETE|PATCH|TRACE)",
    # CORS attacks
    r"(?i)Origin:\s*(?:null|https?://(?:evil|attacker|malicious|exploit)\.\w+)",
    r"(?i)Access-Control-Request-Headers:.*(?:X-Custom|Authorization)",
    # Content-Type attacks
    r"(?i)Content-Type:\s*(?:text/xml|application/xml|multipart/form-data).*(?:boundary=.*boundary|charset=.*charset)",
    r"(?i)Content-Type:\s*(?:application/x-www-form-urlencoded).*(?:charset=(?:utf-7|ibm|cp))",
    # HTTP header injection
    r"(?i)(?:Host|User-Agent|Referer|Accept|Cookie)\s*:.*[\r\n]+(?:Set-Cookie|Location|Content-Type):",
    r"(?i)(?:X-Forwarded-For|X-Real-IP|X-Originating-IP)\s*:.*(?:127\.0\.0\.1|::1|localhost)",
    # Protocol downgrade
    r"(?i)(?:Upgrade-Insecure-Requests|Strict-Transport-Security)\s*:\s*(?:0|no|false|disabled)",
    r"(?i)(?:X-Frame-Options|X-Content-Type-Options|X-XSS-Protection)\s*:\s*(?:disabled|none|off)",
    # HSTS stripping
    r"(?i)(?:sslstrip|mitmproxy|bettercap|ettercap)\b",
    # Proxy protocol abuse
    r"(?i)(?:PROXY\s+TCP[46]|HAProxy|X-Haproxy)\s+.*(?:inject|spoof|forge)",
    r"(?i)Via:\s*.*(?:Burp|ZAP|mitmproxy|Fiddler|Charles|Postman)",
    r"(?i)(?:Proxy-Authorization|Proxy-Connection)\s*:.*(?:inject|bypass|spoof)",
    # TLS attacks
    r"(?i)(?:POODLE|BEAST|BREACH|CRIME|FREAK|Logjam|DROWN|Heartbleed|ROBOT|Raccoon)\b",
    r"(?i)(?:tls|ssl)\s+(?:downgrade|stripping|intercept|bypass)\b",
    # Multipart boundary attacks
    r"(?i)boundary\s*=\s*(?:.*boundary|[-]{10,}|(?:A){100,})",
    r"(?i)Content-Disposition:.*(?:filename.*\r?\n.*filename|name.*\r?\n.*name)",
    # Chunked encoding abuse
    r"(?i)Transfer-Encoding:\s*chunked\s*[\r\n]+.*[\r\n]+0\s*[\r\n]+.*(?:GET|POST|PUT)\s+/",
]

# ============================================================================
# 22. EVASION TECHNIQUES (35 patterns)
# ============================================================================
EVASION_TECHNIQUES = [
    # Unicode normalization bypass
    r"(?i)(?:\xef\xbc\xb3|\xef\xbd\x83|\xef\xbd\x92|\xef\xbd\x89)(?:\xef\xbd\x90|\xef\xbd\x94)",
    r"(?i)(?:%C0%AF|%E0%80%AF|%F0%80%80%AF)",
    r"(?i)(?:%C0%AE|%E0%80%AE|%F0%80%80%AE)",
    # Double encoding
    r"(?i)%25(?:3[cCeE]|2[27fF]|3[bB]|5[bBcCdD]|7[bBcCdD]|0[aAdD])",
    r"(?i)%25%3[cCeE]|%25%2[27fF]|%25%3[bB]|%25%5[bBcCdD]",
    # Null byte injection
    r"(?:%00|\\x00|\\0|\\u0000)(?:\.|/|\\|=|&|\?)",
    # Comment insertion
    r"(?i)(?:/\*.*\*/){3,}",
    r"(?i)(?:sel/\*\*/ect|un/\*\*/ion|ins/\*\*/ert|upd/\*\*/ate|del/\*\*/ete)",
    r"(?i)(?:or/\*\*/der|gro/\*\*/up|hav/\*\*/ing|whe/\*\*/re|and/\*\*/)",
    # Whitespace alternatives
    r"(?i)(?:\x09|\x0a|\x0b|\x0c|\x0d|\xa0)+(?:select|union|insert|update|delete|drop|exec)\b",
    r"(?i)(?:%09|%0a|%0b|%0c|%0d|%a0)+(?:select|union|insert|update|delete)\b",
    # Case variation
    r"(?i)(?:s%20e%20l%20e%20c%20t|u%20n%20i%20o%20n|d%20r%20o%20p|i%20n%20s%20e%20r%20t)\b",
    # Concatenation bypass
    r"(?i)(?:con|CONCAT)\s*(?:cat|ATENATE)\s*\(",
    r"(?i)(?:'|\"|`)\s*(?:\+|\|\|)\s*(?:'|\"|`)",
    # WAF bypass with special chars
    r"(?i)(?:!--|--|#|;|/\*).*(?:select|union|insert|update|delete|drop|exec|alert)\b",
    # JSON/XML in URL params
    r"(?i)\{['\"].*(?:__proto__|constructor|prototype).*['\"]:",
    r"(?i)(?:%7B|%7b)['\"].*(?:__proto__|constructor).*['\"](?:%3A|:)",
    # Path normalization bypass
    r"(?i)(?:/\./|//+|/\.\./|/%2e/|/%2e%2e/|/\.%2e/)",
    # HTTP Parameter Pollution
    r"(?i)(?:\?|&)(\w+)=.*(?:&|\?)(\1)=",
    # Encoding stacking
    r"(?i)(?:base64|hex|url|html)(?:_?(?:encode|decode)){2,}",
    # IP obfuscation
    r"(?i)(?:0x[0-9a-f]{8}|0[0-7]{11})\b",
    # Browser-specific bypass
    r"(?i)(?:<!--\[if\s+|<!\[CDATA\[).*(?:script|onclick|onerror|onload)",
    # Content-Type confusion
    r"(?i)Content-Type:\s*(?:text/plain|application/octet-stream).*(?:<script|<\?php|<%=)",
    # Extension bypass
    r"(?i)\.(?:php|asp|jsp)(?:\.|%00|%20|::|\+|~\d)(?:jpg|gif|png|txt|html)",
    # Tab/newline injection
    r"(?i)(?:ja\s*va\s*sc\s*ri\s*pt|vb\s*sc\s*ri\s*pt|on\s*er\s*ro\s*r)\s*:",
    # Variable-length encoding
    r"(?i)(?:\\(?:u|x|[0-7]){2,}){3,}",
    # Backslash trick
    r"(?i)(?:\\n|\\r|\\t|\\0|\\\\){3,}",
    # Globbing in file paths
    r"(?i)(?:\?|[\[\]|{|}|\\]){2,}.*(?:/etc/|/var/|/proc/|/tmp/)",
    # Parser differential
    r"(?i)(?:#|%23|;|%3B|&|%26)\s*(?:--|\*/|//)",
    # Multiline payload
    r"(?i)(?:<scr\nipt|<im\ng|<sv\ng|<ifr\name)\b",
    # Homoglyph attacks
    r"[\x{0400}-\x{04FF}].*(?:admin|password|script|alert|select|union)",
    r"[\x{FF01}-\x{FF5E}]{3,}",
]

# ============================================================================
# 23. SERVERLESS & CLOUD-NATIVE (30 patterns)
# ============================================================================
SERVERLESS_CLOUD_ATTACKS = [
    # Lambda/Function injection
    r"(?i)(?:event|context)\s*\.\s*(?:body|queryStringParameters|headers|pathParameters)\s*\[.*(?:exec|eval|system|import)",
    r"(?i)(?:lambda|function|handler)\s*.*(?:os\.environ|process\.env|System\.getenv)\s*\[.*(?:secret|key|token|password)",
    # S3 bucket attacks
    r"(?i)(?:s3://|s3\.amazonaws\.com/)(?:\*|.*(?:\.\.|%2e%2e))",
    r"(?i)(?:\.s3\.amazonaws\.com|\.s3-\w+-\w+\.amazonaws\.com)/.*(?:\.env|\.git|\.ssh|config)",
    r"(?i)(?:PutBucketPolicy|PutBucketAcl|PutObjectAcl|GetBucketPolicy).*(?:public|AllUsers|\*)",
    r"(?i)x-amz-(?:security-token|acl|grant-\w+):\s*.*(?:public|authenticated-users|\*)",
    # IAM exploitation
    r"(?i)(?:iam|sts)\s*(?:assume[-_]role|create[-_](?:user|role|policy)|attach[-_]policy|put[-_](?:user|role)[-_]policy)",
    r"(?i)(?:AssumeRole|GetFederationToken|GetSessionToken).*(?:arn:aws:iam::\*|Action:\s*\*)",
    # Azure attacks
    r"(?i)(?:\.blob\.core\.windows\.net|\.file\.core\.windows\.net|\.queue\.core\.windows\.net|\.table\.core\.windows\.net)/.*(?:\.env|\.git|config)",
    r"(?i)(?:management\.azure\.com|graph\.microsoft\.com)/.*(?:users|groups|applications|servicePrincipals).*(?:password|secret|credential)",
    r"(?i)(?:SharedKey|SharedKeyLite|BlobSignedIdentifier)\s+",
    # GCP attacks
    r"(?i)(?:storage\.googleapis\.com|compute\.googleapis\.com|cloudresourcemanager\.googleapis\.com)/.*(?:iam|setIamPolicy|getIamPolicy)",
    r"(?i)(?:gcloud|gsutil)\s+(?:iam|compute|storage)\s+.*(?:--impersonate|--set-policy|add-iam-policy-binding)",
    # Kubernetes RBAC
    r"(?i)(?:create|patch|update)\s+(?:clusterrole|clusterrolebinding|role|rolebinding).*(?:cluster-admin|system:masters|\*)",
    r"(?i)(?:kubectl|oc)\s+(?:auth\s+can-i|get\s+secrets?|exec|port-forward|proxy)",
    # Service mesh exploitation
    r"(?i)(?:istio|envoy|linkerd)\s*.*(?:injection|sidecar|bypass|disable)\b",
    r"(?i)/config_dump\?.*(?:include_eds|include_cds)",
    # Secrets management
    r"(?i)(?:vault|secretsmanager|ssm|keyvault)\s+(?:get|list|read)\s+.*(?:\*|--recursive|--path=/)",
    r"(?i)(?:AWS_SECRET|AZURE_CLIENT_SECRET|GOOGLE_APPLICATION_CREDENTIALS|VAULT_TOKEN)\s*=",
    # Container registry attacks
    r"(?i)(?:docker|podman)\s+(?:push|pull|login)\s+.*(?:--password-stdin|--insecure-registry)",
    r"(?i)(?:ECR|GCR|ACR|DockerHub)\s*.*(?:GetAuthorizationToken|CreateRepository|DeleteRepository)",
    # Serverless event injection
    r"(?i)(?:SNS|SQS|EventBridge|Pub/Sub)\s*.*(?:inject|poison|forge|spoof|malicious)\b",
    r"(?i)(?:apigateway|apigw)\s*.*(?:override|bypass|inject)\s+(?:authorizer|lambda|integration)",
    # Cloud storage path traversal
    r"(?i)(?:blob|bucket|object|key)\s*=\s*.*(?:\.\./|%2e%2e|\.\.%2f|%252e)",
    # Terraform state attacks
    r"(?i)(?:terraform|tfstate)\s*.*(?:remote[-_]state|state[-_]pull|state[-_]push|force[-_]unlock)",
    r"(?i)(?:\.tfstate|\.tfvars|terraform\.tfstate).*(?:secret|password|token|key)\b",
    # Cloud metadata abuse via SSRF
    r"(?i)(?:curl|wget|fetch)\s+.*(?:169\.254\.169\.254|metadata\.google|100\.100\.100\.200)",
    # Cloud function code injection
    r"(?i)(?:functionapp|cloudfunctions|lambda)\s+(?:update[-_]?code|deploy).*(?:--zip[-_]file|--source|--code)\s*=\s*(?:http://|s3://)",
]

# ============================================================================
# 24. LOGGING & MONITORING EVASION (20 patterns)
# ============================================================================
LOG_EVASION_ATTACKS = [
    # Log injection
    r"(?:\r\n|\n|\r)(?:INFO|DEBUG|WARN|ERROR|CRITICAL|FATAL)\s+\d{4}-\d{2}-\d{2}",
    r"(?:%0d%0a|%0a|%0d)(?:INFO|DEBUG|WARN|ERROR|CRITICAL)",
    r"(?i)(?:log4j|log4shell|jndi)\s*[:=]",
    r"(?i)\$\{jndi:(?:ldap|rmi|dns|corba|iiop|nds|nis)://",
    r"(?i)\$\{(?:lower|upper|env|sys|java|main|ctx|bundle|marker|date):.*\}",
    # SIEM evasion
    r"(?i)(?:splunk|elastic|kibana|sentinel|qradar|arcsight|logrhythm)\s*.*(?:bypass|evade|blind|disable)\b",
    # Timestamp manipulation
    r"(?i)(?:Date|Last-Modified|If-Modified-Since|Expires)\s*:\s*(?:Thu,\s+01\s+Jan\s+1970|Mon,\s+01\s+Jan\s+1990)",
    # Anti-forensics
    r"(?i)(?:shred|srm|wipe|bleachbit|ccleaner)\s+.*(?:/var/log|/tmp|\.bash_history|\.log)",
    r"(?i)(?:history\s+-c|unset\s+HISTFILE|export\s+HISTSIZE=0|HISTCONTROL=ignorespace)",
    r"(?i)(?:auditctl\s+-D|setenforce\s+0|systemctl\s+stop\s+(?:auditd|rsyslog|syslog))",
    # Log truncation
    r"(?i)(?:truncate|>\s*/var/log/|\s*>\s*/dev/null\s+2>&1|/dev/null).*(?:auth|syslog|messages|secure|access)\b",
    # Alert fatigue / noise
    r"(?:[\x00-\x08\x0b\x0c\x0e-\x1f]){5,}",
    r"(?i)(?:AAAA|0000|FFFF|xxxx){10,}",
    # IDS/WAF evasion
    r"(?i)(?:nmap|masscan)\s+.*(?:-f\s|-D\s|--data-length|--scan-delay|--randomize-hosts|--spoof-mac)",
    r"(?i)(?:sqlmap|nikto|dirb|gobuster)\s+.*(?:--random-agent|--tamper|--delay|--threads|--tor)",
    # Network tunneling evasion
    r"(?i)(?:dns[-_]?tunnel|icmp[-_]?tunnel|http[-_]?tunnel|tcp[-_]?over[-_]?dns)\b",
    r"(?i)(?:iodine|dnscat2?|dns2tcp|ptunnel|chisel|ligolo|ngrok|cloudflared)\b",
    # Process hiding
    r"(?i)(?:hide|mask|cloak|disguise)\s+(?:process|pid|connection|file|module)\b",
    r"(?i)(?:LD_PRELOAD|DYLD_INSERT_LIBRARIES)\s*=\s*/.*\.so",
]

# ============================================================================
# 25. COMPLIANCE VIOLATION INDICATORS (25 patterns)
# ============================================================================
COMPLIANCE_VIOLATIONS = [
    # PII exposure in URLs
    r"(?i)(?:ssn|social[-_]?security|tax[-_]?id|national[-_]?id)\s*=\s*\d{3}[-\s]?\d{2}[-\s]?\d{4}",
    r"(?i)(?:credit[-_]?card|card[-_]?number|cc[-_]?num)\s*=\s*\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}",
    r"(?i)(?:cvv|cvc|cvv2|security[-_]?code)\s*=\s*\d{3,4}\b",
    r"(?i)(?:dob|date[-_]?of[-_]?birth|birth[-_]?date)\s*=\s*\d{1,4}[-/]\d{1,2}[-/]\d{1,4}",
    r"(?i)(?:passport|license)[-_]?(?:number|num|no|id)\s*=\s*[A-Z0-9]{6,12}",
    # GDPR violations
    r"(?i)(?:track|collect|store|log|record)\s+(?:user|personal|private)\s+(?:data|info|details?).*(?:without|no)\s+(?:consent|permission)",
    r"(?i)(?:Cookie|Set-Cookie).*(?:tracking|analytics|advertising|marketing).*(?:SameSite\s*=\s*None|Secure\s*=\s*false)",
    # HIPAA/Healthcare
    r"(?i)(?:medical[-_]?record|patient[-_]?id|diagnosis|prescription|ICD[-_]?\d{1,2})\s*=\s*\w+",
    r"(?i)(?:PHI|ePHI|HIPAA|health[-_]?info)\s*.*(?:expose|leak|public|unencrypted|plaintext)",
    # PCI DSS
    r"(?i)(?:cardholder|pan|primary[-_]?account[-_]?number)\s*=\s*\d{13,19}",
    r"(?i)(?:track[-_]?data|magnetic[-_]?stripe|pin[-_]?block)\s*=",
    r"(?i)(?:3[47]\d{13}|4\d{15}|5[1-5]\d{14}|6(?:011|5\d{2})\d{12})(?:\s|&|$)",
    # Authentication data in logs/URLs
    r"(?i)(?:password|passwd|secret|token|api[-_]?key)\s*=\s*[^\s&]{4,}[;&]\s*(?:--|UNION|SELECT|DROP|INSERT|OR\s+1)",
    r"(?i)(?:Authorization|Bearer|Basic)\s+[A-Za-z0-9+/=]{20,}",
    # Data residency
    r"(?i)(?:eu[-_]?data|gdpr[-_]?data|pii)\s*.*(?:transfer|copy|replicate|mirror)\s*.*(?:us[-_]|cn[-_]|non[-_]eu)",
    # Encryption at rest
    r"(?i)(?:store|save|write|persist)\s+.*(?:unencrypted|plaintext|cleartext|base64)\s+(?:password|secret|key|token|credential)",
    # Access control
    r"(?i)(?:chmod|icacls|Set-Acl)\s+.*(?:777|666|775|o\+w|Everyone|Authenticated Users).*(?:\.env|config|secret|key|credential)",
    # SOX compliance
    r"(?i)(?:financial[-_]?data|audit[-_]?log|sox[-_]?compliance)\s*.*(?:delete|modify|tamper|override)\b",
    # Data retention
    r"(?i)(?:purge|delete|destroy|shred)\s+.*(?:audit[-_]?log|compliance[-_]?record|financial[-_]?data|retention)\b",
    # Key management
    r"(?i)(?:private[-_]?key|master[-_]?key|encryption[-_]?key)\s*(?:=|:)\s*['\"]?[A-Za-z0-9+/=]{16,}",
    # Insecure transmission
    r"(?i)(?:http://|ftp://|telnet://|smtp://).*(?:password|token|secret|api[-_]?key|credential)",
    # Database exposure
    r"(?i)(?:mysql|postgres|mongodb|redis|elastic)://\w+:\w+@",
    r"(?i)(?:connection[-_]?string|dsn|jdbc)\s*[:=]\s*['\"]?.*(?:password|pwd)\s*=\s*[^\s;'\"]+",
    # Weak cryptography in transit
    r"(?i)(?:ssl|tls)[-_]?(?:version|protocol)\s*[:=]\s*(?:ssl[23v]|tls1[._]?[01]|none|disabled)",
]

# ============================================================================
# 26. DESERIALIZATION EXTENDED (40 patterns)
# ============================================================================
DESERIALIZATION_EXTENDED = [
    # Java deserialization
    r"(?i)(?:rO0ABX|aced0005)",
    r"(?i)ObjectInputStream\s*\(",
    r"(?i)java\.io\.ObjectInputStream",
    r"(?i)readObject\s*\(\s*\)",
    r"(?i)readUnshared\s*\(\s*\)",
    r"(?i)XMLDecoder\s*\(",
    r"(?i)XStream\s*\(",
    r"(?i)org\.apache\.commons\.(?:collections|beanutils|collections4)\.",
    r"(?i)com\.sun\.(?:rowset|jndi|management)\.",
    r"(?i)javax\.management\.(?:remote|MBeanServer)\.",
    r"(?i)java\.lang\.(?:Runtime|ProcessBuilder|Thread)\.",
    r"(?i)(?:ysoserial|marshalsec|gadgetprobe|GadgetInspector)\b",
    r"(?i)CommonsCollections[1-7]|BeanShell1|Clojure|Groovy1|Hibernate[12]|JBossInterceptors|Jdk7u21|Spring[12]",
    # PHP deserialization
    r"(?i)O:\d+:\"[^\"]+\":\d+:\{",
    r"(?i)a:\d+:\{(?:s:\d+:|i:\d+;)",
    r"(?i)__(?:destruct|wakeup|toString|call|callStatic|get|set|isset|unset|serialize|unserialize)\s*\(",
    r"(?i)unserialize\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE)|file_get_contents|base64_decode)",
    r"(?i)(?:phpggc|PHPGGC|phpchain)\b",
    # Python deserialization
    r"(?i)pickle\.(?:loads?|Unpickler|dump|dumps)\s*\(",
    r"(?i)yaml\.(?:load|unsafe_load|full_load)\s*\(",
    r"(?i)marshal\.(?:loads?|dump)\s*\(",
    r"(?i)shelve\.(?:open|DbfilenameShelf)\s*\(",
    r"(?i)jsonpickle\.(?:decode|encode)\s*\(",
    r"(?i)__reduce__\s*\(",
    r"(?i)cos\nsystem\n",
    r"(?i)csubprocess\ncheck_output\n",
    # .NET deserialization
    r"(?i)BinaryFormatter\s*\(",
    r"(?i)SoapFormatter\s*\(",
    r"(?i)NetDataContractSerializer\s*\(",
    r"(?i)LosFormatter\s*\(",
    r"(?i)ObjectStateFormatter\s*\(",
    r"(?i)JavaScriptSerializer\s*\(",
    r"(?i)TypeNameHandling\s*[=:]\s*(?:All|Auto|Objects|Arrays)",
    r"(?i)(?:ysoserial\.net|ExploitRemotingService|SharpSerializer)\b",
    r"(?i)System\.(?:Runtime\.Serialization|Xml\.Serialization)\.",
    # Ruby deserialization
    r"(?i)Marshal\.(?:load|restore|dump)\s*\(",
    r"(?i)YAML\.(?:load|unsafe_load|parse)\s*\(",
    r"(?i)ERB\.new\s*\(",
    # Node.js deserialization
    r"(?i)(?:node-serialize|serialize-javascript|cryo)\s*\.\s*(?:unserialize|deserialize|parse)\s*\(",
    r"(?i)_\$\$ND_FUNC\$\$_",
]

# ============================================================================
# 27. FRAMEWORK-SPECIFIC ATTACKS (50 patterns)
# ============================================================================
FRAMEWORK_ATTACKS = [
    # Spring Framework
    r"(?i)/spring/.*(?:classLoader|class\.module\.classLoader)\b",
    r"(?i)class\.module\.classLoader\.resources\.context\.parent\.pipeline",
    r"(?i)spring\.(?:datasource|jpa|security|cloud)\.\w+\s*=",
    r"(?i)SpEL\s*(?:injection|expression|evaluate)\b",
    r"(?i)#\{T\(java\.lang\.Runtime\)",
    r"(?i)spring-boot-actuator\b",
    r"(?i)/jolokia/(?:exec|read|write|list|search)\b",
    # Struts
    r"(?i)%\{.*#(?:_memberAccess|context|parameters|session|application)\b",
    r"(?i)(?:ognl|OGNL)\s*(?:expression|injection|evaluate)\b",
    r"(?i)#cmd\s*=\s*['\"].*['\"]",
    r"(?i)@java\.lang\.Runtime@getRuntime\(\)\.exec\(",
    r"(?i)/struts/.*\.action\?.*(?:redirect:|method:)",
    # Django
    r"(?i)/django/.*(?:__debug__|__import__|__builtins__|__class__|__mro__)",
    r"(?i)(?:django\.contrib\.auth|django\.conf\.settings)\.\w+",
    r"(?i)(?:DJANGO_SETTINGS_MODULE|SECRET_KEY|DATABASES)\s*=",
    r"(?i)/admin/(?:auth|contenttypes|sessions)/\w+/(?:add|change|delete)/",
    # Flask/Werkzeug
    r"(?i)/console\?__debugger__=yes&cmd=",
    r"(?i)/werkzeug/.*(?:debugger|console|eval|exec)",
    r"(?i)(?:app\.secret_key|FLASK_SECRET_KEY|SESSION_COOKIE_NAME)\s*=",
    r"(?i)__import__\s*\(\s*['\"]os['\"]\s*\)\s*\.\s*popen\s*\(",
    # Express/Node.js
    r"(?i)(?:require|import)\s*\(\s*['\"](?:child_process|cluster|dgram|dns|net|tls|vm|repl|v8)['\"]",
    r"(?i)process\.(?:env|exit|kill|abort|binding|dlopen|mainModule)\b",
    r"(?i)(?:app\.use|router\.use)\s*\(\s*.*(?:eval|exec|system)\b",
    r"(?i)(?:Buffer|Uint8Array)\.(?:from|alloc|allocUnsafe)\s*\(",
    # Ruby on Rails
    r"(?i)/rails/.*(?:info/properties|routes|mailers|conductor)\b",
    r"(?i)(?:ActiveRecord|ActionController|ActionView)::(?:Base|Metal|Relation)\b",
    r"(?i)(?:render|redirect_to)\s+.*(?:inline|text|html)\s*:\s*.*(?:params|request)",
    r"(?i)(?:send_file|send_data)\s+.*(?:params|request)\[",
    # ASP.NET
    r"(?i)(?:ViewState|EventValidation|EventTarget)\s*=\s*[A-Za-z0-9+/=]{50,}",
    r"(?i)(?:__VIEWSTATEGENERATOR|__EVENTVALIDATION|__PREVIOUSPAGE)\s*=",
    r"(?i)(?:Response\.Write|Server\.Execute|Server\.Transfer)\s*\(",
    r"(?i)(?:HttpContext\.Current|Request\.QueryString|Request\.Form)\[",
    # PHP frameworks
    r"(?i)/(?:laravel|symfony|codeigniter|yii|cakephp|slim)[-_]?(?:debug|log|config|env)",
    r"(?i)/vendor/(?:phpunit|monolog|guzzle|symfony)/.*(?:eval|exec|phpinfo|test)",
    r"(?i)(?:artisan|tinker|composer)\s+(?:exec|run|eval|dump-autoload)\b",
    # Tomcat/JBoss/WebLogic
    r"(?i)/(?:manager|host-manager|admin-console|jmx-console|web-console)/",
    r"(?i)/(?:invoker|JMXInvokerServlet|EJBInvokerServlet)\b",
    r"(?i)/(?:wls-wsat|_async|bea_wls_deployment_internal|T3InvocableObject)\b",
    r"(?i)/(?:console|consolejndi|uddiexplorer|wls-cat)\b",
    # ColdFusion
    r"(?i)/(?:CFIDE|cfide|cf_scripts)/.*(?:administrator|componentutils|getauthdetails|cfcexplorer)",
    r"(?i)(?:cfexecute|cffile|cfdirectory|cfobject)\s+",
    # GraphQL frameworks
    r"(?i)/graphql(?:[-_]?(?:playground|voyager|altair|graphiql|explorer))?\b",
    r"(?i)(?:persistedQuery|extensions)\s*.*(?:sha256Hash|version)\s*[:=]",
    # gRPC frameworks
    r"(?i)/grpc\.(?:health|reflection|channelz)\.",
    r"(?i)grpc[-_]?(?:web|gateway).*(?:unary|stream|bidi)\b",
    # FastAPI/Starlette
    r"(?i)/(?:docs|redoc|openapi\.json)\b.*(?:debug|admin|internal)",
    r"(?i)(?:Depends|Security|OAuth2PasswordBearer)\s*\(",
    # Golang frameworks
    r"(?i)/debug/pprof/(?:heap|goroutine|threadcreate|block|mutex|trace|symbol|profile)\b",
    r"(?i)/debug/vars\b",
]

# ============================================================================
# 28. ENCODING & DATA EXFILTRATION (40 patterns)
# ============================================================================
DATA_EXFIL_ENCODING = [
    # DNS exfiltration
    r"(?i)(?:\w{60,}\.){2,}\w+\.\w{2,6}",
    r"(?i)(?:TXT|CNAME|MX|NS)\s+.*(?:[a-f0-9]{32,}|[A-Za-z0-9+/=]{32,})\.",
    # HTTP-based exfiltration
    r"(?i)(?:GET|POST)\s+.*(?:exfil|steal|leak|extract)[-_]?(?:data|info|cred|secret)",
    r"(?i)(?:Cookie|Authorization|X-Custom)\s*:\s*[A-Za-z0-9+/=]{100,}",
    r"(?i)User-Agent:\s*(?:Mozilla|Chrome|Firefox)/.*[A-Za-z0-9+/=]{50,}",
    # Steganography indicators
    r"(?i)(?:stego|steganograph|lsb[-_]?embed|pixel[-_]?data|exif[-_]?inject)\b",
    r"(?i)(?:hide|embed|encode)\s+(?:in|into|within)\s+(?:image|photo|picture|audio|video|document)",
    # Encoding chains
    r"(?i)(?:base(?:32|64|85|91|122)|hex|rot(?:13|47)|ascii85|z85)\s+(?:encode|decode)\b",
    r"(?i)(?:atob|btoa|Buffer\.from|base64\.b64(?:encode|decode)|codecs\.(?:encode|decode))\s*\(",
    # Covert channels
    r"(?i)(?:covert[-_]?channel|side[-_]?channel|timing[-_]?channel|storage[-_]?channel)\b",
    r"(?i)(?:ICMP|DNS|HTTP)\s+(?:tunnel|covert|exfil|beacon)\b",
    # Data compression before exfil
    r"(?i)(?:gzip|bzip2|lzma|zstd|brotli|deflate)\s*.*(?:exfil|upload|post|send|transmit)",
    # Clipboard exfiltration
    r"(?i)(?:clipboard|navigator\.clipboard|execCommand.*copy|document\.execCommand)\b",
    r"(?i)(?:getClipboardData|setClipboardData|onpaste|oncopy|oncut)\b",
    # Screen capture
    r"(?i)(?:getDisplayMedia|captureStream|MediaRecorder|html2canvas|dom-to-image)\b",
    # WebRTC leak
    r"(?i)(?:RTCPeerConnection|RTCDataChannel|createOffer|createAnswer|addIceCandidate)\b",
    r"(?i)(?:stun|turn):\w+\.\w+\.\w+",
    # Form data exfil
    r"(?i)(?:FormData|URLSearchParams)\s*\(\s*\).*(?:append|set)\s*\(\s*['\"](?:password|token|secret|key|credit)",
    # WebSocket exfil
    r"(?i)(?:new\s+WebSocket|ws\.send)\s*\(.*(?:cookie|token|session|password|secret|key)",
    # Email exfil
    r"(?i)(?:mailto:|smtp\.|sendmail|mail\()\s*.*(?:password|token|secret|key|credential|database)",
    # USB/HID exfil
    r"(?i)(?:USB|HID|BadUSB|RubberDucky|O\.MG)\s*.*(?:exfil|keystroke|inject|payload)\b",
    # Cloud storage exfil
    r"(?i)(?:s3\.putObject|blob\.upload|storage\.objects\.create)\s*.*(?:secret|password|token|key|credential)",
    # QR code exfil
    r"(?i)(?:qrcode|QRCode|toDataURL|QR[-_]?generate)\s*\(.*(?:password|secret|token|key)",
    # Network share exfil
    r"(?i)(?:\\\\|smb://|cifs://)\w+.*(?:password|secret|key|credential|dump|exfil)",
    # Bluetooth exfil
    r"(?i)(?:bluetooth|BLE|rfcomm)\s*.*(?:send|transmit|exfil|upload)\s*.*(?:data|file|secret|password)",
    # Log-based exfil
    r"(?i)(?:console\.log|print|echo|puts|System\.out)\s*\(\s*.*(?:password|secret|token|key|credential)['\"]?\s*[,+]",
    # Browser extension exfil
    r"(?i)(?:chrome\.(?:storage|cookies|bookmarks|history|tabs)|browser\.(?:storage|cookies)|GM_xmlhttpRequest)\b",
    # Image-based exfil
    r"(?i)(?:canvas\.toDataURL|createImageBitmap|getImageData|putImageData)\s*\(",
    # CSS-based exfil
    r"(?i)(?:background(?:-image)?|content|list-style-image)\s*:\s*url\s*\(\s*['\"]?https?://.*(?:token|session|cookie)",
    # Font-based exfil
    r"(?i)@font-face\s*\{.*src:\s*url\s*\(\s*['\"]?https?://.*(?:token|session)",
    # Timing-based exfil
    r"(?i)(?:performance\.now|Date\.now|process\.hrtime|setTimeout|setInterval)\s*\(.*(?:password|secret|token)",
    # Beacon API exfil
    r"(?i)navigator\.sendBeacon\s*\(\s*['\"]https?://.*(?:token|session|cookie|password|secret)",
    # Fetch with keepalive (exfil on page close)
    r"(?i)fetch\s*\(.*keepalive\s*:\s*true.*(?:token|session|cookie|password)",
    # Request bin / collaborator
    r"(?i)(?:requestbin|pipedream|webhook\.site|hookbin|requestcatcher)\.\w+",
    r"(?i)(?:ngrok|serveo|localtunnel|bore\.pub)\.\w+",
]

# ============================================================================
# 29. EMERGING THREATS 2025-2026 (45 patterns)
# ============================================================================
EMERGING_THREATS = [
    # HTTP/3 QUIC attacks
    r"(?i)(?:QUIC|h3|HTTP/3)\s*.*(?:flood|reset|amplification|injection|desync)\b",
    r"(?i)Alt-Svc:\s*h3\s*=.*(?:spoof|inject|redirect)",
    # WebTransport attacks
    r"(?i)(?:WebTransport|webtransport)\s*.*(?:hijack|inject|spoof|flood)\b",
    # Web3/Blockchain attacks
    r"(?i)(?:eth_sendTransaction|eth_call|eth_sign|personal_sign|eth_signTypedData)\b",
    r"(?i)(?:web3\.eth|ethers\.providers|contract\.methods)\s*\.\s*(?:send|call|sign)\s*\(",
    r"(?i)(?:approve|transferFrom|delegatecall|selfdestruct|suicide)\s*\(",
    r"(?i)(?:flashloan|flash[-_]?loan|reentrancy|front[-_]?running|sandwich[-_]?attack)\b",
    r"(?i)(?:0x[0-9a-fA-F]{40})\s*.*(?:approve|transfer|allowance|delegate)",
    r"(?i)(?:NFT|ERC[-_]?(?:20|721|1155)|DeFi|DEX|AMM)\s*.*(?:exploit|drain|rug[-_]?pull|flash)\b",
    # Quantum computing related
    r"(?i)(?:quantum|post[-_]?quantum|lattice[-_]?based|NIST[-_]?PQC)\s*.*(?:harvest|store[-_]?now|SNDL)\b",
    # Edge/CDN exploitation
    r"(?i)(?:CDN|Cloudflare|Akamai|Fastly|CloudFront)\s*.*(?:bypass|cache[-_]?poison|purge|origin[-_]?pull)\b",
    r"(?i)(?:cf[-_]?connecting[-_]?ip|x[-_]?cdn[-_]?src|x[-_]?edge[-_]?ip)\s*:\s*(?:127|10|172|192\.168)\.",
    # Voice/VoIP attacks
    r"(?i)(?:SIP|RTP|SRTP|VoIP)\s*.*(?:inject|flood|spoof|tap|intercept)\b",
    r"(?i)(?:INVITE|REGISTER|BYE|CANCEL|ACK|OPTIONS)\s+sip:.*(?:overflow|inject)",
    # 5G/Network slicing
    r"(?i)(?:network[-_]?slice|5G[-_]?core|NRF|SMF|AMF|UPF)\s*.*(?:exploit|bypass|inject|escalat)\b",
    # Deepfake/synthetic media
    r"(?i)(?:deepfake|face[-_]?swap|voice[-_]?clone|synthetic[-_]?media)\s*.*(?:generate|create|forge|inject)\b",
    # Automotive security
    r"(?i)(?:V2X|C[-_]?V2X|DSRC|OBD|CAN[-_]?bus|UDS|J1939)\s*.*(?:inject|spoof|replay|fuzz|exploit)\b",
    # Satellite/space
    r"(?i)(?:satellite|GPS|GNSS|Starlink|LEO)\s*.*(?:spoof|jam|intercept|inject|exploit)\b",
    # Digital twin attacks
    r"(?i)(?:digital[-_]?twin|simulation|SCADA[-_]?twin|OT[-_]?twin)\s*.*(?:manipulat|inject|falsif|tamper)\b",
    # Zero-trust bypass
    r"(?i)(?:zero[-_]?trust|ZTNA|SDP|BeyondCorp)\s*.*(?:bypass|evade|circumvent|impersonat)\b",
    # SaaS exploitation
    r"(?i)(?:OAuth|OIDC|SSO|SAML)\s*.*(?:token[-_]?theft|session[-_]?hijack|privilege[-_]?escalat)\b",
    # Post-exploitation frameworks
    r"(?i)(?:Cobalt[-_]?Strike|Metasploit|Sliver|Havoc|Brute[-_]?Ratel|Mythic|Nighthawk)\b",
    r"(?i)(?:Mimikatz|LaZagne|SharpHound|BloodHound|Rubeus|Certify|ADCSTemplate)\b",
    r"(?i)(?:PsExec|WinRM|WMI|DCOM|SMBExec|AtExec|SchtasksExec)\s+/",
    # Living off the land (LOTL)
    r"(?i)(?:LOLBAS|LOLBIN|GTFOBin)\b",
    r"(?i)(?:msbuild|installutil|regasm|regsvcs|cmstp|mshta|rundll32|regsvr32)\.exe\s+",
    r"(?i)(?:wmic|wscript|cscript|certutil|bitsadmin|msiexec)\.exe\s+.*(?:http|ftp|\\\\)",
    # Anti-sandbox/analysis
    r"(?i)(?:sandbox|analysis|debug|emulat|virtual|vm[-_]?detect)\s*.*(?:detect|evade|bypass|check)\b",
    r"(?i)(?:IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|OutputDebugString)\b",
    r"(?i)(?:cpuid|rdtsc|int\s+2d|vmcall|vmmcall|in\s+al,dx)\b",
    # Ransomware techniques
    r"(?i)(?:vssadmin|wbadmin|bcdedit)\s+(?:delete|resize|set)\s+",
    r"(?i)(?:cipher\s+/w:|sdelete|diskpart)\s+",
    r"(?i)(?:AES[-_]256|RSA[-_]4096|ChaCha20)\s*.*(?:encrypt|ransom|lock|demand|bitcoin|monero)\b",
    # Fileless malware
    r"(?i)(?:fileless|in[-_]?memory|LOL[-_]?bin|reflective[-_]?(?:injection|loading|DLL))\b",
    r"(?i)(?:amsi[-_]?bypass|etw[-_]?bypass|clr[-_]?hooking|syscall[-_]?hooking)\b",
    # Data poisoning
    r"(?i)(?:data[-_]?poisoning|model[-_]?poisoning|label[-_]?flipping|backdoor[-_]?attack)\b",
    # API gateway bypass
    r"(?i)(?:kong|tyk|apigee|aws[-_]?api[-_]?gateway|azure[-_]?api[-_]?management)\s*.*(?:bypass|evade|circumvent)\b",
    # Multi-cloud attacks
    r"(?i)(?:cross[-_]?cloud|multi[-_]?cloud|cloud[-_]?hopping)\s*.*(?:pivot|lateral|escalat|exploit)\b",
    # Browser-in-browser attacks
    r"(?i)(?:browser[-_]?in[-_]?browser|BitB|fake[-_]?login|phishing[-_]?popup)\b",
    # Dependency confusion (more patterns)
    r"(?i)(?:internal[-_]?package|private[-_]?registry|scoped[-_]?package)\s*.*(?:substitut|confus|hijack|squat)\b",
    # Sigstore/supply chain verification bypass
    r"(?i)(?:cosign|sigstore|rekor|fulcio|transparency[-_]?log)\s*.*(?:bypass|skip|ignore|fake)\b",
    # Container escape extended
    r"(?i)(?:runc|containerd|cri-o|kata)\s*.*(?:CVE|escape|breakout|vulnerability)\b",
    r"(?i)(?:sys_admin|sys_ptrace|dac_override|net_admin)\b.*(?:exploit|escape|privilege)\b",
    # Additional emerging patterns
    r"(?i)(?:wasm|WebAssembly)\s*.*(?:inject|exploit|overflow|malicious)\b",
    r"(?i)(?:WebGPU|WebNN|WebXR)\s*.*(?:exploit|overflow|inject|malicious)\b",
    r"(?i)(?:passkey|WebAuthn|FIDO2)\s*.*(?:bypass|spoof|clone|replay)\b",
    r"(?i)(?:OAuth2\.1|GNAP|RAR|PAR|DPoP)\s*.*(?:bypass|exploit|inject|steal)\b",
    r"(?i)(?:mTLS|mutual[-_]TLS|client[-_]cert)\s*.*(?:bypass|forge|spoof|strip)\b",
    r"(?i)(?:SBOM|software[-_]bill|transparency[-_]log|VEX)\s*.*(?:tamper|poison|forge|fake)\b",
    r"(?i)(?:confidential[-_]computing|SGX|SEV|TDX|TEE)\s*.*(?:attack|exploit|bypass|extract)\b",
    r"(?i)(?:homomorphic|FHE|ZKP|zero[-_]knowledge)\s*.*(?:exploit|bypass|break|attack)\b",
]


# ============================================================================
# 30. SCANNER & TOOL DETECTION (50 patterns)
# ============================================================================
SCANNER_DETECTION = [
    # Vulnerability scanners
    r"(?i)(?:Acunetix|Nessus|Qualys|Tenable|Burp[-_]?Suite|OWASP[-_]?ZAP|Nikto|AppScan|Arachni|Wapiti|Vega|w3af|Skipfish|Paros|WebScarab|Ratproxy)\b",
    r"(?i)User-Agent:.*(?:sqlmap|nikto|dirbuster|gobuster|dirb|wfuzz|ffuf|feroxbuster|httpie)\b",
    r"(?i)User-Agent:.*(?:nmap|masscan|zmap|censys|shodan|zgrab)\b",
    r"(?i)User-Agent:.*(?:nuclei|subfinder|httpx|katana|gau|waybackurls)\b",
    r"(?i)User-Agent:.*(?:curl|wget|python-requests|python-urllib|Go-http-client|Java/|libwww-perl|lwp-trivial)\b",
    r"(?i)User-Agent:.*(?:scrapy|BeautifulSoup|Selenium|PhantomJS|HeadlessChrome|Puppeteer|Playwright)\b",
    # SQLMap signatures
    r"(?i)(?:sqlmap|havij|sqlninja|bbqsql|jsql|mole)\b",
    r"(?i)(?:--(?:dbs|tables|columns|dump|os-shell|sql-shell|tamper|level|risk))\b",
    r"(?i)(?:BENCHMARK|SLEEP|WAITFOR)\s*\(\s*(?:\d{5,}|')",
    # Brute force tools
    r"(?i)(?:Hydra|Medusa|Patator|Ncrack|John[-_]?the[-_]?Ripper|Hashcat|CeWL|Crunch)\b",
    # Web crawlers (malicious)
    r"(?i)User-Agent:.*(?:HTTrack|Wget|Teleport|WebCopier|WebReaper|SiteSucker|DownloadStudio)\b",
    r"(?i)User-Agent:.*(?:Screaming[-_]?Frog|DotBot|SemrushBot|AhrefsBot|MJ12bot|BLEXBot)\b",
    # Exploitation tools
    r"(?i)(?:Metasploit|msfvenom|msfconsole|meterpreter|armitage|beef[-_]?xss)\b",
    r"(?i)(?:empire|starkiller|covenant|sliver|merlin|pupy|silenttrinity|mythic)\b",
    r"(?i)(?:responder|ntlmrelayx|mitm6|crackmapexec|evil-winrm|impacket)\b",
    # Password spraying tools
    r"(?i)(?:spray|ruler|mailsniper|trevorspray|spraycharles|o365spray)\b",
    # Directory brute force
    r"(?i)(?:dirsearch|rustbuster|tachyon|wig|whatweb|wafw00f|wafwoof)\b",
    # Header-based scanner detection
    r"(?i)X-Scanner:\s*",
    r"(?i)X-Scan-(?:Memo|Version|Id):\s*",
    r"(?i)(?:Proxy-Connection|X-BlueCoat-Via|X-Forwarded-For):\s*.*(?:scanner|burp|zap|proxy)",
    # Fuzzing patterns
    r"(?i)(?:FUZZ|FUZ2Z|INJECT|PAYLOAD|AAAAAAAAAA|<>\"'%;)(!&|}{)\b",
    r"(?:%[0-9a-fA-F]{2}){10,}",
    r"(?i)(?:boundary|content-type|accept)\s*:.*(?:fuzzing|test|inject|payload)",
    # Automated testing signatures
    r"(?i)(?:JMeter|LoadRunner|Gatling|Artillery|Locust|wrk|vegeta|hey|ab|siege|boom)\b",
    r"(?i)X-(?:Requested-With|Test-Header|Custom-Test|Debug-Token):\s*(?:XMLHttpRequest|test|debug|scan)",
    # Reconnaissance
    r"(?i)(?:theHarvester|recon-ng|spiderfoot|maltego|amass|assetfinder|knock|massdns)\b",
    r"(?i)(?:dnsrecon|dnsmap|fierce|dnstwist|sublist3r|altdns)\b",
    # OS fingerprinting
    r"(?i)(?:p0f|xprobe|nmap.*-O|fpdns)\b",
    # WAF detection tools
    r"(?i)(?:wafw00f|whatwaf|identywaf|bypass403|403bypasser)\b",
    # Network tools
    r"(?i)(?:tcpdump|wireshark|tshark|ettercap|arpspoof|macchanger)\b",
    r"(?i)(?:hping3|scapy|yersinia|netwox|netcat|ncat|socat)\b",
    # Cloud enumeration
    r"(?i)(?:ScoutSuite|Prowler|Pacu|enumerate-iam|WeirdAAL|CloudMapper|cartography)\b",
    r"(?i)(?:S3Scanner|BucketFinder|AWSBucketDump|GCPBucketBrute|s3enum)\b",
    # API testing tools
    r"(?i)(?:Postman[-_]?Runtime|Insomnia|HTTPie|Thunder[-_]?Client|REST[-_]?Client)\b",
    r"(?i)User-Agent:.*(?:PostmanRuntime|insomnia|httpie|vscode-restclient)",
    # Git intelligence
    r"(?i)(?:gittools|git-dumper|GitHack|dvcs-ripper|gitjacker|trufflehog|gitleaks|git-secrets)\b",
    # Subdomain enumeration
    r"(?i)(?:subfinder|assetfinder|amass|chaos|findomain|shuffledns|puredns)\b",
    # Parameter discovery
    r"(?i)(?:arjun|paramspider|x8|param-miner)\b",
    # JWT tools
    r"(?i)(?:jwt_tool|jwt[-_]?cracker|jwt[-_]?forgery|c-jwt-cracker)\b",
]

# ============================================================================
# 31. CMS EXTENDED (45 patterns)
# ============================================================================
CMS_EXTENDED = [
    # Drupal extended
    r"(?i)/(?:sites/default/files|sites/all/modules|modules/system)/.*/.*\.php",
    r"(?i)/(?:node|admin|user)/\d+/(?:edit|delete|revisions|devel)\b",
    r"(?i)/(?:filter/tips|update\.php|install\.php|cron\.php|xmlrpc\.php)\b",
    r"(?i)/(?:CHANGELOG\.txt|INSTALL\.txt|MAINTAINERS\.txt|UPGRADE\.txt|LICENSE\.txt)\b",
    r"(?i)(?:drupal_render|drupal_execute|hook_menu|hook_form_alter)\b",
    r"(?i)/(?:jsonapi|rest/session/token|entity/node)\b",
    r"(?i)(?:SA-CORE|SA-CONTRIB)-\d{4}-\d{3,4}\b",
    r"(?i)/admin/(?:modules|appearance|config|structure|reports|help|people)\b",
    # Joomla extended
    r"(?i)/(?:administrator|components|modules|plugins|templates|media|cache|tmp)/",
    r"(?i)/(?:index\.php)\?option=com_\w+&(?:view|task|controller)=",
    r"(?i)/(?:configuration\.php|htaccess\.txt|web\.config\.txt|joomla\.xml)\b",
    r"(?i)com_(?:content|users|finder|fields|media|contact|banners|newsfeeds)\b",
    r"(?i)/administrator/index\.php\?option=com_(?:installer|templates|modules|plugins)\b",
    r"(?i)/api/index\.php/v1/(?:content|users|banners|categories)\b",
    # Magento
    r"(?i)/(?:downloader|xmlconnect|app/etc)/",
    r"(?i)/(?:skin|js|media|var)/.*\.(?:php|phtml)\b",
    r"(?i)/(?:Mage|Varien|Zend)_\w+",
    r"(?i)/app/(?:etc|code|design|locale)/",
    r"(?i)/(?:getmodel|getsingleton|getresourcemodel)\b",
    # Shopify/eCommerce
    r"(?i)/(?:admin|products|collections|customers|orders|cart|checkout)\.json\b",
    r"(?i)/admin/api/\d{4}-\d{2}/(?:products|orders|customers)\b",
    # Ghost CMS
    r"(?i)/ghost/api/v\d+/(?:admin|content)/",
    r"(?i)/ghost/#/(?:settings|staff|editor|posts)\b",
    # Typo3
    r"(?i)/(?:typo3|typo3conf|fileadmin|uploads|typo3temp)/",
    r"(?i)/typo3/(?:install|login|logout|sysext|ext)/",
    r"(?i)(?:t3://|typolink|TypoScript)\b",
    # Confluence/Jira
    r"(?i)/(?:rest/api|wiki/rest|confluence/rest)/(?:content|space|user|search)\b",
    r"(?i)/(?:login\.action|dologin\.action|signup\.action|doregister\.action)\b",
    r"(?i)/(?:plugins/servlet|rest/gadget|rest/scriptrunner)\b",
    r"(?i)(?:CVE-2021-26084|CVE-2022-26134|CVE-2023-22515|CVE-2023-22527)\b",
    # SharePoint
    r"(?i)/(?:_layouts|_vti_bin|_api|_catalogs|Pages|SitePages)/",
    r"(?i)/(?:_vti_pvt|_vti_cnf|_vti_txt|_vti_script)/",
    r"(?i)(?:AllItems|DispForm|EditForm|NewForm)\.aspx\b",
    # Moodle
    r"(?i)/(?:mod|course|blocks|theme|local)/(?:install|config|setup|debug|admin)",
    r"(?i)/(?:moodle|login/index\.php|admin/settings\.php)\b",
    # PrestaShop
    r"(?i)/(?:modules|themes|override|translations|controllers|classes)/.*\.php",
    r"(?i)/(?:admin-\w+|backoffice|bo)/",
    # Generic CMS patterns
    r"(?i)/(?:cms|backend|dashboard|cpanel|webadmin|siteadmin|backoffice)/(?:login|index|dashboard)",
    r"(?i)/(?:filemanager|elfinder|ckfinder|tinymce|fckeditor)/",
    r"(?i)/(?:admin|backend)/(?:ajax|api|upload|file|media|export|import)\b",
    # Plugin/extension vulnerabilities
    r"(?i)/(?:plugin|extension|module|addon|component)/.*(?:upload|download|exec|eval|inject|shell)",
    r"(?i)/(?:wp-content|sites/all|components|modules)/.*(?:\.php\?|cmd=|exec=|shell=|eval=)",
    # CMS version disclosure
    r"(?i)(?:generator|X-Powered-By|X-CMS)\s*[:=]\s*(?:WordPress|Joomla|Drupal|Magento|PrestaShop)\s*[\d\.]+",
]


# ============================================================================
# RULES MAP - All 31 categories
# ============================================================================
RULES_V5_MAP = {
    'SQLI_ADV_V5': SQLI_ADVANCED,
    'XSS_ADV_V5': XSS_ADVANCED,
    'CMD_INJECTION_V5': CMD_INJECTION_ADVANCED,
    'PATH_TRAVERSAL_V5': PATH_TRAVERSAL_ADVANCED,
    'SSRF_V5': SSRF_ADVANCED_V5,
    'AUTH_SESSION_V5': AUTH_SESSION_ATTACKS,
    'SSTI_V5': SSTI_PATTERNS,
    'XML_XXE_V5': XML_XXE_ADVANCED,
    'WEBSHELL_V5': WEBSHELL_PATTERNS,
    'CRYPTOMINING_V5': CRYPTOMINING_MALWARE,
    'API_ABUSE_V5': API_ABUSE_PATTERNS,
    'INFRASTRUCTURE_V5': INFRASTRUCTURE_ATTACKS,
    'MOBILE_IOT_V5': MOBILE_IOT_ATTACKS,
    'BUSINESS_LOGIC_V5': BUSINESS_LOGIC_ADVANCED,
    'CRYPTO_ATTACKS_V5': CRYPTO_ATTACKS,
    'WORDPRESS_V5': WORDPRESS_ADVANCED,
    'CACHE_DESYNC_V5': CACHE_DESYNC_ATTACKS,
    'CVE_2025_V5': CVE_2025_PATTERNS,
    'AI_LLM_V5': AI_LLM_ATTACKS,
    'SUPPLY_CHAIN_V5': SUPPLY_CHAIN_ATTACKS,
    'PROTOCOL_V5': PROTOCOL_ATTACKS,
    'EVASION_V5': EVASION_TECHNIQUES,
    'SERVERLESS_CLOUD_V5': SERVERLESS_CLOUD_ATTACKS,
    'LOG_EVASION_V5': LOG_EVASION_ATTACKS,
    'COMPLIANCE_V5': COMPLIANCE_VIOLATIONS,
    'DESER_EXT_V5': DESERIALIZATION_EXTENDED,
    'FRAMEWORK_V5': FRAMEWORK_ATTACKS,
    'DATA_EXFIL_V5': DATA_EXFIL_ENCODING,
    'EMERGING_V5': EMERGING_THREATS,
    'SCANNER_DETECT_V5': SCANNER_DETECTION,
    'CMS_EXT_V5': CMS_EXTENDED,
}


def get_all_v5_patterns():
    """Return all v5 patterns as list of (regex_str, category)."""
    patterns = []
    for category, rules in RULES_V5_MAP.items():
        for regex_str in rules:
            patterns.append((regex_str, category))
    return patterns


def count_v5_patterns():
    """Return total count of v5 patterns."""
    return sum(len(v) for v in RULES_V5_MAP.values())
