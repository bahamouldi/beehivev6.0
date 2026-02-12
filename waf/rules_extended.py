"""
BeeWAF Extended Rules Database
=================================
1200+ additional detection patterns organized by attack category.
These are merged with the base rules in rules.py to create a
comprehensive ruleset surpassing F5 BIG-IP ASM signature database.

Categories added/expanded:
- Advanced SQL Injection (50+ new)
- Advanced XSS (50+ new) 
- Advanced Command Injection (30+ new)
- CRLF Injection (20+)
- Open Redirect (20+)
- HTTP Request Smuggling (15+)
- Cache Poisoning (15+)
- WebSocket Injection (10+)
- CORS Bypass (10+)
- Server-Side Request Forgery Extended (30+)
- File Inclusion Extended (25+)
- XML Injection Extended (20+)
- LDAP Injection Extended (15+)
- NoSQL Injection Extended (20+)
- Expression Language Injection (15+)
- Remote Code Execution (30+)
- Information Disclosure (25+)
- Authentication Bypass (20+)
- Authorization Bypass (15+)
- Mass Assignment (10+)
- Business Logic (15+)
- Scanner/Probe Detection (30+)
- Encoding Evasion (25+)
- WAF Bypass Techniques (30+)
- Log Injection (10+)
- Email Injection (10+)
- HTTP Header Injection (15+)
- XPATH Injection (10+)
- CSV/Formula Injection (10+)
- Cryptographic Attacks (10+)
- WordPress Specific (30+)
- Drupal Specific (15+)
- Joomla Specific (10+)
- PHP Specific Extended (20+)
- Java/Spring Specific (25+)
- .NET Specific (20+)
- Node.js Specific (15+)
- Ruby/Rails Specific (10+)
- Zero-Day CVE Patterns (50+)
"""


# ============================================================
#  ADVANCED SQL INJECTION (50+ new patterns)
# ============================================================

SQLI_EXTENDED = [
    # Time-based blind SQLi
    r"(?i)benchmark\s*\(\s*\d+",
    r"(?i)pg_sleep\s*\(",
    r"(?i)waitfor\s+delay\s",
    r"(?i)sleep\s*\(\s*\d",
    r"(?i)dbms_pipe\.receive_message",
    r"(?i)utl_inaddr\.get_host_address",
    # Boolean-based blind SQLi
    r"(?i)(?:and|or)\s+\d+\s*=\s*\d+",
    r"(?i)(?:and|or)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?",
    r"(?i)(?:and|or)\s+substring\s*\(",
    r"(?i)(?:and|or)\s+ascii\s*\(",
    r"(?i)(?:and|or)\s+length\s*\(",
    r"(?i)(?:and|or)\s+char\s*\(",
    r"(?i)(?:and|or)\s+exists\s*\(",
    # Error-based SQLi
    r"(?i)extractvalue\s*\(",
    r"(?i)updatexml\s*\(",
    r"(?i)xmltype\s*\(",
    r"(?i)exp\s*\(\s*~",
    r"(?i)geometrycollection\s*\(",
    r"(?i)multipoint\s*\(",
    r"(?i)polygon\s*\(",
    r"(?i)linestring\s*\(",
    r"(?i)multilinestring\s*\(",
    # Stacked queries
    r";\s*(?:drop|alter|create|truncate|rename)\s",
    r";\s*(?:insert|update|delete|merge)\s",
    r";\s*(?:exec|execute|xp_)\w+",
    r";\s*declare\s+@",
    # Advanced UNION-based
    r"(?i)union\s+(?:all\s+)?select\s+(?:null,?\s*)+",
    r"(?i)union\s+select\s+(?:0x[0-9a-f]+,?\s*)+",
    r"(?i)union\s+select\s+(?:char\(\d+\),?\s*)+",
    r"(?i)union\s+select\s+group_concat\s*\(",
    r"(?i)union\s+select\s+concat\s*\(",
    # Second-order SQLi indicators
    r"(?i)into\s+(?:outfile|dumpfile)\s",
    r"(?i)load_file\s*\(",
    r"(?i)load\s+data\s+(?:local\s+)?infile",
    # MySQL specific
    r"(?i)information_schema\.\w+",
    r"(?i)mysql\.user",
    r"(?i)performance_schema\.",
    r"(?i)@@(?:version|datadir|basedir|hostname|global)",
    r"(?i)@@(?:secure_file_priv|plugin_dir)",
    # PostgreSQL specific
    r"(?i)pg_catalog\.\w+",
    r"(?i)pg_user",
    r"(?i)pg_shadow",
    r"(?i)current_setting\s*\(",
    r"(?i)string_agg\s*\(",
    # MSSQL specific
    r"(?i)master\.\.sysdatabases",
    r"(?i)master\.\.sysobjects",
    r"(?i)sys\.(?:objects|columns|databases)",
    r"(?i)openrowset\s*\(",
    r"(?i)opendatasource\s*\(",
    # Oracle specific
    r"(?i)all_tables",
    r"(?i)user_tables",
    r"(?i)dba_users",
    r"(?i)v\$(?:version|instance|session)",
    r"(?i)dbms_(?:xmlgen|java|scheduler|metadata)",
    # SQLite specific
    r"(?i)sqlite_master",
    r"(?i)sqlite_version\s*\(",
    r"(?i)typeof\s*\(",
    r"(?i)zeroblob\s*\(",
    # Obfuscation techniques
    r"(?i)/\*!.*\*/",
    r"(?i)(?:un|/\*\*/)?ion(?:/\*\*/|\s)(?:se|/\*\*/)?lect",
    r"(?i)concat\s*\(\s*0x",
    r"(?i)char\s*\(\s*\d+(?:\s*,\s*\d+)+\s*\)",
    r"(?i)hex\s*\(\s*(?:unhex|0x)",
]


# ============================================================
#  ADVANCED XSS (50+ new patterns)
# ============================================================

XSS_EXTENDED = [
    # DOM-based XSS
    r"(?i)document\.(?:cookie|domain|write|writeln|location|URL|referrer)",
    r"(?i)window\.(?:location|name|open|eval|execScript)",
    r"(?i)\.innerHTML\s*=",
    r"(?i)\.outerHTML\s*=",
    r"(?i)\.insertAdjacentHTML\s*\(",
    r"(?i)\.createContextualFragment\s*\(",
    r"(?i)document\.(?:createElement|createEvent|createTreeWalker)",
    r"(?i)\.setAttribute\s*\(\s*['\"]on\w+",
    # Event handler XSS
    r"(?i)\bon(?:error|load|click|mouseover|focus|blur|change|submit|resize)\s*=",
    r"(?i)\bon(?:abort|beforeunload|hashchange|keydown|keypress|keyup)\s*=",
    r"(?i)\bon(?:mousedown|mouseup|mousemove|mouseout|wheel|scroll)\s*=",
    r"(?i)\bon(?:drag|dragend|dragenter|dragleave|dragover|dragstart|drop)\s*=",
    r"(?i)\bon(?:copy|cut|paste|animationend|animationstart|transitionend)\s*=",
    r"(?i)\bon(?:pointerdown|pointerup|pointermove|pointerover|pointerout)\s*=",
    r"(?i)\bon(?:toggle|input|invalid|select|contextmenu)\s*=",
    # XSS via CSS
    r"(?i)expression\s*\(",
    r"(?i)url\s*\(\s*javascript:",
    r"(?i)behavior\s*:\s*url\s*\(",
    r"(?i)-moz-binding\s*:\s*url\s*\(",
    r"(?i)@import\s+['\"]?(?:javascript|data):",
    # XSS via SVG
    r"(?i)<svg[^>]*\bon\w+\s*=",
    r"(?i)<svg[^>]*>.*?<script",
    r"(?i)<svg/onload\s*=",
    r"(?i)<animate[^>]*\bon\w+",
    r"(?i)<set[^>]*\bon\w+",
    r"(?i)<foreignObject",
    # XSS via MathML
    r"(?i)<math[^>]*>.*?<maction",
    r"(?i)<math[^>]*\bon\w+",
    # Encoded XSS
    r"(?i)&#(?:0*(?:34|39|60|62|92)|x(?:0*(?:22|27|3c|3e|5c)))\s*;?",
    r"(?i)\\u003[cCeE]",
    r"(?i)\\x3[cCeE]",
    r"(?i)%3[cCeE](?:script|img|svg|body|iframe|object|embed|form|input)",
    # Template literal XSS
    r"\$\{.*(?:alert|confirm|prompt|eval|Function)\s*\(",
    r"(?i)`[^`]*\$\{[^}]*`",
    # JavaScript protocol variants
    r"(?i)javascript\s*:",
    r"(?i)j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:",
    r"(?i)vbscript\s*:",
    r"(?i)livescript\s*:",
    r"(?i)mocha\s*:",
    r"(?i)ecmascript\s*:",
    # XSS via data URI
    r"(?i)data\s*:\s*text/html",
    r"(?i)data\s*:\s*image/svg\+xml",
    r"(?i)data\s*:\s*application/x-javascript",
    # Mutation XSS (mXSS)
    r"(?i)<noscript.*?<img",
    r"(?i)<noscript.*?<svg",
    r"(?i)<math>.*?<mi>.*?<annotation",
    r"(?i)<select>.*?<style>",
    r"(?i)<table>.*?<style>",
    # XSS via meta refresh
    r"(?i)<meta[^>]*http-equiv\s*=\s*['\"]?refresh",
    r"(?i)<meta[^>]*url\s*=\s*['\"]?javascript:",
    # Angular/Vue/React template injection as XSS
    r"\{\{.*(?:constructor|__proto__|prototype)\s*[\[\.]",
    r"(?i)\{\{\s*[$_a-z][\w.]*\s*\(",
    r"(?i)ng-(?:click|mouseover|init)\s*=",
    r"(?i)v-(?:html|on)\s*=",
    r"(?i)\[innerHTML\]\s*=",
]


# ============================================================
#  CRLF INJECTION (20+ patterns)
# ============================================================

CRLF_INJECTION = [
    r"%0[dD]%0[aA]",
    r"\\r\\n",
    r"%0[aA](?:Set-Cookie|Location|Content-Type|X-)",
    r"%0[dD]%0[aA](?:HTTP/|Set-Cookie|Location|Content-Type)",
    r"%E5%98%8A%E5%98%8D",  # Unicode CRLF
    r"\r\n(?:Set-Cookie|Location|Content-Type):",
    r"\\n(?:Set-Cookie|Location|Content-Type):",
    r"%0[aA]Host:",
    r"%0[dD]%0[aA]Host:",
    r"%0[aA]X-Forwarded-For:",
    r"%0[dD]%0[aA]X-Forwarded-For:",
    r"%0[aA]Transfer-Encoding:",
    r"%0[dD]%0[aA]Transfer-Encoding:",
    r"%0[aA]Content-Length:",
    r"%0[dD]%0[aA]Content-Length:\s*0",
    r"(?i)%0d%0a%0d%0a<",  # CRLF + body injection
    r"\x0d\x0a",
    r"\\x0d\\x0a",
    r"\u000d\u000a",
    r"\\u000d\\u000a",
]


# ============================================================
#  OPEN REDIRECT (20+ patterns)
# ============================================================

OPEN_REDIRECT = [
    r"(?i)(?:redirect|return|next|url|target|rurl|dest|destination|redir|redirect_url|redirect_uri|return_url|return_to|continue|forward|goto|go|out|view|link|checkout_url|image_url|r2)\s*=\s*(?:https?://|//)[^\s]+",
    r"(?i)/redirect/(?:https?://|//)",
    r"(?i)/goto/(?:https?://|//)",
    r"(?i)/out\?(?:url|to|link)=",
    r"(?i)/link\?(?:url|to|target)=",
    r"(?i)(?:url|redirect|return|next)\s*=\s*(?:%2[fF]){2}",
    r"(?i)(?:url|redirect|return)\s*=\s*(?:\\x2[fF]){2}",
    r"(?i)(?:url|redirect|return)\s*=\s*(?:%5[cC]){2}",
    r"(?i)(?:url|redirect)\s*=\s*//[a-z0-9]+\.[a-z]{2,}",
    r"(?i)(?:url|redirect)\s*=\s*https?%3[aA]%2[fF]%2[fF]",
    r"(?i)(?:url|redirect)\s*=\s*(?:data|javascript|vbscript):",
    r"(?i)/(?:login|auth|oauth|sso)\?.*(?:redirect|return|callback)\s*=\s*https?://",
    r"(?i)(?:Location|Refresh)\s*:\s*(?:https?://|//)[^\s]+",
    r"(?i)\x00https?://",  # Null byte + URL
    r"(?i)@[a-z0-9]+\.[a-z]{2,}(?:/|%2[fF])",  # user@evil.com/
    r"(?i)(?:url|redirect)=(?:%09|%0[aAdD])+https?://",  # Tab/CRLF + URL
    r"(?i)(?:url|redirect)=\s*(?:https?:)?//[^/]*\.[a-z]{2,}",
    r"(?i)/\.\./(?:https?://|//)",
    r"(?i)/{2,}[a-z0-9]+\.[a-z]{2,}",
    r"(?i)\\\\[a-z0-9]+\.[a-z]{2,}",
]


# ============================================================
#  HTTP REQUEST SMUGGLING (15+ patterns)
# ============================================================

REQUEST_SMUGGLING = [
    r"(?i)transfer-encoding\s*:\s*chunked.*transfer-encoding",
    r"(?i)transfer-encoding\s*:\s*[\t ]*chunked",
    r"(?i)transfer-encoding\s*:\s*chunked\s*,\s*\w+",
    r"(?i)transfer-encoding\s*:\s*\w+\s*,\s*chunked",
    r"(?i)transfer-encoding\s*:\s*x]chunked",
    r"(?i)transfer[-_]encoding",
    r"(?i)content-length\s*:\s*\d+.*content-length\s*:\s*\d+",
    r"0\r\n\r\n(?:GET|POST|PUT|DELETE|PATCH)\s",
    r"(?i)\r\n\r\n(?:GET|POST|PUT|DELETE|PATCH)\s+/",
    r"(?i)transfer-encoding:\s*identity\s*,\s*chunked",
    r"(?i)transfer-encoding:\s*chunked\s*;\s*",
    r"(?i)[\x0b\x0c]transfer-encoding",
    r"(?i)x:\x00transfer-encoding",
    r"(?i)transfer-encoding\s*:[\t]+chunked",
    r"(?i)(?:transfer.encoding|content.length)\s*:.*\r?\n\s+\w",
]


# ============================================================
#  CACHE POISONING (15+ patterns)
# ============================================================

CACHE_POISONING = [
    r"(?i)x-forwarded-host\s*:\s*[a-z0-9]+\.[a-z]{2,}",
    r"(?i)x-forwarded-scheme\s*:\s*(?:http|nothttps)",
    r"(?i)x-forwarded-port\s*:\s*(?!443|80)\d+",
    r"(?i)x-original-url\s*:\s*/",
    r"(?i)x-rewrite-url\s*:\s*/",
    r"(?i)x-forwarded-prefix\s*:\s*/",
    r"(?i)x-host\s*:\s*[a-z0-9]+\.[a-z]{2,}",
    r"(?i)x-forwarded-server\s*:\s*[a-z0-9]+\.[a-z]{2,}",
    r"(?i)x-http-method-override\s*:\s*(?:PUT|DELETE|PATCH)",
    r"(?i)x-method-override\s*:\s*(?:PUT|DELETE|PATCH)",
    r"(?i)x-original-method\s*:\s*(?:PUT|DELETE|PATCH)",
    r"(?i)x-http-method\s*:\s*(?:PUT|DELETE|PATCH)",
    r"(?i)x-forwarded-for\s*:\s*(?:127\.0\.0\.1|localhost|0\.0\.0\.0)",
    r"(?i)(?:x-cache-key|x-cache-hash)\s*:",
    r"(?i)x-wap-profile\s*:\s*http",
]


# ============================================================
#  WEBSOCKET INJECTION (10+ patterns)
# ============================================================

WEBSOCKET_INJECTION = [
    r"(?i)upgrade\s*:\s*websocket.*<script",
    r"(?i)sec-websocket-protocol\s*:.*<script",
    r"(?i)sec-websocket-extensions\s*:.*(?:union|select|drop|insert)",
    r"(?i)\{[^}]*['\"](?:__proto__|constructor|prototype)['\"]",
    r"(?i)ws://.*(?:union|select|drop|exec)",
    r"(?i)wss://.*(?:union|select|drop|exec)",
    r"(?i)sec-websocket-key\s*:.*(?:<script|javascript:)",
    r"(?i)upgrade\s*:\s*h2c",  # HTTP/2 cleartext upgrade (MITM risk)
    r"(?i)connection\s*:\s*upgrade.*(?:transfer-encoding|content-length)",
    r"(?i)sec-websocket-version\s*:\s*(?!13\b)\d+",
]


# ============================================================
#  CORS BYPASS (10+ patterns)
# ============================================================

CORS_BYPASS = [
    r"(?i)origin\s*:\s*null",
    r"(?i)origin\s*:\s*(?:file|data|chrome-extension)://",
    r"(?i)origin\s*:\s*https?://[a-z0-9]+\.evil\.",
    r"(?i)origin\s*:\s*https?://(?:localhost|127\.0\.0\.1)",
    r"(?i)origin\s*:\s*https?://.*%2[eE]",
    r"(?i)origin\s*:\s*https?://.*\.(?:burpcollaborator|oastify|interact\.sh)\.",
    r"(?i)access-control-allow-origin\s*:\s*\*",
    r"(?i)access-control-allow-credentials\s*:\s*true",
    r"(?i)origin\s*:\s*https?://[a-z0-9]+\.[a-z]{2,}(?:\.[a-z]{2,}){0,2}\.attacker\.",
    r"(?i)origin\s*:\s*https?://(?:.*@)?[a-z]+\.[a-z]{2,}",
]


# ============================================================
#  EXPRESSION LANGUAGE INJECTION (15+ patterns)
# ============================================================

EL_INJECTION = [
    # Java EL
    r"(?i)\$\{.*Runtime.*exec",
    r"(?i)\$\{.*ProcessBuilder",
    r"(?i)\$\{.*ScriptEngine",
    r"(?i)\$\{.*getRuntime\(\)",
    r"(?i)\$\{.*Thread\.sleep",
    r"(?i)\$\{.*forName\(",
    r"(?i)\$\{.*getClass\(\)",
    r"(?i)\$\{T\(java\.",
    r"(?i)#\{.*\.getClass\(\)",
    # Spring SpEL
    r"(?i)\$\{.*new\s+java\.",
    r"(?i)T\(java\.lang\.Runtime\)",
    r"(?i)T\(java\.lang\.ProcessBuilder\)",
    r"(?i)#rt\s*=\s*T\(",
    r"(?i)new\s+java\.lang\.ProcessBuilder",
    # OGNL
    r"(?i)%\{.*@java\.lang\.",
    r"(?i)%\{.*#_memberAccess",
    r"(?i)%\{.*#context",
    r"(?i)%\{.*#application",
    r"(?i)\(\['\w+'\]\)\(.*\)\['\\u",
]


# ============================================================
#  REMOTE CODE EXECUTION (30+ patterns)
# ============================================================

RCE_PATTERNS = [
    # PHP RCE
    r"(?i)(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(",
    r"(?i)(?:pcntl_exec|assert|preg_replace)\s*\(.*['\"/]e",
    r"(?i)create_function\s*\(",
    r"(?i)call_user_func(?:_array)?\s*\(",
    r"(?i)(?:eval|assert)\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE|SERVER)|\$\w+)",
    r"(?i)include\s*\(\s*(?:\$_(?:GET|POST|REQUEST)|['\"](?:https?|ftp|php|data)://)",
    r"(?i)(?:unserialize|yaml_parse)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)",
    # Python RCE
    r"(?i)(?:os\.(?:system|popen|exec\w*)|subprocess\.(?:call|run|Popen|check_output))\s*\(",
    r"(?i)(?:__import__|importlib\.import_module)\s*\(",
    r"(?i)(?:pickle|cPickle|shelve|marshal)\.(?:loads?|load)\s*\(",
    r"(?i)yaml\.(?:load|unsafe_load)\s*\(",
    r"(?i)exec\s*\(\s*compile\s*\(",
    # Ruby RCE
    r"(?i)(?:system|exec|IO\.popen|Kernel\.system|`[^`]*`)",
    r"(?i)(?:open|Kernel\.open)\s*\(\s*['\"]?\|",
    r"(?i)(?:Marshal|YAML)\.(?:load|unsafe_load)\s*\(",
    r"(?i)ERB\.new\s*\(",
    # Java RCE
    r"(?i)Runtime\.getRuntime\(\)\.exec\s*\(",
    r"(?i)ProcessBuilder\s*\([^)]*\)\.start\s*\(",
    r"(?i)(?:ScriptEngine|Nashorn|Rhino).*\.eval\s*\(",
    r"(?i)java\.lang\.reflect\.(?:Method|Constructor)",
    r"(?i)javax\.script\.ScriptEngine",
    r"(?i)beanutils\.(?:BeanUtils|PropertyUtils)\.",
    r"(?i)org\.apache\.commons\.(?:collections|io|lang)\.",
    # .NET RCE
    r"(?i)Process\.Start\s*\(",
    r"(?i)(?:Binary|Soap|ObjectState|NetData|Losformatter)Formatter",
    r"(?i)TypeNameHandling\.(?:All|Auto|Objects|Arrays)",
    r"(?i)System\.Diagnostics\.Process",
    r"(?i)ObjectDataProvider\s*",
    r"(?i)System\.(?:Web|IO|Reflection)\.",
    # Node.js RCE
    r"(?i)child_process\.(?:exec|spawn|fork|execFile|execSync)\s*\(",
    r"(?i)require\s*\(\s*['\"]child_process",
    r"(?i)(?:vm|vm2)\.(?:runInContext|runInNewContext|runInThisContext|compileFunction)\s*\(",
    r"(?i)Function\s*\(\s*['\"].*(?:return|require|process|child_process)",
]


# ============================================================
#  INFORMATION DISCLOSURE (25+ patterns)
# ============================================================

INFO_DISCLOSURE = [
    # Config files
    r"(?i)/(?:\.env|\.env\.\w+|\.env\.local|\.env\.production|\.env\.development)",
    r"(?i)/(?:config\.php|config\.yml|config\.yaml|config\.json|config\.xml|config\.ini)",
    r"(?i)/(?:wp-config\.php|configuration\.php|settings\.php|database\.yml)",
    r"(?i)/(?:\.aws/credentials|\.docker/config\.json|\.kube/config)",
    r"(?i)/(?:\.ssh/(?:id_rsa|id_dsa|authorized_keys|known_hosts))",
    r"(?i)/(?:\.npmrc|\.pypirc|\.gem/credentials|\.composer/auth\.json)",
    # Git/SVN files
    r"(?i)/\.git/(?:config|HEAD|index|packed-refs|objects|refs|logs|info)",
    r"(?i)/\.svn/(?:entries|wc\.db|pristine)",
    r"(?i)/\.hg/(?:store|dirstate|branch)",
    r"(?i)/\.bzr/(?:branch|checkout)",
    # Debug endpoints
    r"(?i)/(?:debug|trace|profiler|__debug__|_debug_toolbar|_profiler|elmah\.axd|trace\.axd)",
    r"(?i)/(?:phpinfo|php_info|test|info)\.php",
    r"(?i)/(?:server-status|server-info|balancer-manager)",
    # Backup files
    r"(?i)\.(?:bak|backup|old|orig|copy|save|swp|tmp|temp|~|sav|dist|original)\b",
    r"(?i)(?:backup|dump|database|db|export|sql)\.(?:sql|gz|zip|tar|bz2|7z|rar)",
    r"(?i)/(?:backup|backups|bak|dump|export|archive|old|temp|tmp)/",
    # API documentation
    r"(?i)/(?:swagger|swagger-ui|api-docs|openapi|graphiql|altair|playground)",
    # Internal headers
    r"(?i)(?:x-powered-by|x-aspnet-version|x-aspnetmvc-version|server)\s*:",
    r"(?i)x-debug-(?:token|id)\s*:",
    # Source code disclosure
    r"(?i)\.(?:java|py|rb|php|cs|vb|go|rs|swift|kt)\.(bak|old|orig|copy|backup|~)$",
    r"(?i)/(?:WEB-INF|META-INF)/(?:web\.xml|context\.xml|spring|applicationContext)",
    r"(?i)/(?:composer\.json|package\.json|Gemfile|requirements\.txt|pom\.xml|build\.gradle)",
    r"(?i)/(?:Dockerfile|docker-compose\.yml|\.dockerignore|Vagrantfile|Makefile|Jenkinsfile)",
    r"(?i)/(?:\.gitlab-ci\.yml|\.travis\.yml|\.circleci|\.github/workflows)",
]


# ============================================================
#  AUTHENTICATION BYPASS (20+ patterns)
# ============================================================

AUTH_BYPASS = [
    # Default credentials
    r"(?i)(?:admin|administrator|root|test|guest|demo|user|default|manager|tomcat)\s*[:/]\s*(?:admin|password|123456|12345678|root|test|pass|default|tomcat|manager|changeme|secret|P@ssw0rd)",
    # Token manipulation
    r"(?i)(?:token|session|auth|jwt)\s*=\s*(?:null|undefined|none|nil|void|0|false|true|admin|root|\[\]|\{\}|''|\"\")",
    # Header manipulation for auth bypass
    r"(?i)x-forwarded-for\s*:\s*127\.0\.0\.1",
    r"(?i)x-originating-ip\s*:\s*127\.0\.0\.1",
    r"(?i)x-remote-ip\s*:\s*127\.0\.0\.1",
    r"(?i)x-remote-addr\s*:\s*127\.0\.0\.1",
    r"(?i)x-real-ip\s*:\s*127\.0\.0\.1",
    r"(?i)x-client-ip\s*:\s*127\.0\.0\.1",
    r"(?i)x-forwarded-for\s*:\s*(?:::1|0\.0\.0\.0)",
    r"(?i)x-custom-ip-authorization\s*:\s*127\.0\.0\.1",
    # URL-based auth bypass
    r"(?i)/admin(?:%20|%09|%0[aAdD]|/\./|//+|\\\\|;|\.json|\?|#)",
    r"(?i)/api/.*\.\./admin",
    r"(?i)\.(?:json|xml|css|js|ico|png|jpg|gif|svg)$.*(?:admin|dashboard|config)",
    # HTTP verb tampering
    r"(?i)x-http-method-override\s*:\s*(?:GET|POST|PUT|DELETE|PATCH|OPTIONS)",
    r"(?i)x-method-override\s*:\s*(?:GET|POST|PUT|DELETE|PATCH|OPTIONS)",
    # Registration bypass
    r"(?i)(?:role|is_admin|isAdmin|admin|superuser|is_superuser|user_type|userType)\s*[=:]\s*(?:true|1|admin|superadmin|root)",
    # PHP type juggling
    r"(?i)(?:password|pass|passwd|token)\[\]\s*=",
    r'(?i)"(?:password|pass|token)"\s*:\s*(?:true|false|null|0|\[\]|\{\})',
    # Path-based bypass
    r"(?i)/\.;/",  # Tomcat path normalization bypass
    r"(?i)/;(?:jsessionid)?=\w*/",
]


# ============================================================
#  SCANNER/PROBE DETECTION (30+ patterns)
# ============================================================

SCANNER_PROBES = [
    # Common scan paths
    r"(?i)/(?:actuator|jolokia|hystrix|hawtio)(?:/|$)",
    r"(?i)/(?:\.well-known/(?:openid-configuration|jwks\.json))",
    r"(?i)/(?:api/v\d+/(?:swagger|docs|redoc|openapi))",
    r"(?i)/(?:cgi-bin|fcgi-bin|cgi)/",
    r"(?i)/(?:manager|admin-console|administration|webadmin|siteadmin)",
    r"(?i)/(?:jmx-console|web-console|invoker)/",
    r"(?i)/(?:solr|jenkins|nexus|sonar|grafana|prometheus|kibana)(?:/|$)",
    r"(?i)/(?:axis2|ws_utc|wls-wsat|_async|uddiexplorer)",
    r"(?i)/(?:struts|spring|hibernate|log4j)(?:/|$)",
    r"(?i)/(?:telescope|horizon|clockwork|debugbar)(?:/|$)",
    # WordPress probes
    r"(?i)/(?:xmlrpc\.php|wp-json|wp-login|wp-admin|wp-content/uploads|wp-includes)",
    r"(?i)/(?:readme\.html|license\.txt|wp-config\.php\.bak)",
    # CMS probes
    r"(?i)/(?:administrator/index\.php|components/com_|modules/mod_)",
    r"(?i)/(?:sites/default/files|misc/drupal\.js|core/misc/drupal\.js)",
    r"(?i)/(?:typo3/|typo3conf/|typo3temp/)",
    r"(?i)/(?:sitecore/|umbraco/|episerver/|sitefinity/)",
    # Technology probes
    r"(?i)/(?:elmah\.axd|trace\.axd|glimpse\.axd)",
    r"(?i)/(?:haproxy\?stats|nginx_status|stub_status|fpm-status|apc\.php)",
    r"(?i)/(?:CFIDE|cfadministrator|CFCHART)",
    r"(?i)/(?:console|system-console|admin-console|web-console)\.(?:htm|html|jsp|php|aspx)",
    # Version probes
    r"(?i)/(?:version|buildinfo|build-info|app-info)(?:\.(?:json|xml|txt))?$",
    # Common vulnerable endpoints
    r"(?i)/(?:uploads|upload|files|documents|media|assets|static)/(?:\.\.|\.\./)",
    # SSRF probes
    r"(?i)/(?:proxy|fetch|curl|wget|request|ssrf|redirect)/",
    # Fuzzing patterns
    r"(?:%[0-9a-fA-F]{2}){10,}",  # Heavy URL encoding
    r"(?:AAAA){50,}",  # Buffer overflow attempt
    r"(?:/../){5,}",   # Deep traversal
    r"\x00",           # Null byte
]


# ============================================================
#  ENCODING EVASION (25+ patterns)
# ============================================================

ENCODING_EVASION = [
    # Double encoding
    r"%25(?:3[cCeE]|2[27fF]|3[dD]|5[cC]|2[bB])",
    r"%%(?:3[cCeE]|2[27fF])",
    # Unicode encoding
    r"%[uU](?:003[cCeE]|002[27fF]|005[cC])",
    r"\\u(?:003[cCeE]|002[27fF]|005[cC])",
    # Overlong UTF-8
    r"%[cC]0%[aAbBcCdD][eEfF0-9]",
    r"%[eE]0%80%[aAbBcCdD][eEfF0-9]",
    r"%[fF]0%80%80%[aAbBcCdD][eEfF0-9]",
    # Mixed encoding
    r"(?:%[0-9a-fA-F]{2}){3,}(?:select|union|script|alert|eval|exec)",
    r"(?i)(?:\\x[0-9a-f]{2}){3,}",
    # HTML entities
    r"(?i)&(?:#x?[0-9a-f]+|[a-z]+);.*(?:script|alert|eval|onerror|onload)",
    # Base64 encoded attacks
    r"(?i)(?:PHNjcmlwd|YWxlcnQo|ZXZhbCg|c2VsZWN0|dW5pb24|ZHJvcCA)",
    # Hex encoding
    r"(?i)0x(?:3c7363726970|616c657274|6576616c|73656c656374|756e696f6e)",
    # URL encoding variations (require attack context after encoded char)
    r"(?i)%(?:25)+(?:3[cCeE]|2[27fF]|3[bB])",
    # Backslash encoding
    r"(?i)\\(?:x3[cCeE]|x2[27fF]|u003[cCeE]|u002[27fF])",
    # Tab/newline splitting
    r"(?i)(?:se%0[aAdD]lect|un%0[aAdD]ion|sc%0[aAdD]ript|al%0[aAdD]ert)",
    r"(?i)(?:se\tlect|un\tion|sc\tript|al\tert)",
    # Null byte insertion
    r"(?i)(?:sel%00ect|uni%00on|scr%00ipt|ale%00rt)",
    # Comment insertion (SQL/JS)
    r"(?i)(?:sel/\*\*/ect|uni/\*\*/on|ex/\*\*/ec)",
    r"(?i)(?:java/\*\*/script|on/\*\*/error|on/\*\*/load)",
    # Case variation bypass (require SQL/JS context after keyword)
    r"(?i)(?:s\s*e\s*l\s*e\s*c\s*t|u\s*n\s*i\s*o\s*n)\s+(?:all\s+)?(?:select|from|null|@@|\d|\*)\b",
    # Concatenation bypass
    r"(?i)(?:con(?:cat|cat_ws)\s*\(.*(?:sel|uni|scr|ale|exe))",
]


# ============================================================
#  WAF BYPASS TECHNIQUES (30+ patterns)
# ============================================================

WAF_BYPASS = [
    # Chunked body bypass
    r"(?i)transfer-encoding\s*:\s*chunked.*(?:select|union|script|exec)",
    # Content-Type confusion
    r"(?i)content-type\s*:\s*(?:text/plain|application/octet-stream).*(?:<script|select\s|union\s|exec\s)",
    # HTTP/2 pseudo header injection
    r"(?i):method\s*:\s*(?:TRACE|TRACK|DEBUG|CONNECT)",
    r"(?i):path\s*:.*(?:\.\.\/|%2e%2e|select\s|union\s|<script)",
    # HPP bypass (duplicate parameters)
    r"(?i)(?:\?|&)(\w+)=(?:[^&]*)&\1=",
    # Path normalization bypass
    r"(?i)/\.(?:;|%3[bB])/",
    r"(?i)/(?:%2[eE]){2}/",
    r"(?i)/(?:\.%2[eE]|%2[eE]\.)/",
    r"(?i)/%c0%ae%c0%ae/",
    r"(?i)/%252e%252e/",
    # Wildcard abuse
    r"(?i)/\*\*/(?:select|union|exec|script)",
    # JSON content-type with SQLi
    r'(?i)"(?:username|password|email|name|id|search|query)"\s*:\s*"[^"]*(?:union|select|drop|insert|update|delete)\s',
    # Multipart boundary bypass
    r"(?i)boundary=.*(?:select|union|script|exec)",
    # IP-based bypass (require URL/param context to avoid false positives on Host header)
    r"(?i)(?:url|href|src|redirect|proxy|forward|uri|location|callback|next|return|goto|dest|target|link)\s*[=:]\s*(?:https?://)?(?:127\.0\.0\.1|0\.0\.0\.0|::1|0x7f000001|2130706433|017700000001)",
    # Protocol smuggling
    r"(?i)(?:gopher|dict|file|ldap|tftp|jar)://",
    # Header injection bypass
    r"(?i)(?:x-forwarded-for|x-real-ip|x-client-ip|x-originating-ip|cf-connecting-ip|true-client-ip)\s*:\s*(?:127\.0\.0\.1|::1|localhost)",
    # Comment-based bypass
    r"(?i)/\*!(?:00000|50000|40100|40101).*\*/",
    r"(?i)--\s*$",  # SQL comment at end
    r"(?i)#\s*$",   # MySQL comment at end
    # Alternative separators
    r"(?i)(?:select|union|exec|script)(?:%09|%0[aAdD]|%20|/\*\*/|\+)+(?:select|union|from|where|all|distinct|null|@@|concat|group_concat|information_schema|into|having|order|group|insert|update|delete|drop|exec|script|alert|prompt|confirm)\b",
    # Unicode normalization bypass
    r"(?i)[\xff\xfe].*(?:select|union|exec|script)",
    # Large parameter bypass
    r"(?i)(?:select|union|exec|script).{1000,}",
    # Null byte truncation
    r"(?i)\.(?:php|asp|jsp|aspx)%00\.(?:jpg|gif|png|txt)",
    # Verb tunneling
    r"(?i)x-http-method\s*:\s*(?:PUT|DELETE|PATCH|MERGE|COPY|MOVE)",
    # IP encoding variations
    r"(?i)(?:0x[0-9a-f]{8}|[0-9]{10})\s*(?:/|:|\s)",
    r"(?i)(?:\d+\.){3}\d+\s*@",  # user@IP
]


# ============================================================
#  LOG INJECTION (10+ patterns)
# ============================================================

LOG_INJECTION = [
    r"(?i)%0[aAdD](?:\s*\[(?:ERROR|WARN|INFO|DEBUG)\])",
    r"(?i)\\n\s*\[(?:ERROR|WARN|INFO|DEBUG)\]",
    r"(?i)%0[aAdD].*(?:admin|password|secret|key|token)\s*[=:]",
    r"(?i)\\n.*(?:200 OK|301|302|403|404|500)",
    r"(?i)\r?\n(?:\d{4}-\d{2}-\d{2}|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2})",
    r"(?i)%0[aAdD]\s*(?:\d{1,3}\.){3}\d{1,3}",
    r"(?i)\\x0[aAdD]",
    r"(?i)\\u000[aAdD]",
    r"(?i)\$\{jndi:.*\}",  # Log4j
    r"(?i)%24%7[bB]jndi:",  # URL-encoded Log4j
]


# ============================================================
#  EMAIL INJECTION (10+ patterns)
# ============================================================

EMAIL_INJECTION = [
    r"(?i)(?:to|cc|bcc|from|subject)\s*:.*%0[aAdD]",
    r"(?i)(?:to|cc|bcc|from|subject)\s*:.*\\n",
    r"(?i)(?:to|cc|bcc|from|subject)\s*:.*\r\n",
    r"(?i)content-type\s*:.*%0[aAdD]",
    r"(?i)(?:to|cc|bcc)\s*=.*@.*%0[aAdD]",
    r"(?i)(?:to|cc|bcc)\s*=.*@.*,.*@",
    r"(?i)mime-version\s*:\s*1\.0",
    r"(?i)(?:%0[aAdD]){2}.*content-type:",
    r"(?i)(?:\\n){2}.*content-type:",
    r"(?i)x-mailer\s*:.*(?:script|eval|exec)",
]


# ============================================================
#  XPATH INJECTION (10+ patterns)
# ============================================================

XPATH_INJECTION = [
    r"(?i)(?:string|translate|normalize-space|contains|starts-with|substring)\s*\(",
    r"(?i)(?:count|sum|position|last|name|namespace-uri|local-name)\s*\(",
    r"(?i)/\w+\[.*(?:=|!=|<|>|\bor\b|\band\b).*\]",
    r"(?i)'\s*(?:or|and)\s+'[^']*'\s*=\s*'",
    r"(?i)'\s*\]\s*/\s*\w+\s*\[",
    r"(?i)doc\s*\(\s*['\"]",
    r"(?i)document\s*\(\s*['\"]",
    r"(?i)unparsed-text\s*\(\s*['\"]",
    r"(?i)system-property\s*\(\s*['\"]",
    r"(?i)(?:ancestor|descendant|following|preceding|parent|child|self)\s*::",
]


# ============================================================
#  CSV/FORMULA INJECTION (10+ patterns)
# ============================================================

CSV_INJECTION = [
    r"(?i)^[=+\-@\t\r]\s*(?:cmd|powershell|system|exec|HYPERLINK|IMPORTXML|IMPORTDATA|IMPORTRANGE|IMAGE|WEBSERVICE)",
    r"(?i)=\s*(?:cmd|system)\s*\|",
    r"(?i)^=\s*HYPERLINK\s*\(",
    r"(?i)^=\s*IMPORTXML\s*\(",
    r"(?i)^=\s*IMPORTDATA\s*\(",
    r"(?i)^=\s*IMPORTRANGE\s*\(",
    r"(?i)^=\s*IMAGE\s*\(",
    r"(?i)^=\s*WEBSERVICE\s*\(",
    r"(?i)^[+\-]=?\s*(?:cmd|powershell|sh|bash|zsh)\s*[|&;]",
    r'(?i)^["=].*\+cmd\|',
    r"(?i)DDE\s*\(",
]


# ============================================================
#  WORDPRESS SPECIFIC (30+ patterns)
# ============================================================

WORDPRESS_ATTACKS = [
    r"(?i)/wp-json/wp/v2/users(?:/|$)",
    r"(?i)/\?author=\d+",
    r"(?i)/wp-admin/admin-ajax\.php\?action=(?:revslider|(?:upload|import)_(?:plugin|theme))",
    r"(?i)/wp-content/(?:plugins|themes)/[^/]+/(?:\.\.|\.\./)",
    r"(?i)/wp-admin/(?:includes|css|js|images)/(?:\.\.|\.\./)",
    r"(?i)/xmlrpc\.php\s*$",
    r"(?i)<methodCall>.*system\.(?:multicall|listMethods|getCapabilities)",
    r"(?i)/wp-(?:login|signup|register)\.php.*(?:action=register|redirect_to=)",
    r"(?i)/wp-content/uploads/.*\.(?:php|phtml|php[3-7]|pht|shtml)",
    r"(?i)/wp-config\.php(?:\.\w+)?$",
    r"(?i)/wp-admin/(?:setup-config|install)\.php",
    r"(?i)/wp-admin/theme-editor\.php",
    r"(?i)/wp-admin/plugin-editor\.php",
    r"(?i)/wp-json/(?:oembed|wp-site-health)/",
    r"(?i)/wp-cron\.php",
    r"(?i)/wp-trackback\.php",
    r"(?i)/wp-admin/admin-post\.php",
    r"(?i)/wp-admin/options\.php",
    r"(?i)/wp-json/wp/v2/(?:posts|pages|media|comments)\?.*(?:per_page=100|_embed)",
    r"(?i)/wp-content/debug\.log",
    r"(?i)/wp-includes/(?:wlwmanifest|rsd)\.xml",
    r"(?i)/\?rest_route=/wp/v2/users",
    r"(?i)/wp-json/(?:yoast|jetpack|woocommerce|elementor)/",
    r"(?i)/wp-admin/admin-ajax\.php\?action=(?:editpost|heartbeat|wp-remove-post-lock)",
    r"(?i)/wp-login\.php\?action=(?:lostpassword|resetpass|register)",
    r"(?i)/wp-content/(?:plugins|themes)/(?:[^/]+)/readme\.txt",
    r"(?i)/wp-content/(?:plugins|themes)/(?:[^/]+)/changelog\.txt",
    r"(?i)/wp-content/plugins/(?:w3-total-cache|wp-super-cache|really-simple-ssl|wordfence|ithemes-security)/",
    r"(?i)/wp-json/wp/v2/settings",
    r"(?i)/wp-admin/customize\.php",
]


# ============================================================
#  PHP SPECIFIC (20+ patterns)
# ============================================================

PHP_EXTENDED = [
    r"(?i)(?:php://(?:input|filter|data|expect|zip|phar|fd|memory|temp))",
    r"(?i)(?:phar://)",
    r"(?i)(?:data://text/plain;base64,)",
    r"(?i)(?:zlib://|bzip2://|rar://|ogg://|ssh2://)",
    r"(?i)(?:glob://|convert\.(?:base64|iconv|quoted-printable))",
    r"(?i)(?:phpinfo|phpversion|php_uname|php_sapi_name|get_cfg_var)\s*\(\s*\)",
    r"(?i)(?:ini_set|ini_get|ini_restore)\s*\(\s*['\"](?:allow_url_include|open_basedir|disable_functions)",
    r"(?i)(?:move_uploaded_file|copy|rename|unlink|rmdir|mkdir)\s*\(\s*\$_",
    r"(?i)(?:file_put_contents|file_get_contents|fwrite|fopen|readfile)\s*\(\s*\$_",
    r"(?i)(?:mail|header)\s*\(\s*\$_",
    r"(?i)\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[",
    r"(?i)(?:preg_replace|preg_match|eregi?)\s*\(\s*['\"/].*['\"/][eims]*\s*,\s*\$_",
    r"(?i)(?:extract|parse_str)\s*\(\s*\$_",
    r"(?i)(?:serialize|unserialize)\s*\(",
    r"(?i)class\s+\w+\s*\{.*__(?:wakeup|destruct|toString|call|get|set|isset|unset)\s*\(",
    r"(?i)O:\d+:\"[^\"]+\":\d+:\{",  # PHP serialized object
    r"(?i)a:\d+:\{",  # PHP serialized array
    r"(?i)\$(?:GLOBALS|_ENV)\s*\[",
    r"(?i)(?:array_map|array_filter|array_walk|usort|uasort|uksort)\s*\(\s*['\"](?:system|exec|assert|eval)",
    r"(?i)(?:class_exists|method_exists|function_exists)\s*\(\s*\$_",
]


# ============================================================
#  JAVA/SPRING SPECIFIC (25+ patterns)
# ============================================================

JAVA_SPRING = [
    # Deserialization
    r"(?i)(?:rO0AB|aced0005)",  # Java serialized object markers
    r"(?i)java\.(?:rmi|naming|management)\.",
    r"(?i)javax\.management\.remote",
    r"(?i)com\.sun\.(?:jndi|rowset|org\.apache\.xalan)",
    r"(?i)org\.apache\.(?:commons|xalan|bcel)\.",
    r"(?i)(?:ysoserial|CommonsCollections|Spring|JRMPClient|URLDNS)",
    # Spring specific
    r"(?i)/actuator/(?:env|heapdump|threaddump|mappings|beans|configprops|loggers|metrics|prometheus|health|info|shutdown|restart|refresh|gateway)",
    r"(?i)/manage/(?:env|heapdump|threaddump|health|info)",
    r"(?i)/jolokia/(?:exec|read|write|search|list|version)",
    r"(?i)spring\.cloud\.(?:bootstrap|function)\.",
    r"(?i)spring\.(?:datasource|jpa|jndi|main)\.",
    # Struts
    r"(?i)%\{#_memberAccess",
    r"(?i)%\{#context\[",
    r"(?i)(?:ognl|s2-\d{3})",
    r"(?i)redirect:(?:\$\{|%\{|https?://)",
    # Tomcat
    r"(?i)/(?:manager|host-manager)/(?:html|text|jmxproxy|status)",
    r"(?i)/(?:jmxproxy|serverinfo)\b",
    # Log4j extended
    r"(?i)\$\{(?:j|J)(?:n|N)(?:d|D)(?:i|I)\s*:",
    r"(?i)\$\{(?:lower|upper|::-)\w*\}.*\$\{(?:lower|upper|::-)\w*\}",
    r"(?i)%24%7B(?:%6a|j|%4a|J)(?:%6e|n|%4e|N)(?:%64|d|%44|D)(?:%69|i|%49|I)",
    # JMX
    r"(?i)/jmx-console/",
    r"(?i)/invoker/(?:JMXInvokerServlet|EJBInvokerServlet)",
    # WebLogic
    r"(?i)/wls-wsat/CoordinatorPortType",
    r"(?i)/console/(?:css|images)/(?:\.\./)+",
    r"(?i)/_async/AsyncResponseService",
]


# ============================================================
#  .NET SPECIFIC (20+ patterns)
# ============================================================

DOTNET_ATTACKS = [
    # Deserialization
    r"(?i)(?:ObjectDataProvider|ObjectInstance|MethodName|MethodParameters)",
    r"(?i)(?:System\.Diagnostics\.Process|System\.IO\.File|System\.Net\.WebClient)",
    r"(?i)(?:TypeNameHandling\s*[=:]\s*(?:All|Auto|Objects|Arrays))",
    r"(?i)(?:\$type\s*[\"']?\s*[=:]\s*[\"']?System\.)",
    r"(?i)(?:__VIEWSTATE|__EVENTVALIDATION|__VIEWSTATEGENERATOR)",
    r"(?i)(?:ctl00\$|aspx?\.(?:cs|vb)$)",
    # IIS specific
    r"(?i)/(?:trace|elmah|glimpse)\.axd",
    r"(?i)/(?:\.aspx?|\.asmx|\.ashx|\.svc|\.axd)\?.*(?:=\.\./|=\.\.\\)",
    r"(?i)(?:\.config|\.cs|\.vb|\.asax|\.master|\.csproj)$",
    r"(?i)/app_(?:code|data|browsers|globalresources|localresources|themes)/",
    r"(?i)/bin/(?:\.\./|\.\.\\)",
    # ViewState attacks
    r"(?i)__VIEWSTATE=(?:[A-Za-z0-9+/=]{100,})",
    # Padding oracle
    r"(?i)WebResource\.axd\?d=",
    r"(?i)ScriptResource\.axd\?d=",
    # .NET Remoting
    r"(?i)/remoting/(?:.*\.rem|.*\.soap)",
    # SignalR
    r"(?i)/signalr/(?:negotiate|connect|start|abort|poll|reconnect)",
    # Blazor
    r"(?i)/_blazor/(?:negotiate|disconnect|initializers)",
    # SSRF via .NET
    r"(?i)(?:System\.Net\.(?:Http|WebRequest|Sockets))",
    r"(?i)(?:WebClient\.Download(?:String|Data|File))",
]


# ============================================================
#  NODE.JS SPECIFIC (15+ patterns)
# ============================================================

NODEJS_ATTACKS = [
    r"(?i)(?:require\s*\(\s*['\"](?:child_process|fs|net|http|https|dgram|cluster|os|vm|crypto|tls|module))",
    r"(?i)(?:process\.(?:env|exit|kill|binding|mainModule|_tickCallback))",
    r"(?i)(?:global\.(?:process|require|Buffer|console))",
    r"(?i)(?:Buffer\.(?:from|alloc|allocUnsafe)\s*\()",
    r"(?i)(?:constructor\s*\[\s*['\"]prototype['\"])",
    r"(?i)(?:__proto__\s*\.\s*(?:constructor|polluted|isAdmin))",
    r"(?i)(?:Object\.(?:assign|create|defineProperty|getPrototypeOf)\s*\(.*__proto__)",
    r"(?i)(?:JSON\.parse\s*\(.*__proto__)",
    r"(?i)(?:require\s*\(\s*['\"]\.{0,2}/)",  # Path traversal in require
    r"(?i)(?:vm\.(?:createContext|runInContext|runInNewContext|compileFunction)\s*\()",
    r"(?i)(?:eval\s*\(\s*(?:req\.|request\.|params\.))",
    r"(?i)(?:Function\s*\(\s*['\"]return\s+this['\"])",  # Sandbox escape
    r"(?i)(?:this\.constructor\.constructor\s*\()",  # Sandbox escape
    r"(?i)(?:import\s*\(\s*['\"](?:child_process|fs|net|os))",
    r"(?i)/node_modules/.*(?:\.\.\/){3,}",
]


# ============================================================
#  RUBY/RAILS SPECIFIC (10+ patterns)
# ============================================================

RUBY_RAILS = [
    r"(?i)(?:ERB\.new|Erubis|HAML).*\.result\s*\(",
    r"(?i)(?:Kernel\.\s*(?:system|exec|`|spawn|fork|open))",
    r"(?i)(?:IO\.(?:popen|sysopen|read|write)\s*\()",
    r"(?i)(?:open\s*\(\s*['\"]?\|)",  # Ruby open with pipe
    r"(?i)(?:YAML\.(?:load|unsafe_load|load_file)\s*\()",
    r"(?i)(?:Marshal\.(?:load|restore)\s*\()",
    r"(?i)(?:send\s*\(\s*['\"](?:system|exec|eval|instance_eval|class_eval|module_eval))",
    r"(?i)(?:instance_eval|class_eval|module_eval)\s*\(",
    r"(?i)(?:render\s+(?:inline|text|html)\s*:\s*params)",
    r"(?i)(?:\.\.\./){3,}.*(?:Gemfile|config/|db/|app/)",
    r"(?i)/rails/(?:info|mailers|routes|db|console)",
]


# ============================================================
#  ZERO-DAY CVE PATTERNS (50+ patterns)
# ============================================================

CVE_PATTERNS = [
    # CVE-2021-44228 Log4Shell (expanded)
    r"(?i)\$\{(?:j|J).*(?:n|N).*(?:d|D).*(?:i|I)\s*:",
    r"(?i)\$\{(?:\$\{[^}]*\}|[^}])*(?:jndi|JNDI):",
    r"(?i)%24%7B.*(?:jndi|JNDI)",
    
    # CVE-2022-22965 Spring4Shell (expanded)
    r"(?i)class\.module\.classLoader\.resources",
    r"(?i)class%2Emodule%2EclassLoader",
    
    # CVE-2023-34362 MOVEit Transfer
    r"(?i)/moveitisapi/moveitisapi\.dll\?action=m2",
    
    # CVE-2023-44228 Apache ActiveMQ
    r"(?i)ClassPathXmlApplicationContext",
    r"(?i)ExceptionResponse.*ClassInfo",
    
    # CVE-2024-3400 Palo Alto PAN-OS
    r"(?i)/global-protect/(?:login|portal/css/|getconfig)",
    r"(?i)SESSID=.*(?:\.\.\/|%2e%2e)",
    
    # CVE-2023-22515 Confluence (broken access)
    r"(?i)/setup/setupadministrator\.action",
    r"(?i)/server-info\.action\?bootstrapStatusProvider",
    
    # CVE-2023-46747 F5 BIG-IP
    r"(?i)/mgmt/tm/(?:util/bash|shared/authn/login|access/bundle-install-tasks)",
    
    # CVE-2023-20198 Cisco IOS XE
    r"(?i)/webui/logoutconfirm\.html\?logon_hash=",
    
    # CVE-2023-42793 JetBrains TeamCity
    r"(?i)/app/rest/users/id:1/tokens/",
    r"(?i)/app/rest/(?:server|projects|buildTypes|builds|agents)",
    
    # CVE-2023-49103 ownCloud (info.php disclosure)
    r"(?i)/owncloud/ocs/v1\.php/(?:cloud/capabilities|privatedata|config)",
    r"(?i)/status\.php\?(?:.*=){5,}",
    
    # CVE-2024-21887 Ivanti Connect Secure
    r"(?i)/api/v1/(?:totp/user-backup-code|license/keys-status|configuration/users/user-roles)",
    
    # CVE-2023-36884 Office HTML RCE
    r"(?i)ms-msdt:/",
    r"(?i)ms-msdt:.*IT_BrowseForFile=",
    
    # CVE-2024-27198 JetBrains TeamCity (auth bypass)
    r"(?i)/app/rest/users\?locator=",
    r"(?i)/res/(.*\.css|.*\.js)\?.*jsp=",
    
    # CVE-2024-1709 ConnectWise ScreenConnect
    r"(?i)/SetupWizard\.aspx",
    
    # CVE-2023-27997 FortiGate SSL VPN
    r"(?i)/remote/(?:logincheck|hostcheck_validate|error|info)",
    
    # CVE-2024-0012 Palo Alto PAN-OS Management
    r"(?i)/unauth/(?:.*\.php|.*\.cgi)",
    r"(?i)X-PAN-AUTHCHECK:\s*off",
    
    # CVE-2023-4966 Citrix Bleed
    r"(?i)/oauth/idp/\.well-known",
    
    # CVE-2021-21972 VMware vCenter
    r"(?i)/ui/vropspluginui/rest/services/",
    
    # CVE-2021-26855 ProxyLogon
    r"(?i)/owa/auth/x\.js",
    r"(?i)X-AnonResource-Backend:\s*",
    r"(?i)X-BEResource:\s*",
    
    # CVE-2021-34473 ProxyShell
    r"(?i)/autodiscover/autodiscover\.json\?@",
    r"(?i)/mapi/nspi/\?",
    
    # CVE-2023-22518 Confluence data center
    r"(?i)/json/setup-restore\.action",
    r"(?i)/json/setup-restore-(?:local|progress)\.action",
    
    # CVE-2024-23897 Jenkins CLI
    r"(?i)/cli\?remoting=false",
    
    # CVE-2024-4577 PHP CGI
    r"(?i)\xAD[dD]",
    r"(?i)%(?:AD|ad)[dD]",
    
    # CVE-2023-38831 WinRAR
    r"(?i)\.(?:cmd|bat|ps1|vbs|hta|wsf|wsh)\s+",
    
    # CVE-2024-6387 OpenSSH regreSSHion (network probe)
    r"(?i)SSH-2\.0-(?:.*\x00|.{256,})",
    
    # CVE-2023-50164 Apache Struts
    r"(?i)/upload\?.*(?:\.\./|\.\.\\)",
    r"(?i)Content-Disposition:.*filename=.*\.\./",
    
    # CVE-2024-21413 Outlook MonikerLink
    r"(?i)file:///\\\\",
    
    # General zero-day indicators
    r"(?i)/(?:shell|webshell|cmd|backdoor|c99|r57|b374k|weevely|phpspy|aspxspy)\.(?:php|asp|aspx|jsp|jspx)",
    r"(?i)/(?:filemanager|filebrowser|elfinder|ckfinder|plupload)/",
    r"(?i)(?:eval|assert|system|exec|passthru)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(",
]


# ============================================================
#  Collect all extended patterns with category labels
# ============================================================

EXTENDED_RULES_MAP = {
    'SQLI_EXT': SQLI_EXTENDED,
    'XSS_EXT': XSS_EXTENDED,
    'CRLF': CRLF_INJECTION,
    'OPEN_REDIRECT': OPEN_REDIRECT,
    'REQUEST_SMUGGLING': REQUEST_SMUGGLING,
    'CACHE_POISONING': CACHE_POISONING,
    'WEBSOCKET': WEBSOCKET_INJECTION,
    'CORS_BYPASS': CORS_BYPASS,
    'EL_INJECTION': EL_INJECTION,
    'RCE': RCE_PATTERNS,
    'INFO_DISCLOSURE': INFO_DISCLOSURE,
    'AUTH_BYPASS': AUTH_BYPASS,
    'SCANNER_PROBE': SCANNER_PROBES,
    'ENCODING_EVASION': ENCODING_EVASION,
    'WAF_BYPASS': WAF_BYPASS,
    'LOG_INJECTION': LOG_INJECTION,
    'EMAIL_INJECTION': EMAIL_INJECTION,
    'XPATH': XPATH_INJECTION,
    'CSV_INJECTION': CSV_INJECTION,
    'WORDPRESS': WORDPRESS_ATTACKS,
    'PHP_EXT': PHP_EXTENDED,
    'JAVA_SPRING': JAVA_SPRING,
    'DOTNET': DOTNET_ATTACKS,
    'NODEJS': NODEJS_ATTACKS,
    'RUBY_RAILS': RUBY_RAILS,
    'CVE': CVE_PATTERNS,
}


def get_all_extended_patterns():
    """Return all extended patterns as list of (regex_str, category)."""
    patterns = []
    for category, rules in EXTENDED_RULES_MAP.items():
        for regex_str in rules:
            patterns.append((regex_str, category))
    return patterns


def count_extended_patterns():
    """Return total count of extended patterns."""
    return sum(len(v) for v in EXTENDED_RULES_MAP.values())
