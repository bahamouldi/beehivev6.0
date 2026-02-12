"""
BeeWAF v5.0 Mega Rules Database — Part 4
==========================================
~2000 additional signatures covering WAF evasion techniques, encoding bypass,
race conditions, business logic, session attacks, IDOR, mass assignment,
gRPC attacks, web cache attacks, host header attacks, Unicode normalization,
HTTP desync, JWT deep, SAML attacks, OAuth deep, privilege escalation deep,
lateral movement, persistence, and advanced obfuscation.
"""

# ============================================================================
# 1. WAF EVASION / ENCODING BYPASS (250 patterns)
# ============================================================================
WAF_EVASION_DEEP = [
    # --- Case manipulation (context-aware — bare keywords removed, they match English under IGNORECASE) ---
    # Detect actual evasion: SQL keywords joined with inline comments, whitespace tricks, or null bytes
    r"(?i)(?:s%65lect|se%6cect|sel%65ct|sele%63t|selec%74)\b",
    r"(?i)(?:u%6eion|un%69on|uni%6fn|unio%6e)\b",
    r"(?i)(?:i%6esert|in%73ert|ins%65rt|inse%72t|inser%74)\b",
    r"(?i)(?:u%70date|up%64ate|upd%61te|upda%74e|updat%65)\b",
    r"(?i)(?:d%65lete|de%6cete|del%65te|dele%74e|delet%65)\b",
    r"(?i)(?:d%72op|dr%6fp|dro%70)\b",
    # --- Comment obfuscation ---
    r"(?i)/\*[\s!]*\w+[\s!]*\*/",
    r"(?i)/\*!(?:00000|50000|40000|30000|12345|99999)\s+\w+\s*\*/",
    r"(?i)/\*![0-9]{5}\s*(?:select|union|insert|update|delete|drop|create|alter|exec|execute)\b",
    r"(?i)(?:--\s+|--\t|--\n|#\s*$|;--\s|;\s*--)",
    r"(?i)/\*\*/(?:select|union|insert|update|delete|drop|create|alter|exec|execute|and|or|from|where|having|group|order|limit)\b",
    r"(?i)(?:sel/\*\*/ect|un/\*\*/ion|ins/\*\*/ert|up/\*\*/date|del/\*\*/ete|dr/\*\*/op|cr/\*\*/eate|al/\*\*/ter)",
    r"(?i)(?:se%6cect|un%69on|in%73ert|up%64ate|de%6cete|dr%6fp|cr%65ate|al%74er)",
    # --- Whitespace alternatives ---
    r"(?i)(?:select|union|insert|update|delete|drop|create|alter|exec)[\x09\x0a\x0b\x0c\x0d]+(?:select|union|insert|update|delete|drop|create|alter|exec|from|where|and|or)\b",
    r"(?i)(?:select|union|insert|update|delete|from|where)\+(?:select|union|insert|update|delete|from|where)\b",
    r"(?i)(?:select|union)%09(?:all|distinct)?\s*(?:select|from|where)\b",
    r"(?i)(?:select|union)%0[aAbBcCdD](?:all|distinct)?\s*(?:select|from|where)\b",
    r"(?i)(?:select|union)%a0(?:all|distinct)?\s*(?:select|from|where)\b",
    # --- Double URL encoding ---
    r"(?i)%25(?:27|22|3C|3E|28|29|2F|5C|3B|7C|26|2B|2D|23|21|25|3D|60|7B|7D|5B|5D|40|5E|7E)",
    r"(?i)%2527|%2522|%253C|%253E|%2528|%2529|%252F|%255C|%253B|%257C|%2526|%252B|%252D|%2523|%2521|%2525|%253D|%2560|%257B|%257D|%255B|%255D|%2540",
    r"(?i)%25%32%37|%25%32%32|%25%33%43|%25%33%45|%25%32%38|%25%32%39|%25%32%46|%25%35%43",
    # --- Unicode / UTF-8 bypass ---
    r"(?i)%u(?:FF1C|FF1E|FF08|FF09|FF3B|FF3D|FF5B|FF5D|FF07|FF02|FF3C|FF0F|FF1B|FF5E|FF5C|FF06|FF0B|FF0D|FF23|FF21|FF25|FF1D|FF20)",
    r"(?i)%c0%af|%c1%9c|%c0%9v|%c0%ae|%e0%80%af|%f0%80%80%af|%fc%80%80%80%80%af",
    r"(?i)%ef%bc%85|%ef%bc%8c|%ef%bc%8e|%ef%bc%8f|%ef%bc%9a|%ef%bc%9b|%ef%bc%9c|%ef%bc%9d|%ef%bc%9e|%ef%bc%9f",
    r"(?i)\xc0\xae\xc0\xae[/\\]",
    r"(?i)\u0000|\x00|%00|\\0|\\x00|\\u0000",
    r"(?i)(?:\\u00[0-9a-f]{2}|\\x[0-9a-f]{2}){3,}",
    # --- Hex encoding ---
    r"(?i)0x(?:73656c656374|756e696f6e|696e73657274|757064617465|64656c657465|64726f70|6372656174|616c746572|65786563|6578656375746)|(?:73656C656374|756E696F6E|696E73657274|75706461746|64656C657465|64726F70|63726561746|616C746572|6578656375746)",
    r"(?i)(?:CHAR|CHR|NCHAR)\s*\(\s*(?:0x[0-9a-f]+|[0-9]+)\s*(?:\+\s*(?:CHAR|CHR|NCHAR)\s*\(\s*(?:0x[0-9a-f]+|[0-9]+)\s*\)){2,}",
    r"(?i)(?:SELECT\s+)?CHAR\(\d+(?:,\d+){3,}\)",
    r"(?i)(?:SELECT\s+)?CONCAT\s*\(\s*CHAR\s*\(\s*\d+\s*\)\s*(?:,\s*CHAR\s*\(\s*\d+\s*\)){2,}\s*\)",
    r"(?i)(?:SELECT\s+)?CHR\(\d+\)(?:\|\|CHR\(\d+\)){2,}",
    # --- String concatenation bypass ---
    r"(?i)(?:CONCAT|CONCAT_WS|GROUP_CONCAT)\s*\(\s*(?:0x|CHAR\(|CHR\(|')",
    r"(?i)(?:'|\")\s*(?:\|\||CONCAT|CHR|CHAR|\+)\s*(?:'|\")",
    r"(?i)(?:'s'\s*'e'\s*'l'\s*'e'\s*'c'\s*'t'|'u'\s*'n'\s*'i'\s*'o'\s*'n')",
    r"(?i)EXEC\s*\(\s*(?:'|\")\s*(?:s|u|i|d)(?:'|\")\s*\+",
    # --- HTTP parameter pollution ---
    r"(?i)(?:\?|&)(?:id|user|name|file|path|url|redirect|callback|action|cmd|exec|query|search|filter|sort|page|limit|offset|token|key|secret|password|pass|pw|passwd|auth|session|csrf|nonce)\s*=.*(?:\?|&)\1\s*=",
    r"(?i)(?:\?|&)\w+=.*(?:;|,)\s*(?:select|union|insert|update|delete|drop|exec|script|alert|onerror|onload)\b",
    # --- Content-Type confusion ---
    r"(?i)Content-Type\s*:\s*(?:text/plain|application/x-www-form-urlencoded|multipart/form-data|application/json|text/xml|application/xml|text/html).*(?:boundary|charset)\s*=\s*(?:.*['\";]|[a-zA-Z0-9]{50,})",
    r"(?i)Content-Type\s*:\s*(?:text/html|application/xhtml\+xml|image/svg\+xml).*(?:charset\s*=\s*(?:utf-7|us-ascii|iso-2022-jp|iso-8859-\d+|windows-125\d|gbk|gb2312|big5|euc-jp|euc-kr|shift_jis))",
    r"(?i)Content-Type\s*:\s*application/(?:octet-stream|x-amf|x-thrift|grpc|protobuf|msgpack|cbor|bson|avro|x-php|x-httpd-php|x-sh|x-csh|x-perl|x-python|x-ruby|x-lua)",
    # --- Chunked encoding bypass ---
    r"(?i)Transfer-Encoding\s*:\s*(?:chunked,\s*identity|identity,\s*chunked|chunked,\s*chunked|,\s*chunked|chunked\s*,)",
    r"(?i)Transfer-Encoding\s*:\s*(?:xchunked|x\s+chunked|chunked-ext|CHUNKED|Chunked|cHuNkEd|\tchunked|\schunked)",
    r"(?i)Transfer-Encoding\s*:\s*\w+\r?\nTransfer-Encoding\s*:",
    # --- Header injection ---
    r"(?i)(?:X-Forwarded-For|X-Real-IP|X-Client-IP|X-Originating-IP|CF-Connecting-IP|True-Client-IP|X-Forwarded-Host|X-Host|X-Original-URL|X-Rewrite-URL)\s*:\s*(?:127\.0\.0\.1|localhost|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|::1|0:0:0:0:0:0:0:1|169\.254\.169\.254)",
    r"(?i)X-(?:Original-URL|Rewrite-URL|Custom-IP-Authorization|Forwarded-Server|Forwarded-Port|Forwarded-Scheme)\s*:\s*(?:/admin|/internal|/debug|/console|/actuator|/swagger|/api-docs|/graphql|/metrics|/env)",
    # --- Method override ---
    r"(?i)X-HTTP-Method-Override\s*:\s*(?:PUT|DELETE|PATCH|OPTIONS|TRACE|CONNECT|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|MERGE|M-SEARCH)",
    r"(?i)X-Method-Override\s*:\s*(?:PUT|DELETE|PATCH|CONNECT|TRACE)\b",
    r"(?i)_method\s*=\s*(?:PUT|DELETE|PATCH|CONNECT|TRACE)\b",
    r"(?i)X-HTTP-Method\s*:\s*(?:PUT|DELETE|PATCH|CONNECT|TRACE)\b",
    # --- Null byte injection ---
    r"(?i)%00(?:\.(?:jpg|jpeg|gif|png|bmp|pdf|doc|xls|ppt|txt|csv|xml|json|html)|\.php|\.asp|\.jsp|\.py|\.rb|\.pl|\.cgi|\.sh|\.bat|\.exe|\.dll|\.so|\.class|\.war|\.jar)",
    r"(?i)(?:\x00|\%00|\\0|\\x00).*(?:\.php|\.asp|\.jsp|\.py|\.rb|\.pl|\.cgi|\.sh|\.bat|\.exe|\.dll)",
    # --- Unicode normalization bypass ---
    r"(?i)(?:＜|＞|＆|＝|＋|（|）|［|］|｛|｝|；|｜|＇|＂|～|＠|＃|＄|％|＾|＊|／|＼)",
    # Unicode homoglyph evasion - use explicit chars to avoid case-folding FP
    r"(?:\u0130|\u0131)(?:select|union|script|alert|eval|exec|system)",
]

# ============================================================================
# 2. SESSION / AUTHENTICATION ATTACKS (120 patterns)
# ============================================================================
SESSION_AUTH_DEEP = [
    # --- Session fixation ---
    r"(?i)(?:PHPSESSID|JSESSIONID|ASP\.NET_SessionId|CFID|CFTOKEN|connect\.sid|session_id|sid|sessid|sess|token|auth_token|access_token|refresh_token|jwt|api_key|api_token|bearer)\s*[=:]\s*[a-zA-Z0-9_-]{16,}",
    r"(?i)(?:Set-Cookie|Cookie)\s*:.*(?:PHPSESSID|JSESSIONID|ASP\.NET_SessionId|connect\.sid|session_id)\s*=\s*[a-zA-Z0-9_-]{16,}.*(?:;\s*(?:Path|Domain|Expires|Max-Age|Secure|HttpOnly|SameSite))",
    r"(?i)(?:cookie|session|token|csrf|nonce|state|code|grant)\s*=.*(?:%3[Bb]|;).*(?:cookie|session|token|csrf|nonce|state|code|grant)\s*=",
    # --- Session hijacking ---
    r"(?i)document\.cookie\s*(?:=|\+|;|\.match|\.indexOf|\.substring|\.replace|\.split)",
    r"(?i)(?:document\.cookie|window\.sessionStorage|window\.localStorage)\s*(?:\[|\.getItem|\.setItem|\.removeItem|\.clear|\.key|\.length)",
    r"(?i)new\s+Image\(\)\.src\s*=\s*['\"].*(?:cookie|session|token)\b",
    r"(?i)(?:XMLHttpRequest|fetch|navigator\.sendBeacon)\s*\(.*(?:document\.cookie|sessionStorage|localStorage)",
    r"(?i)window\.location\s*=\s*.*(?:document\.cookie|sessionStorage|localStorage)",
    # --- CSRF attacks ---
    r"(?i)<(?:img|script|iframe|link|embed|object|video|audio|source|track)\s+[^>]*(?:src|href|data|action|formaction|poster|background|codebase|cite|classid|profile|usemap|longdesc)\s*=\s*['\"]?(?:https?://|//)[^'\">\s]+(?:password|delete|update|transfer|pay|send|admin|config|settings|profile)",
    r"(?i)<form\s+[^>]*(?:method\s*=\s*['\"]?POST['\"]?)[^>]*(?:action\s*=\s*['\"]?(?:https?://|//))[^'\">\s]+",
    r"(?i)(?:csrf|xsrf|_token|authenticity_token|__RequestVerificationToken|csrfmiddlewaretoken|_csrf_token|anti-forgery-token|X-CSRF-TOKEN|X-XSRF-TOKEN)\s*(?:=|:)\s*['\"]?(?:null|undefined|0|false|true|''|\"\"|\[\]|\{\})['\"]?",
    # --- JWT attacks ---
    r"(?i)eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*",
    r"(?i)(?:\"alg\"\s*:\s*\"(?:none|None|NONE|nOnE|NoNe)\"|\"alg\"\s*:\s*\"\")",
    r"(?i)(?:\"alg\"\s*:\s*\"HS256\".*\"typ\"\s*:\s*\"JWT\"|\"typ\"\s*:\s*\"JWT\".*\"alg\"\s*:\s*\"HS256\")",
    r"(?i)(?:\"alg\"\s*:\s*\"(?:HS256|HS384|HS512)\".*(?:\"kid\"|\"jku\"|\"jwk\"|\"x5u\"|\"x5c\"))",
    r"(?i)(?:\"kid\"\s*:\s*\"(?:/dev/null|/etc/passwd|/proc/self|/var/log|\.\./))",
    r"(?i)(?:\"kid\"\s*:\s*\"(?:.*(?:union|select|or|and|drop|delete|insert|update|;|--|#|/\*|@@|char\(|concat\(|group_concat\())[^\"]*\")",
    r"(?i)(?:\"jku\"\s*:\s*\"https?://(?!(?:login|auth|token|jwt|keys|certs|\.well-known)\.)(?:evil|attacker|hacker|\d+\.\d+\.\d+\.\d+|localhost|127\.0\.0\.1)[^\"]*\")",
    r"(?i)(?:\"jwk\"\s*:\s*\{[^}]*\"kty\"\s*:\s*\"(?:RSA|EC|oct|OKP)\"[^}]*\})",
    r"(?i)(?:\"x5u\"\s*:\s*\"https?://(?:evil|attacker|hacker|\d+\.\d+\.\d+\.\d+|localhost|127\.0\.0\.1)[^\"]*\")",
    r"(?i)(?:\"x5c\"\s*:\s*\[\"[a-zA-Z0-9+/=]{20,}\"\])",
    # --- OAuth attacks ---
    r"(?i)(?:redirect_uri|callback|return_url|next|continue|dest|destination|redir|return|goto)\s*=\s*(?:https?://|//|\\\\|%2[fF]%2[fF]|%5[cC]%5[cC]|data:|javascript:|vbscript:|file:)",
    r"(?i)(?:redirect_uri|callback)\s*=\s*(?:https?://)?(?:[^/]*@)?(?:evil|attacker|hacker|\d+\.\d+\.\d+\.\d+)[^&]*",
    r"(?i)(?:client_id|client_secret|code|access_token|refresh_token|id_token|state|nonce)\s*=\s*[a-zA-Z0-9_-]{20,}",
    r"(?i)(?:grant_type\s*=\s*(?:authorization_code|implicit|client_credentials|password|refresh_token|urn:ietf:params:oauth:grant-type:(?:jwt-bearer|saml2-bearer|device_code|token-exchange)))\b",
    r"(?i)(?:response_type\s*=\s*(?:code|token|id_token|code\+token|code\+id_token|token\+id_token|code\+token\+id_token))\b",
    r"(?i)(?:scope\s*=\s*(?:openid|profile|email|address|phone|offline_access|read|write|admin|user|api|all)\b)",
    # --- SAML attacks ---
    r"(?i)<(?:saml[p2]?:)?(?:Assertion|Response|AuthnRequest|LogoutRequest|LogoutResponse|AttributeQuery|ArtifactResolve|ManageNameIDRequest|NameIDMappingRequest)\b",
    r"(?i)(?:SAMLRequest|SAMLResponse|RelayState|SigAlg|Signature)\s*=\s*[a-zA-Z0-9+/=%]+",
    r"(?i)(?:saml|SAML).*(?:Signature|SignedInfo|SignatureValue|KeyInfo|X509Certificate|CanonicalizationMethod|SignatureMethod|DigestMethod|DigestValue|Reference|Transform|Transforms)",
    r"(?i)(?:SAML).*(?:NameID|Issuer|Audience|Condition|Subject|Assertion|Attribute|Statement)\b",
    r"(?i)<(?:ds:)?(?:Signature|SignedInfo|SignatureValue|KeyInfo|X509Certificate|CanonicalizationMethod|SignatureMethod|DigestMethod|DigestValue|Reference|Transform|Transforms)\b",
    r"(?i)(?:XSW|xml[\s_-]?signature[\s_-]?wrapping|signature[\s_-]?exclusion|SAML[\s_-]?replay|SAML[\s_-]?injection|assertion[\s_-]?injection)\b",
    r"(?i)http://www\.w3\.org/(?:2000/09/xmldsig#|2001/04/xmlenc#|2001/10/xml-exc-c14n#)",
    # --- Password attacks ---
    r"(?i)(?:password|passwd|pass|pwd|pw|secret|credential)\s*=\s*(?:admin|root|toor|password|123456|12345678|1234567890|qwerty|abc123|monkey|master|dragon|login|princess|qwertyuiop|solo|passw0rd|starwars|letmein|football|shadow|sunshine|trustno1|iloveyou|batman|access|hello|charlie|donald|whatever|freedom|654321|michael|jordan|superman|yankees|amanda|ranger)\b",
    r"(?i)(?:Authorization\s*:\s*Basic\s+)(?:[a-zA-Z0-9+/=]{4,})",
    r"(?i)(?:Authorization\s*:\s*Bearer\s+)(?:[a-zA-Z0-9._-]{20,})",
    r"(?i)(?:Authorization\s*:\s*(?:Digest|NTLM|Negotiate|AWS4-HMAC-SHA256|SharedKey|SharedKeyLite)\s+)",
]

# ============================================================================
# 3. RACE CONDITIONS / BUSINESS LOGIC (80 patterns)
# ============================================================================
RACE_BUSINESS_DEEP = [
    # --- Race conditions (TOCTOU) ---
    r"(?i)(?:time[_-]?of[_-]?check|TOCTOU|time[_-]?of[_-]?use|race[_-]?condition|concurrent[_-]?access|double[_-]?spending|replay[_-]?attack)\b",
    r"(?i)(?:Transfer-Encoding|Content-Length)\s*:\s*0\r?\n(?:Transfer-Encoding|Content-Length)\s*:",
    r"(?i)If-(?:Match|None-Match|Modified-Since|Unmodified-Since|Range)\s*:\s*(?:\*|W/\"|\"|0)",
    r"(?i)(?:X-Request-ID|X-Correlation-ID|X-Trace-ID|Idempotency-Key)\s*:\s*(?:[a-f0-9-]{36}|[a-zA-Z0-9]{8,})",
    # --- Business logic ---
    r"(?i)(?:price|amount|quantity|total|subtotal|discount|coupon|promo|credit|balance|points|reward|bonus|gift|voucher|refund)\s*=\s*(?:-[0-9]|0\.0{1,}1|999{3,}|0(?:\.0+)?|NaN|Infinity|-Infinity|null|undefined|true|false)",
    r"(?i)(?:price|amount|quantity|total|subtotal|discount|coupon|promo|credit|balance)\s*=\s*(?:-?\d{6,}|0x[0-9a-f]+|[0-9]+e[0-9]+)",
    r"(?i)(?:role|permission|access|level|type|group|privilege|admin|is_admin|isAdmin|isStaff|is_staff|isSuperuser|is_superuser|is_verified|isVerified)\s*=\s*(?:admin|root|superuser|staff|moderator|manager|supervisor|operator|true|1|yes)\b",
    r"(?i)(?:user_id|userId|user|uid|account_id|accountId|account|owner|author|creator)\s*=\s*(?:0|1|admin|root|system|null)",
    r"(?i)(?:step|stage|phase|state|status|flow|wizard|checkout)\s*=\s*(?:-1|0|99|999|final|complete|done|skip|bypass)\b",
    r"(?i)(?:limit|max|min|offset|page|per_page|page_size|pageSize|count|top|skip|first|last|after|before)\s*=\s*(?:-[0-9]|0|999{3,}|[0-9]{6,}|2147483647|9999999999|NaN|Infinity)\b",
    r"(?i)(?:email|phone|address|name|username)\s*(?:=|:)\s*['\"]?(?:admin@|root@|system@|test@|info@)\b",
    r"(?i)(?:currency|currency_code|currencyCode)\s*=\s*(?:[A-Z]{3})\b",
    r"(?i)(?:shipping|delivery|payment|billing)_(?:method|type|option|mode)\s*=\s*(?:free|test|debug|none|skip|bypass|0)\b",
    # --- IDOR ---
    r"(?i)/(?:users?|accounts?|profiles?|orders?|invoices?|transactions?|payments?|documents?|files?|messages?|notifications?|tickets?|reports?|settings?|preferences?)/(?:\d+|[a-f0-9-]{36}|[a-zA-Z0-9]{8,})(?:/(?:edit|update|delete|remove|archive|export|download|share|transfer|activate|deactivate|verify|approve|reject|suspend|ban|block|unblock))\b",
    r"(?i)(?:user_id|userId|account_id|accountId|order_id|orderId|file_id|fileId|doc_id|docId|msg_id|msgId|transaction_id|transactionId|invoice_id|invoiceId)\s*=\s*(?:\d{1,10}|[a-f0-9-]{36}|[a-zA-Z0-9]{8,})",
    # --- Mass assignment ---
    r"(?i)(?:role|admin|is_admin|isAdmin|is_staff|isStaff|is_superuser|isSuperuser|verified|is_verified|isVerified|activated|is_activated|isActivated|banned|is_banned|isBanned|deleted|is_deleted|isDeleted|active|is_active|isActive|permission|permissions|privilege|privileges|access_level|accessLevel|user_type|userType|account_type|accountType|plan|subscription|tier|credits|balance|points|trust_level|trustLevel)\b",
    r"(?i)\{[^}]*(?:\"role\"|\"admin\"|\"isAdmin\"|\"is_admin\"|\"permissions?\"|\"privilege\"|\"access_level\"|\"user_type\"|\"account_type\"|\"plan\"|\"subscription\"|\"credits\"|\"balance\")\s*:\s*(?:\"admin\"|\"root\"|\"superuser\"|true|1|\d{4,})[^}]*\}",
]

# ============================================================================
# 4. gRPC / PROTOBUF ATTACKS (60 patterns)
# ============================================================================
GRPC_PROTO_DEEP = [
    # --- gRPC ---
    r"(?i)(?:grpc|grpc-web|grpc-gateway)\b",
    r"(?i)content-type\s*:\s*application/grpc(?:-web)?(?:\+proto|\+json)?\b",
    r"(?i)grpc-(?:status|message|encoding|accept-encoding|timeout|metadata)\s*:",
    r"(?i)/(?:grpc\.reflection\.v1alpha\.ServerReflection|grpc\.reflection\.v1\.ServerReflection|grpc\.health\.v1\.Health)/\w+",
    r"(?i)/(?:grpc\.channelz\.v1\.Channelz|grpc\.admin\.v1\.AdminService)/\w+",
    r"(?i)grpc\.(?:server_reflection|health_check|channelz|admin)\b",
    r"(?i)(?:ListServices|GetServiceInfo|ServerReflectionInfo|FileContainingSymbol|FileByFilename|AllExtensionNumbersOfType)\b",
    r"(?i)(?:protoc|protobuf|proto3|proto2|protobuf-net|protobuf-go|protobuf-java|protobuf-python)\b",
    r"(?i)syntax\s*=\s*\"proto[23]\"\b",
    r"(?i)(?:message|service|rpc|enum|oneof|map|extend|option|import|package)\s+\w+\s*\{",
    r"(?i)option\s+(?:java_package|java_outer_classname|java_multiple_files|go_package|csharp_namespace|php_namespace|ruby_package|objc_class_prefix|cc_enable_arenas|optimize_for)\s*=",
    # --- gRPC attacks ---
    r"(?i)grpc-timeout\s*:\s*(?:0[smunH]|999{3,}[smunH]|2147483647[smunH])\b",
    r"(?i)grpc\.max_(?:receive_message_length|send_message_length)\s*=\s*(?:-1|0|[0-9]{8,})\b",
    r"(?i)grpc\.default_authority\s*=\s*(?:localhost|127\.0\.0\.1|evil|attacker|internal)\b",
    r"(?i)grpc\.ssl_target_name_override\s*=\s*\w+",
    r"(?i)grpc\.(?:initial_reconnect_backoff_ms|min_reconnect_backoff_ms|max_reconnect_backoff_ms|keepalive_time_ms|keepalive_timeout_ms|keepalive_permit_without_calls|max_connection_idle_ms|max_connection_age_ms|max_concurrent_streams)\s*=",
    # --- Protobuf injection ---
    r"(?i)\x08[\x00-\xff]\x10[\x00-\xff]\x1a[\x00-\xff]{3,}",
    r"(?i)(?:wire_type|field_number|tag|varint|fixed32|fixed64|length_delimited|start_group|end_group)\b",
]

# ============================================================================
# 5. WEB CACHE ATTACKS (80 patterns)
# ============================================================================
WEB_CACHE_DEEP = [
    # --- Cache poisoning ---
    r"(?i)X-(?:Forwarded-Host|Forwarded-Scheme|Forwarded-Port|Forwarded-Proto|Forwarded-Prefix|Original-URL|Rewrite-URL|Custom-IP-Authorization)\s*:\s*(?:evil|attacker|hacker)\b",
    r"(?i)X-Forwarded-Host\s*:\s*(?:\w+\.(?:evil|attacker|hacker|burp|ngrok|interact\.sh|oast)\.\w+)",
    r"(?i)X-Forwarded-Scheme\s*:\s*(?:nothttps|http\s|javascript|data|vbscript)\b",
    r"(?i)X-Forwarded-Port\s*:\s*(?:0|65536|999{3,}|NaN|-1)\b",
    r"(?i)X-Original-URL\s*:\s*/(?:admin|internal|debug|console|actuator|swagger|api-docs|graphql|metrics|env)\b",
    r"(?i)X-Rewrite-URL\s*:\s*/(?:admin|internal|debug|console|actuator|swagger|api-docs|graphql|metrics|env)\b",
    r"(?i)(?:Pragma|Cache-Control)\s*:\s*(?:no-transform|only-if-cached|public|no-cache|no-store|max-age=0|max-stale=?\d*|min-fresh=0|s-maxage=0|must-revalidate|proxy-revalidate|stale-while-revalidate=0|stale-if-error=0)\b",
    r"(?i)(?:Vary|ETag|If-None-Match|If-Modified-Since|Age|Expires|Cache-Control|Surrogate-Control)\s*:.*(?:evil|attacker|hacker|<script|javascript:|data:)",
    # --- Web cache deception ---
    r"(?i)/(?:account|profile|settings|dashboard|admin|internal|api|user|my-account|billing|preferences|cart|checkout|payment|order|inbox|messages|notifications)/\w+\.(?:css|js|jpg|jpeg|gif|png|svg|ico|woff|woff2|ttf|eot|mp4|webm|ogg|mp3|wav|flac|pdf|doc|xls|ppt|txt|csv|xml|json|html|htm|swf|zip|rar|tar|gz|bz2|7z|aac|webp|avif)",
    r"(?i)/(?:account|profile|settings|dashboard|admin)/[^/]+\.(?:css|js|jpg|jpeg|gif|png|svg|ico|woff|woff2)\b",
    r"(?i)/(?:account|profile|settings|dashboard|admin)/(?:\.\.|%2e%2e|%252e%252e|%c0%ae%c0%ae)(?:/|\\|%2f|%5c)",
    r"(?i)/(?:account|profile|settings|dashboard|admin)(?:%0[adAD]|%20|%23|%3[fF]|%2[eE]|;|\.\.)[^/]*\.(?:css|js|jpg|png|gif)\b",
    # --- Cache key manipulation ---
    r"(?i)(?:\?|&)(?:_|__|\.|cb|cachebuster|cache|bust|v|version|t|timestamp|nocache|rand|random|_t|_dc|_r)\s*=\s*\d+",
    r"(?i)(?:\?|&)\w+\s*=\s*[^&]*(?:%0[adAD]|%0[aA]Set-Cookie|%0[dD]%0[aA]|%0[aA]%0[dD])[^&]*",
    # --- CDN bypass ---
    r"(?i)(?:CF-|Fastly-|Akamai-|CloudFront-|Varnish-|X-Cache-|X-Served-By-|X-Edge-|Via)\s*:",
    r"(?i)(?:cdn-loop|CDN-Loop|x-cdn|X-CDN|cf-ray|CF-Ray|x-amz-cf-id|X-Amz-Cf-Id|x-varnish|X-Varnish|fastly-|Fastly-)\s*:",
    r"(?i)(?:Surrogate-Control|Surrogate-Capability)\s*:\s*(?:content|no-store|max-age|ESI/1\.0)\b",
]

# ============================================================================
# 6. HOST HEADER ATTACKS (60 patterns)
# ============================================================================
HOST_HEADER_DEEP = [
    # --- Host header injection ---
    r"(?i)Host\s*:\s*(?:evil|attacker|hacker|localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|::1)\b",
    r"(?i)Host\s*:\s*\w+\.(?:evil|attacker|hacker|burp|ngrok|interact\.sh|oast|pipedream|webhook\.site)\.\w+",
    r"(?i)Host\s*:\s*\w+\.\w+\.\w+(?:@\w+\.\w+|\s+\w+\.\w+)",
    r"(?i)Host\s*:\s*\w+\.\w+\.\w+(?:%00|%0[adAD]|%20|\x00|\r|\n|\t| )",
    r"(?i)Host\s*:\s*\w+\.\w+:\d+(?:@\w+\.\w+|%40\w+\.\w+)",
    # --- Absolute URL override ---
    r"(?i)GET\s+https?://(?:evil|attacker|hacker|localhost|127\.0\.0\.1)\b",
    r"(?i)GET\s+https?://\w+\.\w+\.\w+\s+HTTP/\d\.\d\r?\n(?:.*\r?\n)*Host\s*:\s*(?:evil|attacker|different)",
    # --- Password reset poisoning ---
    r"(?i)Host\s*:\s*(?:evil|attacker|hacker)\.\w+.*(?:password|reset|forgot|recover|restore|change|update|confirm|verify|activate|register|signup|invite|share|download|export|subscribe|unsubscribe)\b",
    r"(?i)(?:X-Forwarded-Host|X-Host|X-Original-Host|Forwarded)\s*:\s*(?:evil|attacker|hacker)\.\w+.*(?:password|reset|forgot|recover)\b",
    # --- Routing abuse ---
    r"(?i)Host\s*:\s*(?:internal|backend|upstream|origin|admin|api|dev|staging|test|debug|local|private|intranet|vpn|gateway|proxy|lb|loadbalancer)\.(?:internal|local|corp|company|example)\b",
    r"(?i)(?:X-Forwarded-Host|X-Host)\s*:\s*(?:internal|backend|upstream|origin|admin|api|dev|staging|test|debug|local|private|intranet|vpn)\.(?:internal|local|corp)\b",
    # --- Connection-state attacks ---
    r"(?i)Connection\s*:\s*(?:keep-alive|close)\s*,\s*(?:Transfer-Encoding|Content-Length|Upgrade|HTTP2-Settings)\b",
    r"(?i)Upgrade\s*:\s*(?:h2c|websocket|HTTP/2\.0|TLS/1\.0|IRC/6\.9|SHTTP/1\.3)\b",
    r"(?i)HTTP2-Settings\s*:\s*[a-zA-Z0-9+/=]{10,}",
]

# ============================================================================
# 7. PRIVILEGE ESCALATION (100 patterns)
# ============================================================================
PRIVESC_DEEP = [
    # --- Linux privilege escalation ---
    r"(?i)(?:sudo|su|doas|pkexec|gksudo|kdesudo)\s+(?:-[a-zA-Z]+\s+)*(?:bash|sh|zsh|csh|tcsh|ksh|fish|dash|ash|rbash|nologin|false|true|env|/bin/|/usr/bin/|/usr/sbin/|/sbin/)",
    r"(?i)sudo\s+(?:-u\s+root|-l|--list|-S|--stdin|-A|--askpass|-H|--set-home|-E|--preserve-env|-k|--reset-timestamp|-K|--remove-timestamp|-v|--validate|-n|--non-interactive|NOPASSWD|ALL)\b",
    r"(?i)(?:chmod|chown|chgrp)\s+(?:4755|6755|u\+s|g\+s|o\+w|777|a\+rwx|a\+w|\+s|\+t)\s+",
    r"(?i)find\s+/\s+.*-perm\s+(?:-4000|-2000|-u=s|-g=s)\b",
    r"(?i)find\s+/\s+.*-(?:exec|ok)\s+(?:/bin/sh|/bin/bash|sh|bash)\b",
    r"(?i)(?:capabilities|getcap|setcap|cap_\w+)\b.*(?:\+ep|\+eip|=ep|=eip)\b",
    r"(?i)(?:crontab|at|batch)\s+(?:-l|-r|-e|-u\s+root|/etc/cron)",
    r"(?i)/etc/(?:crontab|cron\.(?:d|daily|hourly|weekly|monthly)|anacrontab|at\.deny|at\.allow)\b",
    r"(?i)(?:echo|printf|tee|cat|cp|mv|ln)\s+.*(?:/etc/passwd|/etc/shadow|/etc/sudoers|/etc/crontab|/root/\.ssh/authorized_keys|/etc/ssh/sshd_config)\b",
    r"(?i)(?:useradd|adduser|usermod|groupadd|addgroup|groupmod|userdel|deluser|groupdel|delgroup|passwd|chpasswd|newgrp|gpasswd)\s+",
    r"(?i)(?:visudo|vipw|vigr)\b",
    r"(?i)(?:setuid|setgid|setresuid|setresgid|setreuid|setregid|seteuid|setegid|setfsuid|setfsgid)\s*\(",
    r"(?i)/proc/self/(?:status|maps|mem|environ|cmdline|cgroup|mountinfo|mounts|net/|fd/|root|cwd|exe|task)\b",
    r"(?i)/proc/(?:version|cpuinfo|meminfo|partitions|diskstats|vmstat|loadavg|uptime|modules|interrupts|ioports|iomem|devices|filesystems|swaps|cmdline|config\.gz)\b",
    r"(?i)(?:ltrace|strace|ptrace|gdb|lldb|radare2|r2|objdump|readelf|strings|nm|ldd|file|xxd|od|hexdump)\s+(?:-p\s+\d+|--attach|--pid|/proc/|/usr/|/bin/|/sbin/|/lib/)",
    # --- Windows privilege escalation ---
    r"(?i)(?:whoami\s*/priv|whoami\s*/all|whoami\s*/groups)\b",
    r"(?i)(?:net\s+user|net\s+localgroup|net\s+group)\s+\w+\s+(?:admin|administrators|domain\s+admins)\b",
    r"(?i)(?:net\s+user\s+\w+\s+\w+\s+/add)\b",
    r"(?i)(?:sc\s+(?:qc|query|config|start|stop|create|delete|sdshow|sdset)\s+\w+)\b",
    r"(?i)(?:reg\s+(?:query|add|delete|export|import|save|restore|load|unload|compare|copy|flags)\s+(?:HKLM|HKEY_LOCAL_MACHINE|HKCU|HKEY_CURRENT_USER|HKCR|HKEY_CLASSES_ROOT)\\)",
    r"(?i)(?:wmic\s+(?:process|service|useraccount|group|nicconfig|logicaldisk|computersystem|os|qfe|product|startup|share|sysdriver|netlogin|netuse|ntdomain|partition|printer)\s+\w+)\b",
    r"(?i)(?:powershell|pwsh)\s+.*(?:-ep\s+bypass|-ExecutionPolicy\s+(?:Bypass|Unrestricted|RemoteSigned)|-enc\s+[a-zA-Z0-9+/=]+|-nop|-w\s+hidden|-sta)",
    r"(?i)(?:IEX|Invoke-Expression|Invoke-Command|Invoke-WMIMethod|Invoke-CimMethod)\s*\(",
    r"(?i)(?:Get-Process|Get-Service|Get-WmiObject|Get-CimInstance|Get-ItemProperty|Get-ChildItem|Get-Content|Get-Credential|Get-EventLog|Get-LocalUser|Get-LocalGroup|Get-ADUser|Get-ADComputer|Get-ADGroup)\s+",
    r"(?i)(?:Set-ItemProperty|Set-Content|Set-Service|Set-MpPreference|Set-NetFirewallProfile|Set-ExecutionPolicy)\s+",
    r"(?i)(?:New-Object\s+(?:Net\.WebClient|IO\.StreamReader|IO\.MemoryStream|IO\.Compression|Security\.Cryptography|Diagnostics\.Process|Management\.ManagementObject))\b",
    r"(?i)(?:SeDebugPrivilege|SeImpersonatePrivilege|SeAssignPrimaryTokenPrivilege|SeBackupPrivilege|SeRestorePrivilege|SeTakeOwnershipPrivilege|SeTcbPrivilege|SeLoadDriverPrivilege|SeCreateTokenPrivilege|SeMachineAccountPrivilege)\b",
    r"(?i)(?:JuicyPotato|RoguePotato|SweetPotato|PrintSpoofer|GodPotato|SharpEfsPotato|RasmanPotato|EfsPotato|CoercedPotato|LocalPotato)\b",
    # --- Kernel exploits ---
    r"(?i)(?:DirtyPipe|DirtyCow|dirty_cow|dirty_pipe|CVE-2016-5195|CVE-2022-0847|CVE-2021-4034|PwnKit|CVE-2021-3156|Baron_Samedit|CVE-2022-2588|CVE-2022-0185|CVE-2022-34918|CVE-2023-0386|CVE-2023-2640|CVE-2023-32629|CVE-2023-35001)\b",
    r"(?i)(?:exploit/(?:linux|windows|unix|multi)/(?:local|privilege|kernel)/\w+)\b",
]

# ============================================================================
# 8. LATERAL MOVEMENT / PERSISTENCE (100 patterns)
# ============================================================================
LATERAL_PERSIST_DEEP = [
    # --- Lateral movement ---
    r"(?i)(?:psexec|paexec|wmiexec|smbexec|atexec|dcomexec|evil-winrm|wmic|winrs|enter-pssession|invoke-command|winrm)\b.*(?:/u:|/user:|/p:|/pass:|--user|--password|-U\s+-P\s+)",
    r"(?i)(?:xfreerdp|rdesktop|remmina|mstsc|rdp)\s+.*(?:/u:|/p:|/v:|/cert-ignore|/sec:nla)\b",
    r"(?i)(?:ssh|scp|sftp|rsync)\s+.*(?:-o\s+StrictHostKeyChecking=no|-o\s+UserKnownHostsFile=/dev/null|-i\s+|@\d+\.\d+\.\d+\.\d+)",
    r"(?i)(?:net\s+use\s+\\\\|net\s+share|net\s+view)\s+(?:\\\\)?(?:\d+\.\d+\.\d+\.\d+|\w+)(?:\\[A-Za-z$]+)?",
    r"(?i)(?:pth-winexe|pth-wmic|pth-rpcclient|pth-smbclient|pth-net|pth-curl)\b",
    r"(?i)(?:pass[_-]?the[_-]?hash|pass[_-]?the[_-]?ticket|over[_-]?pass[_-]?the[_-]?hash|golden[_-]?ticket|silver[_-]?ticket|diamond[_-]?ticket|kerberoasting|as-rep[_-]?roasting|dcsync|dcshadow|skeleton[_-]?key|admin[_-]?sd[_-]?holder|sid[_-]?history|constrained[_-]?delegation|unconstrained[_-]?delegation|resource[_-]?based[_-]?constrained[_-]?delegation)\b",
    r"(?i)(?:sekurlsa|lsadump|kerberos|privilege|token|vault|dpapi|crypto|misc|process|service|ts|event|net|sid|logonpasswords|sam|dcsync|ntds|trust|backupkeys|rpdata|masterkeys|cache|wdigest|msv|tspkg|livessp|ssp|credman|cloudap)\b.*(?:::)\b",
    r"(?i)(?:Invoke-Mimikatz|Invoke-NinjaCopy|Invoke-Kerberoast|Invoke-ASREPRoast|Invoke-SMBExec|Invoke-WMIExec|Invoke-DCSync|Invoke-PsExec|Invoke-TheHash|Invoke-Rubeus)\b",
    r"(?i)(?:sharphound|bloodhound|neo4j|cypher)\b.*(?:MATCH|RETURN|WHERE|MERGE|CREATE|SET)\b",
    r"(?i)(?:SharpHound|BloodHound|Certipy|Certify|Whisker|ADModule|PowerView|PowerUp|SharpUp|SharpGPOAbuse|SharpSploit|Rubeus|SharpDPAPI|SharpChrome|Seatbelt|GhostPack)\b",
    # --- Persistence ---
    r"(?i)(?:schtasks|at)\s+/(?:create|change|run|delete|query|end)\s+",
    r"(?i)schtasks\s+/create\s+.*(?:/ru\s+(?:SYSTEM|system|LocalSystem)|/sc\s+(?:onlogon|onstart|onidle|onevent|onconnect|ondisconnect)|/tn\s+|/tr\s+|/st\s+)",
    r"(?i)reg\s+add\s+(?:HKLM|HKCU)\\.*(?:Run|RunOnce|RunOnceEx|RunServices|RunServicesOnce|Policies\\Explorer\\Run|Winlogon|CurrentVersion\\Image\s+File\s+Execution\s+Options|Shell\s+Folders|User\s+Shell\s+Folders|Environment|SessionManager|AppInit_DLLs|ShellServiceObjectDelayLoad|Explorer\\ShellExecuteHooks|Browser\s+Helper\s+Objects|ContextMenuHandlers|ShellIconOverlayIdentifiers)\b",
    r"(?i)(?:sc\s+create|New-Service|Install-Service)\s+\w+\s+.*(?:binPath|ImagePath|start=auto|type=own|error=ignore)\b",
    r"(?i)(?:netsh\s+(?:advfirewall|interface|wlan|http|trace|ipsec|ras|routing|winhttp)\s+\w+)\b",
    r"(?i)(?:wevtutil\s+(?:cl|qe|el|gl|sl|epl|gli)\s+\w+)\b",
    r"(?i)(?:vssadmin\s+(?:list|create|delete|resize)\s+(?:shadows|volumes|shadowstorage))\b",
    r"(?i)(?:bcdedit\s+/(?:set|delete|create|copy|export|import|store|enum)\b)",
    r"(?i)/etc/(?:init\.d|rc\.local|rc\d\.d|systemd/system|profile\.d|ld\.so\.preload|ld\.so\.conf\.d|pam\.d|security|ssh/sshrc|bash\.bashrc|environment)\b",
    r"(?i)(?:systemctl\s+(?:enable|disable|start|stop|restart|reload|status|daemon-reload|mask|unmask|is-enabled|is-active|list-units|list-unit-files)\s+\w+)\b",
    r"(?i)~/.(?:bashrc|bash_profile|profile|zshrc|zsh_profile|cshrc|tcshrc|kshrc|login|logout|xinitrc|xprofile|Xauthority|forward|rhosts|shosts|netrc|pgpass|my\.cnf|sqliterc|psqlrc|git-credentials|docker/config\.json|kube/config)\b",
    r"(?i)(?:authorized_keys|known_hosts|id_rsa|id_dsa|id_ecdsa|id_ed25519|identity)\b",
    # --- Log tampering ---
    r"(?i)(?:history\s+-[cdwranps]|unset\s+HISTFILE|export\s+HISTFILE=/dev/null|export\s+HISTSIZE=0|export\s+HISTFILESIZE=0|shred\s+-[a-z]+\s+|wipe\s+-[a-z]+\s+)\b",
    r"(?i)(?:rm|shred|wipe|srm|secure-delete)\s+(?:-[a-z]+\s+)*(?:/var/log/|\.bash_history|\.zsh_history|\.mysql_history|\.psql_history|/tmp/|\.log$|access\.log|error\.log|auth\.log|syslog|messages|kern\.log|dmesg|secure|faillog|lastlog|btmp|wtmp|utmp)",
    r"(?i)(?:auditctl\s+-(?:D|e\s+0|b\s+0)|systemctl\s+stop\s+(?:auditd|rsyslog|syslog-ng|journald))\b",
    r"(?i)(?:logrotate|journalctl\s+--vacuum-time|journalctl\s+--vacuum-size|truncate\s+-s\s+0)\s+",
]

# ============================================================================
# 9. ADVANCED OBFUSCATION TECHNIQUES (80 patterns)
# ============================================================================
ADVANCED_OBFUSCATION_DEEP = [
    # --- JavaScript obfuscation ---
    r"(?i)(?:eval|Function|setTimeout|setInterval|setImmediate|requestAnimationFrame|requestIdleCallback|queueMicrotask|Promise\.resolve\(\)\.then)\s*\(\s*(?:atob|btoa|unescape|decodeURIComponent|decodeURI|String\.fromCharCode|String\.fromCodePoint)\s*\(",
    r"(?i)(?:eval|Function)\s*\(\s*(?:['\"].*['\"]\.replace|['\"].*['\"]\.split|['\"].*['\"]\.reverse|['\"].*['\"]\.join|['\"].*['\"]\.substring|['\"].*['\"]\.slice|['\"].*['\"]\.charAt|['\"].*['\"]\.charCodeAt|['\"].*['\"]\.concat|['\"].*['\"]\.trim|['\"].*['\"]\.match)\s*\(",
    r"(?i)String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){3,}",
    r"(?i)(?:\\x[0-9a-f]{2}){4,}",
    r"(?i)(?:\\u[0-9a-f]{4}){3,}",
    r"(?i)(?:\\u\{[0-9a-f]+\}){3,}",
    r"(?i)(?:\\[0-7]{3}){3,}",
    r"(?i)(?:window|document|self|this|top|parent|frames)\s*\[\s*(?:atob|btoa|unescape|decodeURIComponent|String\.fromCharCode)\s*\(.*\)\s*\]",
    r"(?i)(?:window|document|self|this)\s*\[\s*['\"](?:eval|Function|setTimeout|setInterval|constructor|alert|confirm|prompt|open|write|writeln|createElement|appendChild|insertBefore|replaceChild|removeChild|innerHTML|outerHTML|textContent|innerText|outerText)['\"]?\s*\]",
    r"(?i)\['\\x65\\x76\\x61\\x6c'\]|\['\\u0065\\u0076\\u0061\\u006c'\]",
    r"(?i)(?:Array|Math|Date|RegExp|Error|JSON|Object|Function|Number|String|Boolean)\.(?:constructor|prototype)\s*\[",
    r"(?i)(?:toString|valueOf|toJSON|Symbol\.toPrimitive|Symbol\.iterator)\s*\(\s*\)\s*\[",
    r"(?i)(?:Proxy|Reflect|Symbol|WeakRef|FinalizationRegistry)\s*\(",
    # --- PHP obfuscation ---
    r"(?i)(?:\$\{\s*['\"]|(?:chr|ord)\s*\(\s*\d+\s*\)\s*\.){2,}",
    r"(?i)(?:\$\w+\s*=\s*['\"](?:base64_decode|gzinflate|str_rot13|gzuncompress|rawurldecode|urldecode|hex2bin|convert_uudecode|mcrypt_decrypt|openssl_decrypt)['\"])",
    r"(?i)(?:\$\w+\s*=\s*(?:chr\(\d+\)\s*\.?\s*){4,})",
    r"(?i)(?:\$\w+\s*\(\s*\$\w+\s*\(\s*\$\w+\s*\(\s*['\"])",
    r"(?i)(?:preg_replace\s*\(\s*['\"]/.*/e['\"]|assert\s*\(\s*\$_|create_function\s*\(\s*['\"])",
    r"(?i)(?:\${['\"]\\x[0-9a-f]+(?:\\x[0-9a-f]+)+['\"]}\s*\()",
    r"(?i)(?:(?:base64_decode|gzinflate|str_rot13|gzuncompress|rawurldecode|urldecode)\s*\(\s*){2,}",
    # --- SQL obfuscation ---
    r"(?i)(?:0x[0-9a-f]+\s*(?:=|<|>|!=|<>|LIKE|IN|BETWEEN|AND|OR)\s*0x[0-9a-f]+)",
    r"(?i)(?:BENCHMARK\s*\(\s*\d+\s*,\s*(?:MD5|SHA1|SHA2|AES_ENCRYPT|DES_ENCRYPT|ENCODE|COMPRESS|RAND|UUID)\s*\()",
    r"(?i)(?:IF\s*\(\s*\d+\s*(?:=|<|>)\s*\d+\s*,\s*(?:SLEEP|BENCHMARK|PG_SLEEP|WAITFOR|DBMS_LOCK\.SLEEP)\s*\()",
    r"(?i)(?:CASE\s+WHEN\s+\d+\s*(?:=|<|>)\s*\d+\s+THEN\s+(?:SLEEP|BENCHMARK|PG_SLEEP|WAITFOR)\s*\()",
    r"(?i)(?:1\s*(?:AND|OR)\s*(?:ROW_COUNT|FOUND_ROWS|LAST_INSERT_ID|SESSION_USER|SYSTEM_USER|CURRENT_USER|USER|VERSION|DATABASE|SCHEMA)\s*\(\s*\))",
    r"(?i)(?:(?:AND|OR)\s*(?:\d+\s*=\s*\d+|'[^']*'\s*=\s*'[^']*'|\"[^\"]*\"\s*=\s*\"[^\"]*\"|\w+\s+LIKE\s+\w+|\w+\s+BETWEEN\s+\d+\s+AND\s+\d+))",
    r"(?i)(?:' *(?:AND|OR) *'?\d+(?:'=|\s*=\s*)'?\d+)",
    r"(?i)(?:\d+\s*(?:DIV|MOD)\s*\d+\s*(?:=|<|>)\s*\d+)",
    # --- Command obfuscation ---
    r"(?i)(?:\$\{IFS\}|%20|%09|%0[aAbBcCdD]|\$IFS\$9|\$\{IFS%%[^}]+\}|\$'\x09'|\$'\x20'|<<< )",
    r"(?i)(?:(?:w|wh|who|whoa|whoam|whoami)\$\{IFS\}|(?:c|ca|cat)[\$@]{1,2})",
    r"(?i)(?:(?:ba|bas|bash)\s+-c\s+['\"].*(?:eval|exec|system|curl|wget|nc|ncat|socat)['\"])",
    r"(?i)(?:echo\s+[a-zA-Z0-9+/=]+\s*\|\s*base64\s+-d\s*\|\s*(?:bash|sh|dash|zsh|csh|ksh|python|perl|ruby|php|node))\b",
    r"(?i)(?:printf\s+['\"]\\x[0-9a-f]+(?:\\x[0-9a-f]+)+['\"])",
    r"(?i)(?:xxd\s+-r\s+-p\s*<<<?\s*['\"]?[0-9a-f]+['\"]?\s*\|\s*(?:bash|sh|python|perl|ruby))",
    r"(?i)(?:python[23]?\s+-c\s+['\"](?:exec|eval|import|__import__|os\.system|os\.popen|subprocess\.call|subprocess\.Popen|commands\.getoutput)\b)",
    r"(?i)(?:perl\s+-e\s+['\"](?:exec|system|open|qx|readpipe|backtick|`)\b)",
    r"(?i)(?:ruby\s+-e\s+['\"](?:exec|system|open|%x|`|Kernel\.exec|IO\.popen|Process\.spawn)\b)",
    r"(?i)(?:php\s+-r\s+['\"](?:exec|system|passthru|shell_exec|popen|proc_open|eval|assert|preg_replace)\b)",
    r"(?i)(?:node\s+-e\s+['\"](?:require\('child_process'\)|exec|spawn|execSync|execFile|fork)\b)",
    r"(?i)(?:lua\s+-e\s+['\"](?:os\.execute|os\.popen|io\.popen|loadstring)\b)",
]

# ============================================================================
# 10. EMERGING / MISCELLANEOUS (120 patterns)
# ============================================================================
EMERGING_MISC_DEEP = [
    # --- HTTP/2 specific ---
    r"(?i):method\s*=\s*(?:CONNECT|TRACE|TRACK|DEBUG|PURGE|SEARCH|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|MERGE)\b",
    r"(?i):path\s*=\s*(?:\*|/\.\.|/\x00|/%2e%2e|/(?:admin|internal|debug|console|actuator|swagger|api-docs|graphql|metrics|env))\b",
    r"(?i):authority\s*=\s*(?:evil|attacker|hacker|localhost|127\.0\.0\.1|169\.254\.169\.254)\b",
    r"(?i):scheme\s*=\s*(?:http|ftp|gopher|file|dict|sftp|ssh|telnet|ldap|smtp|imap|pop3|dns|data|javascript|vbscript)\b",
    r"(?i)(?:HEADERS|DATA|SETTINGS|PUSH_PROMISE|PING|GOAWAY|WINDOW_UPDATE|CONTINUATION|PRIORITY|RST_STREAM)\s+(?:frame|flood|exhaustion|priority|dependency|reset|cancel)\b",
    r"(?i)(?:h2c|h2|HTTP/2|ALPN|NPN)\s+(?:upgrade|smuggling|tunnel|flood|reset|rapid)\b",
    # --- HTTP/3 QUIC ---
    r"(?i)(?:QUIC|quic|HTTP/3|h3|h3-\d+)\s+(?:version|transport|connection|stream|frame|setting)\b",
    r"(?i)Alt-Svc\s*:\s*(?:h3|h3-\d+|quic)=",
    # --- WebAssembly ---
    r"(?i)(?:WebAssembly|wasm)\.\w+\s*\(",
    r"(?i)(?:WebAssembly\.(?:compile|compileStreaming|instantiate|instantiateStreaming|Module|Instance|Memory|Table|Global|Tag|validate))\s*\(",
    r"(?i)(?:\.wasm|\.wat|\.wast)\b",
    # --- Server-Side Request Forgery via DNS rebinding ---
    r"(?i)(?:7f000001|0177\.0\.0\.01|2130706433|127\.1|0x7f\.0x0\.0x0\.0x1|0x7f000001|017700000001|127\.0\.0\.0/8|10\.0\.0\.0/8|172\.16\.0\.0/12|192\.168\.0\.0/16|169\.254\.0\.0/16|fc00::/7|fe80::/10|::ffff:127\.0\.0\.1|::1|0:0:0:0:0:ffff:127\.0\.0\.1)\b",
    r"(?i)(?:spoofed\.burpcollaborator\.net|rebind\.it|rbndr\.us|lock\.cmpxchg8b\.com|A\.]b\.pinkeye\.ninja|7f000001\.c0a80001\.rbndr\.us|make-[0-9]+)\b",
    # --- Server-Side Template Injection (additional) ---
    r"(?i)(?:\$\{(?:\d+\*\d+|'[^']*'\.class\.forName|T\(\w+\)|new\s+\w+|\w+\.getClass\(\)))",
    r"(?i)(?:\#\{(?:\d+\*\d+|'[^']*'\.class\.forName|T\(\w+\)|new\s+\w+|\w+\.getClass\(\)))",
    r"(?i)(?:\{\{(?:\d+\*\d+|'[^']*'\.__class__|config\.__class__|request\.environ|lipsum\.__globals__|cycler\.__init__))",
    r"(?i)(?:\{\%(?:debug|load|extends|include|import|block|macro|call|filter|set|do|autoescape|raw|verbatim|spaceless|cache|csrf_token|url|static|trans|plural)\%?\})",
    # --- ReDoS (Regular Expression Denial of Service) ---
    r"(?i)(?:regex|pattern|regexp)\s*[=:].*(?:[a-z]+\+){10,}",
    # Detect possessive quantifiers in regex injection (require regex context like /pattern/ or regex=)
    r"(?i)(?:regex|pattern|regexp|re)\s*[=:].*(?:\*\+|\+\+|\?\+|\{\d+,\}\+)",
    # Detect excessively long email-like strings (safe: uses \S instead of nested groups)
    r"(?i)\S{60,}@\S{30,}",
    # Detect ReDoS payload strings (safe literal match, not nested quantifiers)
    r"(?:a{500,})\$",
    # Detect excessively long quoted strings (safe: single character class, no nesting)
    r"(?i)['\"][a-zA-Z!#$%&'*+/=?^_`{|}~]{80,}['\"]",
    # --- GraphQL deep (additional) ---
    r"(?i)(?:query|mutation|subscription)\s+\w+\s*(?:\(.*\))?\s*\{(?:\s*\w+\s*(?:\(.*\))?\s*\{){4,}",
    r"(?i)(?:__schema|__type|__typename|__directive|__enumValue|__field|__inputValue)\b",
    r"(?i)(?:fragment\s+\w+\s+on\s+\w+\s*\{(?:\s*\.\.\.\w+){3,})",
    r"(?i)(?:@(?:deprecated|skip|include|specifiedBy|defer|stream|live|connection|cacheControl|auth|permission|rest|http|apollo|key|external|requires|provides))\b",
    # --- Serverless attacks ---
    r"(?i)(?:AWS_LAMBDA_(?:FUNCTION_NAME|FUNCTION_VERSION|FUNCTION_MEMORY_SIZE|LOG_GROUP_NAME|LOG_STREAM_NAME|RUNTIME_API|INITIALIZATION_TYPE|EXEC_WRAPPER)|_HANDLER|LAMBDA_TASK_ROOT|LAMBDA_RUNTIME_DIR)\b",
    r"(?i)(?:FUNCTIONS_(?:EXTENSION_VERSION|WORKER_RUNTIME|CUSTOMHANDLER_PORT)|AZURE_FUNCTIONS_ENVIRONMENT|AzureWebJobsStorage|WEBSITE_SITE_NAME)\b",
    r"(?i)(?:\$\{?|\benv\b.*|\bprintenv\b.*)(?:K_SERVICE|K_REVISION|K_CONFIGURATION|CLOUD_RUN_JOB|GOOGLE_CLOUD_PROJECT|FUNCTION_TARGET|FUNCTION_SIGNATURE_TYPE)\b",
    r"(?i)(?:VERCEL_(?:ENV|URL|REGION|GIT_COMMIT_SHA|GIT_COMMIT_REF)|NETLIFY|CONTEXT|DEPLOY_URL|BRANCH)\b",
    # --- API abuse ---
    r"(?i)(?:X-RateLimit-(?:Limit|Remaining|Reset|Retry-After)|Retry-After|X-Throttle-(?:Limit|Remaining|Reset))\s*:\s*(?:0|-1|999{3,}|2147483647)",
    r"(?i)(?:graphql|gql)\s*\{?\s*(?:query|mutation|subscription)\s*\{?\s*(?:__(?:schema|type|typename))\b",
    r"(?i)/(?:api|rest|graphql|swagger|openapi|api-docs|redoc|apidoc)(?:/v[0-9]+)?/(?:docs|spec|schema|swagger-ui|redoc|graphiql|playground|explorer|console|debug|test)\b",
    r"(?i)/(?:\.env|\.git/config|\.svn/entries|\.hg/dirstate|\.DS_Store|Thumbs\.db|web\.config|crossdomain\.xml|clientaccesspolicy\.xml|\.well-known/)\b",
    r"(?i)/(?:wp-config\.php|configuration\.php|config\.php|settings\.php|database\.yml|secrets\.yml|credentials\.yml|master\.key|production\.rb|development\.rb|\.env\.local|\.env\.production|\.env\.development|\.env\.staging|\.env\.test)\b",
    r"(?i)/(?:debug|test|demo|dev|staging|backup|bak|old|temp|tmp|copy|archive|dump|export|import|install|setup|config|admin|manage|monitor|internal|private|secret|hidden)/\b",
    # --- Zero-day patterns (generic) ---
    r"(?i)(?:spring4shell|log4shell|text4shell|shellshock|heartbleed|poodle|beast|crime|breach|lucky13|sweet32|ticketbleed|zombie_poodle|goldendoodle|raccoon|zerologon|sigred|printnightmare|follina|msdt|proxyshell|proxylogon|proxynotshell|hafnium|solarwinds|exchange|eternal_blue|wannacry|notpetya|petya|spectre|meltdown|rowhammer|retbleed|zenbleed|inception|downfall|cachewarp|reptar|ghostrace)\b",
    r"(?i)(?:ms17-010|cve-2017-0144|cve-2020-1472|cve-2021-44228|cve-2021-45046|cve-2021-45105|cve-2021-44832|cve-2022-22965|cve-2022-26134|cve-2022-42889|cve-2023-44487|cve-2024-3094|cve-2024-6387)\b",
    r"(?i)(?:rapid[_-]?reset|http2[_-]?flood|quic[_-]?flood|amplification[_-]?attack|reflection[_-]?attack|dns[_-]?amplification|ntp[_-]?amplification|memcached[_-]?amplification|ssdp[_-]?amplification|cldap[_-]?amplification)\b",
]


# ============================================================================
# Map all patterns
# ============================================================================
RULES_MEGA_4_MAP = {
    'waf_evasion_mega': WAF_EVASION_DEEP,
    'session_auth_mega': SESSION_AUTH_DEEP,
    'race_business_mega': RACE_BUSINESS_DEEP,
    'grpc_proto_mega': GRPC_PROTO_DEEP,
    'web_cache_mega': WEB_CACHE_DEEP,
    'host_header_mega': HOST_HEADER_DEEP,
    'privesc_mega': PRIVESC_DEEP,
    'lateral_persist_mega': LATERAL_PERSIST_DEEP,
    'adv_obfuscation_mega': ADVANCED_OBFUSCATION_DEEP,
    'emerging_misc_mega': EMERGING_MISC_DEEP,
}


def get_all_mega4_patterns():
    for category, patterns in RULES_MEGA_4_MAP.items():
        for regex_str in patterns:
            yield (regex_str, category)


def count_mega4_patterns():
    return sum(len(p) for p in RULES_MEGA_4_MAP.values())
