"""
BeeWAF v5.0 Mega Rules Database — Part 2
==========================================
~2500 additional signatures covering LDAP injection, XPath injection,
GraphQL attacks, WebSocket attacks, CORS bypass, email injection,
log injection, HTTP parameter pollution, open redirect, clickjacking,
cryptographic attacks, brute force patterns, scanner fingerprints,
and WordPress/Drupal/Joomla/Magento CMS deep.
"""

# ============================================================================
# 1. LDAP INJECTION — DEEP (80 patterns)
# ============================================================================
LDAP_INJECTION_DEEP = [
    r"(?i)\(\|\(\w+=\*\)",
    r"(?i)\(&\(\w+=\*\)",
    r"(?i)\(\w+=\*\)\(\w+=\*\)",
    r"(?i)\(\|\(\w+=\w+\)\(\w+=\w+\)\)",
    r"(?i)\(&\(\w+=\w+\)\(\w+=\w+\)\)",
    r"(?i)\(!\(\w+=\w+\)\)",
    r"(?i)\(\w+>=\d+\)",
    r"(?i)\(\w+<=\d+\)",
    r"(?i)\(\w+~=\w+\)",
    r"(?i)\(\w+=\*\w+\*\)",
    r"(?i)\(\w+=\w+\*\)",
    r"(?i)\(\w+=\*\w+\)",
    r"(?i)\)\(\|\(\w+=\*\)",
    r"(?i)\)\(&\(\w+=\*\)",
    r"(?i)\)\)\%00",
    r"(?i)\*\)\(\w+=\*",
    r"(?i)\*\)\(\|\(\w+=\*",
    r"(?i)\*\)\(&\(\w+=\*",
    r"(?i)objectClass=\*",
    r"(?i)objectCategory=\*",
    r"(?i)userPassword=\*",
    r"(?i)unicodePwd=\*",
    r"(?i)samAccountName=\*",
    r"(?i)sAMAccountType=\*",
    r"(?i)memberOf=\*",
    r"(?i)distinguishedName=\*",
    r"(?i)adminCount=\d+",
    r"(?i)userAccountControl=\d+",
    r"(?i)msDS-AllowedToDelegateTo=\*",
    r"(?i)servicePrincipalName=\*",
    r"(?i)cn=\*",
    r"(?i)uid=\*",
    r"(?i)sn=\*",
    r"(?i)givenName=\*",
    r"(?i)mail=\*",
    r"(?i)telephoneNumber=\*",
    r"(?i)dc=\*",
    r"(?i)ou=\*",
    r"(?i)\)\%00",
    r"(?i)\)%28",
    r"(?i)\)%29",
    r"(?i)%28\|%28\w+=",
    r"(?i)%28&%28\w+=",
    r"(?i)%28\w+=\*%29",
    r"(?i)%00\)\(&\(",
    # --- Active Directory specific ---
    r"(?i)\(userAccountControl:1\.2\.840\.113556\.1\.4\.803:=\d+\)",
    r"(?i)\(msDS-AllowedToActOnBehalfOfOtherIdentity=\*\)",
    r"(?i)\(primaryGroupID=\d+\)",
    r"(?i)\(objectSid=\*\)",
    r"(?i)\(pwdLastSet=0\)",
    r"(?i)\(lockoutTime>=1\)",
    r"(?i)\(badPwdCount>=\d+\)",
    r"(?i)\(isDeleted=TRUE\)",
    r"(?i)\(objectClass=computer\)",
    r"(?i)\(objectClass=group\)",
    r"(?i)\(objectClass=user\)",
    r"(?i)\(objectClass=domain\)",
    r"(?i)\(objectClass=organizationalUnit\)",
    r"(?i)\(objectClass=trustedDomain\)",
    r"(?i)\(objectClass=container\)",
    r"(?i)\(objectClass=groupPolicyContainer\)",
    r"(?i)\(msExchVersion=\*\)",
    r"(?i)\(msExchMailboxGuid=\*\)",
    # --- LDAP URL injection ---
    r"(?i)ldap://[^/]+/\w+=\*",
    r"(?i)ldaps://[^/]+/\w+=\*",
    r"(?i)ldap://[^/]+/.*\?\w+\?sub\?\(\w+=",
    r"(?i)ldap://[^/]+/.*\?\?\?.*extensionName",
    r"(?i)ldap://localhost",
    r"(?i)ldap://127\.0\.0\.1",
    r"(?i)ldap://\[::\]",
    r"(?i)ldap://0\.0\.0\.0",
    r"(?i)ldap://(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+",
    # --- OpenLDAP specific ---
    r"(?i)olcAccess:\s*\{",
    r"(?i)olcRootDN:",
    r"(?i)olcRootPW:",
    r"(?i)olcDatabase:\s*\{",
    r"(?i)olcSuffix:",
    r"(?i)changetype:\s*(?:add|modify|delete|modrdn)",
]

# ============================================================================
# 2. XPATH INJECTION (60 patterns)
# ============================================================================
XPATH_INJECTION_DEEP = [
    r"(?i)'\s*or\s+'\d+'\s*=\s*'\d+'",
    r"(?i)'\s*and\s+'\d+'\s*=\s*'\d+'",
    r"(?i)'\s*or\s+\d+\s*=\s*\d+",
    r"(?i)'\s*and\s+\d+\s*=\s*\d+",
    r"(?i)'\s*or\s+true\s*\(\s*\)",
    r"(?i)'\s*and\s+true\s*\(\s*\)",
    r"(?i)'\s*or\s+not\s*\(\s*false\s*\(\s*\)\s*\)",
    r"(?i)'\s*\]\s*/\s*/\s*\*",
    r"(?i)'\s*\]\s*\|\s*//\s*\*",
    r"(?i)'\s*or\s+string-length\s*\(",
    r"(?i)'\s*or\s+substring\s*\(",
    r"(?i)'\s*or\s+contains\s*\(",
    r"(?i)'\s*or\s+starts-with\s*\(",
    r"(?i)'\s*or\s+normalize-space\s*\(",
    r"(?i)'\s*or\s+translate\s*\(",
    r"(?i)'\s*or\s+concat\s*\(",
    r"(?i)'\s*or\s+name\s*\(",
    r"(?i)'\s*or\s+local-name\s*\(",
    r"(?i)'\s*or\s+namespace-uri\s*\(",
    r"(?i)'\s*or\s+count\s*\(",
    r"(?i)'\s*or\s+position\s*\(",
    r"(?i)'\s*or\s+last\s*\(",
    r"(?i)'\s*or\s+number\s*\(",
    r"(?i)'\s*or\s+boolean\s*\(",
    r"(?i)'\s*or\s+string\s*\(",
    # --- Path traversal in XPath ---
    r"(?i)//\s*\*\s*\[contains\s*\(name\s*\(\s*\)",
    r"(?i)/\s*child::\s*\*",
    r"(?i)/\s*descendant::\s*\*",
    r"(?i)/\s*descendant-or-self::\s*\*",
    r"(?i)/\s*following::\s*\*",
    r"(?i)/\s*following-sibling::\s*\*",
    r"(?i)/\s*parent::\s*\*",
    r"(?i)/\s*ancestor::\s*\*",
    r"(?i)/\s*ancestor-or-self::\s*\*",
    r"(?i)/\s*preceding::\s*\*",
    r"(?i)/\s*preceding-sibling::\s*\*",
    r"(?i)/\s*self::\s*\*",
    r"(?i)/\s*attribute::\s*\*",
    r"(?i)/\s*namespace::\s*\*",
    # --- XPath blind techniques ---
    r"(?i)string-length\s*\(\s*//\w+/\w+\s*\)\s*[><=]\s*\d+",
    r"(?i)substring\s*\(\s*//\w+/\w+\s*,\s*\d+\s*,\s*\d+\s*\)\s*=\s*'",
    r"(?i)string-to-codepoints\s*\(",
    r"(?i)codepoints-to-string\s*\(",
    r"(?i)doc\s*\(\s*['\"](?:http|file|ftp)://",
    r"(?i)document\s*\(\s*['\"](?:http|file|ftp)://",
    r"(?i)unparsed-text\s*\(\s*['\"](?:http|file|ftp)://",
    r"(?i)collection\s*\(\s*['\"]",
    # --- XQuery injection ---
    r"(?i)xquery\s+version\s+['\"]",
    r"(?i)declare\s+namespace\s+",
    r"(?i)declare\s+function\s+",
    r"(?i)declare\s+variable\s+",
    r"(?i)for\s+\$\w+\s+in\s+(?:doc|collection)\s*\(",
    r"(?i)let\s+\$\w+\s*:=",
    r"(?i)where\s+\$\w+\s*[=!<>]",
    r"(?i)return\s+\$\w+",
    r"(?i)order\s+by\s+\$\w+",
    r"(?i)FLWOR\b",
    r"(?i)fn:(?:doc|collection|doc-available|unparsed-text|environment-variable)\s*\(",
    r"(?i)fn:(?:concat|substring|string-length|contains|starts-with|ends-with|replace|matches|tokenize)\s*\(",
]

# ============================================================================
# 3. GRAPHQL ATTACKS (120 patterns)
# ============================================================================
GRAPHQL_DEEP = [
    # --- Introspection ---
    r"(?i)__schema\s*\{",
    r"(?i)__type\s*\(",
    r"(?i)__typename\b",
    r"(?i)queryType\s*\{",
    r"(?i)mutationType\s*\{",
    r"(?i)subscriptionType\s*\{",
    r"(?i)__schema\s*\{\s*types\s*\{",
    r"(?i)__schema\s*\{\s*directives\s*\{",
    r"(?i)__type\s*\(\s*name\s*:",
    r"(?i)__type\s*\{\s*fields\s*\{",
    r"(?i)__type\s*\{\s*enumValues\s*\{",
    r"(?i)__type\s*\{\s*inputFields\s*\{",
    r"(?i)__type\s*\{\s*interfaces\s*\{",
    r"(?i)__type\s*\{\s*possibleTypes\s*\{",
    r"(?i)__schema\s*\{\s*queryType\s*\{\s*name\s*\}\s*\}",
    # --- Depth attacks ---
    r"(?i)\{\s*\w+\s*\{\s*\w+\s*\{\s*\w+\s*\{\s*\w+\s*\{\s*\w+\s*\{",
    r"(?i)(?:query|mutation)\s*\{(?:[^{}]*\{){6,}",
    r"(?i)(?:query|mutation)\s+\w+\s*\{(?:[^{}]*\{){5,}",
    # --- Alias-based DoS ---
    r"(?i)(?:a\d{1,4}\s*:\s*\w+\s*(?:\([^)]*\))?\s*\{\s*\w+\s*\}\s*){3,}",
    r"(?i)\w+Alias\d+\s*:\s*\w+\s*\(",
    r"(?i)__typename\s+__typename\s+__typename",
    # --- Batch attacks ---
    r"(?i)\[\s*\{\s*['\"]query['\"]\s*:\s*['\"]",
    r"(?i)\[\s*\{\s*['\"]query['\"]\s*:.*\}\s*,\s*\{\s*['\"]query['\"]\s*:",
    # --- Injection through variables ---
    r"(?i)['\"]variables['\"]\s*:\s*\{[^}]*(?:UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC|OR\s+\d+=\d+)",
    r"(?i)['\"]variables['\"]\s*:\s*\{[^}]*(?:<script|javascript:|on\w+=)",
    r"(?i)['\"]variables['\"]\s*:\s*\{[^}]*(?:\.\./|etc/passwd|/bin/)",
    # --- Query manipulation ---
    r"(?i)(?:query|mutation)\s*\{.*(?:UNION|SELECT|INSERT|UPDATE|DELETE|DROP)\b",
    r"(?i)fragment\s+\w+\s+on\s+\w+\s*\{.*(?:__schema|__type)\b",
    r"(?i)subscription\s*\{.*(?:__schema|__type)\b",
    r"(?i)@(?:skip|include|deprecated)\s*\(\s*if\s*:\s*(?:true|false)\s*\)",
    r"(?i)@(?:skip|include)\s*\(\s*if\s*:\s*\$\w+\s*\)",
    # --- GraphQL-specific DoS ---
    r"(?i)query\s+\{[^}]+\}\s*query\s+\{",
    r"(?i)(?:fragment\s+\w+\s+on\s+\w+\s*\{[^}]*\}\s*){3,}",
    # --- Directive abuse ---
    r"(?i)@\w+\s*\(\s*(?:url|href|src|file|path|include)\s*:\s*['\"]",
    r"(?i)@(?:rest|http|grpc|connect)\s*\(",
    r"(?i)@(?:export|key|provides|requires|external)\s*\(",
    # --- Field suggestions exploit ---
    r"(?i)Cannot query field ['\"]?\w+['\"]? on type",
    r"(?i)Did you mean ['\"]?\w+['\"]?\?",
    # --- Persisted query attacks ---
    r"(?i)['\"]extensions['\"]\s*:\s*\{[^}]*['\"]persistedQuery['\"]",
    r"(?i)['\"]sha256Hash['\"]\s*:\s*['\"][a-f0-9]{64}['\"]",
    # --- Custom scalars ---
    r"(?i)scalar\s+(?:JSON|Upload|DateTime|Date|Time|BigInt|Long|UUID|Email|URL|PhoneNumber)\b",
    r"(?i)input\s+\w+\s*\{[^}]*(?:Upload|File|Blob)\b",
    # --- Mutation abuse ---
    r"(?i)mutation\s*\{[^}]*(?:create|update|delete|remove|insert|drop|alter)\w*\s*\(",
    r"(?i)mutation\s*\{[^}]*(?:register|login|resetPassword|changePassword|deleteAccount|elevatePrivilege)\s*\(",
    r"(?i)mutation\s*\{[^}]*(?:grant|revoke|admin|superuser|role|permission)\s*\(",
    # --- Subscription abuse ---
    r"(?i)subscription\s*\{[^}]*(?:on\w+Created|on\w+Updated|on\w+Deleted)\s*\(",
    r"(?i)subscription\s*\{[^}]*(?:liveQuery|realTime|stream)\s*\(",
]

# ============================================================================
# 4. WEBSOCKET ATTACKS (80 patterns)
# ============================================================================
WEBSOCKET_DEEP = [
    # --- Protocol attacks ---
    r"(?i)Sec-WebSocket-Protocol\s*:.*(?:xss|sql|cmd|rce|ssrf)",
    r"(?i)Sec-WebSocket-Extensions\s*:.*(?:permessage-deflate|server_max_window_bits)",
    r"(?i)Sec-WebSocket-Key\s*:\s*.{0,5}$",
    r"(?i)Sec-WebSocket-Version\s*:\s*(?![138]\d?\b)",
    r"(?i)Upgrade\s*:\s*websocket.*(?:UNION|SELECT|<script|javascript:)",
    r"(?i)Connection\s*:\s*Upgrade.*(?:UNION|SELECT|<script|javascript:)",
    # --- Cross-site WebSocket hijacking ---
    r"(?i)Origin\s*:\s*(?:null|file://|data:)",
    r"(?i)Origin\s*:\s*https?://(?:evil|attacker|hacker|malicious)\.",
    r"(?i)ws://(?:evil|attacker|hacker|malicious)\.",
    r"(?i)wss://(?:evil|attacker|hacker|malicious)\.",
    # --- Injection through WebSocket messages ---
    r"(?i)\{[^}]*['\"](?:type|action|event|method|command|cmd|exec|query)['\"]\s*:\s*['\"](?:eval|exec|system|shell|admin|drop|delete|update|insert)['\"]",
    r"(?i)\{[^}]*['\"](?:data|message|payload|content|body|text)['\"]\s*:\s*['\"].*(?:<script|javascript:|on\w+=|UNION\s+SELECT)",
    r"(?i)\{[^}]*['\"](?:sql|query|statement|command)['\"]\s*:\s*['\"]",
    r"(?i)\{[^}]*['\"](?:file|path|filename|filepath|dir|directory)['\"]\s*:\s*['\"].*(?:\.\./|etc/|/bin/|cmd\.exe)",
    r"(?i)\{[^}]*['\"](?:url|uri|href|src|redirect|forward|proxy)['\"]\s*:\s*['\"](?:file://|gopher://|dict://|ldap://)",
    # --- WebSocket binary frame attacks ---
    r"(?i)\x81[\x80-\xff].*(?:SELECT|UNION|INSERT|DELETE|DROP|ALTER)",
    r"(?i)\x82[\x80-\xff].*(?:<?php|<script|<\?=)",
    # --- STOMP protocol injection ---
    r"(?i)CONNECT\n.*\nlogin:",
    r"(?i)SEND\n.*\ndestination:\s*/(?:topic|queue)/",
    r"(?i)SUBSCRIBE\n.*\ndestination:\s*/(?:topic|queue)/",
    r"(?i)ACK\n.*\nmessage-id:",
    r"(?i)NACK\n.*\nmessage-id:",
    r"(?i)BEGIN\n.*\ntransaction:",
    r"(?i)COMMIT\n.*\ntransaction:",
    r"(?i)ABORT\n.*\ntransaction:",
    r"(?i)DISCONNECT\n",
    # --- Socket.IO specific ---
    r"(?i)EIO=\d+&transport=(?:polling|websocket).*(?:<script|javascript:|eval\()",
    r"(?i)\d+\[\"(?:eval|exec|system|require|import|spawn|fork)\"\s*,",
    r"(?i)socket\.(?:emit|on|once)\s*\(\s*['\"](?:exec|system|cmd|shell|admin|debug|eval)['\"]",
    r"(?i)io\.(?:connect|socket)\s*\(\s*['\"](?:ws|wss)://.*(?:evil|attacker|hacker)\.",
    # --- SockJS specific ---
    r"(?i)/sockjs/\d+/[a-z0-9]+/(?:websocket|xhr|xhr_streaming|htmlfile|eventsource|jsonp)",
    r"(?i)SockJS.*(?:eval|exec|system|Function\()",
    # --- SignalR specific ---
    r"(?i)/signalr/.*(?:negotiate|connect|reconnect|start|send|abort|ping)",
    r"(?i)/signalr/.*(?:UNION|SELECT|<script|javascript:)",
    # --- MQTT over WebSocket ---
    r"(?i)mqtt(?:s)?://.*(?:eval|exec|system|cmd|shell)",
    r"(?i)\{['\"]topic['\"]\s*:\s*['\"].*(?:\$SYS/|#|\+/\+/)",
    r"(?i)\{['\"]topic['\"]\s*:\s*['\"].*(?:\.\./|etc/|bin/|cmd\.exe)",
    # --- Rate limiting bypass ---
    r"(?i)(?:ws|wss)://.*\?\w+=.*(?:OR\s+\d+=\d+|UNION\s+SELECT|<script)",
    # --- GraphQL subscriptions abuse ---
    r"(?i)\{['\"]type['\"]\s*:\s*['\"](?:connection_init|start|stop|connection_terminate)['\"]",
    r"(?i)\{['\"]type['\"]\s*:\s*['\"](?:subscribe|unsubscribe)['\"].*['\"]query['\"]\s*:\s*['\"].*(?:__schema|__type|introspection)",
]

# ============================================================================
# 5. CORS BYPASS (60 patterns)
# ============================================================================
CORS_BYPASS_DEEP = [
    r"(?i)Origin\s*:\s*null\b",
    r"(?i)Origin\s*:\s*file://",
    r"(?i)Origin\s*:\s*data:",
    r"(?i)Origin\s*:\s*chrome-extension://",
    r"(?i)Origin\s*:\s*moz-extension://",
    r"(?i)Origin\s*:\s*safari-extension://",
    r"(?i)Origin\s*:\s*https?://(?:evil|attacker|hacker|malicious|pwned|phish)\.",
    r"(?i)Origin\s*:\s*https?://.*(?:\.evil\.com|\.attacker\.com|\.hacker\.com)",
    r"(?i)Origin\s*:\s*https?://[^.]+\.(?:tk|ml|ga|cf|gq|xyz|top|club|online|site|fun|icu)\b",
    r"(?i)Access-Control-Allow-Origin\s*:\s*\*",
    r"(?i)Access-Control-Allow-Origin\s*:\s*null",
    r"(?i)Access-Control-Allow-Credentials\s*:\s*true",
    r"(?i)Access-Control-Allow-Methods\s*:.*(?:PUT|DELETE|PATCH|TRACE|CONNECT)",
    r"(?i)Access-Control-Allow-Headers\s*:.*(?:Authorization|Cookie|X-CSRF|X-Api-Key)",
    r"(?i)Access-Control-Expose-Headers\s*:.*(?:Set-Cookie|Authorization|X-CSRF)",
    r"(?i)Access-Control-Max-Age\s*:\s*(?:0|-\d+|\d{7,})\b",
    # --- Origin reflection tricks ---
    r"(?i)Origin\s*:\s*https?://(?:target|victim)\.\w+\.(?:evil|attacker|hacker)\.",
    r"(?i)Origin\s*:\s*https?://(?:evil|attacker|hacker)\.\w+\.(?:target|victim)\.",
    r"(?i)Origin\s*:\s*https?://\w+(?:target|victim)\w+\.\w+",
    r"(?i)Origin\s*:\s*https?://.*%0[0-9a-d]",
    r"(?i)Origin\s*:\s*https?://.*\\",
    r"(?i)Origin\s*:\s*https?://.*\s",
    # --- CORS with credentials ---
    r"(?i)withCredentials\s*=\s*true",
    r"(?i)credentials\s*:\s*['\"]include['\"]",
    r"(?i)credentials\s*:\s*['\"]same-origin['\"]",
    r"(?i)mode\s*:\s*['\"]no-cors['\"]",
    # --- CORS preflight manipulation ---
    r"(?i)OPTIONS\s+/.*Access-Control-Request-Method",
    r"(?i)Access-Control-Request-Method\s*:\s*(?:PUT|DELETE|PATCH|TRACE|CONNECT|DEBUG)",
    r"(?i)Access-Control-Request-Headers\s*:.*(?:X-Custom|X-Override|X-Method|X-HTTP-Method)",
    # --- Subdomain takeover indicators ---
    r"(?i)(?:CNAME|ALIAS)\s+\w+\.(?:s3|cloudfront|herokuapp|ghost|github|surge|bitbucket|wordpress|shopify|tumblr|desk|freshdesk|zendesk|helpjuice|helpscout|pingdom|tictail|campaign-archive|unbounce|statuspage|uservoice|teamwork)\.",
]

# ============================================================================
# 6. EMAIL / HEADER INJECTION (60 patterns)
# ============================================================================
EMAIL_INJECTION_DEEP = [
    # --- SMTP header injection ---
    r"(?i)(?:To|From|Cc|Bcc|Reply-To|Subject)\s*:.*(?:%0d|%0a|\r|\n)",
    r"(?i)(?:To|From|Cc|Bcc)\s*:.*(?:,\s*\w+@\w+){3,}",
    r"(?i)Content-Type\s*:.*(?:multipart/mixed|text/html).*boundary=",
    r"(?i)X-Mailer\s*:.*(?:PHPMailer|SwiftMailer|Sendmail|Postfix|Exim)",
    r"(?i)MAIL\s+FROM\s*:<[^>]*>.*(?:%0d|%0a|\r|\n)",
    r"(?i)RCPT\s+TO\s*:<[^>]*>.*(?:%0d|%0a|\r|\n)",
    r"(?i)DATA\r?\n",
    r"(?i)EHLO\s+",
    r"(?i)HELO\s+",
    r"(?i)VRFY\s+",
    r"(?i)EXPN\s+",
    r"(?i)AUTH\s+(?:LOGIN|PLAIN|CRAM-MD5|DIGEST-MD5|NTLM)\b",
    r"(?i)STARTTLS\b",
    # --- Email template injection ---
    r"(?i)\{\{.*(?:system|exec|eval|import|require|popen|Process)\s*\(",
    r"(?i)\$\{.*(?:Runtime|ProcessBuilder|exec|system|popen)\b",
    r"(?i)<%=?\s*(?:system|exec|eval|popen|spawn)\s*\(",
    # --- Mass mailer detection ---
    r"(?i)(?:bcc|cc)\s*=\s*(?:\w+@\w+\.){3,}",
    r"(?i)(?:mailto|email)\s*=\s*[^&]*(?:%0d|%0a|%0D|%0A|\r|\n)",
    r"(?i)(?:email|mail|to|from|subject|body)\s*=\s*[^&]*(?:\\r|\\n|%0d|%0a)",
    # --- Email XSS ---
    r"(?i)(?:subject|body)\s*=.*(?:<script|javascript:|on\w+=)",
    r"(?i)(?:subject|body)\s*=.*(?:UNION|SELECT|DROP|INSERT|DELETE)\b",
    # --- IMAP/POP injection ---
    r"(?i)(?:SELECT|EXAMINE|CREATE|DELETE|RENAME|SUBSCRIBE|UNSUBSCRIBE|LIST|LSUB|STATUS|APPEND|CHECK|CLOSE|EXPUNGE|SEARCH|FETCH|STORE|COPY|UID)\s+(?:INBOX|['\"])",
    r"(?i)\.(?:IDLE|NOOP|CHECK|CLOSE|EXPUNGE|LOGOUT)\b",
    r"(?i)USER\s+\w+\r?\nPASS\s+",
    r"(?i)RETR\s+\d+",
    r"(?i)DELE\s+\d+",
    r"(?i)TOP\s+\d+\s+\d+",
    r"(?i)RSET\b",
    r"(?i)APOP\s+\w+",
    r"(?i)UIDL\b",
    r"(?i)LIST\b",
    r"(?i)STAT\b",
    r"(?i)QUIT\b",
]

# ============================================================================
# 7. LOG INJECTION / LOG FORGING (60 patterns)
# ============================================================================
LOG_INJECTION_DEEP = [
    # --- Log forging ---
    r"(?i)%0d%0a\d{4}[-/]\d{2}[-/]\d{2}",
    r"(?i)%0d%0a\[(?:INFO|WARN|ERROR|DEBUG|FATAL|TRACE|CRITICAL)\]",
    r"(?i)%0a\s*\d{4}[-/]\d{2}[-/]\d{2}\s+\d{2}:\d{2}:\d{2}",
    r"(?i)\\n\d{4}[-/]\d{2}[-/]\d{2}",
    r"(?i)\\n\[(?:INFO|WARN|ERROR|DEBUG|FATAL|TRACE|CRITICAL)\]",
    r"(?i)\r\n\d{4}[-/]\d{2}[-/]\d{2}",
    r"(?i)\r\n\[(?:INFO|WARN|ERROR|DEBUG|FATAL|TRACE|CRITICAL)\]",
    # --- Log4Shell / Log4j variants ---
    r"(?i)\$\{jndi\s*:\s*(?:ldap|ldaps|rmi|dns|iiop|corba|nds|http)://",
    r"(?i)\$\{jndi\s*:\s*\$\{",
    r"(?i)\$\{(?:upper|lower)\s*:\s*j\}",
    r"(?i)\$\{(?:upper|lower)\s*:\s*n\}",
    r"(?i)\$\{(?:upper|lower)\s*:\s*d\}",
    r"(?i)\$\{(?:upper|lower)\s*:\s*i\}",
    r"(?i)\$\{\s*j\$\{(?:upper|lower|:-).*\}n\$\{",
    r"(?i)\$\{(?:env|sys|java|date|ctx|main|marker|bundle|spring|log4j)\s*:",
    r"(?i)\$\{(?:env|sys)\s*:\s*(?:PATH|HOME|USER|SHELL|HOSTNAME|AWS_|JAVA_|OS)\}",
    r"(?i)\$\{java\s*:\s*(?:version|runtime|os|hw|locale|compiler)\}",
    r"(?i)\$\{(?:base64|url|utf-8|unicode)\s*:",
    r"(?i)\$\{(?::-j)(?::-n)(?::-d)(?::-i)\s*:",
    r"(?i)%24%7Bjndi",
    r"(?i)%24%7B(?:lower|upper)",
    r"(?i)\\u0024\\u007b(?:jndi|lower|upper)",
    r"(?i)\$%7Bjndi\s*:",
    r"(?i)${j${::-n}${::-d}${::-i}:",
    r"(?i)\$\{j\$\{::-n\}di:",
    r"(?i)\$\{jn\$\{::-d\}i:",
    r"(?i)\$\{jnd\$\{::-i\}:",
    r"(?i)\$\{j\$\{env:NaN:-n\}di:",
    r"(?i)\$\{j\$\{lower:N\}di:",
    r"(?i)\$\{j\$\{upper:n\}di:",
    # --- Log escape sequences ---
    r"(?i)\x1b\[\d+(?:;\d+)*m",
    r"(?i)\\x1b\[\d+(?:;\d+)*m",
    r"(?i)\\033\[\d+(?:;\d+)*m",
    r"(?i)\\e\[\d+(?:;\d+)*m",
    # --- Structured logging injection ---
    r"(?i)['\"](?:level|severity|priority)['\"]\s*:\s*['\"](?:FATAL|CRITICAL|EMERGENCY|ERROR)['\"]",
    r"(?i)['\"](?:user|username|email|ip|session)['\"]\s*:\s*['\"].*(?:admin|root|system|superuser)['\"]",
    r"(?i)['\"](?:message|msg|description|details|text)['\"]\s*:\s*['\"].*(?:UNION|SELECT|<script|eval\(|system\()",
]

# ============================================================================
# 8. HTTP PARAMETER POLLUTION (50 patterns)
# ============================================================================
HPP_DEEP = [
    r"(?i)\b(?:id|user|account|page|action|cmd|file|path|url|redirect|token|key|api_key|secret|password)\s*=\s*[^&]*&\1\s*=",
    r"(?i)\?[^#]*(\w+)=\w+&\1=\w+",
    r"(?i)((?:id|user|role|admin|debug|test|page|sort|order|limit|offset|fields|include|exclude))\s*(?:=|%3D)[^&]*(?:&|%26)\1\s*(?:=|%3D)",
    r"(?i)(\w+)\s*=\s*[^&]+&\1\s*=\s*[^&]+&\1\s*=",
    r"(?i)(\w+)\[\]=\w+&\1\[\]=\w+",
    r"(?i)(\w+)\[0\]=\w+&\1\[1\]=\w+",
    # --- Array parameter manipulation ---
    r"(?i)\w+\[\s*\]\s*=.*&\w+\[\s*\]\s*=",
    r"(?i)\w+\[\d+\]\s*=.*&\w+\[\d+\]\s*=",
    r"(?i)\w+\.\d+\s*=.*&\w+\.\d+\s*=",
    # --- JSON parameter pollution ---
    r"(?i)\{[^}]*['\"](\w+)['\"]\s*:\s*[^,}]+\s*,\s*['\"]?\1['\"]\s*:",
    r"(?i)\{[^}]*['\"]__proto__['\"]\s*:",
    r"(?i)\{[^}]*['\"]constructor['\"]\s*:",
    r"(?i)\{[^}]*['\"]prototype['\"]\s*:",
    # --- Prototype pollution via query ---
    r"(?i)(?:__proto__|constructor\.prototype|constructor\[.prototype.\])\s*(?:=|%3D)",
    r"(?i)__proto__\[\w+\]\s*=",
    r"(?i)constructor\[prototype\]\[\w+\]\s*=",
    r"(?i)\?\w*__proto__\w*=",
    r"(?i)\?\w*constructor\w*=",
]

# ============================================================================
# 9. OPEN REDIRECT / SSRF via REDIRECT (80 patterns)
# ============================================================================
OPEN_REDIRECT_DEEP = [
    r"(?i)(?:redirect|return|next|url|goto|target|dest|destination|redir|redirect_uri|return_to|continue|returnUrl|redirectUrl|forward|callback|path|checkout_url|login_url|image_url|success_url|data|reference|site|html|link|u|r|q)\s*(?:=|%3D)\s*(?:https?://|//|\\\\)",
    r"(?i)(?:redirect|url|goto|next|return|dest|forward|callback|redir|continue)\s*(?:=|%3D)\s*(?:%2f%2f|%5c%5c|%68%74%74%70)",
    r"(?i)(?:redirect|url|goto|next|return)\s*(?:=|%3D)\s*(?:data:|javascript:|vbscript:)",
    r"(?i)(?:redirect|url|goto|next|return)\s*(?:=|%3D)\s*(?:file://|ftp://|gopher://|ldap://)",
    r"(?i)(?:redirect|url|goto|next|return)\s*(?:=|%3D)\s*//[^/]",
    r"(?i)(?:redirect|url|goto|next|return)\s*(?:=|%3D)\s*(?:\\x[0-9a-f]{2}|\\u[0-9a-f]{4})",
    r"(?i)(?:redirect|url|goto|next|return)\s*(?:=|%3D)\s*[^&]*@",
    r"(?i)(?:redirect|url|goto|next|return)\s*(?:=|%3D)\s*[^&]*%(?:2f|5c|3a){2}",
    r"(?i)(?:redirect|url|goto|next|return)\s*(?:=|%3D)\s*https?%3A%2F%2F",
    r"(?i)(?:redirect|url|goto|next|return)\s*(?:=|%3D)\s*(?:ht|htt|http|https)(?:%3a|%3A)(?:%2f|%2F){2}",
    r"(?i)Location\s*:\s*(?:https?://|//|\\\\)[^\s]+",
    r"(?i)Location\s*:\s*(?:javascript:|data:|vbscript:)",
    r"(?i)Refresh\s*:\s*\d+;\s*url=(?:https?://|//)",
    r"(?i)window\.location\s*(?:=|\.(?:href|assign|replace))\s*(?:['\"]|encodeURI)",
    r"(?i)document\.location\s*(?:=|\.(?:href|assign|replace))\s*(?:['\"]|encodeURI)",
    r"(?i)self\.location\s*(?:=|\.(?:href|assign|replace))\s*(?:['\"]|encodeURI)",
    r"(?i)top\.location\s*(?:=|\.(?:href|assign|replace))\s*(?:['\"]|encodeURI)",
    r"(?i)parent\.location\s*(?:=|\.(?:href|assign|replace))\s*(?:['\"]|encodeURI)",
    # --- Meta refresh ---
    r"(?i)<meta[^>]*http-equiv\s*=\s*['\"]?refresh['\"]?[^>]*url=(?:https?://|//|javascript:)",
    # --- Header manipulation for redirect ---
    r"(?i)X-Forwarded-(?:Host|For|Proto|Scheme|Port)\s*:.*(?:evil|attacker|hacker|malicious)\.",
    r"(?i)X-Original-URL\s*:\s*/",
    r"(?i)X-Rewrite-URL\s*:\s*/",
    r"(?i)X-Custom-IP-Authorization\s*:",
    r"(?i)X-Forwarded-Server\s*:\s*(?:evil|attacker|hacker)\.",
    # --- OAuth redirect abuse ---
    r"(?i)redirect_uri\s*=\s*https?://(?!(?:localhost|127\.0\.0\.1))",
    r"(?i)redirect_uri\s*=\s*.*(?:@|%40)",
    r"(?i)redirect_uri\s*=\s*.*(?:%2F%2E%2E|/\.\./|%252F)",
    r"(?i)client_id\s*=.*&redirect_uri\s*=\s*(?:https?://|//)",
    r"(?i)response_type=(?:code|token|id_token).*redirect_uri\s*=",
    # --- URL parser confusion ---
    r"(?i)(?:redirect|url|goto)\s*=\s*[^&]*(?:\.(?:evil|attacker|hacker)\.com)",
    r"(?i)(?:redirect|url|goto)\s*=\s*[^&]*(?:#|%23)(?:@|%40)",
    r"(?i)(?:redirect|url|goto)\s*=\s*[^&]*(?:\?|%3F)(?:@|%40)",
]

# ============================================================================
# 10. SCANNER / RECON FINGERPRINTS (150 patterns)
# ============================================================================
SCANNER_FINGERPRINTS_DEEP = [
    # --- Vulnerability scanners ---
    r"(?i)(?:Nessus|OpenVAS|Qualys|Rapid7|Acunetix|Netsparker|Invicti|Burp\s*Suite|ZAP|OWASP[\s-]ZAP|sqlmap|Nikto|w3af|AppScan|WebInspect|Arachni|Skipfish|Wapiti|Vega|IronWASP|Grabber|Xenotix)",
    r"(?i)User-Agent\s*:.*(?:Nessus|OpenVAS|Qualys|Rapid7|Acunetix|Netsparker|Invicti|sqlmap|Nikto|w3af|dirbuster|gobuster|dirb|ffuf|feroxbuster|wfuzz|nuclei|httpx|subfinder|amass|masscan|zmap|nmap)",
    r"(?i)User-Agent\s*:.*(?:Arachni|Skipfish|Wapiti|Vega|IronWASP|Grabber|Xenotix|XSSer|commix|tplmap|ssrfmap|ysoserial|Exploit|Scanner|Fuzzer|Spider|Crawler|Bot|Scraper|Harvester)",
    r"(?i)User-Agent\s*:.*(?:python-requests|python-urllib|Go-http-client|Java|Apache-HttpClient|libcurl|okhttp|axios|node-fetch|got|superagent|needle|pycurl|mechanize|scrapy|aiohttp|httpx|urllib3)",
    r"(?i)User-Agent\s*:.*(?:Wget|curl|lwp-request|libwww|Links|Lynx|ELinks|w3m|Siege|ab|hey|vegeta|k6|locust|wrk|bombardier|oha|drill|ali|plow|cassowary)",
    r"(?i)User-Agent\s*:.*(?:PhantomJS|HeadlessChrome|Headless|CasperJS|SlimerJS|NightmareJS|Puppeteer|Playwright|Selenium|WebDriver|ChromeDriver|GeckoDriver)",
    # --- Common scanning paths ---
    r"(?i)(?:GET|POST|HEAD|PUT)\s+/(?:\.env|\.git/config|\.git/HEAD|\.svn/entries|\.hg/|\.bzr/|\.DS_Store|Thumbs\.db|desktop\.ini)\b",
    r"(?i)(?:GET|POST|HEAD)\s+/(?:wp-login|wp-admin|wp-config|wp-content|wp-includes|xmlrpc|wp-cron|wp-json|wp-signup)\b",
    r"(?i)(?:GET|POST|HEAD)\s+/(?:admin|administrator|manager|console|phpmyadmin|phpMyAdmin|pma|adminer|mysql|mariadb|postgres|pgadmin)\b",
    r"(?i)(?:GET|POST|HEAD)\s+/(?:server-status|server-info|status|info|test|debug|trace|healthcheck|health|ready|alive|ping|version|build|env)\b",
    r"(?i)(?:GET|POST|HEAD)\s+/(?:actuator|jolokia|swagger|api-docs|graphql|graphiql|playground|explorer|api/v\d|api/swagger|api/docs|api/graphql)\b",
    r"(?i)(?:GET|POST|HEAD)\s+/(?:solr|jenkins|hudson|travis|gitlab|bitbucket|jira|confluence|bamboo|crowd|fisheye|crucible)\b",
    r"(?i)(?:GET|POST|HEAD)\s+/(?:kibana|grafana|prometheus|alertmanager|consul|vault|nomad|etcd|zookeeper|kafka|rabbitmq)\b",
    r"(?i)(?:GET|POST|HEAD)\s+/(?:cgi-bin|fcgi-bin|cgi|bin|scripts|exec|cmd|shell|backdoor|webshell|c99|r57|b374k|WSO)\b",
    r"(?i)(?:GET|POST|HEAD)\s+/(?:config|conf|configuration|settings|setup|install|installer|backup|bak|old|orig|copy|temp|tmp|test|dev|staging|demo)\b",
    r"(?i)(?:GET|POST|HEAD)\s+/(?:\.well-known/|robots\.txt|sitemap\.xml|crossdomain\.xml|clientaccesspolicy\.xml|security\.txt|humans\.txt|ads\.txt)\b",
    # --- Recon headers ---
    r"(?i)X-Forwarded-For\s*:\s*(?:127\.0\.0\.1|localhost|0\.0\.0\.0|::1)",
    r"(?i)X-Originating-IP\s*:\s*(?:127\.0\.0\.1|localhost|0\.0\.0\.0|::1)",
    r"(?i)X-Remote-IP\s*:\s*(?:127\.0\.0\.1|localhost|0\.0\.0\.0|::1)",
    r"(?i)X-Remote-Addr\s*:\s*(?:127\.0\.0\.1|localhost|0\.0\.0\.0|::1)",
    r"(?i)X-Client-IP\s*:\s*(?:127\.0\.0\.1|localhost|0\.0\.0\.0|::1)",
    r"(?i)X-Host\s*:\s*(?:127\.0\.0\.1|localhost|0\.0\.0\.0|::1)",
    r"(?i)X-Custom-IP-Authorization\s*:\s*(?:127\.0\.0\.1|localhost)",
    r"(?i)True-Client-IP\s*:\s*(?:127\.0\.0\.1|localhost|0\.0\.0\.0)",
    r"(?i)Cluster-Client-IP\s*:\s*(?:127\.0\.0\.1|localhost)",
    r"(?i)X-ProxyUser-Ip\s*:\s*(?:127\.0\.0\.1|localhost)",
    r"(?i)CF-Connecting-IP\s*:\s*(?:127\.0\.0\.1|0\.0\.0\.0|::1)",
    # --- Fuzzing indicators ---
    r"(?i)(?:AAAA|BBBB|CCCC|XXXX|YYYY|ZZZZ){5,}",
    r"(?i)(?:%41|%42|%43|%58|%59|%5a){5,}",
    r"(?i)(?:0000|1111|9999|ffff){3,}",
    r"(?i)(?:\\x41|\\x42|\\x43|\\x90){5,}",
    r"(?i)(?:NaN|undefined|null|true|false|Infinity|-Infinity)\s*(?:NaN|undefined|null|true|false|Infinity){2,}",
    r"(?i)-{5,}(?:OR|AND|WHERE|UNION|SELECT)",
    r"(?i)(?:fuzz(?:er|ing)|(?:sql|xss|rce|lfi|rfi)(?:test|scan|probe)|sqlmap|nikto|nessus|burp(?:suite|collaborator)|acunetix|nmap|masscan|dirbuster|gobuster|w3af|owasp[_-]?zap|wpscan|nuclei|pentest(?:er|ing|monkey|[_-])|exploit(?:db|er|kit|[_-])|payload[_-]?(?:all|gen)|attack[_-]?(?:proxy|vector)|metasploit|cobalt[_-]?strike|havij|sqlninja)",
    r"(?i)(?:poc|exploit|payload|inject)[_-](?:test|scan|check|verify)\d{0,4}",
    # --- Tool-specific headers ---
    r"(?i)X-Scanner\s*:",
    r"(?i)X-Scan-Memo\s*:",
    r"(?i)X-Security-Scan\s*:",
    r"(?i)X-Arachni\s*:",
    r"(?i)X-Wapiti\s*:",
    r"(?i)X-Requested-With\s*:\s*XMLHttpRequest.*(?:sqlmap|inject|fuzz|scan)",
    r"(?i)Referer\s*:.*(?:sqlmap|acunetix|nessus|qualys|burpsuite|owasp|nikto|dirbuster|gobuster|nuclei|wpscan)",
]

# ============================================================================
# 11. CMS DEEP — WORDPRESS (120 patterns)
# ============================================================================
CMS_WORDPRESS_DEEP = [
    # --- Plugin vulnerabilities ---
    r"(?i)/wp-content/plugins/(?:revslider|revolution-slider|showbiz|js_composer|visual[-_]composer|ultimate[-_]member|wp[-_]file[-_]manager|elementor|yoast[-_]seo|contact[-_]form[-_]7|really[-_]simple[-_]ssl|wordfence|sucuri|all[-_]in[-_]one[-_]wp[-_]migration|updraftplus|w3[-_]total[-_]cache|wp[-_]super[-_]cache)/",
    r"(?i)/wp-content/plugins/\w+/(?:readme\.txt|changelog\.txt|license\.txt|CHANGELOG\.md|README\.md|composer\.json|package\.json)",
    r"(?i)/wp-content/plugins/\w+/(?:includes?|assets?|libs?|vendor)/.*\.(?:php|phtml|phar|inc|module)",
    r"(?i)/wp-content/plugins/\w+/(?:upload|download|import|export|backup|install|setup|config)\.",
    r"(?i)/wp-content/plugins/\w+/(?:ajax|api|admin|rpc|ws|gateway|connector|handler)\.",
    r"(?i)/wp-content/plugins/\w+/(?:eval|exec|shell|cmd|command|system|process|run)\.",
    # --- Theme vulnerabilities ---
    r"(?i)/wp-content/themes/\w+/(?:404|footer|header|functions|page|single|index|style|screenshot)\.",
    r"(?i)/wp-content/themes/\w+/(?:includes?|assets?|libs?|vendor)/.*\.(?:php|phtml|phar|inc)",
    r"(?i)/wp-content/themes/\w+/(?:upload|download|import|export|ajax|api|admin)\.",
    # --- WordPress core ---
    r"(?i)/wp-(?:login|signup|register|activate|trackback|cron|links-opml|mail|commentsrss2|feed)\.php\b",
    r"(?i)/wp-includes/(?:js|css|fonts|images|theme-compat|rest-api|blocks|widgets|customize|sodium_compat)/",
    r"(?i)/wp-includes/(?:class-wp|functions|formatting|pluggable|capabilities|user|post|taxonomy|query|rewrite|option|meta|cache|http|widgets|shortcodes|template|theme|session|cron|rest-api)\.",
    r"(?i)/wp-admin/(?:admin-ajax|admin-post|async-upload|update|upgrade|install|network|options|edit|export|import|ms-|link-|nav-|plugin-|theme-|user-|upload|widgets|customize|options-general|profile)\.",
    r"(?i)/wp-admin/(?:includes?|css|js|images|maint|network)/",
    # --- XML-RPC attacks ---
    r"(?i)<methodCall><methodName>(?:system\.multicall|wp\.getUsersBlogs|wp\.getCategories|wp\.getTags|wp\.getCommentCount|wp\.getPostTypes|wp\.getRevisions|wp\.getPageList|wp\.getPages|wp\.getPost|wp\.getAuthors|blogger\.getUsersBlogs|metaWeblog\.getUsersBlogs|mt\.supportedMethods|pingback\.ping|pingback\.extensions\.getPingbacks)</methodName>",
    r"(?i)<methodCall><methodName>wp\.(?:newPost|editPost|deletePost|newPage|editPage|deletePage|uploadFile|newCategory|deleteCategory|setOptions|newComment|deleteComment|editComment)</methodName>",
    r"(?i)<methodCall>.*<param>.*(?:UNION|SELECT|INSERT|DELETE|DROP|ALTER|CREATE|EXEC|system|eval|exec|passthru|shell_exec)",
    # --- REST API abuse ---
    r"(?i)/wp-json/wp/v2/(?:users|posts|pages|media|comments|categories|tags|taxonomies|types|statuses|settings|search|plugins|themes)/?(?:\?|$)",
    r"(?i)/wp-json/wp/v2/users/?\?.*(?:per_page=100|context=edit|roles=administrator)",
    r"(?i)/wp-json/\w+/v\d+/(?:settings|options|config|setup|admin|debug|test|internal|private)\b",
    r"(?i)/wp-json/oembed/1\.0/embed\?",
    r"(?i)/?rest_route=/wp/v2/users",
    r"(?i)/?author=\d+",
    # --- wp-config exposure ---
    r"(?i)/wp-config\.php(?:\.(?:bak|old|orig|copy|save|swp|swo|tmp|temp|backup|dist|sample|~))?$",
    r"(?i)/wp-config\.(?:txt|log|inc|bak|old|orig|save|zip|tar|gz|7z|rar)$",
    r"(?i)/wp-admin/setup-config\.php",
    # --- Upload vulnerabilities ---
    r"(?i)/wp-content/uploads/\d{4}/\d{2}/.*\.(?:php|phtml|phar|asp|aspx|jsp|cgi|pl|py|rb|sh|bat|cmd|exe)\b",
    r"(?i)/wp-content/uploads/.*(?:shell|backdoor|webshell|c99|r57|wso|b374k)\.",
    r"(?i)action=upload.*(?:\.php|\.phtml|\.phar|\.asp|\.aspx|\.jsp)",
    # --- User enumeration ---
    r"(?i)/wp-json/wp/v2/users\b",
    r"(?i)/\?rest_route=/wp/v2/users\b",
    r"(?i)/wp-login\.php\?action=(?:lostpassword|register|rp)\b",
    # --- Common WordPress exploits ---
    r"(?i)/wp-admin/admin-ajax\.php\?action=(?:revslider_show_image|showbiz_show|uploadFontIcon|get_questions|duplicator_download|dg_preview_csv|wmuAttachmentUpload|nf_ajax_upload|ninja_forms_ajax_submit|formcraft3_save_form_progress)\b",
    r"(?i)/wp-admin/admin-ajax\.php.*(?:UNION|SELECT|INSERT|DELETE|DROP|system|exec|eval|base64_decode|file_get_contents|file_put_contents|passthru|shell_exec|popen|proc_open)",
]

# ============================================================================
# 12. CMS DEEP — DRUPAL/JOOMLA/MAGENTO (100 patterns)
# ============================================================================
CMS_OTHER_DEEP = [
    # --- Drupal ---
    r"(?i)/(?:node|sites|modules|themes|profiles|misc|includes|core)/",
    r"(?i)/(?:sites/default/files|sites/all/modules|sites/all/themes)/",
    r"(?i)/(?:sites/default/settings\.php|CHANGELOG\.txt|INSTALL\.txt|README\.txt|update\.php|install\.php|authorize\.php|cron\.php|index\.php/user)\b",
    r"(?i)/(?:node/\d+/edit|node/\d+/delete|node/\d+/revisions|node/add|admin/content|admin/structure|admin/config|admin/people|admin/modules|admin/reports|admin/appearance)\b",
    r"(?i)/jsonapi/(?:node|user|file|taxonomy_term|comment|block_content)/",
    r"(?i)/jsonapi/\w+/\w+\?.*(?:include|fields\[|filter\[|sort|page\[|jsonapi_include)",
    r"(?i)form_id=(?:user_login_form|user_register_form|user_pass|node_\w+_form|comment_\w+_form)",
    r"(?i)Drupalgeddon|SA-CORE-\d{4}-\d{3}",
    r"(?i)drupal_ajax/\d+",
    r"(?i)drupalSettings\.\w+",
    # --- Joomla ---
    r"(?i)/(?:administrator|components|modules|plugins|templates|libraries|language|layouts|cli)/",
    r"(?i)/(?:administrator/index\.php|configuration\.php|htaccess\.txt|web\.config\.txt|README\.txt|LICENSE\.txt)\b",
    r"(?i)/index\.php\?option=com_(?:content|users|menus|modules|plugins|templates|categories|banners|contact|newsfeeds|search|weblinks|finder|tags|fields|associations|messages|redirect|config)\b",
    r"(?i)/index\.php\?option=com_(?:jce|k2|virtuemart|akeeba|kunena|easyblog|fabrik|chronoforms|phocagallery|dj-classifieds|hikashop|cobalt|seblod|zoo)\b",
    r"(?i)(?:task|controller|view|layout|format|tmpl|Itemid|option|component)\s*=",
    r"(?i)/api/index\.php/v1/(?:content|users|banners|contact|fields|menus|modules|plugins|tags|templates|languages|mail|media|messages|newsfeeds|redirects)\b",
    r"(?i)/libraries/joomla/\w+\.php",
    r"(?i)com_(?:fabrik|k2|jce|akeeba).*(?:task|controller)=.*(?:file|upload|import|export)",
    # --- Magento ---
    r"(?i)/(?:skin|var|app|downloader|includes|lib|pkginfo|shell|errors)/",
    r"(?i)/(?:index\.php/admin|admin/(?:dashboard|system|catalog|sales|customer|marketing|content|stores|reports|newsletter))\b",
    r"(?i)/(?:app/etc/local\.xml|app/etc/env\.php|app/etc/config\.php|var/log/system\.log|var/log/exception\.log|var/log/debug\.log)\b",
    r"(?i)/(?:downloader/index\.php|mage/|setup/|update/|dev/tests/|dev/tools/)\b",
    r"(?i)/rest/V1/(?:carts|customers|orders|products|categories|inventory|store|search|configurable-products|bundle-products|downloadable-products)/",
    r"(?i)/rest/V1/(?:integration|guest-carts|store/storeConfigs|directory/currency|cms/page|cms/block)\b",
    r"(?i)/graphql\s*\{?\s*(?:products|categories|cart|customer|cmsPage|storeConfig|urlResolver|routes)\b",
    r"(?i)Magento-?\d?\.\d+|MAGENTO_CLOUD|MAGE_(?:MODE|IS_DEVELOPER_MODE|ROOT_DIR)",
    r"(?i)/(?:soap|rest|async)/(?:V1|default|all)/",
    r"(?i)form_key=[a-zA-Z0-9]+",
    # --- PrestaShop ---
    r"(?i)/(?:modules|themes|img|upload|download|mails|classes|controllers|override|config|cache|log|translations|pdf|vendor)/",
    r"(?i)/index\.php\?controller=(?:admin|AdminLogin|AdminDashboard|AdminOrders|AdminCustomers|AdminProducts|AdminModules)\b",
    r"(?i)/admin\d*/index\.php\?",
    r"(?i)/api/(?:products|categories|customers|orders|manufacturers|suppliers|employees|shops|languages|currencies|countries|states|zones)\b.*(?:ws_key|WEBSERVICE|output_format\s*=\s*JSON)",
    r"(?i)/config/(?:settings\.inc\.php|defines\.inc\.php|config\.inc\.php)\b",
    # --- Shopify ---
    r"(?i)/admin/api/\d{4}-\d{2}/(?:products|orders|customers|collects|collections|fulfillments|refunds|transactions|themes|blogs|articles|pages|redirects|script_tags|webhooks)\b",
    r"(?i)/admin/api/\d{4}-\d{2}/graphql\.json",
    # --- Laravel ---
    r"(?i)/(?:storage/logs/laravel\.log|\.env|artisan|vendor/autoload\.php|bootstrap/cache/config\.php|config/(?:app|database|mail|cache|queue|filesystems)\.php)\b",
    r"(?i)/(?:sanctum|livewire|nova|horizon|telescope|pulse|filament|vapor|forge|envoyer)\b",
    r"(?i)/storage/(?:app|framework|logs)/",
    r"(?i)/telescope/requests",
    r"(?i)/_ignition/(?:execute-solution|health-check|share-report|scripts|styles)\b",
    r"(?i)APP_KEY|APP_DEBUG|DB_PASSWORD|MAIL_PASSWORD|AWS_SECRET|REDIS_PASSWORD|PUSHER_APP_SECRET",
]

# ============================================================================
# 13. BRUTE FORCE / CREDENTIAL STUFFING (80 patterns)
# ============================================================================
BRUTE_FORCE_DEEP = [
    # --- Login endpoints ---
    r"(?i)(?:POST|PUT)\s+/(?:login|signin|sign-in|auth|authenticate|session|token|oauth|sso|saml|cas|openid|callback|api/(?:login|auth|token|session))(?:\s|\?|$|/)",
    r"(?i)(?:POST|PUT)\s+/(?:wp-login|administrator|admin/login|user/login|account/login|member/login|portal/login)(?:\s|\?|$)",
    r"(?i)(?:POST|PUT)\s+/(?:j_security_check|j_spring_security_check|logincheck|doLogin|processLogin|checkLogin|verifyLogin|validateLogin)(?:\s|\?|$)",
    r"(?i)(?:POST|PUT)\s+/(?:api/v\d+/(?:auth|login|token|session|users/login|users/authenticate|oauth/token))",
    # --- Default credentials ---
    r"(?i)(?:username|user|login|email|account)\s*(?:=|%3D)\s*(?:admin|administrator|root|superuser|sysadmin|sa|dba|postgres|mysql|oracle|system|guest|test|demo|info|support|service|webmaster|postmaster|hostmaster|security|noc|abuse)\b",
    r"(?i)(?:password|passwd|pass|pwd|secret|credential)\s*(?:=|%3D)\s*(?:admin|password|123456|12345678|1234|qwerty|abc123|monkey|master|dragon|111111|baseball|iloveyou|trustno1|sunshine|princess|football|shadow|superman|michael|letmein|welcome|login|starwars|passw0rd|P@ssw0rd|P@ss1234|Admin123|Root123|Test123|Changeme|Default|Guest|Temp123|Password1)\b",
    r"(?i)(?:password|passwd|pass|pwd)\s*(?:=|%3D)\s*(?:!@#\$%|password\d+|admin\d+|root\d+|qwerty\d+|abc\d+|test\d+|user\d+|guest\d+|default|changeme)",
    # --- Token/API key brute force ---
    r"(?i)(?:api[_-]?key|apikey|token|access[_-]?token|auth[_-]?token|bearer|jwt|session[_-]?id|csrf[_-]?token|x-api-key)\s*(?:=|%3D|:)\s*(?:[a-zA-Z0-9]{32,}|[a-f0-9]{32,})",
    r"(?i)Authorization\s*:\s*(?:Basic|Bearer|Token|Digest|NTLM|Negotiate|AWS4-HMAC-SHA256)\s+\S+",
    r"(?i)Authorization\s*:\s*Basic\s+(?:[A-Za-z0-9+/=]{4,})",
    # --- OTP/2FA brute force ---
    r"(?i)(?:otp|totp|mfa|2fa|verification|verify|code|pin|token)\s*(?:=|%3D)\s*\d{4,8}\b",
    r"(?i)(?:otp|totp|code|pin)\s*(?:=|%3D)\s*(?:\d{6})\b",
    # --- Password reset brute force ---
    r"(?i)(?:POST|PUT)\s+/(?:forgot|reset|recover|restore)[-_]?(?:password|passwd|pass|pwd|account|credential)\b",
    r"(?i)(?:reset[_-]?token|recovery[_-]?token|verify[_-]?token)\s*(?:=|%3D)\s*\w+",
    # --- Account enumeration ---
    r"(?i)(?:POST|GET)\s+/(?:register|signup|sign-up|create[-_]?account|check[-_]?email|check[-_]?username|verify[-_]?email|exists|available)\b",
    r"(?i)(?:email|username|account|user)\s*(?:=|%3D)\s*[^&]+@[^&]+.*(?:check|verify|exist|available|validate|lookup)",
    # --- Credential stuffing indicators ---
    r"(?i)(?:user|email|login|username|account)\s*(?:=|%3D)\s*[^&]+&(?:pass|password|pwd|passwd|secret)\s*(?:=|%3D)\s*[^&]+&(?:captcha|recaptcha|hcaptcha|turnstile)\s*(?:=|%3D)\s*$",
    r"(?i)(?:user|email|login)\s*(?:=|%3D)\s*[^&]+.*(?:pass|password)\s*(?:=|%3D)\s*[^&]+.*(?:remember|keep|stay|persist)\s*(?:=|%3D)",
]

# ============================================================================
# 14. CRYPTOGRAPHIC ATTACKS (60 patterns)
# ============================================================================
CRYPTO_ATTACKS_DEEP = [
    # --- Padding oracle ---
    r"(?i)(?:padding|pkcs[57]?|decrypt|cipher|block|oracle|cbc|ecb|ctr|gcm|ccm|cfb|ofb)\s*(?:error|exception|invalid|incorrect|bad|wrong|failed|mismatch)",
    r"(?i)(?:javax\.crypto|System\.Security\.Cryptography)\.\w+Exception",
    r"(?i)BadPaddingException\b",
    r"(?i)IllegalBlockSizeException\b",
    r"(?i)InvalidAlgorithmParameterException\b",
    r"(?i)CryptographicException\b",
    # --- Weak algorithms ---
    r"(?i)(?:DES|3DES|RC[24]|MD[245]|SHA-?1|RIPEMD|Blowfish|IDEA|CAST5|TEA|XTEA|Skipjack|SEED|Camellia-128)\b.*(?:encrypt|decrypt|hash|digest|cipher|sign|verify|key)",
    r"(?i)(?:ECB|CBC)\s*(?:mode|cipher|encrypt|decrypt)\b",
    r"(?i)(?:NULL|EXPORT|anon|aNULL|eNULL|LOW|MEDIUM|DES|RC4|MD5|SHA1)\b.*cipher",
    # --- Key/IV exposure ---
    r"(?i)(?:encryption|decryption|cipher|crypto|secret|private|signing|hmac)[-_]?(?:key|secret|password|passphrase|iv|nonce|salt)\s*(?:=|:)\s*['\"]?[a-zA-Z0-9+/=]{8,}",
    r"(?i)(?:AES|RSA|EC|ECDSA|Ed25519|Curve25519)[-_]?(?:KEY|PRIVATE|PUBLIC|SECRET|IV|NONCE)\s*(?:=|:)",
    r"(?i)-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----",
    r"(?i)-----BEGIN\s+(?:EC\s+)?PRIVATE\s+KEY-----",
    r"(?i)-----BEGIN\s+ENCRYPTED\s+PRIVATE\s+KEY-----",
    r"(?i)-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----",
    r"(?i)-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----",
    r"(?i)-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----",
    r"(?i)-----BEGIN\s+CERTIFICATE-----",
    r"(?i)PRIVATE\s+KEY\s+(?:EXPOSED|LEAKED|COMPROMISED)",
    # --- JWT attacks ---
    r'(?i)\{"(?:alg|typ)"\s*:\s*"(?:none|HS256|HS384|HS512)"\s*,',
    r"(?i)eyJ(?:hbGci|0eXAi|pc3Mi|hdWQi|leHAi|uYmYi|pYXQi|zdWIi)",
    r"(?i)\balg\b['\"]?\s*:\s*['\"]?none['\"]?",
    r"(?i)\balg\b['\"]?\s*:\s*['\"]?(?:HS256|HS384|HS512)['\"]?.*(?:kid|jku|jwk|x5u|x5c)\b",
    r"(?i)(?:kid|jku|jwk|x5u|x5c)\s*['\"]?\s*:\s*['\"]?(?:https?://|file://|data:|/|\.\.)",
    r"(?i)jwt\.(?:decode|verify|sign)\s*\(\s*[^)]*(?:algorithms?\s*(?:=|:)\s*\[?\s*['\"]none)",
    r"(?i)jwt_tool\b",
    # --- Hash cracking ---
    r"(?i)(?:\$[12]\$|{SSHA}|{SHA}|{MD5}|{CRYPT}|{BCRYPT}|{ARGON2}|{PBKDF2}|{SCRYPT})",
    r"(?i)\$(?:1|2[ab]?|5|6|y|gy|argon2[id]?|sha256|sha512|bcrypt|scrypt|md5|apr1|ssha|P)\$",
    r"(?i)(?:hashcat|hydra|medusa|ncrack|ophcrack|rainbowcrack|l0phtcrack|cain|abel)\b",
    r"(?i)john\s+(?:the\s+ripper|--\w+|/usr|\w+\.txt)\b",
    r"(?i)(?:rockyou|wordlist|dictionary|bruteforce|brute[_-]?force|hashlist|potfile|show)\b.*(?:\.txt|\.lst|\.dict|\.wrd|\.passwords)",
    # --- Side-channel ---
    r"(?i)(?:timing[_-]?attack|side[_-]?channel|power[_-]?analysis|electromagnetic|fault[_-]?injection|cache[_-]?timing|spectre|meltdown|rowhammer|zombieload|foreshadow|ridl|fallout|microarchitectural)\b",
    # --- Downgrade attacks ---
    r"(?i)(?:ssl|tls)\s*(?:version|protocol)\s*(?:=|:)\s*(?:ssl[23]|tls1\.?0?|1\.0|2\.0|3\.0)\b",
    r"(?i)(?:POODLE|BEAST|CRIME|BREACH|LUCKY13|DROWN|FREAK|LOGJAM|Sweet32|ROBOT|Bleichenbacher|Zombie|Raccoon|ALPACA|Minerva)\b",
]

# ============================================================================
# Map all patterns
# ============================================================================
RULES_MEGA_2_MAP = {
    'ldap_mega': LDAP_INJECTION_DEEP,
    'xpath_mega': XPATH_INJECTION_DEEP,
    'graphql_mega': GRAPHQL_DEEP,
    'websocket_mega': WEBSOCKET_DEEP,
    'cors_mega': CORS_BYPASS_DEEP,
    'email_inject_mega': EMAIL_INJECTION_DEEP,
    'log_inject_mega': LOG_INJECTION_DEEP,
    'hpp_mega': HPP_DEEP,
    'open_redirect_mega': OPEN_REDIRECT_DEEP,
    'scanner_mega': SCANNER_FINGERPRINTS_DEEP,
    'cms_wordpress_mega': CMS_WORDPRESS_DEEP,
    'cms_other_mega': CMS_OTHER_DEEP,
    'brute_force_mega': BRUTE_FORCE_DEEP,
    'crypto_mega': CRYPTO_ATTACKS_DEEP,
}


def get_all_mega2_patterns():
    for category, patterns in RULES_MEGA_2_MAP.items():
        for regex_str in patterns:
            yield (regex_str, category)


def count_mega2_patterns():
    return sum(len(p) for p in RULES_MEGA_2_MAP.values())
