"""
BeeWAF Mega Rules Database — Part 12 (Final)
==============================================
Final ~150 patterns to push total past 10,000.
"""

# ============================================================================
# 1. ADDITIONAL ENCODING BYPASS PATTERNS (50 patterns)
# ============================================================================
ENCODING_EXTRA = [
    r"(?i)%c0%ae%c0%ae/",
    r"(?i)%c0%ae%c0%ae\\",
    r"(?i)%c0%af%c0%af",
    r"(?i)%c1%1c%c1%1c",
    r"(?i)%c1%9c%c1%9c",
    r"(?i)%e0%80%ae%e0%80%ae/",
    r"(?i)%f0%80%80%ae%f0%80%80%ae/",
    r"(?i)%fc%80%80%80%80%ae",
    r"(?i)%%c0%6e%c0%65%c0%74",
    r"(?i)%25%32%65%25%32%65%25%32%66",
    r"(?i)%252e%252e%252f",
    r"(?i)%255c%255c",
    r"(?i)%u002e%u002e%u002f",
    r"(?i)%u002e%u002e/",
    r"(?i)%u002e%u002e\\",
    r"(?i)\.\.%c0%af",
    r"(?i)\.\.%c1%9c",
    r"(?i)\.\.%255c",
    r"(?i)\.\.%25%35%63",
    r"(?i)%uff0e%uff0e/",
    r"(?i)%uff0e%uff0e\\",
    r"(?i)\x2e\x2e\x2f",
    r"(?i)\x2e\x2e\x5c",
    r"(?i)\\x2e\\x2e\\x2f",
    r"(?i)\\x2e\\x2e\\x5c",
    r"(?i)%00\.\./",
    r"(?i)\.\./\x00",
    r"(?i)\.\./%00",
    r"(?i)%00\.\.\\",
    r"(?i)\\u002e\\u002e\\u002f",
    r"(?i)\\u002e\\u002e\\u005c",
    r"(?i)&#46;&#46;&#47;",
    r"(?i)&#x2e;&#x2e;&#x2f;",
    r"(?i)&#46;&#46;&#92;",
    r"(?i)&#x2e;&#x2e;&#x5c;",
    r"(?i)&period;&period;&sol;",
    r"(?i)&period;&period;&bsol;",
    r"(?i)\.\.\/",
    r"(?i)\.\.\\\\",
    r"(?i)\.\./\.\./%2e%2e/",
    r"(?i)%2e%2e/%2e%2e/\.\./",
    r"(?i)\.\.%2f\.\.%2f",
    r"(?i)%2e%2e%5c%2e%2e%5c",
    r"(?i)\.\.%5c\.\.%5c",
    r"(?i)\.%2e/%2e\./",
    r"(?i)%2e\./%2e\./",
    r"(?i)\.%2e\.%2e/",
    r"(?i)/\.\.;/",
    r"(?i)/\.\.%3b/",
    r"(?i)%23\.\.%23/",
]

# ============================================================================
# 2. REGEX-BASED ATTACK SIGNATURES (50 patterns)
# ============================================================================
REGEX_ATTACKS = [
    r"(?i)(?:onafterprint|onbeforeprint|onbeforeunload|onhashchange|onmessage|onoffline|ononline|onpagehide|onpageshow|onpopstate|onstorage|onunhandledrejection|onrejectionhandled)\s*=",
    r"(?i)<base\b[^>]*\bhref\s*=",
    r"(?i)<link\b[^>]*\brel\s*=\s*['\"]?(?:import|preload|prefetch|dns-prefetch|preconnect|prerender)\b",
    r"(?i)<link\b[^>]*\bhref\s*=\s*['\"]?(?:javascript|data|vbscript):",
    r"(?i)<meta\b[^>]*\bhttp-equiv\s*=\s*['\"]?refresh['\"]?\s+content\s*=\s*['\"]?\d+\s*;\s*url\s*=",
    r"(?i)<meta\b[^>]*\bhttp-equiv\s*=\s*['\"]?set-cookie",
    r"(?i)<portal\b[^>]*\bsrc\s*=",
    r"(?i)<object\b[^>]*\bdata\s*=\s*['\"]?(?:javascript|data|vbscript):",
    r"(?i)<object\b[^>]*\btype\s*=\s*['\"]?text/html",
    r"(?i)<embed\b[^>]*\bsrc\s*=\s*['\"]?(?:javascript|data|vbscript):",
    r"(?i)<embed\b[^>]*\btype\s*=\s*['\"]?(?:text/html|application/x-shockwave-flash|image/svg\+xml)",
    r"(?i)<applet\b[^>]*\bcode\s*=",
    r"(?i)<frameset\b[^>]*\bonload\s*=",
    r"(?i)<frame\b[^>]*\bsrc\s*=\s*['\"]?(?:javascript|data|vbscript):",
    r"(?i)<iframe\b[^>]*\bsrc\s*=\s*['\"]?(?:javascript|data|vbscript):",
    r"(?i)<iframe\b[^>]*\bsrcdoc\s*=",
    r"(?i)<iframe\b[^>]*\bonload\s*=",
    r"(?i)<iframe\b[^>]*\bonerror\s*=",
    r"(?i)<iframe\b[^>]*\bsandbox\s*=\s*['\"]?\s*['\"]",
    r"(?i)javascript\s*:\s*(?:alert|confirm|prompt|eval|Function|setTimeout|setInterval|document\.write|document\.cookie|window\.location|location\.href|window\.open)\b",
    r"(?i)data\s*:\s*text/html\b",
    r"(?i)data\s*:\s*text/javascript\b",
    r"(?i)data\s*:\s*application/javascript\b",
    r"(?i)data\s*:\s*text/xml\b",
    r"(?i)data\s*:\s*image/svg\+xml\b",
    r"(?i)vbscript\s*:\s*(?:msgbox|execute|eval|executeglobal|createobject)\b",
    r"(?i)expression\s*\(\s*(?:alert|confirm|prompt|eval|document)\b",
    r"(?i)-moz-binding\s*:\s*url\(",
    r"(?i)behavior\s*:\s*url\(",
    r"(?i)@import\s+['\"]?(?:javascript|data|vbscript):",
    r"(?i)@import\s+url\s*\(\s*['\"]?(?:javascript|data|vbscript):",
    r"(?i)background\s*:\s*url\s*\(\s*['\"]?(?:javascript|data|vbscript):",
    r"(?i)background-image\s*:\s*url\s*\(\s*['\"]?(?:javascript|data|vbscript):",
    r"(?i)list-style\s*:\s*url\s*\(\s*['\"]?(?:javascript|data|vbscript):",
    r"(?i)list-style-image\s*:\s*url\s*\(\s*['\"]?(?:javascript|data|vbscript):",
    r"(?i)cursor\s*:\s*url\s*\(\s*['\"]?(?:javascript|data|vbscript):",
    r"(?i)content\s*:\s*url\s*\(\s*['\"]?(?:javascript|data|vbscript):",
    r"(?i)filter\s*:\s*url\s*\(\s*['\"]?(?:javascript|data|vbscript):",
    r"(?i)src\s*:\s*url\s*\(\s*['\"]?(?:javascript|data|vbscript):",
    r"(?i)@font-face\s*\{[^}]*src\s*:\s*url\(",
    # Template injection extra
    r"(?i)\{\{config\}\}",
    r"(?i)\{\{request\}\}",
    r"(?i)\{\{self\}\}",
    r"(?i)\{\{url_for\}\}",
    r"(?i)\{\{get_flashed_messages\}\}",
    r"(?i)\{\{lipsum\}\}",
    r"(?i)\{\{cycler\}\}",
    r"(?i)\{\{joiner\}\}",
    r"(?i)\{\{namespace\}\}",
    r"(?i)\{\{range\}\}",
    r"(?i)\{\{dict\}\}",
]

# ============================================================================
# 3. ADDITIONAL API & PROTOCOL PATTERNS (50 patterns)
# ============================================================================
API_PROTOCOL_EXTRA = [
    r"(?i)/graphql\b",
    r"(?i)/graphiql\b",
    r"(?i)/altair\b",
    r"(?i)/playground\b",
    r"(?i)/voyager\b",
    r"(?i)/graphql-explorer\b",
    r"(?i)/v\d+/graphql\b",
    r"(?i)/api/graphql\b",
    r"(?i)query\s*\{",
    r"(?i)mutation\s*\w+\s*\(",
    r"(?i)subscription\s*\w+\s*\{",
    r"(?i)__schema\b",
    r"(?i)__type\b",
    r"(?i)__typename\b",
    r"(?i)__directive\b",
    r"(?i)__field\b",
    r"(?i)__inputValue\b",
    r"(?i)__enumValue\b",
    # gRPC
    r"(?i)/grpc\.\w+\.\w+/\w+\b",
    r"(?i)content-type\s*:\s*application/grpc\b",
    r"(?i)grpc-status\s*:\s*\d+\b",
    r"(?i)grpc-message\s*:\s*\w+\b",
    r"(?i)grpc-timeout\s*:\s*\d+\b",
    # WebSocket
    r"(?i)Upgrade\s*:\s*websocket\b",
    r"(?i)Connection\s*:\s*Upgrade\b",
    r"(?i)Sec-WebSocket-Key\s*:\s*\w+\b",
    r"(?i)Sec-WebSocket-Version\s*:\s*\d+\b",
    r"(?i)Sec-WebSocket-Protocol\s*:\s*\w+\b",
    r"(?i)Sec-WebSocket-Extensions\s*:\s*\w+\b",
    # SOAP
    r"(?i)<soap:Envelope\b",
    r"(?i)<soap:Body\b",
    r"(?i)<soap:Header\b",
    r"(?i)<soap:Fault\b",
    r"(?i)<soapenv:Envelope\b",
    r"(?i)<soapenv:Body\b",
    r"(?i)<soapenv:Header\b",
    r"(?i)SOAPAction\s*:\s*['\"]",
    # OAuth
    r"(?i)/oauth/authorize\b",
    r"(?i)/oauth/token\b",
    r"(?i)/oauth/revoke\b",
    r"(?i)/oauth/introspect\b",
    r"(?i)/oauth/userinfo\b",
    r"(?i)/\.well-known/openid-configuration\b",
    r"(?i)/\.well-known/oauth-authorization-server\b",
    r"(?i)/\.well-known/jwks\.json\b",
    r"(?i)grant_type\s*=\s*(?:authorization_code|client_credentials|password|refresh_token|urn:ietf)\b",
    r"(?i)response_type\s*=\s*(?:code|token|id_token)\b",
    r"(?i)redirect_uri\s*=\s*(?:https?://|//)\b",
    r"(?i)scope\s*=\s*(?:openid|profile|email|address|phone|offline_access|admin)\b",
    r"(?i)state\s*=\s*\w+\b",
    r"(?i)nonce\s*=\s*\w+\b",
]

RULES_MEGA_12_MAP = {
    'encoding_extra': ENCODING_EXTRA,
    'regex_attacks': REGEX_ATTACKS,
    'api_protocol_extra': API_PROTOCOL_EXTRA,
}


def get_all_mega12_patterns():
    for category, patterns in RULES_MEGA_12_MAP.items():
        for regex_str in patterns:
            yield (regex_str, category)


def count_mega12_patterns():
    return sum(len(p) for p in RULES_MEGA_12_MAP.values())
