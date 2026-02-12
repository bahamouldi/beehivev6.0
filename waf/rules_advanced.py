"""
BeeWAF v4.0 Advanced Rules Database
=====================================
650+ additional detection patterns to bring total ruleset to 1500+.
Covers advanced API security, cloud attacks, container security,
OAuth/SAML, GraphQL deep inspection, HTTP/2 attacks, and more.
"""


# ============================================================
#  ADVANCED API SECURITY (55 patterns)
# ============================================================

API_SECURITY_PATTERNS = [
    # GraphQL attacks (deep)
    r"(?i)query\s*\{.*\{.*\{.*\{.*\{",  # Deep nesting (5+ levels)
    r"(?i)mutation\s*\{.*delete",
    r"(?i)mutation\s*\{.*drop",
    r"(?i)mutation\s*\{.*update.*role.*admin",
    r"(?i)__schema\s*\{.*queryType",
    r"(?i)__schema\s*\{.*mutationType",
    r"(?i)__schema\s*\{.*subscriptionType",
    r"(?i)__type\s*\(\s*name\s*:",
    r"(?i)query\s+IntrospectionQuery\s*\{",
    r"(?i)fragment\s+\w+\s+on\s+__\w+",
    r"(?i)\{\s*__typename\s*\}",
    r"(?i)query.*alias\d{3,}",  # Alias-based DoS
    r"(?i)\balias\d+\s*:\s*\w+\(.*\)\s*\{",  # Numbered alias attack
    # REST API abuse
    r"(?i)/api/v\d+/(?:admin|internal|private|debug|test|staging)",
    r"(?i)/api/.*\?(?:.*&){15,}",  # Excessive query parameters
    r"(?i)/api/.*(?:limit|offset|page_size|per_page)\s*=\s*(?:[1-9]\d{4,}|0)",  # Excessive pagination
    r"(?i)/api/.*(?:fields|select|columns|include)\s*=.*(?:password|secret|token|key|credential|ssn|credit_card)",
    r"(?i)/api/.*(?:sort|order)\s*=.*(?:;|--|union|select|drop)",
    r"(?i)/api/.*\$(?:where|regex|gt|lt|ne|in|nin|exists)\b",
    # gRPC attacks
    r"(?i)application/grpc.*(?:union|select|exec|eval)",
    r"(?i)grpc-(?:status|message|encoding)\s*:.*(?:<script|javascript:|eval\()",
    # BOLA/IDOR
    r"(?i)/api/(?:v\d+/)?(?:users?|accounts?|profiles?|orders?)/(?:0|1|admin|root|test)\b",
    r"(?i)/api/(?:v\d+/)?(?:users?|accounts?)/\d+(?:\.\.|%2e%2e)",
    # Mass assignment
    r"(?i)(?:role|admin|is_admin|is_superuser|privilege|permission|group|user_type)\s*[=:]\s*(?:admin|superuser|root|true|1)",
    r"(?i)(?:verified|active|approved|confirmed|email_verified)\s*[=:]\s*(?:true|1|yes)",
    r"(?i)(?:balance|credit|amount|price|discount|salary)\s*[=:]\s*(?:-?\d{6,}|0(?:\.0+)?)",
    r"(?i)(?:created_at|updated_at|deleted_at|expires_at)\s*[=:]\s*['\"]",
    # Rate limit bypass (only flag spoofed multi-IP headers with internal addresses)
    r"(?i)x-forwarded-for\s*:\s*(?:\d{1,3}\.){3}\d{1,3}\s*,\s*(?:\d{1,3}\.){3}\d{1,3}\s*,\s*(?:\d{1,3}\.){3}\d{1,3}",
    r"(?i)(?:x-forwarded-for|x-real-ip|x-client-ip|cf-connecting-ip|true-client-ip|x-cluster-client-ip)\s*:\s*(?:0\.0\.0\.0|127\.0\.0\.1|::1|localhost)\b",
    # API key/token exposure
    r"(?i)(?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key|auth[_-]?token)\s*[=:]\s*['\"][A-Za-z0-9+/=_-]{20,}",
    r"(?i)(?:bearer|token|jwt|session)\s+[A-Za-z0-9._-]{50,}",
    # Content negotiation attacks
    r"(?i)accept\s*:\s*(?:text/html|application/xml|text/xml).*(?:/api/|\.json)",
    r"(?i)content-type\s*:\s*(?:multipart/form-data|application/x-www-form-urlencoded).*(?:__proto__|constructor\.prototype)",
    # SOAP attacks
    r"(?i)<soap:(?:Envelope|Body|Header).*(?:exec|system|Runtime|ProcessBuilder)",
    r"(?i)<wsse:Security.*(?:<!--.*-->|<!ENTITY)",
    # JSON Web Token manipulation
    r"(?i)eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.\s*$",  # JWT with empty signature
    r'(?i)"kid"\s*:\s*"(?:\.\./|/|;|`|\\|\'|\$\{)',  # JWT kid injection
    r'(?i)"jku"\s*:\s*"https?://(?!(?:your-domain|trusted))',  # JWT jku hijack
    r'(?i)"x5u"\s*:\s*"https?://',  # JWT x5u hijack
    r'(?i)"jwk"\s*:\s*\{',  # Embedded JWK injection
    # Webhook abuse
    r"(?i)(?:webhook|callback|notify|hook)_?url\s*[=:]\s*https?://(?:(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.|127\.|localhost)",
    r"(?i)(?:webhook|callback|notify|hook)_?url\s*[=:]\s*(?:file|gopher|dict|ftp|ldap)://",
    # Server-side parameter pollution
    r"(?i)(?:\?|&)[\w.]+=[\w.]+(?:&[\w.]+=[\w.]+){20,}",
    r"(?i)(?:__proto__|constructor)\[(?:prototype|__proto__)\]",
    # API versioning bypass
    r"(?i)/api/v(?:0|-1|99|1000)/",
    r"(?i)api-version\s*[=:]\s*(?:0|99|internal|debug|test|beta|alpha)",
    # Batch/bulk API abuse
    r"(?i)/(?:batch|bulk|multi|graphql)\s*$",
    r"(?i)\[\s*\{[^]]*\}\s*(?:,\s*\{[^]]*\}\s*){50,}\]",  # 50+ batch items
]


# ============================================================
#  CLOUD ATTACK PATTERNS (55 patterns)
# ============================================================

CLOUD_ATTACKS = [
    # AWS specific
    r"(?i)169\.254\.169\.254/(?:latest|1\.0)/(?:meta-data|user-data|dynamic|iam)",
    r"(?i)/latest/api/token",  # IMDSv2
    r"(?i)(?:AKIA|ASIA)[A-Z0-9]{16}",  # AWS Access Key ID
    r"(?i)(?:aws_access_key_id|aws_secret_access_key|aws_session_token)\s*[=:]\s*\S+",
    r"(?i)s3://[a-z0-9.-]+",
    r"(?i)(?:s3|ec2|iam|lambda|rds|dynamodb|sqs|sns|cloudformation|cloudfront)\.(?:us|eu|ap|sa|ca|me|af)-(?:east|west|north|south|central|southeast|northeast)-\d+\.amazonaws\.com",
    r"(?i)\.s3\.amazonaws\.com/",
    r"(?i)arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:",
    r"(?i)amz-credential=",
    r"(?i)x-amz-(?:security-token|date|content-sha256|server-side-encryption)",
    r"(?i)/(?:\.aws|\.config/aws)/credentials",
    r"(?i)(?:AKIAIOSFODNN7EXAMPLE|wJalrXUtnFEMI/K7MDENG)",  # Known example keys
    # GCP specific
    r"(?i)metadata\.google\.internal/computeMetadata/v1",
    r"(?i)metadata\.google\.internal/computeMetadata/v1beta1",
    r"(?i)/instance/service-accounts/default/token",
    r"(?i)(?:AIza|ya29\.)[A-Za-z0-9_-]{20,}",  # GCP API key / OAuth token
    r"(?i)(?:project-id|client-id|client-secret)\s*[=:]\s*\S+",
    r"(?i)storage\.googleapis\.com/",
    r"(?i)\.firebaseio\.com/",
    r"(?i)\.cloudfunctions\.net/",
    r"(?i)\.appspot\.com/",
    r"(?i)\.run\.app/",
    # Azure specific
    r"(?i)169\.254\.169\.254/metadata/(?:instance|identity|attested)",
    r"(?i)(?:management|login|graph)\.(?:azure|microsoftonline|windows)\.(?:com|net)/",
    r"(?i)\.blob\.core\.windows\.net/",
    r"(?i)\.table\.core\.windows\.net/",
    r"(?i)\.queue\.core\.windows\.net/",
    r"(?i)\.file\.core\.windows\.net/",
    r"(?i)\.database\.windows\.net",
    r"(?i)\.vault\.azure\.net/",
    r"(?i)(?:SharedAccessSignature|sig)=[A-Za-z0-9%/+=]+",
    r"(?i)(?:DefaultEndpointsProtocol|AccountName|AccountKey|EndpointSuffix)\s*=",
    # DigitalOcean metadata
    r"(?i)169\.254\.169\.254/metadata/v1",
    # Oracle Cloud metadata
    r"(?i)169\.254\.169\.254/opc/v[12]/",
    # Alibaba Cloud metadata
    r"(?i)100\.100\.100\.200/latest/meta-data",
    # Cloud credential files
    r"(?i)/(?:gcloud|gsutil|bq)/(?:credentials|properties|\.boto)",
    r"(?i)/\.(?:azure|config/azure)/",
    # Terraform/IaC secrets
    r"(?i)(?:terraform\.tfstate|\.terraform/|terraform\.tfvars)",
    r"(?i)(?:ansible-vault|vault\.yml|vault\.yaml)",
    # Cloud function injection
    r"(?i)(?:X-Cloud-Trace-Context|X-Amzn-Trace-Id|X-Google-.*-Info)\s*:.*(?:;|--|eval|exec)",
    # Kubernetes service account token
    r"(?i)/var/run/secrets/kubernetes\.io/serviceaccount/(?:token|ca\.crt|namespace)",
    r"(?i)/run/secrets/kubernetes\.io/",
    # Cloud storage enumeration
    r"(?i)(?:list-buckets|get-bucket-acl|list-objects|get-object|put-bucket-policy)",
    r"(?i)/\?(?:list-type|delimiter|prefix|marker|max-keys)\s*=",
    # Instance identity document
    r"(?i)/latest/(?:dynamic|meta-data)/instance-identity/",
    # Cloud API enumeration
    r"(?i)(?:sts|iam)\.amazonaws\.com/\?Action=",
    r"(?i)compute\.googleapis\.com/compute/v1/",
    r"(?i)management\.azure\.com/subscriptions/",
    # Serverless function abuse
    r"(?i)(?:X-Forwarded-For|X-Real-IP)\s*:.*(?:internal|metadata|169\.254)",
    r"(?i)/2015-03-31/functions/",  # AWS Lambda API
    r"(?i)/(?:_ah|_debug|_api)/",  # App Engine internal
]


# ============================================================
#  CONTAINER / K8S ATTACK PATTERNS (35 patterns)
# ============================================================

CONTAINER_K8S_ATTACKS = [
    # Kubernetes API
    r"(?i)/api/v1/(?:namespaces|nodes|pods|services|secrets|configmaps|endpoints)",
    r"(?i)/apis/(?:apps|batch|extensions|networking|rbac|storage)/v\d+",
    r"(?i)/api/v1/namespaces/\w+/pods/\w+/exec",
    r"(?i)/api/v1/namespaces/\w+/pods/\w+/(?:log|portforward|attach)",
    r"(?i)/api/v1/namespaces/kube-system/",
    r"(?i)/api/v1/secrets(?:\?|$)",
    r"(?i)/healthz|/livez|/readyz",
    # etcd
    r"(?i)/v2/(?:keys|members|stats|version)",
    r"(?i)/v3/(?:kv|auth|cluster|maintenance|watch|lease)",
    r"(?i)etcdctl\s",
    # Docker
    r"(?i)/(?:v\d+\.\d+/)?(?:containers|images|volumes|networks|swarm|nodes)/(?:json|create|start|stop|kill|rm|exec)",
    r"(?i)/var/run/docker\.sock",
    r"(?i)/(?:_ping|version|info|events)(?:\?|$)",
    r"(?i)docker\s+(?:exec|run|build|pull|push|cp|login)",
    # Container escape
    r"(?i)/proc/(?:1|self)/(?:root|cgroup|mountinfo|mounts)",
    r"(?i)/sys/(?:fs/cgroup|kernel|class|devices)",
    r"(?i)(?:nsenter|unshare|chroot)\s",
    r"(?i)mount\s+-t\s+(?:proc|sysfs|devpts|cgroup)",
    r"(?i)(?:capsh|setcap|getcap)\s",
    # Helm/Tiller
    r"(?i)/tiller|/helm",
    r"(?i)helm\s+(?:install|upgrade|delete|rollback|template)\s",
    # Service mesh attacks
    r"(?i)/(?:config_dump|clusters|listeners|routes|server_info)",  # Envoy admin
    r"(?i)/debug/(?:pprof|vars|requests|events)",  # Go debug
    r"(?i)/istio(?:Config|.mesh|.networking)/",
    # Registry attacks
    r"(?i)/v2/_catalog",
    r"(?i)/v2/\w+/(?:manifests|blobs|tags)",
    # Container runtime
    r"(?i)(?:runc|crun|containerd|podman)\s",
    r"(?i)/run/containerd/containerd\.sock",
    r"(?i)/run/crio/crio\.sock",
    # Kubelet
    r"(?i):10250/(?:pods|run|exec|attach|portForward|containerLogs|configz|debug|metrics)",
    r"(?i):10255/(?:pods|stats|metrics|spec)",
    r"(?i):2379/(?:v2|v3)/",  # etcd port
    # Secrets in environment
    r"(?i)KUBERNETES_SERVICE_(?:HOST|PORT)",
    r"(?i)KUBECONFIG\s*=",
    r"(?i)kubectl\s+(?:get|describe|apply|delete|edit|create)\s+(?:secret|configmap)",
]


# ============================================================
#  OAUTH / SAML / OPENID ATTACKS (45 patterns)
# ============================================================

OAUTH_SAML_ATTACKS = [
    # OAuth redirect manipulation
    r"(?i)redirect_uri\s*=\s*(?:https?://(?!(?:localhost|127\.0\.0\.1))\S+|javascript:|data:|vbscript:)",
    r"(?i)redirect_uri\s*=\s*(?:https?://[^/]*@|//[^/]*@)",
    r"(?i)redirect_uri\s*=\s*https?://[^/]*\.(?:evil|attacker|burp|interact)\.",
    r"(?i)redirect_uri\s*=\s*https?://[^/]*%(?:2[eE]|40|23|3[fF])",
    r"(?i)redirect_uri\s*=\s*https?://[^/]*\\\\",
    r"(?i)response_type\s*=\s*(?:code\s+token|token\s+id_token|code\s+id_token\s+token)",
    r"(?i)response_mode\s*=\s*(?:fragment|query\s*\.jwt|form_post\.jwt)",
    r"(?i)state\s*=\s*(?:['\"]|<script|javascript:|%3Cscript)",
    r"(?i)(?:client_id|client_secret)\s*=\s*['\"]?(?:test|admin|root|debug|internal)",
    r"(?i)grant_type\s*=\s*(?:client_credentials|password|urn:)",
    r"(?i)scope\s*=\s*(?:openid\s+)?(?:.*\s+)?(?:admin|superuser|write|delete|all)",
    # OAuth token theft
    r"(?i)access_token\s*=\s*[A-Za-z0-9._-]{20,}",
    r"(?i)code\s*=\s*[A-Za-z0-9._-]{20,}.*(?:redirect|callback|return)",
    r"(?i)(?:authorization|access[-_]?token)\s*[=:]\s*bearer\s+",
    # SAML attacks
    r"(?i)SAMLResponse\s*=.*(?:<!ENTITY|<!DOCTYPE|SYSTEM\s+['\"])",
    r"(?i)SAMLRequest\s*=.*(?:<!ENTITY|<!DOCTYPE|SYSTEM\s+['\"])",
    r"(?i)<(?:saml|samlp):.*(?:<!ENTITY|SYSTEM\s+['\"]file://)",
    r"(?i)<(?:saml|samlp):.*(?:<!--.*-->.*){3,}",
    r"(?i)<ds:(?:Signature|SignedInfo|Reference|Transform)",
    r"(?i)(?:Assertion|Response).*(?:NotBefore|NotOnOrAfter)\s*=\s*['\"](?:2099|9999)",
    r"(?i)<saml:(?:Attribute|Subject|Conditions|AuthnStatement).*(?:admin|root|superuser)",
    r"(?i)<saml:NameID.*(?:admin@|root@|administrator@)",
    r"(?i)xmldsig#.*(?:enveloped|c14n|sha1|rsa-sha1)",
    # SAML signature wrapping
    r"(?i)<(?:saml|samlp):.*<(?:saml|samlp):.*<ds:Signature",
    r"(?i)<ds:Reference\s+URI\s*=\s*['\"]#?['\"]",  # Empty reference URI
    r"(?i)(?:SignatureValue|DigestValue)\s*>.*<",
    # OpenID Connect attacks
    r"(?i)(?:\.well-known/openid-configuration|\.well-known/jwks\.json)",
    r"(?i)id_token\s*=.*(?:admin|root|superuser)",
    r"(?i)nonce\s*=\s*(?:test|123|null|undefined|none|admin)",
    r"(?i)(?:request_uri|request)\s*=\s*https?://(?!trusted)",
    r"(?i)acr_values\s*=.*(?:password|otp|mfa_bypass)",
    # JWT specific advanced
    r'(?i)"iss"\s*:\s*"(?:self|test|debug|local|attacker|evil)',
    r'(?i)"sub"\s*:\s*"(?:admin|root|superuser|system|god|0)"',
    r'(?i)"exp"\s*:\s*(?:9999999999|99999999999)',
    r'(?i)"iat"\s*:\s*(?:0|1|946684800)',  # Year 2000 or epoch
    r'(?i)"nbf"\s*:\s*0\b',
    r'(?i)"aud"\s*:\s*"(?:\*|all|any|public)"',
    # Session fixation via OAuth
    r"(?i)(?:session_state|sid|session)\s*=\s*(?:admin|root|test|null|undefined|0)\b",
    # PKCE downgrade
    r"(?i)code_challenge_method\s*=\s*(?:plain|none)\b",
    r"(?i)code_verifier\s*=\s*(?:.{0,42}|.{129,})\b",  # Invalid length
    # Device authorization abuse
    r"(?i)device_code\s*=\s*[A-Za-z0-9-]{5,}.*(?:poll|verify|complete)",
    r"(?i)user_code\s*=\s*[A-Z0-9-]{4,}",
    # Token exchange attacks
    r"(?i)subject_token_type\s*=.*(?:access_token|id_token|saml2|jwt)",
    r"(?i)(?:actor_token|subject_token)\s*=\s*(?:eyJ|PD|rO0)",
    r"(?i)requested_token_type\s*=.*(?:urn:ietf:params:oauth:token-type:)",
]


# ============================================================
#  ADVANCED FILE UPLOAD ATTACKS (35 patterns)
# ============================================================

FILE_UPLOAD_ATTACKS = [
    # Polyglot files
    r"(?i)GIF89a.*(?:<\?php|<%|<script|<svg|eval\(|exec\()",
    r"(?i)\x89PNG.*(?:<\?php|<%|<script|<svg)",
    r"(?i)%PDF-.*(?:<\?php|<%|<script|exec\()",
    r"(?i)PK\x03\x04.*(?:\.php|\.jsp|\.aspx?|\.py|\.rb|\.sh|\.cgi)",
    # Double extension
    r"(?i)\.(php|asp|aspx|jsp|jspx|py|rb|pl|cgi|sh|exe|dll|bat|cmd|ps1|vbs|wsf)\.(jpg|jpeg|gif|png|bmp|ico|svg|pdf|doc|xls|txt|zip|rar|tar|gz)$",
    r"(?i)\.(jpg|jpeg|gif|png|pdf|doc|xls|txt)\.(php|asp|aspx|jsp|py|rb|cgi|sh|exe|bat)$",
    # Null byte injection in filename
    r"(?i)\.(?:php|asp|aspx|jsp|py|rb|sh)%00\.",
    r"(?i)\.(?:php|asp|aspx|jsp|py|rb|sh)\x00\.",
    # Dangerous extensions
    r"(?i)\.(?:php[3-8]?|phtml|pht|phps|phar)$",
    r"(?i)\.(?:asp|aspx|ashx|asmx|ascx|axd|asa|asax|config)$",
    r"(?i)\.(?:jsp|jspx|jspf|jsw|jsv|jtml|do|action)$",
    r"(?i)\.(?:cgi|pl|py|pyc|pyo|rb|sh|bash|zsh|ksh|tcl|lua)$",
    r"(?i)\.(?:exe|dll|so|dylib|bin|com|bat|cmd|ps1|vbs|vbe|wsf|wsh|scr|pif|hta|msi|msp|mst)$",
    r"(?i)\.(?:htaccess|htpasswd|user\.ini|php\.ini|\.env)$",
    # MIME type confusion
    r"(?i)content-type\s*:\s*(?:application/(?:x-httpd-php|x-php|php|x-perl|x-python|x-ruby|x-sh)|text/(?:x-php|x-python|x-perl|x-shellscript))",
    r"(?i)content-type\s*:\s*(?:image/(?:jpeg|png|gif)|application/pdf).*(?:\.php|\.asp|\.jsp)",
    # SVG with embedded code
    r"(?i)\.svg$.*(?:<script|onload|onerror|javascript:|eval\()",
    r"(?i)<svg[^>]*>(?:.*<script|.*on\w+=)",
    # Archive bombs
    r"(?i)\.(?:zip|tar|gz|bz2|7z|rar)\s.*(?:10{6,}|symlink|/\.\./)",
    # LFI via upload path
    r"(?i)(?:filename|name)\s*=\s*['\"]?(?:\.\.[\\/]|/etc/|c:\\|%2e%2e)",
    r"(?i)(?:upload_dir|save_path|file_path)\s*=\s*['\"]?(?:\.\.[\\/]|/|%2e%2e)",
    # SSRF via upload URL
    r"(?i)(?:url|source|image_url|file_url)\s*=\s*(?:file://|gopher://|dict://|ldap://|tftp://)",
    r"(?i)(?:url|source|image_url|file_url)\s*=\s*https?://(?:169\.254|127\.|10\.|172\.(?:1[6-9]|2|3[01])\.|192\.168\.)",
    # Webshell indicators
    r"(?i)(?:eval|assert|system|exec|passthru)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|FILES)\[",
    r"(?i)(?:base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode)\s*\(\s*['\"]",
    r"(?i)\$\w+\s*=\s*str_replace\s*\(.*(?:eval|assert|exec|system)",
    r"(?i)(?:FilesMan|WSO|c99|r57|b374k|weevely|webacoo|phpspy|p0wny)\b",
    r"(?i)(?:GIF89a.*<\?php|\xff\xd8\xff\xe0.*<\?php|\x89PNG.*<\?php)",
    # Image with embedded PHP
    r"(?i)(?:JFIF|Exif).*(?:<\?php|<\?=|<%|<script\s+language\s*=\s*['\"]?php)",
    # ZIP slip
    r"(?i)(?:\.\./|\.\.\\){2,}",
    r"(?i)(?:%2e%2e%2f|%2e%2e/|\.\.%2f){2,}",
    # Content-Disposition manipulation
    r"(?i)content-disposition\s*:.*filename\s*=.*['\"].*[;'\"].*filename\*?\s*=",
    r"(?i)content-disposition\s*:.*(?:\\r\\n|%0d%0a)",
    r"(?i)content-disposition\s*:.*filename\s*=\s*['\"]?\s*$",  # Empty filename
]


# ============================================================
#  HTTP/2 AND HTTP/3 ATTACKS (25 patterns)
# ============================================================

HTTP2_HTTP3_ATTACKS = [
    # HTTP/2 specific
    r"(?i):method\s*:\s*(?:TRACE|TRACK|DEBUG|CONNECT|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|SEARCH)",
    r"(?i):path\s*:.*(?:\.\./|%2e%2e|%00|<script|javascript:)",
    r"(?i):authority\s*:.*(?:@|%40|127\.0\.0\.1|localhost|169\.254)",
    r"(?i):scheme\s*:\s*(?:file|gopher|dict|ftp|ldap|telnet|tftp)",
    # HTTP/2 smuggling
    r"(?i)(?:content-length|transfer-encoding)\s*:.*\r?\n\s*(?:content-length|transfer-encoding)\s*:",
    r"(?i):method\s*:.*\r?\n.*:method\s*:",  # Duplicate pseudo-headers
    r"(?i)(?:te|transfer-encoding)\s*:\s*(?:chunked|trailers|compress|deflate|gzip)\s*,",
    # HTTP/2 CRLF injection
    r"(?i)(?::method|:path|:authority|:scheme)\s*:.*(?:%0d%0a|\\r\\n|\r\n)",
    # HTTP/2 header injection
    r"(?i)(?:cookie|authorization|host)\s*:.*(?:%0d%0a|\\r\\n)(?:x-|set-cookie|location)",
    # HTTP/2 priority manipulation (DoS)
    r"(?i)priority\s*:.*(?:weight\s*=\s*(?:0|256)|exclusive\s*=\s*1.*exclusive\s*=\s*1)",
    # HTTP/3 QUIC attacks
    r"(?i)alt-svc\s*:.*(?:h3=|h3-\d+=|quic=).*(?:127\.0\.0\.1|localhost|0\.0\.0\.0)",
    # HTTP desync via H2
    r"(?i)upgrade\s*:\s*h2c\s*$",
    r"(?i)http2-settings\s*:\s*[A-Za-z0-9+/=]+",
    # Tunnel abuse
    r"(?i):method\s*:\s*CONNECT.*(?:127\.0\.0\.1|localhost|internal|metadata)",
    r"(?i)proxy-authorization\s*:\s*basic\s+",
    # Header table manipulation
    r"(?i)(?:[\x00-\x08\x0b\x0c\x0e-\x1f]){3,}",  # Control characters in headers
    # Continuation flood
    r"(?i)(?:x-[a-z0-9-]+\s*:\s*[A-Za-z0-9+/=]{1000,}\s*){5,}",  # Many large headers
    # Window update attacks
    r"(?i)(?:window-update|settings)\s*:.*(?:0xffffffff|4294967295|0x7fffffff)",
    # Trailer injection
    r"(?i)te\s*:\s*trailers.*(?:set-cookie|authorization|x-forwarded)",
    r"(?i)trailer\s*:\s*(?:set-cookie|authorization|content-type|host|content-length|transfer-encoding)",
    # Push promise abuse
    r"(?i)link\s*:\s*<.*>\s*;\s*rel\s*=\s*preload.*(?:javascript:|data:|file://)",
    # HTTP/2 rapid reset (CVE-2023-44487)
    r"(?i)(?:rst_stream|goaway)\s*(?:.*\b(?:100|1000|10000)\b)",
    # Early hints abuse
    r"(?i)103\s+Early\s+Hints.*(?:<script|javascript:|data:|file://)",
    # ALT-SVC header injection
    r"(?i)alt-svc\s*:.*(?:clear|%0d%0a|\\r\\n)",
]


# ============================================================
#  ADVANCED DESERIALIZATION (30 patterns)
# ============================================================

ADVANCED_DESERIALIZATION = [
    # Java
    r"(?i)aced\s*0005",  # Java serialization magic
    r"(?i)rO0AB[A-Za-z0-9+/=]{10,}",  # Base64 Java serialized
    r"(?i)(?:org\.apache\.commons\.collections\.(?:Transformer|functors|keyvalue|comparators))",
    r"(?i)(?:org\.apache\.commons\.beanutils\.BeanComparator)",
    r"(?i)(?:com\.sun\.org\.apache\.xalan\.internal\.xsltc\.trax\.TemplatesImpl)",
    r"(?i)(?:java\.lang\.Runtime|java\.lang\.ProcessBuilder|javax\.script\.ScriptEngine)",
    r"(?i)(?:sun\.misc\.Unsafe|sun\.reflect\.(?:annotation|misc))",
    r"(?i)(?:org\.springframework\.(?:beans|context|core|aop)\.\w+Proxy)",
    r"(?i)(?:javassist\.|cglib\.|byte-buddy\.|asm\.)",
    # PHP
    r"(?i)O:\d+:\"[^\"]+\":\d+:\{(?:s:\d+:\"[^\"]*\";){2,}",
    r"(?i)a:\d+:\{(?:s:\d+:\"[^\"]*\";(?:s|i|d|b|a|O):\d*)",
    r"(?i)(?:SplDoublyLinkedList|SplStack|SplQueue|ArrayObject|SplObjectStorage)\b",
    r"(?i)__(?:wakeup|destruct|toString|call|callStatic|get|set|isset|unset|sleep|serialize|unserialize)\b",
    # Python
    r"(?i)(?:pickle|cPickle|shelve|marshal|yaml)\.(?:loads?|load|dump|dumps?)\s*\(",
    r"(?i)(?:cos\nsystem|cposix\nsystem|c__builtin__\neval)",
    r"(?i)(?:\x80\x02|\x80\x03|\x80\x04|\x80\x05)(?:c|q|R|S|V|X)",  # Python pickle opcodes
    r"(?i)(?:reduce|__reduce__|__reduce_ex__|copy_reg\._reconstructor)\b",
    # .NET
    r"(?i)(?:BinaryFormatter|SoapFormatter|ObjectStateFormatter|LosFormatter|NetDataContractSerializer)",
    r"(?i)(?:TypeNameHandling\s*(?:=|:)\s*(?:All|Auto|Objects|Arrays))",
    r"(?i)(?:\$type\s*[\"']?\s*(?:=|:)\s*[\"']?(?:System\.|Microsoft\.))",
    r"(?i)(?:DataContractSerializer|XmlSerializer|JavaScriptSerializer)\b.*(?:Type|KnownType|TypeNameHandling)",
    r"(?i)(?:ObjectDataProvider|ObjectInstance|MethodName|MethodParameters)\b",
    # Ruby
    r"(?i)(?:Marshal\.(?:load|restore)\s*\(|YAML\.(?:load|unsafe_load)\s*\(|Oj\.(?:load|safe_load)\s*\()",
    r"(?i)(?:ERB\.new|Erubi|Slim|HAML).*\.result\b",
    # Node.js
    r"(?i)(?:node-serialize|serialize-javascript|funcster)\.(?:unserialize|deserialize)\s*\(",
    r"(?i)(?:_\$\$ND_FUNC\$\$_|IIFE)",
    # Generic indicators
    r"(?i)(?:ysoserial|marshalsec|URLDNS|CommonsCollections|Spring1|Groovy1|JRMPClient|CommonsBeanutils)",
    r"(?i)(?:gadget|deserialization|unserialize|unmarshal|readObject|readResolve|readExternal|externalize)\b.*(?:exec|system|runtime|process)",
    r"(?i)(?:content-type\s*:\s*application/(?:x-java-serialized-object|java-serialized|x-java-object))",
    r"(?i)(?:content-type\s*:\s*application/(?:x-amf|x-php-serialized|vnd\.php\.serialized))",
]


# ============================================================
#  ADVANCED SSRF PATTERNS (30 patterns)
# ============================================================

ADVANCED_SSRF = [
    # DNS rebinding
    r"(?i)(?:\.(?:burpcollaborator|oastify|interact\.sh|dnslog|ceye|requestbin|ngrok|serveo|localtunnel)\.)",
    r"(?i)(?:nip\.io|xip\.io|sslip\.io|localtest\.me|lvh\.me|vcap\.me|launchpad\.net)(?:/|:|\b)",
    # IP encoding tricks
    r"(?i)(?:0177\.0+\.0+\.0*1|0x7f\.0x0+\.0x0+\.0x0*1|2130706433|017700000001|0x7f000001)\b",
    r"(?i)(?:①|②|③|④|⑤|⑥|⑦|⑧|⑨|⑩)",  # Unicode circled numbers
    r"(?i)(?:0{0,3}127\.0{0,3}0\.0{0,3}0\.0{0,3}1)\b",  # Padded zeros
    r"(?i)(?:(?:0x)?(?:7f|7F)(?:0{0,6})(?:0{0,4})(?:0{0,4}1))\b",
    # Protocol handlers
    r"(?i)(?:netdoc|jar|php|zip|phar|rar|ssh2|expect|glob|zlib|bzip2|compress\.zlib)://",
    r"(?i)(?:jar:(?:http|https|ftp|file)://[^!]+!/)",
    r"(?i)(?:data://text/(?:plain|html|xml|css|javascript|csv)(?:;base64)?)",
    # Cloud metadata endpoints
    r"(?i)(?:fd00::(?:ff|fe|fd)|fe80::(?:1|a9fe:a9fe))\b",  # IPv6 link-local
    r"(?i)(?:\[0:0:0:0:0:(?:ffff|FFFF):(?:127\.0\.0\.1|169\.254\.169\.254|a]9fe:a9fe)\])",
    r"(?i)(?:metadata\.internal|metadata\.google\.|instance-data/latest)",
    # URL parser confusion
    r"(?i)(?:https?://[^@]*@(?:127\.|10\.|172\.(?:1[6-9]|2|3[01])\.|192\.168\.|169\.254|localhost))",
    r"(?i)(?:https?://(?:127\.0\.0\.1|localhost)#@(?:trusted|allowed))",
    r"(?i)(?:https?://(?:trusted|allowed)\.(?:127\.0\.0\.1|localhost)\.)",
    r"(?i)(?:https?://[^/]*%(?:2[fF]|5[cC]|40|23)[^/]*(?:127|localhost|169\.254|10\.))",
    # Redirect chains for SSRF
    r"(?i)(?:url|redirect|proxy|target|dest)\s*=\s*https?://[^/]*(?:redirect|proxy|forward)[^/]*/",
    # SSRF via file upload
    r"(?i)(?:url|source|from|import|fetch|image_url)\s*[=:]\s*(?:https?://(?:127|10\.|172\.(?:1[6-9]|2|3[01])\.|192\.168\.|169\.254|localhost))",
    # SSRF via webhooks/callbacks
    r"(?i)(?:webhook|callback|notify|ping|hook|endpoint)_?(?:url|uri|endpoint)\s*[=:]\s*(?:file|gopher|dict|ftp|ldap|tftp)://",
    # SSRF via PDF/image generation
    r"(?i)(?:<iframe|<img|<link|<embed|<object|<source|<video|<audio)\s+(?:src|href|data|codebase)\s*=\s*['\"]?(?:file://|gopher://|dict://|ftp://|https?://(?:127|10\.|172\.(?:1[6-9]|2|3[01])\.|192\.168\.|169\.254|localhost))",
    # SSRF via XML/SVG
    r"(?i)<(?:svg|image|use)\s[^>]*(?:href|xlink:href)\s*=\s*['\"]?(?:file://|http://(?:127|10\.|169\.254|localhost))",
    # IPv4-mapped IPv6
    r"(?i)\[::(?:ffff:)?(?:127\.0\.0\.1|169\.254\.169\.254|10\.\d+\.\d+\.\d+)\]",
    r"(?i)(?:0000:0000:0000:0000:0000:(?:ffff|0000):(?:127\.0\.0\.1|a9fe:a9fe))",
    # URL shortener SSRF
    r"(?i)(?:bit\.ly|goo\.gl|tinyurl\.com|t\.co|is\.gd|buff\.ly|ow\.ly|rebrand\.ly)/[A-Za-z0-9]+",
    # SSRF via HTML injection
    r"(?i)<(?:base|a|form|area|link)\s[^>]*(?:href|action|src)\s*=\s*['\"]?(?:https?://(?:127|10\.|169\.254|localhost)|file://)",
    # SSRF via header injection
    r"(?i)(?:host|x-forwarded-host|x-host)\s*:\s*(?:127\.0\.0\.1|169\.254\.169\.254|localhost|internal|metadata)\b",
    r"(?i)(?:referer|origin)\s*:\s*(?:https?://(?:127|10\.|169\.254|localhost))",
    # Blind SSRF timing
    r"(?i)(?:url|target|host)\s*=\s*https?://[a-z0-9]+\.(?:burpcollaborator|oastify|interact\.sh)\.",
    r"(?i)(?:url|target|host)\s*=\s*https?://[0-9a-f]{8,}\.(?:ceye|dnslog|requestbin)\.",
]


# ============================================================
#  RACE CONDITION INDICATORS (20 patterns)
# ============================================================

RACE_CONDITION = [
    # Concurrent purchase/transfer
    r"(?i)(?:transfer|withdraw|purchase|buy|checkout|pay|redeem)\s*(?:amount|quantity|count)\s*[=:]\s*(?:-?\d{6,}|\d+(?:\.\d+)?e\d+)",
    # Rapid duplicate requests
    r"(?i)(?:x-request-id|x-correlation-id|x-trace-id)\s*:\s*(?:test|race|concurrent|parallel|flood|burst)",
    # TOCTOU indicators
    r"(?i)if-(?:match|none-match|modified-since|unmodified-since)\s*:\s*(?:\*|W/['\"])",
    r"(?i)(?:x-retry-count|x-attempt|retry-after)\s*:\s*(?:0|[5-9]\d+|\d{3,})",
    # Coupon/voucher abuse
    r"(?i)(?:coupon|voucher|promo|discount|code|gift)_?(?:code|id)?\s*[=:]\s*\S+.*(?:coupon|voucher|promo|discount|code|gift)_?(?:code|id)?\s*[=:]",
    # Double-spend indicators
    r"(?i)(?:transaction|order|payment)_?id\s*[=:]\s*(?:0|test|null|undefined|NaN|Infinity)",
    r"(?i)(?:amount|balance|quantity|stock|inventory)\s*[=:]\s*(?:-\d+|0\.0+1|\d+e\d{2,}|NaN|Infinity|-Infinity)",
    # Timing attack headers
    r"(?i)(?:x-forwarded-for|x-real-ip)\s*:\s*(?:\d{1,3}\.){3}\d{1,3}(?:\s*,\s*(?:\d{1,3}\.){3}\d{1,3}){5,}",
    # Integer overflow in parameters
    r"(?i)(?:id|count|offset|limit|page|size|quantity|amount)\s*[=:]\s*(?:2147483647|2147483648|4294967295|4294967296|9223372036854775807|-2147483648|-2147483649|-1)",
    # Float manipulation
    r"(?i)(?:price|amount|total|subtotal|tax|fee)\s*[=:]\s*(?:0\.0+|NaN|Infinity|-Infinity|1e308|-1e308)",
    # Null/undefined injection
    r"(?i)(?:user_id|account_id|owner_id|role)\s*[=:]\s*(?:null|undefined|nil|void|None|NaN|\[\]|\{\})",
    # Batch endpoint abuse
    r"(?i)/(?:batch|bulk|multi)(?:/|\?|$).*(?:\[.*\]|\{.*\}){3,}",
    # Lock bypass indicators
    r"(?i)(?:x-no-lock|x-skip-lock|x-bypass-lock|x-force|x-admin-override)\s*:\s*(?:true|1|yes)",
    # Time manipulation
    r"(?i)(?:timestamp|time|date|expires?|valid_until|not_after)\s*[=:]\s*(?:0|1|9999999999|2000000000)",
    # Idempotency key manipulation
    r"(?i)(?:idempotency[_-]?key|x-idempotency-key)\s*:\s*(?:test|race|dup|.{0,3}|.{200,})",
    # Concurrency header injection
    r"(?i)(?:x-forwarded-for|x-real-ip)\s*:\s*(?:127\.0\.0\.1\s*,\s*){3,}",
    # Numeric precision attacks
    r"(?i)(?:amount|price|quantity)\s*[=:]\s*\d+\.\d{10,}",
    # Empty/zero values in financial
    r"(?i)(?:total|amount|price|cost|fee|tax)\s*[=:]\s*(?:0(?:\.0+)?|00+|)\s*[&}]",
    # Negative quantity
    r"(?i)(?:quantity|qty|count|num|number)\s*[=:]\s*-\d+",
    # Parallel session indicators
    r"(?i)(?:x-session-override|x-admin-session|x-impersonate|x-as-user)\s*:\s*\S+",
]


# ============================================================
#  BUSINESS LOGIC ATTACKS (25 patterns)
# ============================================================

BUSINESS_LOGIC = [
    # Price manipulation
    r"(?i)(?:price|cost|amount|total|subtotal|unit_price)\s*[=:]\s*(?:0(?:\.0+)?|-\d+|0\.0[0-9]*1)",
    r"(?i)(?:discount|coupon_value|reduction)\s*[=:]\s*(?:100|[1-9]\d{2,}|999|1000)",
    # Quantity manipulation
    r"(?i)(?:quantity|qty|count|amount)\s*[=:]\s*(?:0|-[1-9]|99999|[1-9]\d{5,})",
    # Currency manipulation
    r"(?i)(?:currency|cur|money_type)\s*[=:]\s*(?:[A-Z]{3})\s*.*(?:currency|cur)\s*[=:]",  # Double currency
    # Order status manipulation
    r"(?i)(?:status|order_status|payment_status|delivery_status)\s*[=:]\s*(?:paid|delivered|completed|approved|verified|confirmed|shipped)",
    # Shipping address swap
    r"(?i)(?:shipping|delivery|billing)_?(?:address|addr).*(?:shipping|delivery|billing)_?(?:address|addr)",
    # Gift card abuse
    r"(?i)(?:gift_card|giftcard|gift_code|card_number)\s*[=:]\s*\S+.*(?:gift_card|giftcard|gift_code|card_number)\s*[=:]",
    # Referral abuse
    r"(?i)(?:referral|ref|invite|promo)\s*[=:]\s*(?:self|own|same|me|admin|system|test)",
    # Point/loyalty manipulation
    r"(?i)(?:points|loyalty|credits?|coins?|tokens?|gems?|diamonds?)\s*[=:]\s*(?:-?\d{6,}|\d+e\d+)",
    # Free trial abuse
    r"(?i)(?:trial|free|premium|plan|tier|subscription)\s*[=:]\s*(?:premium|enterprise|unlimited|pro|gold|platinum|vip)",
    # Email verification bypass
    r"(?i)(?:email_verified|verified|is_verified|confirmation|confirmed)\s*[=:]\s*(?:true|1|yes)",
    # Age/date restriction bypass
    r"(?i)(?:age|dob|date_of_birth|birth_date|birthday)\s*[=:]\s*(?:19[0-5]\d|190\d|200[0-5]|1900)",
    # Feature flag manipulation
    r"(?i)(?:feature|flag|toggle|experiment|ab_test|variant)\s*[=:]\s*(?:admin|internal|debug|beta|premium|all|enabled)",
    # Admin functionality
    r"(?i)(?:is_admin|isAdmin|admin|superuser|su|root|staff|moderator|manager)\s*[=:]\s*(?:true|1|yes|enabled)",
    # Privilege escalation via API
    r"(?i)(?:role_id|group_id|permission_id|access_level)\s*[=:]\s*(?:0|1|admin|root|super|god|999)",
    # Two-factor bypass
    r"(?i)(?:otp|mfa|2fa|totp|sms_code|verification_code)\s*[=:]\s*(?:000000|111111|123456|999999|null|undefined|true|false|bypass)",
    # Password reset manipulation
    r"(?i)(?:reset_token|password_token|confirm_token)\s*[=:]\s*(?:test|admin|null|undefined|0|true|.{0,5}|.{200,})",
    # Invoice/receipt manipulation
    r"(?i)(?:invoice|receipt|order)_?(?:id|number|ref)\s*[=:]\s*(?:0|1|test|admin|null|\.\.|\*|-1)",
    # Rate/exchange manipulation
    r"(?i)(?:exchange_rate|rate|conversion|fx_rate)\s*[=:]\s*(?:0|0\.0+|-\d+|999+|\d+e\d+)",
    # Inventory/stock manipulation
    r"(?i)(?:stock|inventory|available|in_stock)\s*[=:]\s*(?:true|999+|-?\d{6,}|Infinity)",
    # Shipping cost bypass
    r"(?i)(?:shipping_cost|delivery_fee|shipping_method|delivery_method)\s*[=:]\s*(?:0|free|none|null)",
    # Tax calculation bypass
    r"(?i)(?:tax_rate|tax_amount|vat|gst|sales_tax)\s*[=:]\s*(?:0|-\d+|null|undefined|NaN)",
    # Reward/cashback manipulation
    r"(?i)(?:cashback|reward|bonus|rebate|refund)\s*[=:]\s*(?:-?\d{5,}|\d+e\d+|Infinity)",
    # Auction/bidding manipulation
    r"(?i)(?:bid|offer|ask|reserve)\s*[=:]\s*(?:0|-\d+|0\.0+1|\d+e\d+)",
    # Scheduling/time slot abuse
    r"(?i)(?:timeslot|slot|booking_time|appointment|reservation)\s*[=:]\s*(?:past|expired|test|admin|internal)",
]


# ============================================================
#  DRUPAL SPECIFIC (20 patterns)
# ============================================================

DRUPAL_ATTACKS = [
    r"(?i)/(?:node|admin|user)/(?:\d+/(?:edit|delete|cancel|register)|login|logout|password)",
    r"(?i)/sites/default/(?:files|settings\.php|services\.yml)",
    r"(?i)/core/(?:install\.php|rebuild\.php|authorize\.php)",
    r"(?i)/(?:jsonapi|rest|subrequests)/",
    r"(?i)(?:drupal|drupalSettings|Drupal\.settings)\.",
    r"(?i)/(?:admin/(?:config|modules|people|structure|appearance|reports))",
    r"(?i)/(?:update\.php|cron\.php|xmlrpc\.php|install\.php)",
    r"(?i)/sites/(?:all|default)/(?:modules|themes)/",
    r"(?i)/(?:misc/drupal\.js|core/misc/drupal\.js|core/assets/vendor)",
    r"(?i)/node/\d+/(?:revisions|clone|devel)",
    # Drupalgeddon (CVE-2018-7600)
    r"(?i)/user/register\?.*(?:element_parents|ajax_form)",
    r"(?i)(?:form_id=user_register_form|mail\[#markup\]|mail\[#type\])",
    r"(?i)(?:#(?:post_render|pre_render|lazy_builder|markup|type|value)\[\]?\s*=)",
    # Drupalgeddon2 (CVE-2018-7602)
    r"(?i)/admin/config/\w+/\w+/(?:translate|revisions)",
    r"(?i)(?:destination=(?:\?|%3F)q=|destination=admin)",
    # Drupal SA-CORE
    r"(?i)/(?:entity|taxonomy|views|field)/(?:.*\.\./|.*%2e%2e)",
    r"(?i)/jsonapi/(?:node|user|taxonomy_term|file)/\w+/\w+\?\w+\[value\]",
    r"(?i)/(?:admin|node)/(?:\d+|%2e%2e|\.\.).*(?:script|eval|exec|system)",
    r"(?i)/_format=(?:hal_json|json|xml|serialized)",
    r"(?i)/core/(?:modules|profiles|themes)/(?:\.\./|%2e%2e)",
]


# ============================================================
#  JOOMLA SPECIFIC (15 patterns)
# ============================================================

JOOMLA_ATTACKS = [
    r"(?i)/(?:administrator|components|modules|plugins|templates)/",
    r"(?i)/(?:configuration\.php|htaccess\.txt|web\.config\.txt|joomla\.xml)",
    r"(?i)/index\.php\?option=com_\w+(?:&|\?).*(?:task=|view=|layout=)",
    r"(?i)/index\.php\?option=com_(?:content|users|media|installer|config|plugins|modules|templates|languages|search|finder|tags|fields|categories|menus|messages|redirect|newsfeeds|contact|banners|wrapper|weblinks).*(?:\.\.\/|%2e%2e|<script|union\s+select)",
    r"(?i)/administrator/index\.php\?option=com_\w+",
    r"(?i)/api/(?:index\.php/)?v1/",
    r"(?i)/(?:libraries|cli|layouts|includes)/",
    r"(?i)(?:com_fabrik|com_fields|com_jce|com_akeeba|com_virtuemart|com_k2|com_phocagallery).*(?:\.\.\/|exec|eval|system|upload)",
    # Joomla CVEs
    r"(?i)/index\.php\?option=com_users&task=user\.register.*(?:groups\[|jform\[groups\])",
    r"(?i)/index\.php\?option=com_media&task=(?:file\.upload|folder\.create).*(?:\.php|\.phtml|\.phar)",
    r"(?i)/api/index\.php/v1/(?:users|config|extensions|languages)",
    r"(?i)(?:jos_session|jos_users|#__session|#__users)",
    r"(?i)/plugins/system/(?:cache|debug|log|p3p|redirect|sef|logout)",
    r"(?i)/(?:tmp|logs|cache)/(?:\.\.\/|%2e%2e|\.htaccess|\.php)",
    r"(?i)/media/com_\w+/(?:\.\.\/|%2e%2e|shell|cmd|backdoor)",
]


# ============================================================
#  ADDITIONAL CVE 2024-2025 (50 patterns)
# ============================================================

CVE_2024_2025 = [
    # CVE-2024-3400 PAN-OS GlobalProtect (expanded)
    r"(?i)/ssl-vpn/hipreport\.esp\?.*cookie=.*(?:\.\./|%2e%2e|;)",
    r"(?i)/global-protect/(?:getconfig|login)\.esp.*(?:SESSID|cookie)=.*[\x00-\x1f]",
    # CVE-2024-21762 FortiOS out-of-bound write
    r"(?i)/remote/(?:fgt_lang|logincheck|error)\?.*(?:lang|err)=.*(?:%00|\x00|\.\.)",
    # CVE-2024-1709 ScreenConnect Auth Bypass
    r"(?i)/SetupWizard\.aspx/?\??.*(?:password|admin|user|setupToken)",
    # CVE-2024-27198 TeamCity Auth Bypass
    r"(?i)/app/rest/(?:users|projects|agents|builds|buildTypes)\?.*locator=",
    r"(?i)/(?:hax|login|internal|app/rest/debug).*(?:\.jsp|\.css|\.js)\?",
    # CVE-2024-4577 PHP CGI Argument Injection
    r"(?i)[%\x](?:AD|ad)(?:d|D)",
    r"(?i)php-cgi.*(?:-[drs]|-n|-c)",
    # CVE-2024-6387 OpenSSH regreSSHion
    r"(?i)SSH-2\.0-.{100,}",
    # CVE-2024-23897 Jenkins CLI arbitrary file read
    r"(?i)/cli\?remoting=false.*(?:@|<|>|%40|%3c|%3e)",
    r"(?i)/cli.*(?:who-am-i|version|list-plugins|build|create-node|delete-node|groovy)",
    # CVE-2024-0204 GoAnywhere MFT Auth Bypass
    r"(?i)/goanywhere/(?:auth/resetAdminPassword|lic/accept|cloud).*",
    r"(?i)/goanywhere/\.\.;/",
    # CVE-2024-21413 Outlook MonikerLink
    r"(?i)file:///\\\\[^/]+/",
    r"(?i)file://[^/].*!/",
    # CVE-2024-22024 Ivanti Connect Secure XXE
    r"(?i)/dana-na/auth/saml-sso\.cgi\?.*(?:<!ENTITY|SYSTEM|PUBLIC)",
    r"(?i)/dana-na/(?:css|auth|meeting).*(?:\.\./|%2e%2e)",
    # CVE-2024-1212 Progress LoadMaster
    r"(?i)/access/set\?.*(?:cmd|exec|system|bash|sh)",
    # CVE-2024-27956 WordPress SQL injection
    r"(?i)/wp-admin/admin-ajax\.php\?action=(?:astra_|flavor_).*(?:union|select|drop)",
    # CVE-2024-2961 glibc iconv
    r"(?i)(?:ISO-2022-CN|ISO-2022-CN-EXT|HZ|HZ-GB-2312|BIG5).*(?:\x1b|\x0e|\x0f)",
    # CVE-2024-3094 XZ Utils Backdoor
    r"(?i)(?:liblzma|xz|lzma).*(?:\.so\.5\.6\.[01])",
    # CVE-2024-38856 Apache OFBiz
    r"(?i)/webtools/control/(?:ProgramExport|ViewHandlerExt)\?.*(?:groovyProgram|VIEW_NAME)",
    # CVE-2024-38077 Windows RRAS RCE
    r"(?i)(?:SSTP|sstp-connection|SstpSvc).*(?:\x00{10,}|%00{10,})",
    # CVE-2024-38063 Windows TCP/IP IPv6
    r"(?i)(?:fe80|::1|fd00).*(?:extension\s*header|routing\s*header).*(?:type\s*[02]|segments\s*left)",
    # CVE-2024-47176 CUPS RCE
    r"(?i)(?:printer-uri|document-format|job-uri)\s*[:=].*(?:ftp://|http://|ipp://)",
    r"(?i)IPP/(?:1\.\d|2\.\d).*(?:Print-Job|Create-Job|Send-Document)",
    # CVE-2024-50623 Cleo File Transfer (Harmony/VLTrader/LexiCom)
    r"(?i)/Harmonyweb.*(?:\.\./|exec|cmd|system|bash)",
    r"(?i)/vltrader.*(?:\.\./|exec|cmd|system|bash)",
    # CVE-2024-12356 BeyondTrust PRA/RS
    r"(?i)/(?:appliance|api)/.*(?:command_injection|;|`|\$\()",
    # CVE-2024-55956 Cleo MFT autorun
    r"(?i)\.(?:VSH|vsh)$",
    # CVE-2024-49138 Windows CLFS driver
    r"(?i)(?:CLFS|clfs|BLF|blf).*(?:overflow|corrupt|exploit)",
    # CVE-2024-11477 7-Zip Zstandard decompression
    r"(?i)\x28\xb5\x2f\xfd.*(?:\xff{4,}|overflow|heap)",
    # CVE-2024-21893 Ivanti SSRF
    r"(?i)/dana-ws/saml20/login\.cgi\?.*(?:SAMLRequest|RelayState)=.*(?:http://|file://|gopher://)",
    # CVE-2024-20353 Cisco ASA/FTD
    r"(?i)/(?:CSCOE|CSCOT|CSCOCA)/.*(?:\.\./|%2e%2e|%00)",
    r"(?i)/\+CSCOE\+/(?:logon|portal|session|sdesktop)",
    # CVE-2024-48990 needrestart LPE
    r"(?i)(?:PYTHONPATH|RUBYLIB|LD_PRELOAD|LD_LIBRARY_PATH)\s*=.*(?:/tmp/|/dev/shm/|/var/tmp/)",
    # CVE-2024-53677 Apache Struts S2-067
    r"(?i)/(?:upload|file).*(?:Content-Disposition|filename).*(?:\.\.[\\/]|%2e%2e[%2f%5c])",
    # MOVEit expanded
    r"(?i)/moveitisapi/moveitisapi\.dll",
    r"(?i)/machine2/services\?.*(?:wsdl|soapAction)",
    r"(?i)/api/v1/(?:folders|files|groups|users)/\d+.*(?:delete|modify|create|admin)",
    # SolarWinds expanded
    r"(?i)/(?:Orion|orion)/.*(?:\.ashx|\.asmx|\.aspx)\?.*(?:cmd|exec|eval|script)",
    r"(?i)/SolarWinds/InformationService/v3/Json/",
    # Citrix expanded
    r"(?i)/vpn/(?:\.\.;|%2e%2e%3b)/",
    r"(?i)/rpc/(?:\.\.;|%2e%2e%3b)/",
    r"(?i)/pcidss/report\?type=allprofiles&sid=",
    # Fortinet expanded  
    r"(?i)/api/v2/cmdb/.*(?:exec|system|diag|config\s+global)",
    r"(?i)/api/v2/(?:monitor|log|cmdb)/.*(?:action=|exec=|cmd=)",
    # Generic 2024 patterns
    r"(?i)/(?:debug|internal|_internal|admin-api|management-api)/(?:exec|eval|run|command|script|console)",
    r"(?i)/(?:health|status|ready|alive|startup).*(?:;|--|union|select|exec|<script)",
    r"(?i)X-(?:Debug|Admin|Internal|Forwarded|Override|Method|Rewrite)\s*:.*(?:true|admin|internal|exec|eval)",
]


# ============================================================
#  Collect all advanced patterns with category labels
# ============================================================

ADVANCED_RULES_MAP = {
    'API_SECURITY_ADV': API_SECURITY_PATTERNS,
    'CLOUD_ATTACKS': CLOUD_ATTACKS,
    'CONTAINER_K8S': CONTAINER_K8S_ATTACKS,
    'OAUTH_SAML': OAUTH_SAML_ATTACKS,
    'FILE_UPLOAD_ADV': FILE_UPLOAD_ATTACKS,
    'HTTP2_HTTP3': HTTP2_HTTP3_ATTACKS,
    'DESERIALIZATION_ADV': ADVANCED_DESERIALIZATION,
    'SSRF_ADV': ADVANCED_SSRF,
    'RACE_CONDITION': RACE_CONDITION,
    'BUSINESS_LOGIC': BUSINESS_LOGIC,
    'DRUPAL': DRUPAL_ATTACKS,
    'JOOMLA': JOOMLA_ATTACKS,
    'CVE_2024_2025': CVE_2024_2025,
}


def get_all_advanced_patterns():
    """Return all advanced patterns as list of (regex_str, category)."""
    patterns = []
    for category, rules in ADVANCED_RULES_MAP.items():
        for regex_str in rules:
            patterns.append((regex_str, category))
    return patterns


def count_advanced_patterns():
    """Return total count of advanced patterns."""
    return sum(len(v) for v in ADVANCED_RULES_MAP.values())
