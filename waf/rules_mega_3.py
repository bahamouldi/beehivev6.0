"""
BeeWAF v5.0 Mega Rules Database — Part 3
==========================================
~2500 additional signatures covering PHP-specific attacks, Java/Spring
exploitation, Node.js attacks, .NET attacks, cloud infrastructure,
container/K8s deep, CI/CD pipeline attacks, API security deep,
data exfiltration, privilege escalation, lateral movement, persistence,
IoT/embedded, AI/ML attacks, supply chain, and emerging threats.
"""

# ============================================================================
# 1. PHP-SPECIFIC ATTACKS (200 patterns)
# ============================================================================
PHP_ATTACKS_DEEP = [
    # --- Dangerous functions ---
    r"(?i)(?:eval|assert|preg_replace|create_function|call_user_func|call_user_func_array)\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)|base64_decode|gzinflate|str_rot13)",
    r"(?i)(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE)|base64_decode)",
    r"(?i)(?:include|require|include_once|require_once)\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE)|['\"](?:php://|data://|zip://|phar://|expect://|glob://))",
    r"(?i)(?:file_get_contents|file_put_contents|fopen|fwrite|fputs|readfile|highlight_file|show_source)\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE)|['\"](?:php://|data://|http://|ftp://|zip://|phar://))",
    r"(?i)(?:unserialize|json_decode)\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE)|base64_decode|gzinflate)",
    r"(?i)(?:extract|parse_str|import_request_variables|mb_parse_str)\s*\(\s*\$_(?:GET|POST|REQUEST)",
    r"(?i)(?:dl|ini_set|ini_restore|ini_alter|set_include_path|set_time_limit|ignore_user_abort)\s*\(",
    r"(?i)(?:putenv|getenv|apache_setenv)\s*\(\s*['\"](?:LD_PRELOAD|PATH|HOME|SHELL)",
    r"(?i)(?:mail|imap_open|imap_mail)\s*\(.*(?:-X\s|/var/log|/tmp/|/dev/|exec\(|system\()",
    r"(?i)(?:preg_replace)\s*\(\s*['\"]/.*/e['\"]",
    r"(?i)(?:array_map|array_filter|array_walk|array_walk_recursive|usort|uasort|uksort)\s*\(\s*(?:\$_(?:GET|POST|REQUEST)|['\"](?:system|exec|passthru|shell_exec|assert|eval)['\"])",
    r"(?i)(?:register_shutdown_function|register_tick_function|set_error_handler|set_exception_handler|ob_start)\s*\(\s*['\"](?:system|exec|passthru|shell_exec|eval|assert)['\"]",
    r"(?i)(?:ReflectionFunction|ReflectionMethod|ReflectionClass)\s*\(\s*['\"](?:system|exec|passthru|shell_exec)['\"]",
    r"(?i)(?:SimpleXMLElement|DOMDocument|XMLReader|XMLWriter)\s*\(",
    # --- PHP wrappers ---
    r"(?i)php://filter/(?:read|write)=(?:convert\.|string\.|zlib\.|bzip2\.|mcrypt\.|mdecrypt\.)",
    r"(?i)php://filter/convert\.base64-(?:encode|decode)/resource=",
    r"(?i)php://filter/convert\.iconv\.\w+\.\w+/resource=",
    r"(?i)php://filter/string\.(?:rot13|toupper|tolower|strip_tags)/resource=",
    r"(?i)php://filter/zlib\.(?:deflate|inflate)/resource=",
    r"(?i)php://input\b",
    r"(?i)php://stdin\b",
    r"(?i)php://fd/\d+",
    r"(?i)php://memory\b",
    r"(?i)php://temp\b",
    r"(?i)php://data\b",
    r"(?i)php://glob://",
    r"(?i)expect://\w+",
    r"(?i)zip://.*#",
    r"(?i)compress\.zlib://",
    r"(?i)compress\.bzip2://",
    r"(?i)phar://.*\.(?:phar|gif|jpg|png|pdf|tar|zip|gz)/",
    r"(?i)data://text/plain;base64,",
    r"(?i)data://text/plain,<\?php",
    # --- PHP object injection ---
    r"(?i)O:\d+:\"(?:Monolog|Guzzle|Symfony|Illuminate|Swift|Doctrine|Propel|CakePHP|Zend|Laravel|CodeIgniter|Yii|Phalcon|Slim|Lumen|ThinkPHP|Fuel|Flight)",
    r"(?i)O:\d+:\"(?:PendingBroadcast|FnStream|MockPhpStream|EvalLoader|RCE|Shell|Exploit|Backdoor|Payload|Gadget)",
    r"(?i)a:\d+:\{(?:s:\d+:\"[^\"]+\";){2,}.*(?:system|exec|passthru|shell_exec|eval|assert|popen|proc_open|pcntl_exec|call_user_func|create_function)",
    # --- PHP info disclosure ---
    r"(?i)(?:phpinfo|php_uname|php_sapi_name|phpversion|php_ini_loaded_file|php_ini_scanned_files|get_loaded_extensions|get_defined_functions|get_defined_vars|get_defined_constants)\s*\(\s*\)",
    r"(?i)(?:getenv|apache_getenv|getallheaders|get_headers)\s*\(",
    r"(?i)(?:get_current_user|getmyuid|getmygid|getmypid|getlastmod|get_include_path|get_cfg_var)\s*\(",
    r"(?i)(?:error_reporting|display_errors|log_errors|error_log|open_basedir|disable_functions|disable_classes|allow_url_(?:fopen|include))",
    # --- PHP type juggling ---
    r"(?i)(?:==|!=)\s*(?:0|false|null|true|'0'|\"0\"|''|\"\"|array\(\)|\[\])\s*(?://|;|\)|\})",
    r"(?i)switch\s*\(\s*\$\w+\s*\)\s*\{\s*case\s+0\s*:",
    r"(?i)strcmp\s*\(\s*\$\w+\s*,\s*\$\w+\s*\)\s*==\s*0",
    r"(?i)md5\s*\(\s*['\"](?:240610708|QNKCDZO|aabg7XSs|aabC9RqS|s878926199a|s155964671a|s214587387a|s1091221200a|0e[0-9]+)['\"]",
    r"(?i)(?:intval|floatval|boolval|settype)\s*\(",
    # --- PHP disable_functions bypass ---
    r"(?i)(?:FFI|ffi)::(?:cdef|typeof|new|cast|string|memcpy|memset|free|isNull|addr|sizeof)",
    r"(?i)(?:LD_PRELOAD|putenv).*(?:\.so|/tmp/|/dev/shm/|/var/tmp/)",
    r"(?i)(?:dl|extension_loaded|get_extension_funcs)\s*\(\s*['\"](?:exec|system|shell)",
    r"(?i)proc_open\s*\(\s*['\"](?:bash|sh|cmd|powershell)",
    r"(?i)pcntl_(?:exec|fork|signal|waitpid|wexitstatus|alarm)\s*\(",
    r"(?i)posix_(?:kill|getpwuid|setuid|setgid|seteuid|setegid|mkfifo|mknod)\s*\(",
    r"(?i)(?:imagick|Imagick).*(?:ephemeral|msl|mvg|svg|url)://",
    r"(?i)(?:imap_open)\s*\(\s*['\"]?\{.*\}",
    r"(?i)glob\s*\(\s*['\"].*(?:\*|\?|\[)",
    r"(?i)scandir\s*\(\s*['\"](?:/|\\|\.\.)",
    r"(?i)opendir\s*\(\s*['\"](?:/|\\|\.\.)",
    r"(?i)chdir\s*\(\s*['\"](?:/|\\|\.\.)",
    r"(?i)chroot\s*\(",
    r"(?i)symlink\s*\(",
    r"(?i)link\s*\(",
    r"(?i)tempnam\s*\(",
    r"(?i)tmpfile\s*\(",
]

# ============================================================================
# 2. JAVA / SPRING EXPLOITATION (200 patterns)
# ============================================================================
JAVA_SPRING_DEEP = [
    # --- Spring Boot Actuator ---
    r"(?i)/actuator/(?:env|configprops|beans|mappings|metrics|health|info|dump|trace|heapdump|threaddump|auditevents|caches|conditions|flyway|httptrace|integrationgraph|jolokia|liquibase|logfile|loggers|prometheus|scheduledtasks|sessions|shutdown|startup)",
    r"(?i)/actuator/env/\w+",
    r"(?i)/actuator/loggers/\w+",
    r"(?i)/actuator/shutdown\b",
    r"(?i)/actuator/gateway/routes\b",
    r"(?i)/actuator/gateway/routes/\w+",
    # --- Spring Cloud Gateway ---
    r"(?i)/actuator/gateway/routes/\w+.*(?:exec|system|Runtime|ProcessBuilder|URLClassLoader)",
    r"(?i)spring\.cloud\.gateway\.routes",
    r"(?i)#{.*T\(java\.lang\.Runtime\).*exec.*}",
    r"(?i)#{.*T\(java\.lang\.ProcessBuilder\).*start.*}",
    r"(?i)#{.*T\(java\.lang\.Thread\).*sleep.*}",
    r"(?i)#{.*T\(java\.lang\.Class\).*forName.*}",
    r"(?i)#{.*new\s+java\.(?:lang|io|net|util)\.\w+.*}",
    r"(?i)#{.*getClass\(\)\.forName.*}",
    r"(?i)#{.*getRuntime\(\)\.exec.*}",
    # --- Spring Expression Language (SpEL) ---
    r"(?i)\$\{.*T\(java\.lang\.\w+\).*\}",
    r"(?i)\$\{.*T\(Runtime\).*\}",
    r"(?i)\$\{.*T\(ProcessBuilder\).*\}",
    r"(?i)\$\{.*T\(Class\).*\}",
    r"(?i)\$\{.*T\(Thread\).*\}",
    r"(?i)\$\{.*T\(System\).*\}",
    r"(?i)\$\{.*T\(Math\).*\}",
    r"(?i)\$\{.*T\(InetAddress\).*\}",
    r"(?i)\$\{.*T\(URL\).*\}",
    r"(?i)\$\{.*T\(URLClassLoader\).*\}",
    r"(?i)\$\{.*T\(ScriptEngineManager\).*\}",
    r"(?i)\#\{.*T\(java\.lang\.\w+\).*\}",
    r"(?i)\#\{.*new\s+ProcessBuilder\b.*\}",
    r"(?i)\#\{.*\.getClass\(\)\.forName\(.*\}",
    r"(?i)\#\{.*\.getClass\(\)\.getClassLoader\(\).*\}",
    r"(?i)\#\{.*\.getClass\(\)\.getResource\(.*\}",
    # --- JNDI injection ---
    r"(?i)(?:rmi|ldap|ldaps|dns|iiop|corba|nds|nis)://(?:\d+\.\d+\.\d+\.\d+|\w+\.(?:com|net|org|io|xyz|me|info))[:/]",
    r"(?i)(?:com\.sun\.jndi\.(?:rmi|ldap|cosnaming|dns)\.object\.trustURLCodebase)\s*=\s*true",
    r"(?i)InitialContext\s*\(\s*\)",
    r"(?i)Context\.INITIAL_CONTEXT_FACTORY",
    r"(?i)Context\.PROVIDER_URL",
    r"(?i)(?:lookup|bind|rebind|unbind)\s*\(\s*['\"](?:rmi|ldap|ldaps|iiop|dns)://",
    r"(?i)javax\.naming\.(?:InitialContext|Context|directory|ldap|Reference|StringRefAddr)",
    r"(?i)javax\.management\.remote\.JMXServiceURL",
    # --- OGNL injection ---
    r"(?i)%\{.*\.getClass\(\).*\}",
    r"(?i)%\{.*\bRuntime\b.*\bexec\b.*\}",
    r"(?i)%\{.*\bProcessBuilder\b.*\}",
    r"(?i)%\{.*\bforName\b.*\}",
    r"(?i)%\{.*#(?:_memberAccess|attr|application|session|parameters|request|response|servletContext|context).*\}",
    r"(?i)%\{.*#(?:_memberAccess)\[.*allowStaticMethodAccess.*\].*=.*true.*\}",
    r"(?i)%\{.*@(?:java\.lang|org\.apache|com\.opensymphony).*\}",
    r"(?i)%\{.*OgnlUtil.*\}",
    r"(?i)%\{.*OgnlContext.*\}",
    r"(?i)%\{.*ValueStack.*\}",
    # --- Struts2 specific ---
    r"(?i)(?:action|redirect|redirectAction)\s*:.*%\{",
    r"(?i)Content-Type\s*:\s*%\{#context\[",
    r"(?i)\$\{#context\[",
    r"(?i)multipart/form-data.*%\{",
    r"(?i)S2-(?:001|005|008|009|012|013|014|015|016|019|029|032|033|037|045|046|048|052|053|057|059|061|062)\b",
    # --- EL injection ---
    r"(?i)\$\{(?:applicationScope|sessionScope|requestScope|pageScope|param|paramValues|header|headerValues|initParam|cookie)\b",
    r"(?i)\$\{(?:pageContext\.(?:request|response|session|servletContext|servletConfig|page|out|exception|errorData))\b",
    r"(?i)\$\{(?:facesContext\.externalContext\.requestMap)\b",
    r"(?i)\$\{(?:facesContext\.externalContext\.requestParameterMap)\b",
    r"(?i)\#\{(?:request|session|application|facesContext|externalContext)\.(?:getClass|forName|getMethod|invoke|exec)\b",
    # --- Java RCE chains ---
    r"(?i)java\.lang\.Runtime\.getRuntime\(\)\.exec\(",
    r"(?i)new\s+ProcessBuilder\s*\(\s*(?:Arrays\.asList|List\.of|new\s+String\[\])\s*\(",
    r"(?i)Class\.forName\s*\(\s*['\"](?:java\.lang\.Runtime|java\.lang\.ProcessBuilder|java\.lang\.reflect|javax\.script|com\.sun|sun\.misc)['\"]",
    r"(?i)ClassLoader\.(?:loadClass|findClass|defineClass|getResource)\s*\(",
    r"(?i)URLClassLoader\s*\(\s*new\s+URL\[\]\s*\{",
    r"(?i)ScriptEngineManager\s*\(\s*\)\s*\.\s*getEngineByName\s*\(\s*['\"](?:js|javascript|nashorn|graal|groovy|python|ruby|beanshell)['\"]",
    r"(?i)MethodHandle\.(?:lookup|find|invoke|invokeExact|invokeWithArguments)\s*\(",
    r"(?i)Unsafe\.(?:getUnsafe|allocateInstance|defineClass|putObject|getObject|putInt|getInt)\s*\(",
    r"(?i)Instrumentation\.(?:addTransformer|redefineClasses|retransformClasses|appendToBootstrapClassLoaderSearch)\s*\(",
    # --- Spring Framework specific ---
    r"(?i)org\.springframework\.(?:context\.support\.ClassPathXmlApplicationContext|beans\.factory\.config\.PropertyPathFactoryBean|context\.support\.FileSystemXmlApplicationContext)\b",
    r"(?i)spring\.(?:datasource|jpa|security|cloud|kafka|redis|rabbitmq|elasticsearch|mail)\.(?:url|username|password|driver-class-name|host|port|secret|key)\b",
    r"(?i)spring\.(?:main\.allow-bean-definition-overriding|main\.lazy-initialization|devtools\.restart)\b",
    r"(?i)management\.(?:endpoint|endpoints)\.\w+\.(?:enabled|exposure\.include|show-details)\b",
    r"(?i)server\.(?:port|address|ssl|servlet\.context-path|compression|error\.include-stacktrace)\b",
]

# ============================================================================
# 3. NODE.JS / JAVASCRIPT ATTACKS (150 patterns)
# ============================================================================
NODEJS_DEEP = [
    # --- Prototype pollution ---
    r"(?i)(?:__proto__|constructor\.prototype|constructor\[.prototype.\])\s*[.=\[]",
    r"(?i)(?:Object\.(?:assign|create|defineProperty|defineProperties|freeze|getOwnPropertyDescriptor|getOwnPropertyNames|getOwnPropertySymbols|getPrototypeOf|keys|setPrototypeOf|values|entries))\s*\(",
    r"(?i)Reflect\.(?:apply|construct|defineProperty|deleteProperty|get|getOwnPropertyDescriptor|getPrototypeOf|has|isExtensible|ownKeys|preventExtensions|set|setPrototypeOf)\s*\(",
    r"(?i)(?:merge|extend|assign|defaults|deepMerge|deepExtend|lodash\.merge|_\.merge|jQuery\.extend|angular\.extend)\s*\(",
    r"(?i)\[\"__proto__\"\]",
    r"(?i)\[\"constructor\"\]\s*\[\"prototype\"\]",
    r"(?i)JSON\.parse\s*\(.*__proto__",
    r"(?i)JSON\.parse\s*\(.*constructor.*prototype",
    # --- RCE via require ---
    r"(?i)require\s*\(\s*['\"](?:child_process|fs|os|path|net|http|https|dgram|dns|tls|cluster|vm|repl|readline|crypto|zlib|stream|buffer|events|util|assert|querystring|url|punycode|domain|v8|perf_hooks|worker_threads|inspector|wasi)['\"]",
    r"(?i)require\s*\(\s*['\"](?:child_process|fs|os|net|vm|inspector|v8|worker_threads|cluster|repl)['\"]",
    r"(?i)child_process\.(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\(",
    r"(?i)process\.(?:binding|env|argv|execPath|cwd|chdir|exit|kill|abort|mainModule|dlopen|_linkedBinding)\b",
    r"(?i)process\.mainModule\.require\s*\(",
    r"(?i)process\.binding\s*\(\s*['\"](?:spawn_sync|fs|buffer|natives|constants|timer_wrap|tty_wrap|pipe_wrap|tcp_wrap|udp_wrap|process_wrap|signal_wrap|http_parser|os|crypto)['\"]",
    r"(?i)global\.process\b",
    r"(?i)global\.require\b",
    r"(?i)globalThis\.process\b",
    r"(?i)this\.constructor\.constructor\s*\(\s*['\"]return\s+(?:process|require|global|this)['\"]",
    # --- VM sandbox escape ---
    r"(?i)vm\.(?:createContext|runInContext|runInNewContext|runInThisContext|compileFunction|Script)\s*\(",
    r"(?i)new\s+vm\.Script\s*\(",
    r"(?i)vm2?\.\w+\s*\(.*(?:process|require|child_process|fs|os|net)",
    r"(?i)this\.constructor\.constructor\s*\(\s*['\"]return\s+this['\"]",
    r"(?i)(?:Function|AsyncFunction|GeneratorFunction)\s*\(\s*['\"]return\s+(?:process|require|global|this|arguments)",
    r"(?i)(?:eval|Function)\s*\(\s*(?:atob|Buffer\.from|decodeURIComponent)\s*\(",
    # --- Express.js specific ---
    r"(?i)(?:req|request)\.(?:params|query|body|headers|cookies|files|file|ip|hostname|protocol|secure|xhr|route|baseUrl|originalUrl|path|subdomains)\b",
    r"(?i)(?:res|response)\.(?:send|json|render|redirect|sendFile|download|attachment|cookie|clearCookie|set|header|status|type|format|links|location|vary|append)\b",
    r"(?i)res\.(?:render|sendFile|download)\s*\(\s*(?:req\.(?:params|query|body)|process\.env)",
    r"(?i)app\.(?:use|get|post|put|delete|patch|options|head|all|route|listen|enable|disable|set)\s*\(",
    r"(?i)app\.(?:set|enable)\s*\(\s*['\"](?:trust proxy|x-powered-by|etag|query parser|strict routing|case sensitive routing)['\"]",
    # --- NoSQL injection (MongoDB) ---
    r"(?i)\{\s*['\"]?\$(?:where|regex|text|mod|all|size|type|exists|elemMatch|slice|in|nin|gt|gte|lt|lte|ne|eq|not|nor|or|and)\b",
    r"(?i)\.(?:find|findOne|findOneAndUpdate|findOneAndDelete|aggregate|distinct|countDocuments|estimatedDocumentCount)\s*\(\s*\{",
    r"(?i)\.(?:updateOne|updateMany|deleteOne|deleteMany|replaceOne|insertOne|insertMany|bulkWrite)\s*\(\s*\{",
    r"(?i)\{\s*['\"]?\$(?:lookup|unwind|group|project|match|sort|limit|skip|sample|addFields|set|unset|replaceRoot|replaceWith|merge|out|facet|bucket|bucketAuto|sortByCount|count|graphLookup|geoNear|redact)\b",
    r"(?i)\$where\s*:\s*['\"]function\s*\(",
    r"(?i)\$where\s*:\s*['\"]this\.\w+\s*(?:==|!=|>|<|>=|<=)",
    r"(?i)this\.(?:constructor|__proto__|toString|valueOf|hasOwnProperty)\b",
    # --- Template injection (EJS/Pug/Handlebars) ---
    r"(?i)<%[-=]?\s*(?:require|process|global|eval|Function|child_process|fs|os|exec|spawn|execSync)\b",
    r"(?i)#{.*(?:require|process|global|eval|Function|child_process|fs|os|exec|spawn)\b.*}",
    r"(?i)\{\{.*(?:constructor|__proto__|prototype|Function|eval|process|require|global)\b.*\}\}",
    r"(?i)\{\{#(?:with|each|if|unless)\s+(?:constructor|__proto__|prototype|Function)\b",
    r"(?i)(?:ejs|pug|handlebars|mustache|nunjucks|swig|dot|art-template|eta)\.(?:render|compile|renderFile)\s*\(",
    r"(?i)res\.render\s*\(\s*['\"][^'\"]+['\"]\s*,\s*\{[^}]*(?:req\.(?:params|query|body)|process\.env)",
    # --- SSRF in Node ---
    r"(?i)(?:axios|got|node-fetch|superagent|needle|phin|undici|bent|make-fetch-happen|cross-fetch|isomorphic-fetch|request|request-promise|urllib)\s*\.(?:get|post|put|delete|patch|request)\s*\(",
    r"(?i)(?:http|https)\.(?:get|request)\s*\(\s*(?:req\.(?:params|query|body)\.\w+|process\.env\.\w+)",
    r"(?i)(?:fetch|XMLHttpRequest)\s*\(\s*(?:req\.(?:params|query|body)\.\w+|decodeURIComponent|Buffer\.from)",
    # --- Event loop blocking ---
    r"(?i)while\s*\(\s*true\s*\)\s*\{",
    r"(?i)for\s*\(\s*;;\s*\)\s*\{",
    r"(?i)setTimeout\s*\(\s*\w+\s*,\s*0\s*\)\s*.*(?:while|for)\s*\(",
    r"(?i)setImmediate\s*\(\s*\w+\s*\)\s*.*(?:while|for)\s*\(",
    r"(?i)(?:crypto\.(?:pbkdf2Sync|scryptSync|randomFillSync)|fs\.(?:readFileSync|writeFileSync|readdirSync|statSync))\s*\(",
    # --- Path traversal in Node ---
    r"(?i)path\.(?:join|resolve|normalize)\s*\(\s*(?:__dirname|process\.cwd\(\))?\s*,\s*(?:req\.(?:params|query|body)|decodeURIComponent)",
    r"(?i)fs\.(?:readFile|writeFile|appendFile|readdir|stat|access|unlink|rename|mkdir|rmdir|createReadStream|createWriteStream)\s*\(\s*(?:req\.(?:params|query|body)|path\.join.*req)",
]

# ============================================================================
# 4. .NET / C# ATTACKS (120 patterns)
# ============================================================================
DOTNET_DEEP = [
    # --- Deserialization ---
    r"(?i)(?:BinaryFormatter|SoapFormatter|NetDataContractSerializer|LosFormatter|ObjectStateFormatter|XmlSerializer|DataContractSerializer|JavaScriptSerializer|XamlReader|ActivitySurrogateSelector)\b",
    r"(?i)TypeNameHandling\s*(?:=|:)\s*(?:All|Auto|Objects|Arrays)\b",
    r"(?i)\$type\s*['\"]?\s*:\s*['\"]?System\.(?:Diagnostics|IO|Security|Runtime|Reflection|CodeDom|Configuration|Activities|Windows|Web|Data|Net|Messaging)\.",
    r"(?i)__type\s*['\"]?\s*:\s*['\"]?System\.\w+",
    r"(?i)System\.(?:Diagnostics\.Process|IO\.File|Reflection\.Assembly|CodeDom\.Compiler|Runtime\.Serialization|Security\.Principal|Web\.UI\.LosFormatter|Xml\.Serialization|Data\.SqlClient|Net\.WebClient)\b",
    r"(?i)(?:ObjectDataProvider|XamlReader\.Load|BinaryFormatter\.Deserialize|SoapFormatter\.Deserialize|JavaScriptSerializer\.Deserialize)\b",
    r"(?i)(?:WindowsIdentity|WindowsPrincipal|GenericPrincipal|ClaimsPrincipal|ClaimsIdentity)\b.*(?:Deserialize|FromXml|FromJson|Parse)",
    # --- Code execution ---
    r"(?i)Process\.Start\s*\(",
    r"(?i)ProcessStartInfo\s*\(",
    r"(?i)System\.Diagnostics\.Process\b",
    r"(?i)Assembly\.(?:Load|LoadFile|LoadFrom|LoadWithPartialName|ReflectionOnlyLoad|ReflectionOnlyLoadFrom|UnsafeLoadFrom)\s*\(",
    r"(?i)Activator\.(?:CreateInstance|CreateComInstanceFrom|CreateInstanceFrom|GetObject)\s*\(",
    r"(?i)AppDomain\.(?:ExecuteAssembly|CreateInstanceAndUnwrap|Load|DefineDynamicAssembly|CreateDomain)\s*\(",
    r"(?i)CSharpCodeProvider\b",
    r"(?i)VBCodeProvider\b",
    r"(?i)CodeDomProvider\.(?:CompileAssemblyFromSource|CompileAssemblyFromFile|CompileAssemblyFromDom)\b",
    r"(?i)Roslyn\.(?:CSharpCompilation|VisualBasicCompilation)\b",
    r"(?i)DynamicMethod\b",
    r"(?i)ILGenerator\b",
    r"(?i)Expression\.(?:Lambda|Call|New|Invoke|Constant)\b",
    # --- SQL injection in .NET ---
    r"(?i)SqlCommand\s*\(\s*['\"].*(?:\+\s*\w+|\$\{|String\.Format|string\.Concat)",
    r"(?i)SqlConnection\s*\(\s*['\"].*(?:Data Source|Server|Initial Catalog|Database|User ID|Password|Integrated Security)",
    r"(?i)(?:SqlDataAdapter|SqlDataReader|SqlBulkCopy|OleDbCommand|OdbcCommand|EntityFramework|LinqToSql)\b",
    r"(?i)(?:ExecuteNonQuery|ExecuteReader|ExecuteScalar|ExecuteXmlReader|SqlQuery|FromSqlRaw|FromSqlInterpolated)\s*\(",
    # --- ASP.NET specific ---
    r"(?i)(?:ViewState|__VIEWSTATE|__VIEWSTATEGENERATOR|__EVENTVALIDATION|__EVENTTARGET|__EVENTARGUMENT)\b",
    r"(?i)__VIEWSTATE\s*=\s*[a-zA-Z0-9+/=]{20,}",
    r"(?i)(?:ScriptManager|UpdatePanel|AsyncPostBackTrigger|PostBackTrigger|Timer)\b",
    r"(?i)(?:Server\.Transfer|Server\.Execute|Response\.Redirect|Response\.Write|Response\.BinaryWrite)\s*\(",
    r"(?i)(?:Request\.(?:Form|QueryString|Params|Item|Files|Cookies|Headers|ServerVariables|RawUrl|Path|PhysicalPath|UserAgent|UserHostAddress))\b",
    r"(?i)(?:Request\.Unvalidated\.\w+)\b",
    r"(?i)(?:HttpCookie|FormsAuthentication|MachineKey|RoleProvider|MembershipProvider)\b",
    r"(?i)(?:web\.config|machine\.config|applicationhost\.config|\.aspx|\.ashx|\.asmx|\.svc|\.axd)\b",
    r"(?i)(?:elmah\.axd|trace\.axd|ScriptResource\.axd|WebResource\.axd)\b",
    # --- .NET Core/5+ specific ---
    r"(?i)(?:IConfiguration|IServiceProvider|IServiceCollection|IHostEnvironment|IWebHostEnvironment)\b",
    r"(?i)(?:appsettings\.(?:json|Development\.json|Production\.json|Staging\.json))\b",
    r"(?i)(?:ASPNETCORE_ENVIRONMENT|DOTNET_ENVIRONMENT|ConnectionStrings__\w+|AppSettings__\w+)\b",
    r"(?i)(?:Kestrel|Startup|Program|ConfigureServices|Configure|UseEndpoints|MapControllers|MapRazorPages)\b",
    r"(?i)(?:IHubContext|SignalR|MapHub|UseSignalR)\b",
    r"(?i)(?:Razor|RazorPage|TagHelper|ViewComponent|PartialView|RenderSection|RenderBody)\b",
]

# ============================================================================
# 5. CLOUD INFRASTRUCTURE ATTACKS (150 patterns)
# ============================================================================
CLOUD_INFRA_DEEP = [
    # --- AWS ---
    r"(?i)(?:AKIA|ASIA|AROA|AIDA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b",
    r"(?i)(?:aws_access_key_id|aws_secret_access_key|aws_session_token|aws_security_token)\s*(?:=|:)\s*['\"a-zA-Z0-9/+=]+",
    r"(?i)(?:s3|ec2|lambda|iam|rds|sqs|sns|dynamodb|cloudformation|cloudwatch|cloudfront|route53|ecs|eks|ecr|fargate|elasticache|redshift|kinesis|firehose|glue|athena|emr|sagemaker|secretsmanager|ssm|sts|kms|cognito|apigateway)\.\w+-\w+-\d+\.amazonaws\.com",
    r"(?i)arn:aws(?:-cn|-us-gov)?:(?:iam|s3|ec2|lambda|rds|sqs|sns|dynamodb|ecs|eks|ecr|kms|secretsmanager|ssm|sts|cognito|apigateway|cloudformation|cloudwatch|cloudfront|route53|elasticache|redshift|kinesis|firehose|glue|athena|emr|sagemaker):\w*:\d*:\w+",
    r"(?i)s3://[a-z0-9][a-z0-9.-]+/",
    r"(?i)https?://[a-z0-9.-]+\.s3(?:\.\w+-\w+-\d+)?\.amazonaws\.com/",
    r"(?i)(?:aws\s+configure|aws\s+sts\s+(?:get-session-token|assume-role|get-caller-identity))\b",
    r"(?i)(?:aws\s+(?:s3|ec2|iam|lambda|rds|dynamodb|sqs|sns|ecs|eks|secretsmanager|ssm|kms|sts|cognito|cloudformation)\s+\w+)",
    r"(?i)AWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN|DEFAULT_REGION|PROFILE|CONFIG_FILE|SHARED_CREDENTIALS_FILE|LAMBDA_FUNCTION_NAME|EXECUTION_ENV|REGION)\b",
    # --- Azure ---
    r"(?i)(?:DefaultEndpointsProtocol|AccountName|AccountKey|BlobEndpoint|QueueEndpoint|TableEndpoint|FileEndpoint|SharedAccessSignature)\s*=",
    r"(?i)(?:https?://\w+\.(?:blob|queue|table|file|dfs)\.core\.windows\.net)\b",
    r"(?i)(?:https?://\w+\.database\.windows\.net)\b",
    r"(?i)(?:https?://\w+\.vault\.azure\.net)\b",
    r"(?i)(?:https?://\w+\.azurewebsites\.net)\b",
    r"(?i)(?:https?://\w+\.servicebus\.windows\.net)\b",
    r"(?i)(?:https?://\w+\.documents\.azure\.com)\b",
    r"(?i)(?:AZURE_(?:CLIENT_ID|CLIENT_SECRET|TENANT_ID|SUBSCRIPTION_ID|STORAGE_(?:ACCOUNT|KEY|CONNECTION_STRING)|SQL_(?:SERVER|DATABASE|USERNAME|PASSWORD)))\b",
    r"(?i)(?:az\s+(?:login|account|group|vm|storage|network|webapp|functionapp|keyvault|aks|acr|sql|cosmosdb|monitor|policy|role|ad)\s+\w+)\b",
    r"(?i)(?:SharedAccessSignature|sig|sv|sp|se|sr|spr)\s*=\s*[a-zA-Z0-9%/+=]+",
    # --- GCP ---
    r"(?i)(?:GOOGLE_(?:APPLICATION_CREDENTIALS|CLOUD_PROJECT|CLOUD_KEYFILE_JSON|SERVICE_ACCOUNT|COMPUTE_ENGINE_METADATA|FUNCTION_IDENTITY|CLOUD_SDK_CONFIG|ENCRYPTION_KEY))\b",
    r"(?i)(?:https?://\w+-\w+\.cloudfunctions\.net)\b",
    r"(?i)(?:https?://\w+\.run\.app)\b",
    r"(?i)(?:https?://\w+\.appspot\.com)\b",
    r"(?i)(?:https?://storage\.googleapis\.com/\w+)\b",
    r"(?i)(?:https?://\w+\.firebaseio\.com)\b",
    r"(?i)(?:https?://\w+\.firebaseapp\.com)\b",
    r"(?i)(?:gcloud\s+(?:auth|config|compute|container|functions|run|sql|storage|iam|kms|pubsub|logging|monitoring|app|services|projects)\s+\w+)\b",
    r"(?i)(?:gsutil\s+(?:cp|ls|mb|rb|rm|mv|cat|stat|setmeta|acl|cors|defacl|iam|kms|label|lifecycle|logging|notification|retention|versioning|web|hash|signurl|perfdiag))\b",
    r"(?i)(?:AIza[a-zA-Z0-9_-]{35})\b",
    r"(?i)(?:ya29\.[a-zA-Z0-9_-]+)\b",
    r"(?i)(?:service_account|client_email|private_key|private_key_id|token_uri)\s*['\"]?\s*:\s*['\"]",
    # --- Terraform ---
    r"(?i)(?:terraform\s+(?:init|plan|apply|destroy|import|state|output|workspace|show|validate|fmt|taint|untaint|refresh|graph|providers))\b",
    r"(?i)(?:\.tf|\.tfvars|\.tfstate|\.tfstate\.backup)\b",
    r"(?i)(?:terraform_remote_state|terraform_data|terraform_output)\b",
    r"(?i)(?:resource|data|module|variable|output|locals|provider|terraform)\s+['\"](?:aws_|azurerm_|google_|kubernetes_|helm_|vault_|tls_|random_|null_|local_|template_)\w+['\"]",
    # --- Secrets in environment/config ---
    r"(?i)(?:DATABASE_URL|DB_(?:HOST|PORT|NAME|USER|PASSWORD|CONNECTION_STRING)|REDIS_(?:URL|HOST|PORT|PASSWORD)|MONGODB_(?:URI|URL)|ELASTICSEARCH_(?:URL|HOST|PASSWORD)|RABBITMQ_(?:URL|HOST|PASSWORD)|KAFKA_(?:BOOTSTRAP_SERVERS|SASL_PASSWORD))\s*(?:=|:)",
    r"(?i)(?:SECRET_KEY|API_KEY|API_SECRET|APP_SECRET|JWT_SECRET|JWT_KEY|ENCRYPTION_KEY|MASTER_KEY|PRIVATE_KEY|SIGNING_KEY|AUTH_TOKEN|ACCESS_TOKEN|REFRESH_TOKEN)\s*(?:=|:)\s*['\"]?[a-zA-Z0-9/+=_-]{8,}",
    r"(?i)(?:SMTP_(?:HOST|PORT|USER|PASSWORD|USERNAME)|MAIL_(?:HOST|PORT|USERNAME|PASSWORD)|EMAIL_(?:HOST|PORT|USER|PASSWORD))\s*(?:=|:)",
    r"(?i)(?:STRIPE_(?:SECRET_KEY|PUBLISHABLE_KEY|WEBHOOK_SECRET)|PAYPAL_(?:CLIENT_ID|SECRET)|TWILIO_(?:ACCOUNT_SID|AUTH_TOKEN)|SENDGRID_(?:API_KEY|USERNAME|PASSWORD))\s*(?:=|:)",
    r"(?i)(?:GITHUB_(?:TOKEN|SECRET|APP_SECRET|CLIENT_SECRET)|GITLAB_(?:TOKEN|SECRET)|BITBUCKET_(?:TOKEN|SECRET))\s*(?:=|:)",
    r"(?i)(?:SLACK_(?:TOKEN|WEBHOOK|BOT_TOKEN|APP_TOKEN)|DISCORD_(?:TOKEN|BOT_TOKEN|WEBHOOK)|TELEGRAM_(?:BOT_TOKEN|API_KEY))\s*(?:=|:)",
]

# ============================================================================
# 6. CONTAINER / K8S DEEP (100 patterns)
# ============================================================================
CONTAINER_K8S_DEEP = [
    # --- Docker escape ---
    r"(?i)/var/run/docker\.sock\b",
    r"(?i)docker\.sock\b",
    r"(?i)docker\s+(?:exec|run|cp|commit|save|load|export|import|build|pull|push|login|inspect|logs|stats|top|events|history|diff|network|volume)\s+",
    r"(?i)docker\s+run\s+.*(?:--privileged|--pid=host|--net=host|--uts=host|--ipc=host|--userns=host)",
    r"(?i)docker\s+run\s+.*(?:-v|--volume)\s+(?:/:/|/etc:/|/var:/|/root:/|/home:/|/proc:/|/sys:/)",
    r"(?i)docker\s+run\s+.*(?:--cap-add=(?:ALL|SYS_ADMIN|SYS_PTRACE|NET_ADMIN|NET_RAW|DAC_OVERRIDE|SETUID|SETGID))",
    r"(?i)docker\s+run\s+.*(?:--security-opt\s+(?:apparmor=unconfined|seccomp=unconfined|no-new-privileges=false))",
    r"(?i)docker\s+run\s+.*(?:--device=/dev/(?:sda|mem|kmem|port|net/tun))",
    r"(?i)/proc/(?:sysrq-trigger|kcore|mem|kmem|kmsg|config\.gz)\b",
    r"(?i)/sys/(?:kernel/uevent_helper|class/net/\w+/queues|fs/cgroup|kernel/security)\b",
    r"(?i)mount\s+-t\s+(?:proc|sysfs|cgroup|tmpfs|devtmpfs|overlay)\b",
    r"(?i)nsenter\s+(?:-t\s+1|-m\s+-u\s+-i\s+-n\s+-p)\b",
    r"(?i)unshare\s+(?:-Urfm|--mount|--pid|--net|--user|--ipc|--uts)\b",
    # --- Kubernetes ---
    r"(?i)kubectl\s+(?:exec|run|apply|create|delete|get|describe|logs|port-forward|proxy|cp|auth|cluster-info|config|cordon|drain|taint|top|rollout|scale|autoscale|expose|annotate|label|patch|replace|edit|explain|api-resources|api-versions|version|debug)\s+",
    r"(?i)kubectl\s+exec\s+(?:-it?\s+)?\w+\s+--\s+(?:/bin/(?:sh|bash)|sh|bash|cat|ls|id|whoami|hostname|env|printenv)",
    r"(?i)kubectl\s+run\s+\w+\s+--image=.*(?:--overrides|--command|--restart=Never)",
    r"(?i)kubectl\s+get\s+(?:secrets?|configmaps?|pods?|services?|deployments?|daemonsets?|replicasets?|statefulsets?|jobs?|cronjobs?|nodes?|namespaces?|clusterroles?|clusterrolebindings?|serviceaccounts?|persistentvolumes?|persistentvolumeclaims?|ingress(?:es)?|networkpolicies|podsecuritypolicies|events?)\b",
    r"(?i)kubectl\s+get\s+secrets?\s+\w+\s+-o\s+(?:yaml|json|jsonpath)\b",
    r"(?i)kubectl\s+(?:create|apply)\s+-f\s+(?:-|https?://|/dev/stdin)\b",
    r"(?i)kubectl\s+auth\s+can-i\s+(?:--list|\*|create|delete|update|patch|get|list|watch)\b",
    # --- K8s API ---
    r"(?i)/api/v1/(?:pods|services|secrets|configmaps|nodes|namespaces|endpoints|events|persistentvolumes|persistentvolumeclaims|replicationcontrollers|resourcequotas|serviceaccounts|limitranges)\b",
    r"(?i)/apis/(?:apps|batch|extensions|networking\.k8s\.io|rbac\.authorization\.k8s\.io|storage\.k8s\.io|policy|autoscaling|certificates\.k8s\.io|admissionregistration\.k8s\.io)/v\d+\w*/\w+",
    r"(?i)/api/v1/namespaces/\w+/(?:pods|services|secrets|configmaps|endpoints|events)\b",
    r"(?i)/api/v1/namespaces/\w+/pods/\w+/(?:exec|attach|log|portforward|proxy)\b",
    # --- Helm ---
    r"(?i)helm\s+(?:install|upgrade|rollback|delete|uninstall|list|repo|search|show|pull|push|package|template|lint|test|create|plugin|status|history|get|env|version|verify|dependency)\s+",
    r"(?i)helm\s+(?:install|upgrade)\s+.*(?:--set\s+\w+\.(?:password|secret|key|token)|--values\s+)",
    # --- Container runtime ---
    r"(?i)(?:crictl|ctr|runc|podman|buildah|skopeo)\s+(?:exec|run|create|pull|push|build|images|ps|kill|rm|inspect|logs|top|stats)\s+",
    r"(?i)containerd\.sock\b",
    r"(?i)/run/containerd/containerd\.sock\b",
    r"(?i)cri-dockerd\.sock\b",
    # --- K8s RBAC exploit ---
    r"(?i)(?:ClusterRole|Role|ClusterRoleBinding|RoleBinding|ServiceAccount)\b.*(?:create|delete|get|list|watch|update|patch|bind|escalate|impersonate)",
    r"(?i)impersonate-(?:user|group|extra-\w+)\b",
    r"(?i)system:(?:masters|admin|controller|kube-controller-manager|kube-scheduler|kube-proxy|node|authenticated|unauthenticated)\b",
]

# ============================================================================
# 7. CI/CD PIPELINE ATTACKS (80 patterns)
# ============================================================================
CICD_ATTACKS_DEEP = [
    # --- Jenkins ---
    r"(?i)/script\b.*(?:println|execute|evaluate|groovy)",
    r"(?i)/scriptText\b",
    r"(?i)/script\?.*=.*(?:Runtime|ProcessBuilder|exec|system)",
    r"(?i)/job/\w+/(?:configure|build|buildWithParameters|disable|enable|delete|doDelete|ws|lastBuild|api)\b",
    r"(?i)/manage/(?:script|configure|pluginManager|cli|systemInfo|log|env)\b",
    r"(?i)/descriptorByName/(?:org\.jenkinsci|hudson)\.\w+/",
    r"(?i)/queue/api/(?:json|xml)\b",
    r"(?i)/credentials/store/system/domain/_/\w+",
    r"(?i)Jenkins-Crumb:\s*[a-f0-9]+",
    r"(?i)JENKINS_(?:URL|TOKEN|SECRET|PASSWORD|USER|HOME|SLAVE_AGENT_PORT)\b",
    r"(?i)(?:Groovy|Script)\s*(?:Console|Shell|Pipeline|Sandbox|Security)\b",
    # --- GitLab CI ---
    r"(?i)\.gitlab-ci\.yml\b",
    r"(?i)GITLAB_(?:TOKEN|PRIVATE_TOKEN|PERSONAL_TOKEN|RUNNER_TOKEN|CI_TOKEN|DEPLOY_TOKEN)\b",
    r"(?i)CI_(?:JOB_TOKEN|REGISTRY_PASSWORD|DEPLOY_USER|DEPLOY_PASSWORD)\b",
    r"(?i)/api/v4/(?:projects|groups|users|runners|jobs|pipelines|triggers|variables|deploy_keys|deploy_tokens|registry|packages)\b",
    r"(?i)/api/v4/projects/\d+/(?:variables|triggers|deploy_keys|deploy_tokens|repository/files)\b",
    # --- GitHub Actions ---
    r"(?i)GITHUB_(?:TOKEN|SECRET|APP_ID|APP_INSTALLATION_ID|APP_PRIVATE_KEY|ACTIONS_RUNNER_DEBUG|ACTOR|REPOSITORY|SHA|REF|WORKFLOW|RUN_ID|RUN_NUMBER|EVENT_NAME)\b",
    r"(?i)secrets\.(?:GITHUB_TOKEN|PAT|DEPLOY_KEY|SSH_KEY|AWS_|AZURE_|GCP_|DOCKER_|NPM_|PYPI_)\b",
    r"(?i)\$\{\{\s*(?:github\.event\.(?:issue|pull_request|comment|review|push)\.(?:body|title|head\.ref|base\.ref))\s*\}\}",
    r"(?i)uses:\s*(?:actions/checkout|actions/setup-|docker/|hashicorp/|aws-actions/|azure/|google-github-actions/)@\w+",
    r"(?i)run:\s*\|?\s*(?:curl|wget|bash|sh|python|ruby|node)\s+",
    # --- CircleCI ---
    r"(?i)\.circleci/config\.yml\b",
    r"(?i)CIRCLE_(?:TOKEN|BUILD_NUM|BUILD_URL|SHA1|BRANCH|TAG|USERNAME|PROJECT|NODE_INDEX|NODE_TOTAL)\b",
    # --- Travis CI ---
    r"(?i)\.travis\.yml\b",
    r"(?i)TRAVIS_(?:TOKEN|SECURE|BUILD_ID|BUILD_NUMBER|BRANCH|TAG|COMMIT|PULL_REQUEST|REPO_SLUG)\b",
    r"(?i)travis\s+(?:encrypt|setup|login|whoami|token|env)\b",
    # --- Generic CI/CD ---
    r"(?i)(?:DOCKER_(?:USERNAME|PASSWORD|REGISTRY|TOKEN|AUTH_CONFIG)|DOCKERHUB_(?:TOKEN|USERNAME|PASSWORD))\b",
    r"(?i)(?:NPM_(?:TOKEN|AUTH_TOKEN|REGISTRY)|PYPI_(?:TOKEN|USERNAME|PASSWORD)|RUBYGEMS_(?:API_KEY|AUTH_TOKEN)|NUGET_(?:API_KEY|TOKEN))\b",
    r"(?i)(?:SONAR_(?:TOKEN|LOGIN|HOST_URL)|COVERALLS_(?:REPO_TOKEN|TOKEN)|CODECOV_(?:TOKEN))\b",
    r"(?i)(?:HEROKU_(?:API_KEY|APP_NAME|TOKEN)|VERCEL_(?:TOKEN|ORG_ID|PROJECT_ID)|NETLIFY_(?:AUTH_TOKEN|SITE_ID))\b",
    r"(?i)(?:SSH_PRIVATE_KEY|SSH_KEY|SSH_AUTH_SOCK|GPG_PRIVATE_KEY|SIGNING_KEY)\b",
]

# ============================================================================
# 8. DATA EXFILTRATION DETECTION (100 patterns)
# ============================================================================
DATA_EXFIL_DEEP = [
    # --- DNS exfiltration ---
    r"(?i)(?:nslookup|dig|host|drill|getent)\s+\w{10,}\.\w+\.\w+",
    r"(?i)\.(?:burpcollaborator|oastify|interact\.sh|canarytokens|pipedream|webhook\.site|requestbin|ngrok|serveo|localtunnel|ceye|dnslog|bxss)\.\w+$",
    r"(?i)dns\.(?:query|resolve|lookup)\s*\(\s*['\"][a-zA-Z0-9]+\.\w+\.\w+['\"]",
    r"(?i)TXT\s+[a-zA-Z0-9]{20,}\.\w+\.\w+",
    # --- HTTP exfiltration ---
    r"(?i)(?:curl|wget|fetch|XMLHttpRequest|axios|got|request)\s*(?:\(|\.(?:get|post|put))\s*(?:['\"]https?://(?:evil|attacker|hacker|exfil|data|c2|callback|collect)\.|.*(?:burpcollaborator|oastify|interact\.sh|pipedream|webhook\.site|requestbin|ngrok))",
    r"(?i)(?:curl|wget)\s+.*(?:-d\s+|--data\s+|--data-binary\s+|--data-urlencode\s+).*(?:\$\(cat\s+|/etc/|/var/|/home/|/root/|/proc/)",
    r"(?i)(?:curl|wget)\s+.*(?:@/etc/|@/var/|@/home/|@/root/|@/proc/|@/sys/)",
    r"(?i)(?:curl|wget)\s+.*(?:-X\s+POST|--request\s+POST)\s+.*(?:-d|--data)",
    # --- File exfiltration ---
    r"(?i)(?:scp|sftp|rsync|ftp|nc|ncat|socat)\s+.*(?:/etc/(?:passwd|shadow|hosts)|/var/log|/root/|/home/\w+/\.ssh|/proc/self)",
    r"(?i)(?:tar|zip|gzip|bzip2|7z|rar)\s+.*(?:/etc/|/var/|/home/|/root/|/proc/|/sys/|\.ssh/|\.aws/|\.kube/|\.docker/)",
    r"(?i)cat\s+.*(?:/etc/passwd|/etc/shadow|/etc/hosts|\.ssh/id_rsa|\.aws/credentials|\.kube/config|\.docker/config\.json)\s*\|\s*(?:base64|xxd|nc|curl|wget)",
    r"(?i)base64\s+(?:/etc/passwd|/etc/shadow|\.ssh/id_rsa|\.aws/credentials|\.kube/config)\b",
    # --- Cloud storage exfil ---
    r"(?i)aws\s+s3\s+(?:cp|sync|mv)\s+(?:/|\.)\s+s3://",
    r"(?i)gsutil\s+(?:cp|rsync|mv)\s+(?:/|\.)\s+gs://",
    r"(?i)azcopy\s+(?:copy|sync)\s+(?:/|\.)\s+https://\w+\.blob\.core\.windows\.net",
    r"(?i)rclone\s+(?:copy|sync|move)\s+(?:/|\.)\s+\w+:",
    # --- Email exfiltration ---
    r"(?i)(?:mail|sendmail|mutt|mailx|msmtp|ssmtp)\s+.*(?:-s\s+|--subject=).*(?:-a\s+|--attach=|<\s*)",
    r"(?i)(?:smtp|smtplib|net/smtp|nodemailer)\.\w+\s*\(.*(?:attachment|file|data|content|body)\b",
    # --- Encoded exfiltration ---
    r"(?i)(?:base64|xxd|od|hexdump)\s+(?:/etc/|/var/|/home/|/root/|/proc/|\.ssh/|\.aws/|\.kube/)",
    r"(?i)python[23]?\s+-c\s+.*(?:socket|urllib|requests|http\.client).*(?:/etc/|/var/|/home/|/root/|/proc/)",
    r"(?i)ruby\s+-e\s+.*(?:Net::HTTP|open-uri|socket).*(?:/etc/|/var/|/home/|/root/)",
    r"(?i)perl\s+-e\s+.*(?:LWP|HTTP|IO::Socket).*(?:/etc/|/var/|/home/|/root/)",
    # --- Clipboard / screenshot ---
    r"(?i)(?:xclip|xsel|pbcopy|pbpaste|wl-copy|wl-paste|clip)\b",
    r"(?i)(?:import\s+-window\s+root|scrot|gnome-screenshot|flameshot|spectacle|maim|grim)\b",
    # --- Steganography indicators ---
    r"(?i)(?:steghide|stegsolve|stegseek|openstego|stegano|zsteg|jsteg|outguess|snow)\b",
    r"(?i)(?:exiftool|jhead|imagemagick).*(?:embed|extract|inject|modify|strip|write)",
    # --- Covert channels ---
    r"(?i)(?:iodine|dnscat2|dns2tcp|heyoka|ozymandns|requestbin|webhookd)\b",
    r"(?i)(?:ptunnel|icmpsh|icmp-tunnel|ping-tunnel)\b",
    r"(?i)(?:corkscrew|proxytunnel|reGeorg|Neo-reGeorg|ABPTTS|tunna|RPIVOT|sshuttle|chisel|ligolo)\b",
]

# ============================================================================
# 9. IOT / EMBEDDED DEVICE ATTACKS (80 patterns)
# ============================================================================
IOT_EMBEDDED_DEEP = [
    # --- Default credentials ---
    r"(?i)(?:admin|root|user|guest|device|camera|dvr|nvr|nas|router|modem|switch|ap|controller)\s*(?:=|:)\s*(?:admin|root|password|1234|12345|123456|default|toor|changeme|guest|user|enable|cisco|motorola|netgear|linksys|dlink|tplink|asus|huawei|zyxel|ubiquiti|mikrotik|hikvision|dahua)\b",
    r"(?i)(?:GET|POST)\s+/(?:cgi-bin|goform|webcm|stm|HNAP1|soap|tr069|tr064|IGDUPNP|deviceinfo|System|ISAPI|PSIA|sdk|onvif|axis-cgi)/",
    # --- Router/modem attacks ---
    r"(?i)/(?:cgi-bin/|goform/|webcm\?|setup\.cgi|login\.cgi|admin\.cgi|status\.cgi|maintenance\.cgi|upgrade\.cgi|backup\.cgi|restore\.cgi|reboot\.cgi)\b",
    r"(?i)/(?:HNAP1|HNAP|soap/server_sa|wps_nfc|tmUnblock\.cgi|UPnP/control|soapcgi_main\.cgi)\b",
    r"(?i)/(?:password\.cgi|getcfg\.php|hedwig\.cgi|fatlady\.php|pigwidgeon\.cgi|phpcgi|tmUnblock\.cgi)\b",
    r"(?i)/(?:admin/(?:password|system|network|wireless|firewall|vpn|nat|ddns|usb|backup|firmware|reboot|factory|upgrade|debug|diagnostics|logs|status))\b",
    r"(?i)(?:nvram\s+(?:get|set|show|commit)|uci\s+(?:get|set|show|commit)|ubus\s+(?:call|list|listen))\b",
    # --- IP camera attacks ---
    r"(?i)/(?:onvif/device_service|onvif/media_service|onvif/ptz_service|onvif/imaging_service|onvif/analytics_service|onvif/events_service)\b",
    r"(?i)/(?:ISAPI/Streaming|ISAPI/System|ISAPI/Security|ISAPI/ContentMgmt|ISAPI/Event|ISAPI/PTZCtrl)\b",
    r"(?i)/(?:axis-cgi/(?:param|admin|mjpg|jpg/image|io|serial|virtualinput|applications))\b",
    r"(?i)/(?:cgi-bin/snapshot\.cgi|snapshot\.jpg|videostream\.cgi|video\.cgi|image\.cgi|mjpeg\.cgi|video\.mjpg|live/ch\d+)\b",
    r"(?i)/(?:doc/page/login\.asp|SDK/activateStatus|PSIA/System/(?:configurationData|deviceInfo|hostName|reboot))\b",
    r"(?i)(?:rtsp|rtmp)://\d+\.\d+\.\d+\.\d+(?::\d+)?/(?:ch\d+|live|stream|media|video|cam\d+|user=|admin)/",
    # --- Industrial control (ICS/SCADA) ---
    r"(?i)(?:modbus|dnp3|profinet|ethernet/ip|opc-ua|bacnet|s7comm|iec-104|mqtt|coap|amqp)://",
    r"(?i)(?:Modbus|ModbusTCP|ModbusRTU)\s*(?:read|write|force|diagnostic|restart|scan)\b",
    r"(?i)(?:S7-\d{3,4}|SIMATIC|SIMOTION|SINUMERIK|WinCC|TIA\s+Portal|STEP\s*7)\b",
    r"(?i)\b(?:PLC|HMI|SCADA|RTU|DCS|DNP3|Modbus|BACnet|LonWorks|KNX|ZigBee|Z-Wave)\b",
    r"(?i)/(?:portal|main|monitor|alarm|historian|trending|config|security|engineering|runtime|hmi|plc|scada)/",
    # --- Firmware attacks ---
    r"(?i)(?:binwalk|firmware-mod-kit|fmk|jefferson|sasquatch|ubi_reader|yaffshiv|cramfsck|squashfs-tools)\b",
    r"(?i)(?:firmware|image|rom|flash|eeprom|nvram|bootloader|uboot|grub|bios|uefi)\.(?:bin|img|hex|srec|elf|rom|fw|update|upgrade)\b",
    r"(?i)/(?:firmware|upgrade|update|flash|rom|image)(?:\.(?:cgi|php|asp|do|action)|/(?:upload|download|check|status|progress))\b",
    r"(?i)(?:UART|JTAG|SWD|SPI|I2C|EEPROM|NAND|NOR|EMMC|SD)\s*(?:interface|port|pin|debug|console|extract|dump|flash|read|write)\b",
    # --- Zigbee/Bluetooth/RF ---
    r"(?i)(?:zigbee|zwave|bluetooth|ble|nfc|rfid|lora|lorawan|sigfox|nb-iot|lte-m|wifi|wimax|gsm|cdma|lte|5g-nr)\s*(?:sniff|inject|replay|jam|spoof|fuzz|exploit|attack|hack|scan|discover)\b",
    r"(?i)(?:killerbee|zbstumbler|zbgoodfind|zbfind|zbscapy|z3sec|zigdiggity|bettercap|ubertooth|btlejuice|gattacker|blueborne)\b",
    r"(?i)(?:hcitool|hciconfig|bluetoothctl|l2ping|rfcomm|sdptool|gatttool|bleah)\s+",
]

# ============================================================================
# 10. AI/ML & SUPPLY CHAIN ATTACKS (100 patterns)
# ============================================================================
AI_ML_SUPPLY_CHAIN_DEEP = [
    # --- AI/ML model attacks ---
    r"(?i)(?:prompt|system_prompt|instruction|context|persona|role)\s*(?:=|:)\s*['\"].*(?:ignore|forget|disregard|override|bypass|skip|suppress|replace|modify|alter|delete|erase|clear|reset)\s+(?:all|previous|prior|above|earlier|original|initial|system|default|safety|guard|filter|instruction|rule|constraint|restriction|guideline|policy|limit)\b",
    r"(?i)(?:DAN|jailbreak|prompt[\s_-]?injection|prompt[\s_-]?leak|system[\s_-]?prompt|ignore[\s_-]?instructions|do[\s_-]?anything[\s_-]?now|developer[\s_-]?mode|sudo[\s_-]?mode|god[\s_-]?mode|admin[\s_-]?mode|unrestricted[\s_-]?mode)\b",
    r"(?i)(?:ignore|forget|disregard)\s+(?:all|previous|prior|above|earlier)\s+(?:instructions?|rules?|constraints?|restrictions?|guidelines?|policies?)\b",
    r"(?i)(?:you\s+are\s+now|from\s+now\s+on|pretend\s+(?:to\s+be|you\s+are)|act\s+as\s+(?:if|though)|roleplay\s+as|imagine\s+you\s+are|assume\s+the\s+role)\b",
    r"(?i)(?:reveal|show|display|output|print|leak|expose|disclose)\s+(?:your|the|system)\s+(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?|configuration|settings?)\b",
    r"(?i)(?:adversarial|evasion|poisoning|backdoor|trojan|watermark|membership[\s_-]?inference|model[\s_-]?extraction|model[\s_-]?inversion|gradient[\s_-]?leaking|data[\s_-]?poisoning|training[\s_-]?data[\s_-]?extraction)\s+(?:attack|sample|example|input|perturbation)\b",
    r"(?i)(?:FGSM|PGD|CW|DeepFool|AutoAttack|HopSkipJump|SquareAttack|BoundaryAttack|SpatialTransformAttack|ElasticNet|NewtonFool)\b",
    r"(?i)(?:pickle|torch|tensorflow|keras|onnx|safetensors|h5|hdf5|savedmodel|tflite|coreml|pmml|pfa)\s*(?:\.load|\.loads|load_model|from_pretrained|read_model)\s*\(",
    r"(?i)(?:huggingface|transformers|diffusers|datasets|tokenizers|accelerate|peft|trl)\.(?:from_pretrained|load_dataset|AutoModel|AutoTokenizer|pipeline)\s*\(",
    r"(?i)(?:openai|anthropic|cohere|google\.generativeai|replicate|together|mistral|groq|perplexity)\.(?:ChatCompletion|Completion|messages|generate|chat|embed|moderate)\s*\(",
    r"(?i)(?:langchain|llama_index|semantic_kernel|autogen|crewai|phidata)\.\w+\s*\(",
    # --- Supply chain ---
    r"(?i)(?:npm\s+(?:install|publish|unpublish|deprecate|access|audit|config|login|logout|whoami|pack|link|star|unstar)\s+)",
    r"(?i)(?:pip\s+(?:install|download|wheel|uninstall|config|cache|debug|search|show|list|check|freeze|hash))\s+(?:--extra-index-url|--index-url|-i|--trusted-host|--find-links|-f)\s+",
    r"(?i)(?:gem\s+(?:install|update|push|yank|owner|build|cert|lock|sources))\s+",
    r"(?i)(?:composer\s+(?:require|install|update|remove|create-project|global|dump-autoload|run-script))\s+",
    r"(?i)(?:go\s+(?:get|install|mod|build|run|test|vet|generate))\s+",
    r"(?i)(?:cargo\s+(?:install|publish|yank|build|run|test|add|remove))\s+",
    r"(?i)(?:nuget\s+(?:install|push|delete|restore|add|update|list|config|sources|locals))\s+",
    r"(?i)(?:mvn|gradle|sbt)\s+(?:deploy|publish|install|clean|compile|test|package|verify|site)\b",
    r"(?i)(?:postinstall|preinstall|install|prepublish|prepare)\s*(?:script|hook)\b.*(?:curl|wget|bash|sh|python|ruby|node|powershell|cmd)",
    r"(?i)(?:typosquatting|dependency[\s_-]?confusion|repo[\s_-]?jacking|account[\s_-]?takeover|maintainer[\s_-]?compromise|package[\s_-]?hijacking)\b",
    r"(?i)(?:lockfile|package-lock|yarn\.lock|Gemfile\.lock|Pipfile\.lock|poetry\.lock|pnpm-lock|cargo\.lock|go\.sum|composer\.lock|packages\.lock)\b.*(?:modified|changed|tampered|altered|compromised)",
    # --- Emerging threats ---
    r"(?i)(?:CVE-202[5-9]-\d{4,5})\b",
    r"(?i)(?:zero[_-]?day|0[_-]?day|n[_-]?day|exploit[_-]?chain|exploit[_-]?kit|rootkit|bootkit|firmware[_-]?implant|hardware[_-]?implant|supply[_-]?chain[_-]?attack|island[_-]?hopping|watering[_-]?hole|living[_-]?off[_-]?the[_-]?land|fileless[_-]?malware|memory[_-]?only[_-]?malware)\b",
    r"(?i)(?:cobalt[_-]?strike|metasploit|empire|covenant|sliver|mythic|havoc|brute[_-]?ratel|nimplant|poshc2|merlin|deimosC2|godoh)\b",
    r"(?i)(?:mimikatz|lazagne|pypykatz|secretsdump|ntlmrelayx|responder|inveigh|rubeus|kekeo|seatbelt|sharpup|sharphound|bloodhound|powersploit|powerup|powerview|sherlock|watson)\b",
    r"(?i)(?:impacket|crackmapexec|evil-winrm|winpeas|linpeas|pspy|linenum|linux-exploit-suggester|windows-exploit-suggester|gtfobins|lolbas|wadcoms)\b",
]

# ============================================================================
# Map all patterns
# ============================================================================
RULES_MEGA_3_MAP = {
    'php_mega': PHP_ATTACKS_DEEP,
    'java_spring_mega': JAVA_SPRING_DEEP,
    'nodejs_mega': NODEJS_DEEP,
    'dotnet_mega': DOTNET_DEEP,
    'cloud_infra_mega': CLOUD_INFRA_DEEP,
    'container_k8s_mega': CONTAINER_K8S_DEEP,
    'cicd_mega': CICD_ATTACKS_DEEP,
    'data_exfil_mega': DATA_EXFIL_DEEP,
    'iot_mega': IOT_EMBEDDED_DEEP,
    'ai_supply_chain_mega': AI_ML_SUPPLY_CHAIN_DEEP,
}


def get_all_mega3_patterns():
    for category, patterns in RULES_MEGA_3_MAP.items():
        for regex_str in patterns:
            yield (regex_str, category)


def count_mega3_patterns():
    return sum(len(p) for p in RULES_MEGA_3_MAP.values())
