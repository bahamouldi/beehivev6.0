#!/usr/bin/env python3
"""
BeeWAF False Positive Test Script for idts.dpc.com.tn
Tests common Angular application patterns to identify false positives
"""

import requests
import json
import sys

# Target URL - will be tested via BeeWAF proxy
BEEWAF_URL = "http://localhost:8000"
REAL_URL = "https://idts.dpc.com.tn"

# Test results storage
results = {
    "false_positives": [],
    "blocked_attacks": [],
    "passed_tests": []
}

def test_via_beewaf(path, method="GET", data=None, json_data=None, headers=None):
    """Send request through BeeWAF"""
    url = f"{BEEWAF_URL}{path}"
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Content-Type": "application/json"
    }
    if headers:
        default_headers.update(headers)
    
    try:
        if method == "GET":
            r = requests.get(url, headers=default_headers, timeout=10)
        elif method == "POST":
            if json_data:
                r = requests.post(url, json=json_data, headers=default_headers, timeout=10)
            elif data:
                r = requests.post(url, data=data, headers=default_headers, timeout=10)
            else:
                r = requests.post(url, headers=default_headers, timeout=10)
        return r.status_code, r.text[:200]
    except Exception as e:
        return 0, str(e)

def test_legitimate_requests():
    """Test legitimate traffic patterns that IDTS might use"""
    print("\n" + "="*60)
    print("TESTING LEGITIMATE TRAFFIC (False Positives)")
    print("="*60)
    
    # Common Angular authentication patterns
    test_cases = [
        # Login endpoints
        ("/api/login", "POST", {"username": "admin", "password": "admin123"}),
        ("/api/auth/login", "POST", {"email": "user@test.com", "password": "pass123"}),
        ("/api/auth/signin", "POST", {"username": "testuser", "password": "password123"}),
        ("/api/v1/auth/login", "POST", {"user": "admin", "pass": "admin123"}),
        
        # User profile endpoints
        ("/api/user/profile", "GET", None),
        ("/api/user", "GET", None),
        ("/api/users/me", "GET", None),
        
        # Dashboard and data endpoints
        ("/api/dashboard", "GET", None),
        ("/api/dashboard/stats", "GET", None),
        ("/api/home", "GET", None),
        
        # Menu and navigation
        ("/api/menu", "GET", None),
        ("/api/menus", "GET", None),
        
        # Data endpoints with IDs
        ("/api/orders/123", "GET", None),
        ("/api/products/456", "GET", None),
        ("/api/users/789", "GET", None),
        
        # Search endpoints
        ("/api/search", "POST", {"query": "test search"}),
        ("/api/search", "POST", {"q": "product name"}),
        
        # Health check
        ("/api/health", "GET", None),
        ("/api/status", "GET", None),
        
        # Angular CSRF tokens
        ("/api/csrf-token", "GET", None),
        
        # Form submissions with common field names
        ("/api/contact", "POST", {"name": "John Doe", "email": "john@test.com", "message": "Hello"}),
        ("/api/feedback", "POST", {"rating": 5, "comment": "Great service"}),
        
        # File upload (metadata only)
        ("/api/upload", "POST", {"filename": "document.pdf", "size": 1024}),
        
        # Pagination
        ("/api/users?page=1&limit=10", "GET", None),
        ("/api/orders?page=2&size=20", "GET", None),
        
        # Sorting and filtering
        ("/api/products?sort=name&order=asc", "GET", None),
        ("/api/users?filter=active", "GET", None),
        
        # Common query parameters
        ("/api/data?id=123&type=standard", "GET", None),
        ("/api/search?term=example&lang=en", "GET", None),
    ]
    
    for path, method, json_data in test_cases:
        status, response = test_via_beewaf(path, method, json_data=json_data)
        
        # Consider 200, 201, 204, 404 as "passed" (not blocked)
        if status in [200, 201, 204, 404]:
            result = f"✓ PASS"
            results["passed_tests"].append(f"{method} {path}")
        else:
            result = f"✗ BLOCKED ({status})"
            results["false_positives"].append(f"{method} {path}: {status}")
        
        print(f"{method:6} {path:40} {result}")

def test_attack_requests():
    """Test that attacks are properly blocked"""
    print("\n" + "="*60)
    print("TESTING ATTACK DETECTION")
    print("="*60)
    
    attack_cases = [
        # SQL Injection
        ("/api/login", "POST", {"username": "' OR '1'='1", "password": "anything"}),
        ("/api/search", "POST", {"q": "' UNION SELECT * FROM users--"}),
        ("/api/user/1' OR '1'='1", "GET", None),
        
        # XSS
        ("/api/test", "GET", {"q": "<script>alert(1)</script>"}),
        ("/api/search", "POST", {"q": "<img src=x onerror=alert(1)>"}),
        
        # Command Injection
        ("/api/file", "GET", {"name": ";ls -la"}),
        ("/api/cmd", "POST", {"cmd": "$(whoami)"}),
        
        # Path Traversal
        ("/api/file", "GET", {"path": "../../../../etc/passwd"}),
        
        # LDAP Injection
        ("/api/login", "POST", {"username": "*)(uid=*))(|(uid=*"}),
        
        # XML Injection
        ("/api/xml", "POST", {"data": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"}),
    ]
    
    for path, method, json_data in attack_cases:
        status, response = test_via_beewaf(path, method, json_data=json_data)
        
        if status == 403:
            result = f"✓ BLOCKED"
            results["blocked_attacks"].append(f"{method} {path}")
        else:
            result = f"✗ NOT BLOCKED ({status})"
        
        print(f"{method:6} {path:40} {result}")

def main():
    print("BeeWAF False Positive Test for IDTS Application")
    print("Testing against:", BEEWAF_URL)
    
    # First check if BeeWAF is running
    try:
        r = requests.get(f"{BEEWAF_URL}/health", timeout=5)
    except:
        print(f"\n❌ ERROR: BeeWAF not running at {BEEWAF_URL}")
        print("Please start BeeWAF first:")
        print("  docker run -d --name beewaf_sklearn -p 8000:8000 beewaf:sklearn")
        sys.exit(1)
    
    # Run tests
    test_legitimate_requests()
    test_attack_requests()
    
    # Summary
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    print(f"Passed tests (legitimate traffic): {len(results['passed_tests'])}")
    print(f"False positives (incorrectly blocked): {len(results['false_positives'])}")
    print(f"Attacks blocked: {len(results['blocked_attacks'])}")
    
    if results["false_positives"]:
        print("\n❌ FALSE POSITIVES FOUND:")
        for fp in results["false_positives"]:
            print(f"  - {fp}")
    
    print("\n" + "="*60)
    
    return len(results["false_positives"])

if __name__ == "__main__":
    sys.exit(main())
