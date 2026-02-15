#!/usr/bin/env python3
"""
Test script to verify false positive fixes for /api/orders
"""
import sys
sys.path.insert(0, '/home/kali/Downloads/beehivepfe2-main')

from waf import rules

# Test cases
test_cases = [
    # Should NOT be blocked (legitimate requests)
    {'path': '/api/orders', 'body': '', 'headers': {}, 'expected': False, 'desc': 'Legitimate /api/orders'},
    {'path': '/api/products', 'body': '', 'headers': {}, 'expected': False, 'desc': 'Legitimate /api/products'},
    {'path': '/api/users', 'body': '', 'headers': {}, 'expected': False, 'desc': 'Legitimate /api/users'},
    {'path': '/api/status', 'body': '', 'headers': {}, 'expected': False, 'desc': 'Legitimate /api/status'},
    {'path': '/api/orders/123', 'body': '', 'headers': {}, 'expected': False, 'desc': 'Legitimate /api/orders/123'},
    
    # Legitimate proxy headers (should NOT be blocked)
    {'path': '/api/orders', 'body': '', 'headers': {'X-Forwarded-Host': 'idts.dpc.com.tn'}, 'expected': False, 'desc': 'Legitimate X-Forwarded-Host'},
    {'path': '/api/orders', 'body': '', 'headers': {'X-Forwarded-For': '192.168.1.100'}, 'expected': False, 'desc': 'Legitimate X-Forwarded-For'},
    {'path': '/api/orders', 'body': '', 'headers': {'X-Forwarded-Proto': 'https'}, 'expected': False, 'desc': 'Legitimate X-Forwarded-Proto'},
    {'path': '/api/orders', 'body': '', 'headers': {'X-Forwarded-Port': '443'}, 'expected': False, 'desc': 'Legitimate X-Forwarded-Port'},
    {'path': '/api/orders', 'body': '', 'headers': {'Via': '1.1 HAProxy'}, 'expected': False, 'desc': 'Legitimate Via header'},
    {'path': '/api/orders', 'body': '', 'headers': {'Cache-Control': 'no-cache'}, 'expected': False, 'desc': 'Legitimate Cache-Control'},
    
    # Should be blocked (attacks)
    {'path': '/api/orders?id=1\' OR \'1\'=\'1', 'body': '', 'headers': {}, 'expected': True, 'desc': 'SQL injection'},
    {'path': '/api/orders', 'body': '<script>alert(1)</script>', 'headers': {}, 'expected': True, 'desc': 'XSS attack'},
    {'path': '/api/orders', 'body': '', 'headers': {'X-Forwarded-Host': 'evil.attacker.com'}, 'expected': True, 'desc': 'Malicious X-Forwarded-Host'},
    {'path': '/api/orders', 'body': '', 'headers': {'X-Forwarded-Host': 'test.interact.sh'}, 'expected': True, 'desc': 'OAST domain in X-Forwarded-Host'},
    {'path': '/api/orders', 'body': '', 'headers': {'X-Original-URL': '/admin'}, 'expected': True, 'desc': 'X-Original-URL admin bypass'},
    {'path': '/api/orders', 'body': '', 'headers': {'X-Forwarded-For': '127.0.0.1'}, 'expected': True, 'desc': 'Loopback in X-Forwarded-For'},
    {'path': '/account/profile.css', 'body': '', 'headers': {}, 'expected': True, 'desc': 'Cache deception attack'},
]

print("=" * 60)
print("Testing False Positive Fixes")
print("=" * 60)

passed = 0
failed = 0
false_positives = 0
false_negatives = 0

for test in test_cases:
    blocked, reason = rules.check_regex_rules(test['path'], test['body'], test['headers'])
    result = 'BLOCKED' if blocked else 'ALLOWED'
    expected = 'BLOCKED' if test['expected'] else 'ALLOWED'
    
    if blocked == test['expected']:
        status = 'PASS'
        passed += 1
    else:
        status = 'FAIL'
        failed += 1
        if blocked and not test['expected']:
            false_positives += 1
        else:
            false_negatives += 1
    
    print(f"\n[{status}] {test['desc']}")
    print(f"  Path: {test['path']}")
    if test['headers']:
        print(f"  Headers: {test['headers']}")
    print(f"  Expected: {expected}, Got: {result}")
    if blocked:
        print(f"  Reason: {reason}")

print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)
print(f"Total: {len(test_cases)}")
print(f"Passed: {passed}")
print(f"Failed: {failed}")
print(f"False Positives: {false_positives} (legitimate requests blocked)")
print(f"False Negatives: {false_negatives} (attacks allowed)")

if false_positives > 0:
    print("\n[!] FALSE POSITIVES DETECTED - Fix needed!")
    sys.exit(1)
elif false_negatives > 0:
    print("\n[!] FALSE NEGATIVES DETECTED - Security risk!")
    sys.exit(1)
else:
    print("\n[+] All tests passed!")
    sys.exit(0)