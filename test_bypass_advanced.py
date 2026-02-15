#!/usr/bin/env python3
"""Test advanced bypass techniques against BeeWAF"""
import requests
import sys

print('=== ADVANCED BYPASS TESTS ===\n')

bypass_tests = [
    ('UTF-7', '+ADw-script+AD4-alert(1)+ADw-/script+AD4-'),
    ('HTML Entity', '<script>alert(1)</script>'),
    ('Decimal Enc', '&#60;script&#62;alert(1)&#60;/script&#62;'),
    ('SQL Boolean', "admin' AND '1'='1"),
    ('SQL Time', "admin' AND SLEEP(5)--"),
    ('Path: ..', '....//....//etc/passwd'),
    ('Path: encoded', '%2e%2e%2f%2f%2e%2e%2fetc%2fpasswd'),
    ('CMD: |', '|cat /etc/passwd'),
    ('CMD: ;', ';ls'),
    ('XSS: img', '<img src=x onerror=alert(1)>'),
    ('XSS: svg', '<svg onload=alert(1)>'),
    ('XSS: body', '<body onload=alert(1)>'),
    ('XSS: iframe', '<iframe src="javascript:alert(1)">'),
]

blocked = 0
passed = 0

for name, payload in bypass_tests:
    try:
        r = requests.get(f'http://localhost:8000/api/test?q={payload}', timeout=2)
        if r.status_code == 403:
            print(f'BLOCKED: {name}')
            blocked += 1
        else:
            print(f'PASSED: {name} ({r.status_code})')
            passed += 1
    except Exception as e:
        print(f'ERROR: {name} - {e}')
        passed += 1

print(f'\n=== RESULT ===')
print(f'Blocked: {blocked}')
print(f'Passed: {passed}')
if passed == 0:
    print('ALL BYPASS ATTEMPTS BLOCKED!')
else:
    print(f'{passed} BYPASS TECHNIQUES WORKED!')
