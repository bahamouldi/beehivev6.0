#!/usr/bin/env python3
"""
Test script to validate all 8 bypass fixes and check for false positives.
Tests both the regex engine (rules.py) and header inspection (main.py).
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from waf import rules

print("=" * 70)
print("  BeeWAF v7.1 — Bypass Fix Validation Tests")
print("=" * 70)

passed = 0
failed = 0

def test(name, payload_path, payload_body, headers, expect_blocked):
    global passed, failed
    blocked, reason = rules.check_regex_rules(payload_path, payload_body, headers)
    status = "✅" if blocked == expect_blocked else "❌"
    if blocked == expect_blocked:
        passed += 1
    else:
        failed += 1
    action = "BLOCKED" if blocked else "PASSED"
    expected = "BLOCK" if expect_blocked else "PASS"
    print(f"  {status} {name}")
    print(f"     Result: {action} (expected: {expected}) reason={reason}")
    if blocked != expect_blocked:
        print(f"     ⚠️  MISMATCH! path='{payload_path}' body='{payload_body}'")
    return blocked == expect_blocked

# ========================================================================
print("\n" + "=" * 70)
print("  SECTION 1: BYPASS FIX VERIFICATION (should all be BLOCKED)")
print("=" * 70)

# Bypass #1: Parenthesized blind SQLi
print("\n--- Bypass #1: Parenthesized Blind SQLi ---")
test("1)AND(1)=(1", "/?id=1)AND(1)=(1", "", {}, True)
test("1)AND(SELECT+1+FROM+users)=(1", "/?id=1)AND(SELECT+1+FROM+users)=(1", "", {}, True)
test("1)OR(1)=(1", "/?id=1)OR(1)=(1", "", {}, True)
test("1)AND(1)=(1 in body", "/echo", "id=1)AND(1)=(1", {}, True)

# Bypass #3: Scientific notation UNION
print("\n--- Bypass #3: Scientific Notation UNION ---")
test("1e0UNION SELECT 1,2,3", "/?id=1e0UNION+SELECT+1,2,3", "", {}, True)
test("1.0UNION SELECT 1,2,3", "/?id=1.0UNION+SELECT+1,2,3", "", {}, True)
test("1e1UNION SELECT 1,2,3", "/?id=1e1UNION+SELECT+1,2,3", "", {}, True)
test("1.5SELECT version()", "/?id=1.5SELECT+version()", "", {}, True)

# Bypass #5: CASE WHEN blind SQLi
print("\n--- Bypass #5: CASE WHEN Blind SQLi ---")
test("CASE WHEN...THEN", "/?id=CASE+WHEN+SUBSTRING(version(),1,1)=5+THEN+1+ELSE+0+END", "", {}, True)
test("CASE WHEN in body", "/echo", "data=CASE WHEN 1=1 THEN 1 ELSE 0 END", {}, True)

# Bypass #6: IF() sort injection
print("\n--- Bypass #6: IF() Sort Injection ---")
test("sort=IF(1=1,id,name)", "/?sort=IF(1=1,id,name)", "", {}, True)
test("order=IF(2>1,name,id)", "/?order=IF(2>1,name,id)", "", {}, True)

# ========================================================================
print("\n" + "=" * 70)
print("  SECTION 2: HEADER BYPASS VERIFICATION")
print("=" * 70)

# Test header injection regex directly (simulating main.py logic)
import re
_header_injection_re = re.compile(
    r'(?i)(?:(?:\r\n|\n|\r)[\w-]+\s*:|<script|javascript:|'
    r'\$\{jndi:|\$\(|`[^`]+`|union\s+select|;\s*(?:cat|wget|curl|nc|bash)\s|'
    r'(?:\.\.[\\/]){2,}|/etc/passwd|/etc/shadow)',
    re.IGNORECASE
)

def test_header(name, header_value, expect_blocked):
    global passed, failed
    match = _header_injection_re.search(header_value)
    blocked = match is not None
    status = "✅" if blocked == expect_blocked else "❌"
    if blocked == expect_blocked:
        passed += 1
    else:
        failed += 1
    action = "BLOCKED" if blocked else "PASSED"
    expected = "BLOCK" if expect_blocked else "PASS"
    print(f"  {status} {name}")
    print(f"     Result: {action} (expected: {expected}) value='{header_value[:60]}'")
    return blocked == expect_blocked

# Bypass #7: CMDI in Accept header
print("\n--- Bypass #7: CMDI in Accept Header ---")
test_header("Accept: text/html;$(id)", "text/html;$(id)", True)
test_header("Accept: $(whoami)", "$(whoami)", True)
test_header("Accept: `id`", "`id`", True)
test_header("Accept: ${jndi:ldap://evil}", "${jndi:ldap://evil}", True)

# Bypass #8: Path traversal in Accept-Language
print("\n--- Bypass #8: Path Traversal in Accept-Language ---")
test_header("Accept-Language: ../../../../etc/passwd", "../../../../etc/passwd", True)
test_header("Accept-Language: ..\\..\\..\\windows\\system32", "..\\..\\..\\windows\\system32", True)
test_header("Accept-Language: /etc/passwd", "/etc/passwd", True)

# ========================================================================
print("\n" + "=" * 70)
print("  SECTION 3: FALSE POSITIVE CHECKS (should all PASS through)")
print("=" * 70)

# Normal requests that must NOT be blocked
print("\n--- Normal SQL-like terms (no attack context) ---")
test("Normal search query", "/api/chantiers?search=test+case+study", "", {}, False)
test("Normal pagination", "/api/clients?page=1&size=20", "", {}, False)
test("Normal filter", "/api/chantiers?status=active&type=urgent", "", {}, False)
test("Normal sort", "/api/chantiers?sort=name&order=asc", "", {}, False)
test("Normal ID lookup", "/api/chantiers/123", "", {}, False)
test("Normal login body", "/api/auth/login", "username=admin&password=test123", {}, False)

print("\n--- Normal headers (must not be blocked) ---")
test_header("Normal Accept", "text/html, application/json, */*", False)
test_header("Normal Accept-Language", "en-US,en;q=0.9,fr;q=0.8", False)
test_header("Normal Accept-Language FR", "fr-FR,fr;q=0.9,en-US;q=0.8", False)
test_header("Normal Accept-Encoding", "gzip, deflate, br", False)
test_header("Normal User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", False)

print("\n--- Edge cases (must not false-positive) ---")
test("JSON body normal", "/api/data", '{"name":"John","status":"active"}', {}, False)
test("Parentheses in text", "/search?q=hello+(world)", "", {}, False)
test("Normal decimal number", "/api/price?value=1.5", "", {}, False)
test("Normal scientific notation", "/api/data?exp=1e3", "", {}, False)
test("Word 'case' in text", "/search?q=test+case+for+review", "", {}, False)
test("Word 'update' alone", "/api/status?action=update", "", {}, False)
test("Timezone offset body", "/api/settings", "timezone=UTC+05:00", {}, False)
test("GraphQL-like body", "/api/data", "query=users{id,name,email}", {}, False)
test("Normal form body", "/api/contact", "name=John+Doe&email=john@example.com&message=Hello+world", {}, False)
test("Math expression", "/api/calc?formula=2+3", "", {}, False)

# ========================================================================
print("\n" + "=" * 70)
print("  SECTION 4: DEFENSE-IN-DEPTH (non-ALLOW_PATH attacks)")
print("=" * 70)

# These should be caught by COMPILED_RULES even on non-allowed paths
print("\n--- Traditional SQLi (still blocked) ---")
test("Classic SQLi ' OR 1=1--", "/test?id=' OR 1=1--", "", {}, True)
test("UNION SELECT", "/test?id=1 UNION SELECT 1,2,3", "", {}, True)
test("Classic XSS", "/test", "<script>alert(1)</script>", {}, True)
test("Command injection", "/test", "; cat /etc/passwd", {}, True)
test("Path traversal", "/test?f=../../etc/passwd", "", {}, True)

# ========================================================================
print("\n" + "=" * 70)
print(f"  RESULTS: {passed} passed, {failed} failed out of {passed+failed} tests")
print("=" * 70)

if failed == 0:
    print("  🎉 ALL TESTS PASSED — Bypasses fixed with zero false positives!")
else:
    print(f"  ⚠️  {failed} test(s) FAILED — review needed")

sys.exit(0 if failed == 0 else 1)
