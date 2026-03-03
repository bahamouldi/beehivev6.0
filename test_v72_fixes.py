#!/usr/bin/env python3
"""
BeeWAF v7.2 — Test all 17 bypass fixes + false positive safety
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from waf.rules import check_regex_rules

def test_bypass(label, path, body="", expect_blocked=True):
    result = check_regex_rules(path, body, {})
    blocked = result[0] if isinstance(result, tuple) else result
    status = "✅" if blocked == expect_blocked else "❌ FAIL"
    action = "BLOCKED" if blocked else "ALLOWED"
    print(f"  {status} {label}: {action}")
    return blocked == expect_blocked

passed = 0
total = 0

# =============================================================================
# PART 1: All 17 v7.1 Red Team Bypasses — ALL MUST BE BLOCKED
# =============================================================================
print("\n" + "="*70)
print("PART 1: 17 BYPASS PAYLOADS (must all be BLOCKED)")
print("="*70)

bypasses = [
    ("Bypass #1  UNION(SELECT(1),(2),(3))",        "/?id=UNION(SELECT(1),(2),(3))"),
    ("Bypass #2  1-(SELECT+0)",                     "/?id=1-(SELECT+0)"),
    ("Bypass #3  1+(SELECT+0)",                     "/?id=1%2B(SELECT%2B0)"),
    ("Bypass #4  1 XOR (SELECT 1)",                 "/?id=1+XOR+(SELECT+1)"),
    ("Bypass #5  (SELECT(1)FROM(users))",           "/?id=(SELECT(1)FROM(users))"),
    ("Bypass #6  (SELECT(password)FROM(users)WHERE(id=1))", "/?id=(SELECT(password)FROM(users)WHERE(id%3D1))"),
    ("Bypass #7  1 RLIKE (SELECT 1)",               "/?id=1+RLIKE+(SELECT+1)"),
    ("Bypass #8  1 REGEXP (SELECT 1)",              "/?id=1+REGEXP+(SELECT+1)"),
    ("Bypass #9  1 DIV (SELECT 0)",                 "/?id=1+DIV+(SELECT+0)"),
    ("Bypass #10 1 XOR 1",                          "/?id=1+XOR+1"),
    ("Bypass #11 1%(SELECT 1)",                     "/?id=1%25(SELECT+1)"),
    ("Bypass #12 GROUP BY 1 HAVING 1=1",            "/?id=GROUP+BY+1+HAVING+1%3D1"),
    ("Bypass #13 ELT(1,version())",                 "/?id=ELT(1,version())"),
    ("Bypass #14 MAKE_SET(1,version())",            "/?id=MAKE_SET(1,version())"),
    ("Bypass #15 1 & (SELECT 1)",                   "/?id=1+%26+(SELECT+1)"),
    ("Bypass #16 1 DIV 0",                          "/?id=1+DIV+0"),
    ("Bypass #17 1 MOD 0",                          "/?id=1+MOD+0"),
]

for label, path in bypasses:
    total += 1
    if test_bypass(label, path, expect_blocked=True):
        passed += 1

# =============================================================================
# PART 2: Original 8 v7.0 Bypasses — MUST STILL BE BLOCKED
# =============================================================================
print("\n" + "="*70)
print("PART 2: 8 ORIGINAL v7.0 BYPASSES (must still be BLOCKED)")
print("="*70)

v70_bypasses = [
    ("v7.0 #1  1)AND(1)=(1",                       "/?id=1)AND(1)%3D(1"),
    ("v7.0 #2  1)AND(SELECT 1 FROM users)=(1",     "/?id=1)AND(SELECT+1+FROM+users)%3D(1"),
    ("v7.0 #3  1e0UNION SELECT 1,2,3",             "/?id=1e0UNION+SELECT+1,2,3"),
    ("v7.0 #4  1.0UNION SELECT 1,2,3",             "/?id=1.0UNION+SELECT+1,2,3"),
    ("v7.0 #5  CASE WHEN SUBSTRING",               "/?id=CASE+WHEN+SUBSTRING(version(),1,1)%3D5+THEN+1+ELSE+0+END"),
    ("v7.0 #6  sort=IF(1=1,id,name)",              "/?sort=IF(1%3D1,id,name)"),
    # v7.0 #7 & #8 are header-based attacks validated in main.py middleware (not check_regex_rules)
]

for label, path in v70_bypasses:
    total += 1
    if test_bypass(label, path, expect_blocked=True):
        passed += 1

# =============================================================================
# PART 3: Classic Attacks — MUST STILL BE BLOCKED
# =============================================================================
print("\n" + "="*70)
print("PART 3: CLASSIC ATTACKS (must be BLOCKED)")
print("="*70)

classics = [
    ("Classic SQLi ' OR 1=1--",                    "/echo", "' OR 1=1--"),
    ("Classic XSS <script>alert(1)</script>",      "/echo", "<script>alert(1)</script>"),
    ("Classic CMDI ; cat /etc/passwd",             "/echo", "; cat /etc/passwd"),
    ("Classic Path Traversal ../../etc/passwd",    "/echo", "../../etc/passwd"),
    ("UNION SELECT in body",                       "/echo", "UNION SELECT 1,2,3"),
    ("SQLi in query ' OR 1=1",                     "/?id=' OR 1=1--", ""),
]

for label, path, body in classics:
    total += 1
    if test_bypass(label, path, body, expect_blocked=True):
        passed += 1

# =============================================================================
# PART 4: FALSE POSITIVE CHECKS — MUST ALL BE ALLOWED
# =============================================================================
print("\n" + "="*70)
print("PART 4: FALSE POSITIVE CHECKS (must all be ALLOWED)")
print("="*70)

safe_requests = [
    ("Normal search query",                         "/?q=hello+world"),
    ("Normal pagination",                           "/?page=1&size=20"),
    ("Normal sorting",                              "/?sort=name&order=asc"),
    ("Normal filter",                               "/?filter=active&type=user"),
    ("Normal parens in text",                       "/?q=(test)"),
    ("Normal parens grouped",                       "/?q=(hello+world)"),
    ("Timezone offset",                             "/?tz=UTC+5"),
    ("Email in query",                              "/?email=user@example.com"),
    ("Decimal number",                              "/?price=19.99"),
    ("Scientific notation number",                  "/?val=1e3"),
    ("Word 'case' in text",                         "/?q=business+case+study"),
    ("Word 'update' alone",                         "/?action=update"),
    ("Word 'select' alone (no SQL ctx)",            "/?action=select"),
    ("Normal form login body",                      "/api/auth/login", "username=admin&password=test123"),
    ("Normal JSON body",                            "/api/data", '{"name":"John","age":30}'),
    ("Normal API endpoint /api/users",              "/api/users"),
    ("Normal API with ID /api/users/123",           "/api/users/123"),
    ("Normal search with special chars",            "/?q=test+%26+value"),
    ("Word 'having' in sentence",                   "/?q=having+a+good+time"),
    ("Word 'group' in query",                       "/?group=admin"),
    ("Word 'mod' alone (no SQL ctx)",               "/?mode=dark"),
    ("Normal bracketed value",                      "/?tags=[electronics,books]"),
    ("Hash fragment in URL",                        "/?ref=#section1"),
    ("Angular route path",                          "/dashboard"),
    ("Angular nested path",                         "/chantiers/123"),
]

for label, path, *rest in safe_requests:
    body = rest[0] if rest else ""
    total += 1
    if test_bypass(label, path, body, expect_blocked=False):
        passed += 1

# =============================================================================
# SUMMARY
# =============================================================================
print("\n" + "="*70)
print(f"RESULTS: {passed}/{total} tests passed")
if passed == total:
    print("🎉 ALL TESTS PASSED — v7.2 is ready!")
else:
    print(f"⚠️  {total - passed} test(s) FAILED — review needed")
print("="*70)
sys.exit(0 if passed == total else 1)
