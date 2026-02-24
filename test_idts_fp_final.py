#!/usr/bin/env python3
"""Verify that all IDTS legitimate paths pass WAF rules without false positives."""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from waf.rules import check_regex_rules

# All legitimate IDTS Angular frontend routes
ANGULAR_ROUTES = [
    '/', '/login', '/forgetPassword', '/reset/finish', '/erreur',
    '/profile', '/changePassword',
    '/dashboard', '/dashboard/conducteur', '/dashboard/conducteur/facture',
    '/dashboard/conducteur/chantiers', '/dashboard/conducteur/planing',
    '/dashboard/conducteur/planing/tasks/42',
    '/dashboard/conducteur/planing/affectChefChantier/5',
    '/dashboard/conducteur/planing/tableOccupation',
    '/dashboard/conducteur/planing/calendrier',
    '/dashboard/conducteur/planing/calendrierChantier',
    '/dashboard/pointage/7', '/dashboard/affectOuvrier/3',
    '/dashboard/monPointage',
    '/dashboard/rh', '/dashboard/rh/ouvriers', '/dashboard/rh/projet',
    '/dashboard/rh/chantiers', '/dashboard/rh/clients',
    '/dashboard/rh/fournisseur', '/dashboard/rh/verifpointage/1/2026-02-24',
    '/dashboard/rh/pointage', '/dashboard/rh/facture',
    '/dashboard/rh/remboursement', '/dashboard/rh/facture/remboursement/10',
    '/dashboard/rh/consomamation', '/dashboard/rh/consomamation/pays',
    '/dashboard/rh/consomamation/depense',
]

# All legitimate IDTS Spring Boot API endpoints  
API_ENDPOINTS = [
    '/api/auth/login', '/api/auth/reset-password/init',
    '/api/auth/reset-password/finish', '/api/auth/validKey',
    '/api/auth/change-password',
    '/api/chantiers/', '/api/chantiers/5',
    '/api/users/', '/api/users/3',
    '/api/clients/', '/api/clients/2',
    '/api/factures/getFacturesByChantierAndDate',
    '/api/factures/saveNewFacture',
    '/api/fournisseurs/', '/api/fournisseurs/1',
    '/api/roles/', '/api/roles/4',
    '/api/pointages/', '/api/pointages/5',
    '/api/pointageChefChantierAndConducteur/savePointagesChefChantierAndConducteurByDuree',
    '/api/pointageChefChantierAndConducteur/getPointageChefConducteurByDate',
    '/api/taches/', '/api/taches/2',
    '/api/salaires/', '/api/salaires/1',
    '/api/remboursements/', '/api/remboursements/3',
    '/api/notifications/', '/api/user-details/',
    '/api/user-details/findUserDetailsByUser/5',
    '/api/user-details/findImageUser/test@dpc.com',
    '/api/fileFacture/', '/api/uploadPhoto/',
    '/api/payes/', '/api/chantierUsers/',
]

# Referer headers that should NOT be blocked
SAFE_REFERERS = [
    'https://dev.idts.dpc.com.tn/dashboard/conducteur',
    'https://dev.idts.dpc.com.tn/dashboard/rh',
    'https://dev.idts.dpc.com.tn/dashboard/rh/ouvriers',
    'https://dev.idts.dpc.com.tn/login',
    'https://dev.idts.dpc.com.tn/dashboard/conducteur/planing',
    'https://idts.dpc.com.tn/dashboard/rh/facture',
]

# Known attacks that MUST still be blocked
ATTACKS = [
    ("/?id=1'+OR+1=1--", '', {}, 'SQLi in query'),
    ("/api/test?x=<script>alert(1)</script>", '', {}, 'XSS in query'),
    ("/../../../etc/passwd", '', {}, 'Path traversal'),
    ("/cmd?c=;cat /etc/passwd", '', {}, 'Command injection'),
]

print("=" * 60)
print("IDTS FALSE POSITIVE VERIFICATION")
print("=" * 60)

failures = 0

# Test Angular routes
print("\n[1] Angular Frontend Routes (should PASS):")
for route in ANGULAR_ROUTES:
    blocked, reason = check_regex_rules(route, '', {})
    status = "FAIL - BLOCKED" if blocked else "OK"
    if blocked:
        print(f"  ✗ {route} → BLOCKED ({reason})")
        failures += 1
    else:
        print(f"  ✓ {route}")

# Test API endpoints
print("\n[2] Spring Boot API Endpoints (should PASS):")
for ep in API_ENDPOINTS:
    blocked, reason = check_regex_rules(ep, '', {})
    status = "FAIL - BLOCKED" if blocked else "OK"
    if blocked:
        print(f"  ✗ {ep} → BLOCKED ({reason})")
        failures += 1
    else:
        print(f"  ✓ {ep}")

# Test Referer headers
print("\n[3] Referer Headers (should PASS):")
for ref in SAFE_REFERERS:
    import re
    check_value = re.sub(r'^https?://', '', ref)
    blocked, reason = check_regex_rules('', check_value, {})
    status = "FAIL - BLOCKED" if blocked else "OK"
    if blocked:
        print(f"  ✗ Referer: {ref} → BLOCKED ({reason})")
        failures += 1
    else:
        print(f"  ✓ Referer: {ref}")

# Test attacks still blocked
print("\n[4] Known Attacks (should BLOCK):")
for path, body, headers, desc in ATTACKS:
    blocked, reason = check_regex_rules(path, body, headers)
    if not blocked:
        print(f"  ✗ {desc} → NOT BLOCKED (security gap!)")
        failures += 1
    else:
        print(f"  ✓ {desc} → Blocked ({reason})")

print("\n" + "=" * 60)
if failures:
    print(f"RESULT: {failures} FAILURE(S)")
    sys.exit(1)
else:
    print("RESULT: ALL TESTS PASSED ✓")
    sys.exit(0)
