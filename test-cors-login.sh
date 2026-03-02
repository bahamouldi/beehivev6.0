#!/bin/bash
# Test CORS login flow after BeeWAF fix

TARGET="${1:-https://dev.idts.dpc.com.tn}"
USERNAME="${2:-user@example.com}"
PASSWORD="${3:-password123}"

echo "🐝 BeeWAF CORS Login Flow Test"
echo "================================"
echo "Target: $TARGET"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Step 1: Test CORS OPTIONS preflight
echo -e "${YELLOW}Step 1: CORS Preflight (OPTIONS)${NC}"
OPTIONS_RESPONSE=$(curl -s -X OPTIONS \
    -H "Origin: https://dev.idts.dpc.com.tn" \
    -H "Access-Control-Request-Method: POST" \
    -H "Access-Control-Request-Headers: content-type, authorization" \
    -w "\n%{http_code}" \
    --insecure \
    "$TARGET/api/auth/login")

OPTIONS_CODE=$(echo "$OPTIONS_RESPONSE" | tail -n 1)
OPTIONS_BODY=$(echo "$OPTIONS_RESPONSE" | head -n -1)

echo "Response Code: $OPTIONS_CODE"
if [ "$OPTIONS_CODE" = "200" ] || [ "$OPTIONS_CODE" = "204" ]; then
    echo -e "${GREEN}✅ OPTIONS passed (CORS preflight allowed)${NC}"
else
    echo -e "${RED}❌ OPTIONS blocked: $OPTIONS_CODE${NC}"
    echo "Body: $OPTIONS_BODY"
    exit 1
fi
echo ""

# Step 2: Test login POST
echo -e "${YELLOW}Step 2: Login POST${NC}"
if [ -z "$USERNAME" ] || [ -z "$PASSWORD" ]; then
    echo -e "${YELLOW}⚠️  Skipping POST (no credentials provided)${NC}"
    echo "Usage: $0 <target> <username> <password>"
    echo "Example: $0 https://dev.idts.dpc.com.tn user@example.com password123"
    exit 0
fi

LOGIN_RESPONSE=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    -H "Origin: https://dev.idts.dpc.com.tn" \
    -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}" \
    -w "\n%{http_code}" \
    --insecure \
    "$TARGET/api/auth/login")

LOGIN_CODE=$(echo "$LOGIN_RESPONSE" | tail -n 1)
LOGIN_BODY=$(echo "$LOGIN_RESPONSE" | head -n -1)

echo "Response Code: $LOGIN_CODE"
echo "Response Body:"
echo "$LOGIN_BODY" | jq . 2>/dev/null || echo "$LOGIN_BODY"

if [ "$LOGIN_CODE" = "200" ]; then
    echo -e "${GREEN}✅ Login successful!${NC}"
    TOKEN=$(echo "$LOGIN_BODY" | jq -r '.token // .access_token // .jwt' 2>/dev/null)
    if [ -n "$TOKEN" ] && [ "$TOKEN" != "null" ]; then
        echo "Token: ${TOKEN:0:50}..."
    fi
elif [ "$LOGIN_CODE" = "403" ]; then
    echo -e "${RED}❌ Login blocked by WAF${NC}"
    exit 1
elif [ "$LOGIN_CODE" = "401" ]; then
    echo -e "${YELLOW}⚠️  Invalid credentials (401) - WAF passed, check credentials${NC}"
else
    echo -e "${YELLOW}⚠️  Unexpected response: $LOGIN_CODE${NC}"
fi
echo ""

echo -e "${GREEN}✨ Test complete!${NC}"
