#!/bin/bash
# Deploy CORS preflight fix to BeeWAF pod

set -e

echo "🐝 BeeWAF CORS Preflight Fix Deployment"
echo "========================================"

# 1. Check if pod is running
POD=$(kubectl get pods -n beewaf -l app=beewaf -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [ -z "$POD" ]; then
    echo "❌ No BeeWAF pod found. Exiting."
    exit 1
fi

echo "✅ Found pod: $POD"

# 2. Copy updated files
echo "📝 Copying updated WAF files..."
kubectl cp app/main.py beewaf/$POD:/app/app/main.py -c beewaf
kubectl cp waf/rules_mega_2.py beewaf/$POD:/app/waf/rules_mega_2.py -c beewaf
kubectl cp waf/rules_v5.py beewaf/$POD:/app/waf/rules_v5.py -c beewaf

# 3. Reload the application
echo "🔄 Reloading application..."
kubectl exec -n beewaf $POD -c beewaf -- pkill -HUP -f uvicorn || true

sleep 3

# 4. Verify pod is still running
READY=$(kubectl get pods -n beewaf $POD -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')
if [ "$READY" = "True" ]; then
    echo "✅ Pod reloaded successfully!"
else
    echo "⏳ Waiting for pod to become ready..."
    kubectl wait --for=condition=ready pod/$POD -n beewaf --timeout=30s
fi

# 5. Test the fix
echo ""
echo "🧪 Testing CORS preflight fix..."
BASE_URL="https://dev.idts.dpc.com.tn"

# Get OPTIONS status code
OPTIONS_CODE=$(curl -s -X OPTIONS \
    -H "Origin: https://dev.idts.dpc.com.tn" \
    -H "Access-Control-Request-Method: POST" \
    -H "Access-Control-Request-Headers: content-type" \
    -o /dev/null -w "%{http_code}" \
    --insecure "$BASE_URL/api/auth/login" 2>/dev/null || echo "000")

if [ "$OPTIONS_CODE" = "200" ] || [ "$OPTIONS_CODE" = "204" ]; then
    echo "✅ CORS preflight (OPTIONS): $OPTIONS_CODE - FIXED!"
else
    echo "⚠️  CORS preflight (OPTIONS): $OPTIONS_CODE - Still needs investigation"
fi

echo ""
echo "✨ Deployment complete!"
