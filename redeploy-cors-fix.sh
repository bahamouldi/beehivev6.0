#!/bin/bash
# Rebuild BeeWAF image with CORS preflight fix and redeploy to K8s

set -e

REGISTRY="${DOCKER_REGISTRY:-docker.io}"
IMAGE="${REGISTRY}/beewaf:v6.0-cors-fix"
NAMESPACE="beewaf"

echo "🐝 BeeWAF CORS Fix - Rebuild & Deploy"
echo "====================================="
echo "Image: $IMAGE"
echo ""

# 1. Build the image using optimized Dockerfile.k8s
echo "🔨 Building Docker image..."
docker build -f Dockerfile.k8s -t $IMAGE .

if [ $? -eq 0 ]; then
    echo "✅ Image built successfully: $IMAGE"
else
    echo "❌ Build failed"
    exit 1
fi

# 2. Load image if using local Docker (for kind/minikube)
if [ -n "$LOAD_IMAGE" ] || command -v kind &>/dev/null && kind get clusters | grep -q beewaf; then
    echo "📦 Loading image into kind cluster..."
    kind load docker-image $IMAGE --name beewaf
fi

# 3. Update K8s deployment with new image
echo "🚀 Updating Kubernetes deployment..."
kubectl set image deployment/beewaf beewaf=$IMAGE -n $NAMESPACE

# 4. Wait for rollout
echo "⏳ Waiting for rollout to complete..."
kubectl rollout status deployment/beewaf -n $NAMESPACE --timeout=3m

# 5. Get new pod name
NEW_POD=$(kubectl get pods -n $NAMESPACE -l app=beewaf -o jsonpath='{.items[0].metadata.name}')
echo "✅ New pod: $NEW_POD"

# 6. Wait for pod to be ready
echo "🔄 Waiting for pod to be ready..."
kubectl wait --for=condition=ready pod/$NEW_POD -n $NAMESPACE --timeout=30s

# 7. Test the fix
echo ""
echo "🧪 Testing CORS preflight fix..."
sleep 2

# Option A: Via port-forward
echo "Setting up port-forward..."
kubectl port-forward svc/beewaf-svc 8080:80 -n $NAMESPACE &>/dev/null &
PF_PID=$!
sleep 2

echo "Testing OPTIONS /api/auth/login..."
OPTIONS_CODE=$(curl -s -X OPTIONS \
    -H "Origin: http://localhost:3000" \
    -H "Access-Control-Request-Method: POST" \
    -H "Access-Control-Request-Headers: content-type" \
    -o /dev/null -w "%{http_code}" \
    http://localhost:8080/api/auth/login 2>/dev/null || echo "000")

kill $PF_PID 2>/dev/null || true
wait $PF_PID 2>/dev/null || true

if [ "$OPTIONS_CODE" = "200" ] || [ "$OPTIONS_CODE" = "204" ] || [ "$OPTIONS_CODE" = "405" ]; then
    echo "✅ CORS preflight (OPTIONS): $OPTIONS_CODE - FIXED!"
    echo ""
    echo "✨ Deployment complete! Login should now work."
    exit 0
else
    echo "⚠️  OPTIONS returned: $OPTIONS_CODE"
    echo "Checking logs..."
    kubectl logs -n $NAMESPACE $NEW_POD -c beewaf --tail=20
    exit 1
fi
