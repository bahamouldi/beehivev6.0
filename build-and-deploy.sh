#!/bin/bash
# ============================================================
# BeeWAF v7.0 — Build Docker Image + Deploy to K8s
# ============================================================
# Usage:
#   ./build-and-deploy.sh          # Build + compress only
#   ./build-and-deploy.sh deploy   # Build + compress + deploy
# ============================================================

set -e

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGE_NAME="beewaf"
IMAGE_TAG="sklearn"
FULL_IMAGE="${IMAGE_NAME}:${IMAGE_TAG}"
TAR_FILE="/tmp/beewaf-sklearn.tar.gz"

# Deploy chain config
PASSRELLE="passrelle.dpc.com.tn"
PASSRELLE_PORT=258
HAPROXY="haproxystage.dpc.com.tn"
HAPROXY_PORT=8520
K8S_MASTER="192.168.90.10"
REMOTE_PATH="/tmp/beewaf-sklearn.tar.gz"
PASSRELLE_USER="baha"
HAPROXY_USER="baha"
K8S_USER="baha"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║        🐝 BeeWAF v7.0 — Build & Deploy Pipeline 🐝        ║"
echo "║                                                            ║"
echo "║  ML: IF=0%, RF=45%, GB=55%, threshold=0.65                 ║"
echo "║  FP filter: timezone, GraphQL, pipe-lists, math            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ────────────────────────────────────────────────────────────
# Step 1: Build Docker image using Dockerfile.k8s
# ────────────────────────────────────────────────────────────
echo "🔨 Étape 1/3 : Build de l'image Docker (Dockerfile.k8s)..."
echo "   Répertoire : ${PROJECT_DIR}"
echo ""

cd "${PROJECT_DIR}"

docker build \
  -f Dockerfile.k8s \
  -t "${FULL_IMAGE}" \
  --no-cache \
  .

echo ""
echo "✅ Image construite : ${FULL_IMAGE}"
docker images "${IMAGE_NAME}" --format "   📦 {{.Repository}}:{{.Tag}}  Size: {{.Size}}  Created: {{.CreatedSince}}"
echo ""

# ────────────────────────────────────────────────────────────
# Step 2: Save & compress the image
# ────────────────────────────────────────────────────────────
echo "📦 Étape 2/3 : Compression de l'image → ${TAR_FILE}..."

docker save "${FULL_IMAGE}" | gzip > "${TAR_FILE}"

TAR_SIZE=$(du -h "${TAR_FILE}" | cut -f1)
echo "✅ Image compressée : ${TAR_FILE} (${TAR_SIZE})"
echo ""

# ────────────────────────────────────────────────────────────
# Step 3: Quick validation
# ────────────────────────────────────────────────────────────
echo "🧪 Étape 3/3 : Validation rapide de l'image..."

# Test that the container starts and health check passes
CONTAINER_ID=$(docker run -d --rm -p 18765:8000 "${FULL_IMAGE}")
echo "   Container démarré : ${CONTAINER_ID:0:12}"

# Wait for startup (ML model loading takes ~15-20s)
echo "   Attente du démarrage (30s max)..."
HEALTHY=false
for i in $(seq 1 30); do
    sleep 1
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:18765/health 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" = "200" ]; then
        HEALTHY=true
        break
    fi
    printf "   ⏳ %d/30s (HTTP: %s)\r" "$i" "$HTTP_CODE"
done
echo ""

if [ "$HEALTHY" = true ]; then
    echo "   ✅ Health check OK"
    
    # Get ML status
    HEALTH_RESP=$(curl -s http://localhost:18765/health 2>/dev/null)
    echo "   📊 Health response:"
    echo "      ${HEALTH_RESP}" | python3 -m json.tool 2>/dev/null || echo "      ${HEALTH_RESP}"
    echo ""
    
    # Test ML detection
    echo "   🧪 Test ML — requête normale :"
    NORMAL_RESP=$(curl -s -X POST http://localhost:18765/echo -d "username=john&password=test123" 2>/dev/null)
    echo "      → ${NORMAL_RESP}"
    
    echo "   🧪 Test ML — SQLi :"
    SQLI_RESP=$(curl -s -X POST http://localhost:18765/echo -d "' OR 1=1--" 2>/dev/null)
    echo "      → ${SQLI_RESP}"
    
    echo "   🧪 Test ML — XSS :"
    XSS_RESP=$(curl -s -X POST http://localhost:18765/echo -d "<script>alert(1)</script>" 2>/dev/null)
    echo "      → ${XSS_RESP}"
    
    echo ""
else
    echo "   ⚠️  Health check timeout (container peut être lent au premier démarrage)"
    echo "   Les logs du container :"
    docker logs "${CONTAINER_ID}" 2>&1 | tail -20
    echo ""
fi

# Stop test container
docker stop "${CONTAINER_ID}" >/dev/null 2>&1 || true
echo "   🛑 Container de test arrêté"
echo ""

# ────────────────────────────────────────────────────────────
# Deploy (optional)
# ────────────────────────────────────────────────────────────
if [ "${1}" = "deploy" ]; then
    echo "═══════════════════════════════════════════════════════════"
    echo "🚀 DÉPLOIEMENT sur K8s cluster"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    echo "Chemin : Kali → passrelle → haproxystage → K8s master"
    echo ""
    
    # Transfer to passrelle
    echo "📤 [1/4] Kali → passrelle (${PASSRELLE}:${PASSRELLE_PORT})..."
    scp -P ${PASSRELLE_PORT} "${TAR_FILE}" ${PASSRELLE_USER}@${PASSRELLE}:${REMOTE_PATH}
    echo "   ✅ Transféré"
    
    # Transfer to haproxystage  
    echo "📤 [2/4] passrelle → haproxystage (${HAPROXY}:${HAPROXY_PORT})..."
    ssh -p ${PASSRELLE_PORT} ${PASSRELLE_USER}@${PASSRELLE} \
      "scp -P ${HAPROXY_PORT} ${REMOTE_PATH} ${HAPROXY_USER}@${HAPROXY}:${REMOTE_PATH} && rm -f ${REMOTE_PATH}"
    echo "   ✅ Transféré"
    
    # Transfer to K8s master
    echo "📤 [3/4] haproxystage → K8s master (${K8S_MASTER})..."
    ssh -p ${PASSRELLE_PORT} ${PASSRELLE_USER}@${PASSRELLE} \
      "ssh -p ${HAPROXY_PORT} ${HAPROXY_USER}@${HAPROXY} \
        'scp ${REMOTE_PATH} ${K8S_USER}@${K8S_MASTER}:${REMOTE_PATH} && rm -f ${REMOTE_PATH}'"
    echo "   ✅ Transféré"
    
    # Import + restart
    echo "🚀 [4/4] Import containerd + rollout restart..."
    ssh -p ${PASSRELLE_PORT} ${PASSRELLE_USER}@${PASSRELLE} \
      "ssh -p ${HAPROXY_PORT} ${HAPROXY_USER}@${HAPROXY} \
        'ssh ${K8S_USER}@${K8S_MASTER} \"
          echo \\\"Importing image into containerd...\\\" && \
          sudo ctr -n k8s.io images import ${REMOTE_PATH} && \
          echo \\\"Image imported. Restarting deployment...\\\" && \
          kubectl rollout restart deployment/beewaf -n beewaf && \
          kubectl rollout status deployment/beewaf -n beewaf --timeout=120s && \
          sleep 5 && \
          echo \\\"\\\" && \
          echo \\\"=== Pod Status ===\\\" && \
          kubectl get pods -n beewaf -l app=beewaf -o wide && \
          echo \\\"\\\" && \
          echo \\\"=== Health Check ===\\\" && \
          POD=\\\$(kubectl get pods -n beewaf -l app=beewaf -o jsonpath=\\\"{.items[0].metadata.name}\\\") && \
          kubectl exec -n beewaf \\\$POD -- curl -s http://localhost:8000/health && \
          echo \\\"\\\" && \
          rm -f ${REMOTE_PATH} && \
          echo \\\"✅ Déploiement terminé !\\\"
        \"'"
    echo ""
    echo "🐝 BeeWAF v7.0 déployé avec succès sur le cluster K8s !"
else
    echo "═══════════════════════════════════════════════════════════"
    echo "📋 RÉSUMÉ"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    echo "   Image  : ${FULL_IMAGE}"
    echo "   Archive: ${TAR_FILE} (${TAR_SIZE})"
    echo ""
    echo "   Pour déployer automatiquement :"
    echo "   ./build-and-deploy.sh deploy"
    echo ""
    echo "   Ou manuellement :"
    echo "   scp -P 258 ${TAR_FILE} baha@passrelle.dpc.com.tn:/tmp/"
    echo "   # puis suivre la chaîne passrelle → haproxy → K8s master"
    echo ""
fi

echo ""
echo "🐝 Changements v7.0 :"
echo "   • ML weights: IF=0% (disabled), RF=45%, GB=55%"
echo "   • ML threshold: 0.65 (reduced FP)"
echo "   • _is_obviously_safe: JSON, form-urlencoded, 40+ keywords"
echo "   • FP filter: timezone, GraphQL, pipe-lists, math"
echo "   • Cookie security: injection-only blocking"
echo ""
