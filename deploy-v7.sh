#!/bin/bash
# ============================================================
# BeeWAF v7.0 Deployment Script
# Transfer via: Kali → passrelle → haproxystage → K8s Master
# ============================================================

set -e

IMAGE_FILE="/tmp/beewaf-v7.tar.gz"
PASSRELLE="passrelle.dpc.com.tn"
PASSRELLE_PORT=258
HAPROXY="haproxystage.dpc.com.tn"
HAPROXY_PORT=8520
K8S_MASTER="192.168.90.10"
REMOTE_PATH="/tmp/beewaf-v7.tar.gz"

echo "🐝 BeeWAF v7.0 — Déploiement sur K8s"
echo "======================================"
echo ""

# Step 1: Transfer to passrelle
echo "📤 Étape 1/4 : Kali → passrelle ($PASSRELLE:$PASSRELLE_PORT)..."
scp -P $PASSRELLE_PORT "$IMAGE_FILE" root@$PASSRELLE:$REMOTE_PATH
echo "✅ Image transférée à passrelle"

# Step 2: Transfer to haproxystage
echo "📤 Étape 2/4 : passrelle → haproxystage ($HAPROXY:$HAPROXY_PORT)..."
ssh -p $PASSRELLE_PORT root@$PASSRELLE \
  "scp -P $HAPROXY_PORT $REMOTE_PATH root@$HAPROXY:$REMOTE_PATH && rm -f $REMOTE_PATH"
echo "✅ Image transférée à haproxystage"

# Step 3: Transfer to K8s master
echo "📤 Étape 3/4 : haproxystage → K8s master ($K8S_MASTER)..."
ssh -p $PASSRELLE_PORT root@$PASSRELLE \
  "ssh -p $HAPROXY_PORT root@$HAPROXY \
    'scp $REMOTE_PATH root@$K8S_MASTER:$REMOTE_PATH && rm -f $REMOTE_PATH'"
echo "✅ Image transférée au master K8s"

# Step 4: Import image + restart pods
echo "🚀 Étape 4/4 : Import containerd + rollout restart..."
ssh -p $PASSRELLE_PORT root@$PASSRELLE \
  "ssh -p $HAPROXY_PORT root@$HAPROXY \
    'ssh root@$K8S_MASTER \"
      echo \\\"Importing image...\\\" && \
      ctr -n k8s.io images import $REMOTE_PATH && \
      echo \\\"Image imported. Restarting pods...\\\" && \
      kubectl rollout restart deployment/beewaf -n default && \
      sleep 5 && \
      kubectl get pods -n default -l app=beewaf && \
      rm -f $REMOTE_PATH && \
      echo \\\"✅ Déploiement terminé !\\\"
    \"'"

echo ""
echo "🐝 BeeWAF v7.0 déployé avec succès !"
echo "   Changements:"
echo "   • ML: IF=0%, RF=45%, GB=55%, threshold=0.65"
echo "   • FP filter: timezone, GraphQL, pipe-lists, math"
echo "   • Cookie security: injection-only blocking"
echo "   • _is_obviously_safe: 40+ attack keywords"
