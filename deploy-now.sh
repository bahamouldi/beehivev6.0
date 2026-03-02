#!/bin/bash
# ================================================================
# BeeWAF Deployment Script — Run from Kali
# ================================================================
# Usage: ./deploy-now.sh
# 
# This transfers the image through:
#   Kali → Passerelle(:258) → HAProxy(:8520) → Master(192.168.90.10)
# ================================================================

set -e
IMAGE_FILE="/tmp/beewaf-sklearn.tar.gz"
IMAGE_NAME="beewaf:sklearn"

echo "============================================"
echo "  BeeWAF v6.0 — Deployment Pipeline"
echo "============================================"

# Step 1: Verify image exists
if [ ! -f "$IMAGE_FILE" ]; then
    echo "❌ Image not found at $IMAGE_FILE"
    echo "   Run: docker save beewaf:sklearn | gzip > $IMAGE_FILE"
    exit 1
fi
echo "✅ Image ready: $(ls -lh $IMAGE_FILE | awk '{print $5}')"

# Step 2: Transfer to Passerelle
echo ""
echo "📤 Step 1/3: Transferring to Passerelle..."
scp -P 258 "$IMAGE_FILE" baha@passrelle.dpc.com.tn:~/beewaf-sklearn.tar.gz

# Step 3: From Passerelle → HAProxy → Master (run in one SSH session)
echo ""
echo "📤 Step 2/3: Transferring Passerelle → HAProxy → Master..."
ssh -p 258 baha@passrelle.dpc.com.tn << 'PASSERELLE_EOF'
echo "  → On Passerelle, forwarding to HAProxy..."
scp -P 8520 ~/beewaf-sklearn.tar.gz baha@haproxystage.dpc.com.tn:~/beewaf-sklearn.tar.gz
ssh -p 8520 baha@haproxystage.dpc.com.tn << 'HAPROXY_EOF'
echo "  → On HAProxy, forwarding to Master..."
scp ~/beewaf-sklearn.tar.gz baha@192.168.90.10:~/beewaf-sklearn.tar.gz
ssh baha@192.168.90.10 << 'MASTER_EOF'
echo "  → On Master, importing image..."
sudo ctr -n k8s.io images import ~/beewaf-sklearn.tar.gz
echo "  → Restarting BeeWAF deployment..."
sudo kubectl rollout restart deployment/beewaf -n beewaf
echo "  → Waiting for rollout..."
sudo kubectl rollout status deployment/beewaf -n beewaf --timeout=120s
echo "  → Checking pod status..."
sudo kubectl get pods -n beewaf -o wide
echo "✅ Deployment complete!"
MASTER_EOF
HAPROXY_EOF
PASSERELLE_EOF

echo ""
echo "============================================"
echo "  ✅ BeeWAF v6.0 Deployed!"
echo "============================================"
