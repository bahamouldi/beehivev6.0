#!/bin/bash
# =============================================================================
# BeeWAF v6.0 — Script de Déploiement Complet
# Date: 21 Février 2026
# Cible: Cluster K8s DPC (3 masters + 2 workers)
# Auteur: Baha (PFE DPC Tunisia)
# =============================================================================
#
# ARCHITECTURE:
#   Internet → HAProxy (207.180.211.157:443)
#          → Nginx Ingress (NodePort 32419)
#          → BeeWAF (ClusterIP beewaf-svc:80 → pod:8000)
#          → Backends:
#              dev.idts.dpc.com.tn    → idts-front-service (Angular)
#              secure.idts.dpc.com.tn → idts-back (Spring Boot)
#              idts.back.dpc.com.tn   → idts-back (Spring Boot)
#
# CHAÎNE SSH:
#   Kali → passrelle.dpc.com.tn:258 → haproxystage.dpc.com.tn:8520 → 192.168.90.10
#
# USAGE:
#   Ce script génère les commandes pour chaque étape.
#   Exécuter les sections une par une sur la bonne machine.
# =============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PROJECT_DIR="/home/kali/Downloads/beehivepfe2-main"

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     🐝 BeeWAF v6.0 — Déploiement Production DPC          ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"

# ═══════════════════════════════════════════════════════════════
# ÉTAPE 1 : Build & Test Local (Kali)
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${YELLOW}═══ ÉTAPE 1: Build de l'image Docker (sur Kali) ═══${NC}"
echo ""

cd "$PROJECT_DIR"

echo -e "${GREEN}[1.1] Construction de l'image...${NC}"
docker build -f Dockerfile.k8s -t beewaf:latest --no-cache .

echo ""
echo -e "${GREEN}[1.2] Test local rapide (5 secondes)...${NC}"
# Lancer en background, tester, puis tuer
docker run --rm -d --name beewaf-test -p 9999:8000 beewaf:latest
echo "Attente démarrage (15s)..."
sleep 15

# Test health
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:9999/health 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}✅ Health check OK (HTTP $HTTP_CODE)${NC}"
    HEALTH=$(curl -s http://localhost:9999/health)
    echo "   $HEALTH"
else
    echo -e "${RED}❌ Health check FAILED (HTTP $HTTP_CODE)${NC}"
    echo "Logs du container:"
    docker logs beewaf-test --tail=20
    docker stop beewaf-test 2>/dev/null
    echo ""
    echo -e "${RED}ARRÊT: L'image ne démarre pas correctement.${NC}"
    echo -e "${RED}Corriger le problème avant de continuer.${NC}"
    exit 1
fi

# Test reverse proxy (simuler dev.idts)
echo ""
echo -e "${GREEN}[1.3] Vérification imports numpy/sklearn...${NC}"
docker exec beewaf-test python -c "import numpy; print(f'numpy {numpy.__version__}')" 2>/dev/null && echo "  ✅ numpy OK" || echo "  ❌ numpy FAILED"
docker exec beewaf-test python -c "import sklearn; print(f'sklearn {sklearn.__version__}')" 2>/dev/null && echo "  ✅ sklearn OK" || echo "  ❌ sklearn FAILED"

# Cleanup
docker stop beewaf-test 2>/dev/null
echo ""
echo -e "${GREEN}[1.4] Sauvegarde du tarball...${NC}"
docker save beewaf:latest -o /tmp/beewaf-latest.tar
ls -lh /tmp/beewaf-latest.tar

echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✅ ÉTAPE 1 TERMINÉE — Image construite et testée${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"

# ═══════════════════════════════════════════════════════════════
# ÉTAPE 2 : Transfert via chaîne SSH
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${YELLOW}═══ ÉTAPE 2: Transfert de l'image vers le cluster ═══${NC}"
echo ""
echo -e "${BLUE}Exécuter ces commandes manuellement (2FA requise):${NC}"
echo ""
cat << 'TRANSFER_EOF'
# --- Depuis Kali ---
scp -P 258 /tmp/beewaf-latest.tar baha@passrelle.dpc.com.tn:/home/baha/

# --- Depuis passrelle ---
ssh -p 258 baha@passrelle.dpc.com.tn
scp -P 8520 beewaf-latest.tar baha@haproxystage.dpc.com.tn:/home/baha/

# --- Depuis haproxystage ---
ssh -p 8520 baha@haproxystage.dpc.com.tn
scp /home/baha/beewaf-latest.tar baha@192.168.90.10:/home/baha/

TRANSFER_EOF

echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✅ Transférer le tar, puis passer à l'étape 3${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"
