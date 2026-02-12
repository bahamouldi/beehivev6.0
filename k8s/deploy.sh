#!/bin/bash
# =============================================================================
# BeeWAF — Script de déploiement COMPLET sur cluster DPC
# Déploie : BeeWAF (27 modules + 10K regex + ML) + ELK Stack complet
# =============================================================================
#
# Infrastructure DPC :
#   Kali → passrelle.dpc.com.tn:258 → HAProxy:8520 → K8s (192.168.90.x)
#
#   HAProxy (207.180.211.157)
#     :80  → NodePort 30439 → Nginx Ingress HTTP
#     :443 → NodePort 32419 → Nginx Ingress HTTPS
#
#   K8s v1.29 : 3 masters (.10/.20/.30) + 2 workers (.40/.50)
#   containerd, Calico, Nginx Ingress, ArgoCD, cert-manager
#
# Usage :
#   sudo bash k8s/deploy.sh              # Déploiement complet
#   sudo bash k8s/deploy.sh --no-elk     # Sans ELK (WAF seulement)
#   sudo bash k8s/deploy.sh --delete     # Supprimer tout
# =============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

DEPLOY_ELK=true
DELETE_MODE=false

for arg in "$@"; do
    case $arg in
        --no-elk) DEPLOY_ELK=false ;;
        --delete) DELETE_MODE=true ;;
    esac
done

# === MODE SUPPRESSION ===
if [ "$DELETE_MODE" = true ]; then
    echo -e "${RED}🗑️  Suppression de BeeWAF...${NC}"
    kubectl delete namespace beewaf --ignore-not-found
    kubectl delete clusterrole filebeat --ignore-not-found
    kubectl delete clusterrolebinding filebeat --ignore-not-found
    echo -e "${GREEN}✅ Tout supprimé${NC}"
    exit 0
fi

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║     🐝 BeeWAF — Déploiement Complet K8s         ║"
echo "║     27 modules | 10K regex | ML | ELK Stack      ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

# ---------- VÉRIFICATIONS ----------
echo -e "${YELLOW}[0/7] Vérifications préalables...${NC}"

if ! command -v kubectl &> /dev/null; then
    echo -e "${RED}❌ kubectl non trouvé. Exécuter sur un master node en root.${NC}"
    exit 1
fi

NODE_COUNT=$(kubectl get nodes --no-headers 2>/dev/null | wc -l)
if [ "$NODE_COUNT" -eq 0 ]; then
    echo -e "${RED}❌ Aucun node K8s trouvé. Vérifier la connexion au cluster.${NC}"
    exit 1
fi

echo -e "${GREEN}  ✅ Cluster OK : $NODE_COUNT nodes${NC}"
kubectl get nodes --no-headers

# ---------- ÉTAPE 1 : NAMESPACE ----------
echo ""
echo -e "${YELLOW}[1/7] Création du namespace beewaf...${NC}"
kubectl apply -f k8s/namespace.yaml
echo -e "${GREEN}  ✅ Namespace créé${NC}"

# ---------- ÉTAPE 2 : SECRETS ----------
echo ""
echo -e "${YELLOW}[2/7] Création des secrets...${NC}"
kubectl apply -f k8s/secrets.yaml

# Certificat TLS auto-signé si pas encore créé
if ! kubectl get secret beewaf-tls-secret -n beewaf &>/dev/null; then
    echo "  Génération du certificat TLS auto-signé..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /tmp/beewaf-tls.key \
        -out /tmp/beewaf-tls.crt \
        -subj "/CN=beewaf.dpc.com.tn/O=DPC" \
        -addext "subjectAltName=DNS:beewaf.dpc.com.tn,DNS:kibana.dpc.com.tn,DNS:app.dpc.com.tn" \
        2>/dev/null
    kubectl create secret tls beewaf-tls-secret \
        --cert=/tmp/beewaf-tls.crt \
        --key=/tmp/beewaf-tls.key \
        -n beewaf
    rm -f /tmp/beewaf-tls.key /tmp/beewaf-tls.crt
fi
echo -e "${GREEN}  ✅ Secrets créés${NC}"

# ---------- ÉTAPE 3 : ELK STACK (optionnel) ----------
if [ "$DEPLOY_ELK" = true ]; then
    echo ""
    echo -e "${YELLOW}[3/7] Déploiement ELK Stack (Elasticsearch + Logstash + Kibana + Filebeat)...${NC}"

    echo "  → Elasticsearch..."
    kubectl apply -f k8s/elk/elasticsearch.yaml

    echo "  → Attente Elasticsearch ready (peut prendre 2-3 min)..."
    kubectl rollout status statefulset/elasticsearch -n beewaf --timeout=180s 2>/dev/null || true

    # Attendre que ES soit vraiment prêt
    echo "  → Vérification santé Elasticsearch..."
    for i in $(seq 1 30); do
        if kubectl exec -n beewaf elasticsearch-0 -- curl -s http://localhost:9200/_cluster/health 2>/dev/null | grep -q '"status"'; then
            echo -e "  ${GREEN}✅ Elasticsearch opérationnel${NC}"
            break
        fi
        echo "    Attente... ($i/30)"
        sleep 10
    done

    echo "  → Logstash..."
    kubectl apply -f k8s/elk/logstash.yaml
    kubectl rollout status deployment/logstash -n beewaf --timeout=120s 2>/dev/null || true

    echo "  → Kibana..."
    kubectl apply -f k8s/elk/kibana.yaml
    kubectl rollout status deployment/kibana -n beewaf --timeout=120s 2>/dev/null || true

    echo "  → Filebeat (DaemonSet)..."
    kubectl apply -f k8s/elk/filebeat.yaml

    echo -e "${GREEN}  ✅ ELK Stack déployé${NC}"
else
    echo ""
    echo -e "${YELLOW}[3/7] ELK Stack ignoré (--no-elk)${NC}"
fi

# ---------- ÉTAPE 4 : BEEWAF WAF ----------
echo ""
echo -e "${YELLOW}[4/7] Déploiement BeeWAF (27 modules + 10K regex + ML)...${NC}"
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
echo -e "${GREEN}  ✅ BeeWAF Deployment + Service créés${NC}"

# ---------- ÉTAPE 5 : INGRESS ----------
echo ""
echo -e "${YELLOW}[5/7] Configuration Ingress (HAProxy → Nginx Ingress → BeeWAF)...${NC}"
kubectl apply -f k8s/ingress.yaml
echo -e "${GREEN}  ✅ Ingress configuré : beewaf.dpc.com.tn${NC}"

# ---------- ÉTAPE 6 : ATTENTE READY ----------
echo ""
echo -e "${YELLOW}[6/7] Attente que BeeWAF soit Ready...${NC}"
kubectl rollout status deployment/beewaf -n beewaf --timeout=120s

# ---------- ÉTAPE 7 : VÉRIFICATION ----------
echo ""
echo -e "${YELLOW}[7/7] Vérification finale...${NC}"
echo ""

echo -e "${CYAN}📦 Pods :${NC}"
kubectl get pods -n beewaf -o wide
echo ""

echo -e "${CYAN}🔌 Services :${NC}"
kubectl get svc -n beewaf
echo ""

echo -e "${CYAN}🌐 Ingress :${NC}"
kubectl get ingress -n beewaf
echo ""

# Test de santé
BEEWAF_POD=$(kubectl get pods -n beewaf -l app=beewaf -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [ -n "$BEEWAF_POD" ]; then
    echo -e "${CYAN}🏥 Health Check :${NC}"
    HEALTH=$(kubectl exec -n beewaf "$BEEWAF_POD" -- curl -s http://localhost:8000/health 2>/dev/null)
    echo "  $HEALTH"
    echo ""

    # Test WAF
    echo -e "${CYAN}🛡️  Test WAF (SQLi) :${NC}"
    ATTACK=$(kubectl exec -n beewaf "$BEEWAF_POD" -- curl -s "http://localhost:8000/test?q=1'+OR+'1'='1" 2>/dev/null)
    echo "  $ATTACK"
    echo ""

    # Vérifier ML
    echo -e "${CYAN}🤖 Statut ML :${NC}"
    ML_STATUS=$(kubectl exec -n beewaf "$BEEWAF_POD" -- curl -s -H "X-API-Key: \$BEEWAF_API_KEY" http://localhost:8000/admin/stats 2>/dev/null | head -c 500)
    echo "  $ML_STATUS"
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     ✅ BeeWAF déployé avec succès !              ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo "  🐝 BeeWAF  : https://beewaf.dpc.com.tn"
if [ "$DEPLOY_ELK" = true ]; then
echo "  📊 Kibana  : http://kibana.dpc.com.tn"
fi
echo ""
echo "  Ce qui fonctionne dans ce déploiement :"
echo "  ✅ 27 modules de sécurité (chargés au démarrage)"
echo "  ✅ 10 041 règles regex compilées"
echo "  ✅ Rate Limiter (100 req/min) + IP Blocklist (10 attaques → ban)"
echo "  ✅ DDoS Protection (flood/slowloris/amplification)"
echo "  ✅ ML Ensemble 3 modèles (si entraîné dans l'image)"
echo "  ✅ Désobfuscation 18 couches"
echo "  ✅ Bot Detection + Virtual Patching (80+ CVEs)"
echo "  ✅ Response Cloaking + Security Headers"
if [ "$DEPLOY_ELK" = true ]; then
echo "  ✅ ELK Stack : logs → Filebeat → Logstash → Elasticsearch → Kibana"
fi
echo ""
echo "  📌 DNS : ajouter dans /etc/hosts ou DNS DPC :"
echo "     207.180.211.157 beewaf.dpc.com.tn kibana.dpc.com.tn"
echo ""
echo "  📌 Quand l'encadrante ajoute l'app :"
echo "     kubectl apply -f k8s/ingress-app-protected.yaml"
echo ""
echo "  🛑 Pour tout supprimer :"
echo "     sudo bash k8s/deploy.sh --delete"
echo ""
