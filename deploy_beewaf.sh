#!/bin/bash
# =============================================================================
# BeeWAF v6.0 — Script de déploiement K8s complet
# Cluster DPC : 3 masters + 2 workers
# HAProxy (207.180.211.157) → Nginx Ingress → BeeWAF → idts-back
# =============================================================================
set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

NAMESPACE="beewaf"
IMAGE_NAME="beewaf"
IMAGE_TAG="v6.0"
GITHUB_REPO="https://github.com/bahamouldi/beehivev6.0.git"
BRANCH="master"

log_info()  { echo -e "${BLUE}[INFO]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[✅ OK]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[⚠️  WARN]${NC} $1"; }
log_err()   { echo -e "${RED}[❌ ERR]${NC} $1"; }

echo ""
echo "=============================================="
echo "  🐝 BeeWAF v6.0 — Déploiement K8s"
echo "=============================================="
echo ""

# =============================================================================
# Étape 0 : Vérifications préliminaires
# =============================================================================
log_info "Étape 0 : Vérifications préliminaires..."

# Vérifier kubectl
if ! command -v kubectl &>/dev/null; then
    log_err "kubectl non trouvé. Installez kubectl ou vérifiez votre PATH."
    exit 1
fi
log_ok "kubectl trouvé : $(kubectl version --client --short 2>/dev/null || kubectl version --client 2>/dev/null | head -1)"

# Vérifier la connexion au cluster
if ! kubectl cluster-info &>/dev/null; then
    log_err "Impossible de se connecter au cluster K8s. Vérifiez KUBECONFIG."
    exit 1
fi
log_ok "Connecté au cluster K8s"

# Afficher les nœuds
log_info "Nœuds du cluster :"
kubectl get nodes -o wide 2>/dev/null || kubectl get nodes

# Vérifier Docker / containerd
if command -v docker &>/dev/null; then
    RUNTIME="docker"
    log_ok "Docker disponible"
elif command -v nerdctl &>/dev/null; then
    RUNTIME="nerdctl"
    log_ok "nerdctl (containerd) disponible"
elif command -v ctr &>/dev/null; then
    RUNTIME="ctr"
    log_ok "ctr (containerd) disponible"
else
    log_warn "Aucun runtime container trouvé localement. On tentera avec crictl/import."
    RUNTIME="none"
fi

echo ""

# =============================================================================
# Étape 1 : Cloner le dépôt
# =============================================================================
log_info "Étape 1 : Clonage du dépôt depuis GitHub..."

WORK_DIR="/tmp/beewaf-deploy"
rm -rf "$WORK_DIR"

if git clone --branch "$BRANCH" --depth 1 "$GITHUB_REPO" "$WORK_DIR" 2>/dev/null; then
    log_ok "Dépôt cloné dans $WORK_DIR (branche $BRANCH)"
else
    log_warn "Branche $BRANCH non trouvée, essai avec 'main'..."
    git clone --branch main --depth 1 "$GITHUB_REPO" "$WORK_DIR"
    log_ok "Dépôt cloné (branche main)"
fi

cd "$WORK_DIR"
echo ""

# =============================================================================
# Étape 2 : Construire l'image Docker
# =============================================================================
log_info "Étape 2 : Construction de l'image Docker..."

if [ "$RUNTIME" = "docker" ]; then
    docker build -t ${IMAGE_NAME}:${IMAGE_TAG} -f Dockerfile.full .
    docker tag ${IMAGE_NAME}:${IMAGE_TAG} ${IMAGE_NAME}:latest
    log_ok "Image construite : ${IMAGE_NAME}:${IMAGE_TAG}"

    # Si le cluster utilise containerd, exporter et importer l'image
    if command -v ctr &>/dev/null; then
        log_info "Export de l'image vers containerd..."
        docker save ${IMAGE_NAME}:${IMAGE_TAG} | ctr -n k8s.io images import -
        docker save ${IMAGE_NAME}:latest | ctr -n k8s.io images import -
        log_ok "Image importée dans containerd"
    fi

elif [ "$RUNTIME" = "nerdctl" ]; then
    nerdctl build -t ${IMAGE_NAME}:${IMAGE_TAG} -f Dockerfile.full .
    nerdctl tag ${IMAGE_NAME}:${IMAGE_TAG} ${IMAGE_NAME}:latest
    log_ok "Image construite avec nerdctl"

elif [ "$RUNTIME" = "ctr" ]; then
    # Utiliser buildctl ou un autre builder
    log_warn "ctr ne supporte pas 'build'. Tentative avec buildkit..."
    if command -v buildctl &>/dev/null; then
        buildctl build --frontend dockerfile.v0 --local context=. --local dockerfile=. \
            --opt filename=Dockerfile.full \
            --output type=image,name=${IMAGE_NAME}:${IMAGE_TAG}
    else
        log_err "Installez Docker ou nerdctl pour construire l'image."
        log_info "Alternative : construire sur une autre machine et transférer avec:"
        echo "  docker save ${IMAGE_NAME}:${IMAGE_TAG} > beewaf.tar"
        echo "  scp beewaf.tar user@master-node:/tmp/"
        echo "  ctr -n k8s.io images import /tmp/beewaf.tar"
        exit 1
    fi
else
    log_err "Pas de runtime container disponible."
    log_info "Construisez l'image manuellement :"
    echo "  docker build -t ${IMAGE_NAME}:${IMAGE_TAG} -f Dockerfile.full ."
    exit 1
fi

echo ""

# =============================================================================
# Étape 3 : Créer le namespace
# =============================================================================
log_info "Étape 3 : Création du namespace '$NAMESPACE'..."

if kubectl get namespace "$NAMESPACE" &>/dev/null; then
    log_ok "Namespace '$NAMESPACE' existe déjà"
else
    kubectl create namespace "$NAMESPACE"
    log_ok "Namespace '$NAMESPACE' créé"
fi

echo ""

# =============================================================================
# Étape 4 : Créer les secrets
# =============================================================================
log_info "Étape 4 : Création des secrets..."

# Secret API Key
API_KEY=$(openssl rand -hex 32 2>/dev/null || python3 -c "import secrets; print(secrets.token_hex(32))")

if kubectl get secret beewaf-secrets -n "$NAMESPACE" &>/dev/null; then
    log_ok "Secret 'beewaf-secrets' existe déjà"
else
    kubectl create secret generic beewaf-secrets \
        --from-literal=BEEWAF_API_KEY="$API_KEY" \
        -n "$NAMESPACE"
    log_ok "Secret 'beewaf-secrets' créé (API_KEY: ${API_KEY:0:8}...)"
fi

# Secret TLS (auto-signé si pas de cert-manager)
if kubectl get secret beewaf-tls-secret -n "$NAMESPACE" &>/dev/null; then
    log_ok "Secret TLS existe déjà"
else
    if [ -f k8s/tls/tls.crt ] && [ -s k8s/tls/tls.crt ]; then
        kubectl create secret tls beewaf-tls-secret \
            --cert=k8s/tls/tls.crt \
            --key=k8s/tls/tls.key \
            -n "$NAMESPACE"
        log_ok "Secret TLS créé depuis les fichiers existants"
    else
        log_info "Génération d'un certificat auto-signé..."
        mkdir -p /tmp/beewaf-tls
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /tmp/beewaf-tls/tls.key \
            -out /tmp/beewaf-tls/tls.crt \
            -subj "/CN=beewaf.dpc.com.tn/O=DPC" 2>/dev/null
        kubectl create secret tls beewaf-tls-secret \
            --cert=/tmp/beewaf-tls/tls.crt \
            --key=/tmp/beewaf-tls/tls.key \
            -n "$NAMESPACE"
        rm -rf /tmp/beewaf-tls
        log_ok "Secret TLS auto-signé créé"
    fi
fi

echo ""

# =============================================================================
# Étape 5 : Déployer les manifestes K8s
# =============================================================================
log_info "Étape 5 : Déploiement des manifestes K8s..."

# Appliquer le Deployment
kubectl apply -f k8s/deployment.yaml
log_ok "Deployment appliqué"

# Appliquer le Service
kubectl apply -f k8s/service.yaml
log_ok "Service appliqué"

# Appliquer l'Ingress
kubectl apply -f k8s/ingress.yaml
log_ok "Ingress appliqué"

echo ""

# =============================================================================
# Étape 6 : Attendre que les pods soient prêts
# =============================================================================
log_info "Étape 6 : Attente du démarrage des pods (timeout: 120s)..."

if kubectl rollout status deployment/beewaf -n "$NAMESPACE" --timeout=120s 2>/dev/null; then
    log_ok "Deployment 'beewaf' prêt !"
else
    log_warn "Timeout atteint. Vérification de l'état..."
fi

echo ""

# =============================================================================
# Étape 7 : Vérification finale
# =============================================================================
log_info "Étape 7 : Vérification finale..."

echo ""
echo "📦 Pods :"
kubectl get pods -n "$NAMESPACE" -o wide
echo ""
echo "🔌 Service :"
kubectl get svc -n "$NAMESPACE"
echo ""
echo "🌐 Ingress :"
kubectl get ingress -n "$NAMESPACE"
echo ""

# Test de santé
POD_NAME=$(kubectl get pods -n "$NAMESPACE" -l app=beewaf -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [ -n "$POD_NAME" ]; then
    log_info "Test de santé sur le pod $POD_NAME..."
    HEALTH=$(kubectl exec -n "$NAMESPACE" "$POD_NAME" -- curl -s http://localhost:8000/health 2>/dev/null || echo "N/A")
    if echo "$HEALTH" | grep -q "healthy\|ok\|running"; then
        log_ok "Health check : $HEALTH"
    else
        log_warn "Health check : $HEALTH"
        log_info "Les pods peuvent prendre quelques instants à démarrer (ML models loading)."
    fi
fi

echo ""
echo "=============================================="
echo "  🐝 BeeWAF v6.0 — Déploiement terminé !"
echo "=============================================="
echo ""
echo "  📋 Résumé :"
echo "     Namespace : $NAMESPACE"
echo "     Image     : ${IMAGE_NAME}:${IMAGE_TAG}"
echo "     Service   : beewaf-svc (port 80 → 8000)"
echo "     Ingress   : beewaf.dpc.com.tn"
echo ""
echo "  🔧 Commandes utiles :"
echo "     kubectl get pods -n beewaf -w"
echo "     kubectl logs -n beewaf -l app=beewaf -f"
echo "     kubectl describe pod -n beewaf -l app=beewaf"
echo "     curl -k https://beewaf.dpc.com.tn/health"
echo ""
echo "  📊 API Dashboard :"
echo "     https://beewaf.dpc.com.tn/dashboard"
echo "     https://beewaf.dpc.com.tn/docs"
echo ""
