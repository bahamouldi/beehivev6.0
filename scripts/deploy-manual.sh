#!/bin/bash
# =============================================================================
# BeeWAF — Script de déploiement manuel (alternative au CI/CD)
# =============================================================================
# Ce script permet de déployer BeeWAF manuellement sans CI/CD
# Usage: ./scripts/deploy-manual.sh [dev|prod] [image-tag]
# =============================================================================

set -e

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Configuration
ENVIRONMENT=${1:-dev}
IMAGE_TAG=${2:-latest}
NAMESPACE="beewaf"
OVERLAY_PATH="k8s/overlays/${ENVIRONMENT}"

# Vérifications
if [[ ! -d "$OVERLAY_PATH" ]]; then
    log_error "Overlay non trouvé: $OVERLAY_PATH"
    echo "Environnements disponibles: dev, prod"
    exit 1
fi

echo ""
echo "=========================================="
echo "   BeeWAF Manual Deployment Script       "
echo "=========================================="
echo ""
echo "Environment: $ENVIRONMENT"
echo "Image Tag: $IMAGE_TAG"
echo "Namespace: $NAMESPACE"
echo ""

# Demander confirmation
read -p "Continuer? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    log_warning "Déploiement annulé"
    exit 0
fi

# Étape 1: Build de l'image Docker
log_info "Build de l'image Docker..."
docker build \
    -f Dockerfile.k8s \
    -t beewaf:${IMAGE_TAG} \
    --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
    --build-arg VCS_REF=$(git rev-parse --short HEAD 2>/dev/null || echo "manual") \
    .

log_success "Image construite: beewaf:${IMAGE_TAG}"

# Étape 2: Importer l'image dans le cluster (si containerd)
log_info "Import de l'image dans le cluster..."
if command -v ctr &> /dev/null; then
    # Sauvegarder l'image
    docker save beewaf:${IMAGE_TAG} | gzip > /tmp/beewaf-${IMAGE_TAG}.tar.gz
    
    # Importer dans containerd (namespace k8s.io)
    sudo ctr -n k8s.io images import /tmp/beewaf-${IMAGE_TAG}.tar.gz
    
    # Nettoyer
    rm /tmp/beewaf-${IMAGE_TAG}.tar.gz
    
    log_success "Image importée dans le cluster"
else
    log_warning "ctr non disponible - assurez-vous que l'image est accessible par le cluster"
fi

# Étape 3: Mettre à jour le tag dans kustomization
log_info "Mise à jour du tag d'image..."
if command -v kustomize &> /dev/null; then
    cd $OVERLAY_PATH
    kustomize edit set image docker.io/library/beewaf=beewaf:${IMAGE_TAG}
    cd -
else
    log_warning "kustomize non disponible - mise à jour manuelle requise"
fi

# Étape 4: Appliquer les manifests
log_info "Application des manifests Kubernetes..."
if command -v kustomize &> /dev/null; then
    kustomize build $OVERLAY_PATH | kubectl apply -f -
else
    kubectl apply -k $OVERLAY_PATH
fi

# Étape 5: Attendre le rollout
log_info "Attente du déploiement..."
kubectl rollout status deployment/beewaf -n $NAMESPACE --timeout=300s

# Étape 6: Vérification
log_info "Vérification du déploiement..."
POD=$(kubectl get pod -n $NAMESPACE -l app=beewaf -o jsonpath='{.items[0].metadata.name}')
kubectl exec $POD -n $NAMESPACE -- curl -s http://localhost:8000/health || log_warning "Health check échoué"

# Résumé
echo ""
echo "=========================================="
echo "       DÉPLOIEMENT TERMINÉ               "
echo "=========================================="
echo ""
echo "Environment: $ENVIRONMENT"
echo "Image: beewaf:${IMAGE_TAG}"
echo "Namespace: $NAMESPACE"
echo ""
echo "Pods:"
kubectl get pods -n $NAMESPACE -l app=beewaf
echo ""
echo "Services:"
kubectl get svc -n $NAMESPACE
echo ""
echo "Pour voir les logs:"
echo "  kubectl logs -f deployment/beewaf -n $NAMESPACE"
echo ""
