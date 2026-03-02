#!/bin/bash
# =============================================================================
# BeeWAF — Script de déploiement adapté au cluster DPC
# =============================================================================
# Architecture: Kali → Passerelle → HAProxy → Master1 (K8s)
# 
# Usage: ./scripts/deploy-to-cluster.sh [build|deploy|status|logs]
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

# =============================================================================
# CONFIGURATION - Adapter selon votre environnement
# =============================================================================

# Serveurs
PASSERELLE_HOST="passrelle.dpc.com.tn"
PASSERELLE_PORT="258"
PASSERELLE_USER="baha"

HAPROXY_HOST="haproxystage.dpc.com.tn"
HAPROXY_PORT="8520"
HAPROXY_USER="baha"

MASTER_HOST="192.168.90.10"
MASTER_USER="baha"

# Image Docker
IMAGE_NAME="beewaf"
IMAGE_TAG="${1:-latest}"
ARCHIVE_PATH="/tmp/beewaf-${IMAGE_TAG}.tar.gz"

# Kubernetes
K8S_NAMESPACE="beewaf"
K8S_DEPLOYMENT="beewaf"

# =============================================================================
# FONCTIONS
# =============================================================================

# Build l'image Docker localement sur Kali
build_image() {
    log_info "Build de l'image Docker..."
    
    docker build \
        -f Dockerfile.k8s \
        -t ${IMAGE_NAME}:${IMAGE_TAG} \
        --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
        --build-arg VCS_REF=$(git rev-parse --short HEAD 2>/dev/null || echo "manual") \
        .
    
    log_success "Image construite: ${IMAGE_NAME}:${IMAGE_TAG}"
    
    # Sauvegarder l'image
    log_info "Sauvegarde de l'image..."
    docker save ${IMAGE_NAME}:${IMAGE_TAG} | gzip > ${ARCHIVE_PATH}
    
    log_success "Image sauvegardée: ${ARCHIVE_PATH}"
    ls -lh ${ARCHIVE_PATH}
}

# Transférer l'image à travers la chaîne SSH
transfer_image() {
    log_info "Transfert de l'image vers le cluster..."
    
    if [[ ! -f ${ARCHIVE_PATH} ]]; then
        log_error "Archive non trouvée: ${ARCHIVE_PATH}"
        log_info "Exécutez d'abord: $0 build"
        exit 1
    fi
    
    # Étape 1: Kali → Passerelle
    log_info "Transfert Kali → Passerelle..."
    scp -P ${PASSERELLE_PORT} ${ARCHIVE_PATH} ${PASSERELLE_USER}@${PASSERELLE_HOST}:/tmp/
    
    # Étape 2: Passerelle → HAProxy
    log_info "Transfert Passerelle → HAProxy..."
    ssh -p ${PASSERELLE_PORT} ${PASSERELLE_USER}@${PASSERELLE_HOST} \
        "scp -P ${HAPROXY_PORT} /tmp/$(basename ${ARCHIVE_PATH}) ${HAPROXY_USER}@${HAPROXY_HOST}:/tmp/"
    
    # Étape 3: HAProxy → Master
    log_info "Transfert HAProxy → Master..."
    ssh -p ${PASSERELLE_PORT} ${PASSERELLE_USER}@${PASSERELLE_HOST} \
        "ssh -p ${HAPROXY_PORT} ${HAPROXY_USER}@${HAPROXY_HOST} \
        'scp /tmp/$(basename ${ARCHIVE_PATH}) ${MASTER_USER}@${MASTER_HOST}:/tmp/'"
    
    log_success "Image transférée vers le Master"
}

# Importer l'image et déployer sur le cluster
deploy_image() {
    log_info "Déploiement sur le cluster Kubernetes..."
    
    # Commandes à exécuter sur le Master
    ssh -p ${PASSERELLE_PORT} ${PASSERELLE_USER}@${PASSERELLE_HOST} << 'ENDSSH'
ssh -p 8520 baha@haproxystage.dpc.com.tn << 'ENDSSH2'
ssh baha@192.168.90.10 << 'ENDSSH3'
sudo su << 'ENDROOT'

# Importer l'image dans containerd (namespace k8s.io)
echo "Import de l'image dans containerd..."
ctr -n k8s.io images import /tmp/beewaf-latest.tar.gz || echo "Import déjà fait ou erreur mineure"

# Redémarrer le déploiement
echo "Rollout du déploiement..."
kubectl rollout restart deployment/beewaf -n beewaf
kubectl rollout status deployment/beewaf -n beewaf --timeout=120s

# Vérifier
echo "Vérification..."
POD=$(kubectl get pod -n beewaf -l app=beewaf -o jsonpath='{.items[0].metadata.name}')
kubectl exec $POD -n beewaf -- curl -s http://localhost:8000/health

ENDROOT
ENDSSH3
ENDSSH2
ENDSSH
    
    log_success "Déploiement terminé"
}

# Vérifier le statut du déploiement
check_status() {
    log_info "Vérification du statut..."
    
    ssh -p ${PASSERELLE_PORT} ${PASSERELLE_USER}@${PASSERELLE_HOST} << 'ENDSSH'
ssh -p 8520 baha@haproxystage.dpc.com.tn << 'ENDSSH2'
ssh baha@192.168.90.10 << 'ENDSSH3'
sudo su << 'ENDROOT'

echo "=== PODS ==="
kubectl get pods -n beewaf -o wide

echo ""
echo "=== SERVICES ==="
kubectl get svc -n beewaf

echo ""
echo "=== INGRESS ==="
kubectl get ingress -n beewaf

echo ""
echo "=== DERNIERS ÉVÉNEMENTS ==="
kubectl get events -n beewaf --sort-by='.lastTimestamp' | tail -10

ENDROOT
ENDSSH3
ENDSSH2
ENDSSH
}

# Voir les logs
view_logs() {
    log_info "Récupération des logs..."
    
    ssh -p ${PASSERELLE_PORT} ${PASSERELLE_USER}@${PASSERELLE_HOST} << 'ENDSSH'
ssh -p 8520 baha@haproxystage.dpc.com.tn << 'ENDSSH2'
ssh baha@192.168.90.10 << 'ENDSSH3'
sudo su << 'ENDROOT'

POD=$(kubectl get pod -n beewaf -l app=beewaf -o jsonpath='{.items[0].metadata.name}')
echo "Pod: $POD"
echo "=== LOGS (dernières 100 lignes) ==="
kubectl logs $POD -n beewaf --tail=100

ENDROOT
ENDSSH3
ENDSSH2
ENDSSH
}

# Pipeline complet
full_deploy() {
    log_info "=== PIPELINE COMPLET DE DÉPLOIEMENT ==="
    
    build_image
    transfer_image
    deploy_image
    check_status
    
    log_success "=== DÉPLOIEMENT TERMINÉ ==="
}

# =============================================================================
# MENU PRINCIPAL
# =============================================================================

show_help() {
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commandes disponibles:"
    echo "  build      Build l'image Docker localement"
    echo "  transfer   Transférer l'image vers le cluster"
    echo "  deploy     Déployer sur le cluster (import + rollout)"
    echo "  full       Pipeline complet (build + transfer + deploy)"
    echo "  status     Vérifier le statut du déploiement"
    echo "  logs       Voir les logs de l'application"
    echo "  help       Afficher cette aide"
    echo ""
    echo "Exemples:"
    echo "  $0 build          # Build l'image"
    echo "  $0 full           # Déploiement complet"
    echo "  $0 status         # Vérifier l'état"
    echo ""
}

# Main
case "${1:-help}" in
    build)
        build_image
        ;;
    transfer)
        transfer_image
        ;;
    deploy)
        deploy_image
        ;;
    full)
        full_deploy
        ;;
    status)
        check_status
        ;;
    logs)
        view_logs
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        log_error "Commande inconnue: $1"
        show_help
        exit 1
        ;;
esac
