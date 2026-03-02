#!/bin/bash
# =============================================================================
# BeeWAF — Script d'installation CI/CD (Jenkins + ArgoCD)
# =============================================================================
# Ce script installe Jenkins et ArgoCD sur le cluster Kubernetes
# Usage: ./scripts/setup-cicd.sh [jenkins|argocd|all]
# =============================================================================

set -e

# Couleurs pour les messages
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonctions utilitaires
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Vérifier les prérequis
check_prerequisites() {
    log_info "Vérification des prérequis..."
    
    # Vérifier kubectl
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl n'est pas installé"
        exit 1
    fi
    
    # Vérifier helm
    if ! command -v helm &> /dev/null; then
        log_warning "helm n'est pas installé - installation via apt"
        curl https://baltocdn.com/helm/signing.asc | sudo apt-key add -
        sudo apt-get install -y apt-transport-https
        echo "deb https://baltocdn.com/helm/stable/debian/ all main" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list
        sudo apt-get update
        sudo apt-get install -y helm
    fi
    
    # Vérifier la connexion au cluster
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Impossible de se connecter au cluster Kubernetes"
        exit 1
    fi
    
    log_success "Prérequis vérifiés avec succès"
}

# Installation de Jenkins
install_jenkins() {
    log_info "Installation de Jenkins..."
    
    # Créer le namespace
    kubectl create namespace jenkins --dry-run=client -o yaml | kubectl apply -f -
    
    # Ajouter le repo Helm Jenkins
    helm repo add jenkins https://charts.jenkins.io
    helm repo update
    
    # Créer les valeurs personnalisées
    cat > /tmp/jenkins-values.yaml <<EOF
controller:
  serviceType: LoadBalancer
  servicePort: 8080
  serviceAgentPort: 50000
  
  # Plugins essentiels
  installPlugins: false
  additionalPlugins:
    - kubernetes:latest
    - workflow-aggregator:latest
    - git:latest
    - docker:latest
    - pipeline-stage-view:latest
    - credentials-binding:latest
    - ssh-credentials:latest
    - docker-workflow:latest
  
  # Ressources
  resources:
    requests:
      cpu: "500m"
      memory: "1Gi"
    limits:
      cpu: "2000m"
      memory: "4Gi"
  
  # Persistence
  persistence:
    enabled: true
    size: 50Gi
  
  # Configuration sécurité
  adminSecret: true
  
# Agent configuration
agent:
  enabled: true
  image: jenkins/inbound-agent
  tag: latest
EOF
    
    # Installer Jenkins
    helm upgrade --install jenkins jenkins/jenkins \
        --namespace jenkins \
        --values /tmp/jenkins-values.yaml \
        --wait --timeout 10m
    
    # Attendre que Jenkins soit prêt
    log_info "Attente du démarrage de Jenkins..."
    kubectl rollout status deployment/jenkins -n jenkins --timeout=10m
    
    # Récupérer le mot de passe admin
    log_info "Récupération du mot de passe admin..."
    ADMIN_PASSWORD=$(kubectl exec --namespace jenkins -it svc/jenkins -c jenkins -- /bin/cat /run/secrets/additional/chart-admin-password 2>/dev/null || echo "N/A")
    
    # Afficher les informations de connexion
    echo ""
    echo "=========================================="
    echo "       JENKINS INSTALLÉ AVEC SUCCÈS       "
    echo "=========================================="
    echo ""
    echo "URL: http://$(kubectl get svc jenkins -n jenkins -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo 'localhost'):8080"
    echo "Username: admin"
    echo "Password: $ADMIN_PASSWORD"
    echo ""
    echo "Pour port-forward: kubectl port-forward svc/jenkins 8080:8080 -n jenkins"
    echo ""
    
    log_success "Jenkins installé avec succès"
}

# Installation d'ArgoCD
install_argocd() {
    log_info "Installation d'ArgoCD..."
    
    # Créer le namespace
    kubectl create namespace argocd --dry-run=client -o yaml | kubectl apply -f -
    
    # Installer ArgoCD
    kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
    
    # Attendre que les pods soient prêts
    log_info "Attente du démarrage d'ArgoCD..."
    kubectl rollout status deployment/argocd-server -n argocd --timeout=10m
    kubectl rollout status deployment/argocd-repo-server -n argocd --timeout=10m
    kubectl rollout status deployment/argocd-application-controller -n argocd --timeout=10m
    
    # Récupérer le mot de passe admin
    log_info "Récupération du mot de passe admin..."
    ARGOCD_PASSWORD=$(kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d 2>/dev/null || echo "N/A")
    
    # Créer l'Ingress pour ArgoCD
    cat > /tmp/argocd-ingress.yaml <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: argocd-server-ingress
  namespace: argocd
  annotations:
    nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
    nginx.ingress.kubernetes.io/ssl-passthrough: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
spec:
  ingressClassName: nginx
  rules:
  - host: argocd.dpc.com.tn
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: argocd-server
            port:
              number: 443
EOF
    
    kubectl apply -f /tmp/argocd-ingress.yaml 2>/dev/null || log_warning "Impossible de créer l'Ingress ArgoCD"
    
    # Afficher les informations de connexion
    echo ""
    echo "=========================================="
    echo "       ARGOCD INSTALLÉ AVEC SUCCÈS        "
    echo "=========================================="
    echo ""
    echo "URL: https://argocd.dpc.com.tn"
    echo "Username: admin"
    echo "Password: $ARGOCD_PASSWORD"
    echo ""
    echo "Pour port-forward: kubectl port-forward svc/argocd-server -n argocd 8080:443"
    echo ""
    
    log_success "ArgoCD installé avec succès"
}

# Configuration des applications ArgoCD
configure_argocd_apps() {
    log_info "Configuration des applications ArgoCD..."
    
    # Appliquer le AppProject
    kubectl apply -f argocd/appproject.yaml
    
    # Appliquer les Applications
    kubectl apply -f argocd/application-dev.yaml
    kubectl apply -f argocd/application-prod.yaml
    
    log_success "Applications ArgoCD configurées"
}

# Installation de l'CLI ArgoCD
install_argocd_cli() {
    log_info "Installation de l'CLI ArgoCD..."
    
    if command -v argocd &> /dev/null; then
        log_warning "ArgoCD CLI déjà installé"
        return
    fi
    
    # Télécharger et installer
    curl -sSL -o /tmp/argocd https://github.com/argoproj/argo-cd/releases/latest/download/argocd-linux-amd64
    sudo install -m 555 /tmp/argocd /usr/local/bin/argocd
    
    log_success "ArgoCD CLI installé: $(argocd version --client)"
}

# Afficher l'aide
show_help() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commandes disponibles:"
    echo "  jenkins    Installer Jenkins uniquement"
    echo "  argocd     Installer ArgoCD uniquement"
    echo "  all        Installer Jenkins et ArgoCD"
    echo "  apps       Configurer les applications ArgoCD"
    echo "  cli        Installer l'CLI ArgoCD"
    echo "  help       Afficher cette aide"
    echo ""
}

# Main
main() {
    local command=${1:-all}
    
    echo ""
    echo "=========================================="
    echo "   BeeWAF CI/CD Installation Script       "
    echo "=========================================="
    echo ""
    
    case $command in
        jenkins)
            check_prerequisites
            install_jenkins
            ;;
        argocd)
            check_prerequisites
            install_argocd
            ;;
        all)
            check_prerequisites
            install_jenkins
            install_argocd
            configure_argocd_apps
            install_argocd_cli
            ;;
        apps)
            configure_argocd_apps
            ;;
        cli)
            install_argocd_cli
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            log_error "Commande inconnue: $command"
            show_help
            exit 1
            ;;
    esac
    
    echo ""
    log_success "Installation terminée!"
    echo ""
}

# Exécuter
main "$@"
