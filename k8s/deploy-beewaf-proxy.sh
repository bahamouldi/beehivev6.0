#!/bin/bash
# =============================================================================
# BeeWAF — Script de configuration Reverse Proxy vers idts-back
# Architecture: Internet → HAProxy → Ingress → BeeWAF → idts-back
# 
# Exécution: bash deploy-beewaf-proxy.sh
# =============================================================================

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${BLUE}[INFO]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[✅ OK]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[⚠️  WARN]${NC} $1"; }
log_err()   { echo -e "${RED}[❌ ERR]${NC} $1"; }

echo ""
echo "=============================================="
echo "  🐝 BeeWAF — Configuration Reverse Proxy"
echo "  Architecture: BeeWAF → idts-back"
echo "=============================================="
echo ""

# =============================================================================
# Étape 1 : Vérifier que idts-back est accessible
# =============================================================================
log_info "Étape 1 : Vérification de idts-back..."

if kubectl get svc idts-back -n idts-test &>/dev/null; then
    IDTS_IP=$(kubectl get svc idts-back -n idts-test -o jsonpath='{.spec.clusterIP}')
    IDTS_PORT=$(kubectl get svc idts-back -n idts-test -o jsonpath='{.spec.ports[0].port}')
    log_ok "Service idts-back trouvé: $IDTS_IP:$IDTS_PORT"
else
    log_err "Service idts-back non trouvé dans le namespace idts-test"
    exit 1
fi

# =============================================================================
# Étape 2 : Mettre à jour le deployment BeeWAF avec BACKEND_URL
# =============================================================================
log_info "Étape 2 : Configuration de BeeWAF avec BACKEND_URL..."

# Vérifier si le deployment existe
if ! kubectl get deployment beewaf -n beewaf &>/dev/null; then
    log_err "Deployment beewaf non trouvé dans le namespace beewaf"
    exit 1
fi

# Appliquer le patch pour ajouter BACKEND_URL
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: beewaf
  namespace: beewaf
spec:
  template:
    spec:
      containers:
      - name: beewaf
        env:
        - name: BEEWAF_MODEL_PATH
          value: "/app/models/model.pkl"
        - name: BEEWAF_TRAIN_DATA
          value: "/app/data/train_demo.csv"
        - name: ML_MODE
          value: "advanced"
        - name: BACKEND_URL
          value: "http://idts-back.idts-test.svc.cluster.local:80"
EOF

log_ok "Deployment mis à jour avec BACKEND_URL"

# =============================================================================
# Étape 3 : Redémarrer le pod BeeWAF pour appliquer les changements
# =============================================================================
log_info "Étape 3 : Redémarrage du pod BeeWAF..."

kubectl rollout restart deployment/beewaf -n beewaf
log_ok "Rollout déclenché"

# Attendre que le pod soit prêt
log_info "Attente du démarrage du nouveau pod..."
kubectl rollout status deployment/beewaf -n beewaf --timeout=120s
log_ok "Pod BeeWAF redémarré"

# =============================================================================
# Étape 4 : Vérifier la configuration
# =============================================================================
log_info "Étape 4 : Vérification de la configuration..."

# Vérifier que le pod tourne
POD_STATUS=$(kubectl get pods -n beewaf -l app=beewaf -o jsonpath='{.items[0].status.phase}')
if [ "$POD_STATUS" = "Running" ]; then
    log_ok "Pod BeeWAF en cours d'exécution"
else
    log_err "Pod BeeWAF non running: $POD_STATUS"
    kubectl describe pod -n beewaf -l app=beewaf
    exit 1
fi

# Vérifier les logs
log_info "Derniers logs BeeWAF:"
kubectl logs -n beewaf -l app=beewaf --tail=10

# =============================================================================
# Étape 5 : Tester la connexion BeeWAF → idts-back
# =============================================================================
log_info "Étape 5 : Test de connexion BeeWAF → idts-back..."

# Tester depuis le pod BeeWAF
kubectl exec -n beewaf -l app=beewaf -- curl -s -o /dev/null -w "%{http_code}" http://idts-back.idts-test.svc.cluster.local:80/ 2>/dev/null || echo "curl non disponible"

log_ok "Configuration terminée"

# =============================================================================
# Étape 6 : Créer l'Ingress (optionnel)
# =============================================================================
log_info "Étape 6 : Configuration de l'Ingress..."

read -p "Voulez-vous créer un nouvel Ingress pour secure.idts.dpc.com.tn ? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Vérifier si cert-manager est installé
    if kubectl get clusterissuer letsencrypt-prod &>/dev/null; then
        log_info "Cert-manager détecté, création de l'Ingress avec TLS..."
    else
        log_warn "Cert-manager non détecté, Ingress sans TLS automatique"
    fi
    
    kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: beewaf-protected-idts
  namespace: beewaf
  annotations:
    kubernetes.io/ingress.class: nginx
    nginx.ingress.kubernetes.io/proxy-body-size: "50m"
    nginx.ingress.kubernetes.io/use-forwarded-headers: "true"
spec:
  rules:
  - host: secure.idts.dpc.com.tn
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: beewaf-svc
            port:
              number: 80
EOF
    log_ok "Ingress créé pour secure.idts.dpc.com.tn"
fi

# =============================================================================
# Résumé
# =============================================================================
echo ""
echo "=============================================="
echo "  ✅ Configuration terminée !"
echo "=============================================="
echo ""
echo "📊 Architecture:"
echo "   Internet → HAProxy → Ingress → BeeWAF → idts-back"
echo ""
echo "🔗 URLs d'accès:"
echo "   • BeeWAF direct:  http://beewaf-svc.beewaf.svc.cluster.local"
echo "   • Kibana:         http://kibana.dpc.com.tn"
echo "   • Protégé:        http://secure.idts.dpc.com.tn (si Ingress créé)"
echo ""
echo "🧪 Tests à effectuer:"
echo "   1. Test normal:    curl http://secure.idts.dpc.com.tn/"
echo "   2. Test attaque:   curl 'http://secure.idts.dpc.com.tn/?id=1%27%20OR%20%271%27=%271'"
echo "   3. Health check:   curl http://beewaf-svc.beewaf.svc.cluster.local/health"
echo ""
