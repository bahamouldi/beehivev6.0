#!/bin/bash
# =============================================================================
# BeeWAF — Installation de Jenkins sur le cluster DPC (Version corrigée v2)
# =============================================================================
# Cluster: 3 masters + 2 workers, K8s v1.29.15, Helm v3.20.0
# Usage: sudo ./scripts/install-jenkins.sh
# =============================================================================

set -e

echo "=========================================="
echo "   Installation de Jenkins sur DPC        "
echo "=========================================="
echo ""

# Vérifier Helm
if ! command -v helm &> /dev/null; then
    echo "❌ Helm n'est pas installé"
    exit 1
fi

echo "✅ Helm version: $(helm version --short)"

# Créer le namespace Jenkins
echo ""
echo "📦 Création du namespace jenkins..."
kubectl create namespace jenkins --dry-run=client -o yaml | kubectl apply -f -

# Ajouter le repo Helm Jenkins
echo ""
echo "📥 Ajout du repo Helm Jenkins..."
helm repo add jenkins https://charts.jenkins.io
helm repo update

# Créer les valeurs personnalisées pour Jenkins (VERSION CORRIGÉE v2)
echo ""
echo "⚙️ Création de la configuration Jenkins..."
cat > /tmp/jenkins-values.yaml <<'EOF'
controller:
  # Type de service
  serviceType: ClusterIP
  
  # Plugins essentiels pour CI/CD
  installPlugins: false
  additionalPlugins:
    - kubernetes:4296.v20a_7e4d77cf6
    - workflow-aggregator:600.vb_57cdd26f247
    - git:5.7.0
    - docker-workflow:580.vc0c34057f3a_4
    - pipeline-stage-view:2.34
    - credentials-binding:687.v6192d0ec7b_d2
    - ssh-credentials:343.v884f71d78167
  
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
    size: 20Gi
  
  # Configuration Java
  javaOpts: "-Xms512m -Xmx2g"
  
  # Admin user (CORRIGÉ)
  admin:
    createSecret: true
    user: admin
  
  # Exécuteurs
  numExecutors: 2

# Agent configuration (CORRIGÉ)
agent:
  enabled: true
  image:
    repository: jenkins/inbound-agent
    tag: "3261.v9c670a_4748a_9"
    pullPolicy: IfNotPresent
  resources:
    requests:
      cpu: "200m"
      memory: "256Mi"
    limits:
      cpu: "500m"
      memory: "512Mi"

# Service account
serviceAccount:
  create: true
  name: jenkins

# RBAC
rbac:
  create: true
EOF

# Installer Jenkins
echo ""
echo "🚀 Installation de Jenkins..."
helm upgrade --install jenkins jenkins/jenkins \
    --namespace jenkins \
    --values /tmp/jenkins-values.yaml \
    --wait --timeout 15m

# Attendre que Jenkins soit prêt
echo ""
echo "⏳ Attente du démarrage de Jenkins..."
kubectl rollout status deployment/jenkins -n jenkins --timeout=10m

# Récupérer le mot de passe admin
echo ""
echo "🔑 Récupération du mot de passe admin..."
ADMIN_PASSWORD=$(kubectl exec --namespace jenkins -it svc/jenkins -c jenkins -- /bin/cat /run/secrets/additional/chart-admin-password 2>/dev/null || echo "Voir les logs du pod")

# Créer l'Ingress pour Jenkins
echo ""
echo "🌐 Création de l'Ingress Jenkins..."
cat > /tmp/jenkins-ingress.yaml <<'EOF'
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: jenkins-ingress
  namespace: jenkins
  annotations:
    nginx.ingress.kubernetes.io/backend-protocol: "HTTP"
    nginx.ingress.kubernetes.io/proxy-body-size: "50m"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "300"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "300"
spec:
  ingressClassName: nginx
  rules:
  - host: jenkins.dpc.com.tn
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: jenkins
            port:
              number: 8080
EOF

kubectl apply -f /tmp/jenkins-ingress.yaml

# Afficher les informations de connexion
echo ""
echo "=========================================="
echo "       JENKINS INSTALLÉ AVEC SUCCÈS       "
echo "=========================================="
echo ""
echo "URL: http://jenkins.dpc.com.tn"
echo "Username: admin"
echo "Password: $ADMIN_PASSWORD"
echo ""
echo "Pour port-forward:"
echo "  kubectl port-forward svc/jenkins -n jenkins 8080:8080"
echo ""
echo "Pour voir les logs:"
echo "  kubectl logs -f deployment/jenkins -n jenkins"
echo ""

# Nettoyer
rm -f /tmp/jenkins-values.yaml /tmp/jenkins-ingress.yaml

echo "✅ Installation terminée"
