#!/bin/bash
# =============================================================================
# Script à exécuter sur le Master pour collecter les informations du cluster
# Usage: sudo ./scripts/cluster-info.sh > cluster-info.txt 2>&1
# =============================================================================

echo "============================================================================="
echo "                    INFORMATIONS CLUSTER KUBERNETES DPC"
echo "============================================================================="
echo ""

echo "=== 1. CLUSTER INFO ==="
kubectl cluster-info
echo ""

echo "=== 2. NODES ==="
kubectl get nodes -o wide
echo ""

echo "=== 3. NAMESPACES ==="
kubectl get namespaces
echo ""

echo "=== 4. ALL PODS ==="
kubectl get pods -A -o wide
echo ""

echo "=== 5. ALL SERVICES ==="
kubectl get svc -A
echo ""

echo "=== 6. ALL INGRESS ==="
kubectl get ingress -A
echo ""

echo "=== 7. BEEWAF DEPLOYMENT ==="
kubectl get all -n beewaf
echo ""

echo "=== 8. BEEWAF DEPLOYMENT DETAILS ==="
kubectl describe deployment beewaf -n beewaf 2>/dev/null || echo "Deployment non trouvé"
echo ""

echo "=== 9. BEEWAF POD IMAGE ==="
kubectl get pods -n beewaf -o yaml 2>/dev/null | grep -A2 "image:" || echo "Pas de pods"
echo ""

echo "=== 10. NODE RESOURCES ==="
kubectl top nodes 2>/dev/null || echo "Metrics server non disponible"
echo ""

echo "=== 11. STORAGE CLASSES ==="
kubectl get storageclass
echo ""

echo "=== 12. HELM RELEASES ==="
helm version 2>/dev/null || echo "Helm non installé"
helm list -A 2>/dev/null || echo "Pas de releases Helm"
echo ""

echo "=== 13. ARGOCD ==="
kubectl get pods -n argocd 2>/dev/null || echo "ArgoCD non installé"
echo ""

echo "=== 14. JENKINS ==="
kubectl get pods -n jenkins 2>/dev/null || echo "Jenkins non installé"
echo ""

echo "=== 15. CONTAINERD IMAGES (beewaf) ==="
ctr -n k8s.io images ls 2>/dev/null | grep -i beewaf || echo "Pas d'images beewaf"
echo ""

echo "=== 16. KUBERNETES VERSION ==="
kubectl version -o yaml
echo ""

echo "=== 17. CONFIGMAPS (beewaf) ==="
kubectl get configmaps -n beewaf 2>/dev/null || echo "Pas de configmaps"
echo ""

echo "=== 18. SECRETS (beewaf) ==="
kubectl get secrets -n beewaf 2>/dev/null || echo "Pas de secrets"
echo ""

echo "=== 19. INGRESS DETAILS (beewaf) ==="
kubectl get ingress -n beewaf -o yaml 2>/dev/null || echo "Pas d'ingress"
echo ""

echo "=== 20. BEEWAF LOGS (last 30 lines) ==="
POD=$(kubectl get pod -n beewaf -l app=beewaf -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [ -n "$POD" ]; then
    kubectl logs $POD -n beewaf --tail=30 2>/dev/null || echo "Impossible de récupérer les logs"
else
    echo "Pas de pod beewaf trouvé"
fi
echo ""

echo "=== 21. NODE DESCRIPTION (master1) ==="
kubectl describe node testhamaster1 2>/dev/null | head -50
echo ""

echo "=== 22. AVAILABLE API RESOURCES ==="
kubectl api-resources | head -30
echo ""

echo "============================================================================="
echo "                    FIN DES INFORMATIONS"
echo "============================================================================="
