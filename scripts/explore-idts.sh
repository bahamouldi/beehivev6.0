#!/bin/bash
# =============================================================================
# Script pour explorer l'architecture IDTS + BeeWAF
# Exécutez sur le Master: sudo ./scripts/explore-idts.sh
# =============================================================================

echo "============================================================================="
echo "           EXPLORATION ARCHITECTURE IDTS + BEEWAF"
echo "============================================================================="
echo ""

echo "=== 1. NAMESPACE IDTS-TEST ==="
kubectl get all -n idts-test
echo ""

echo "=== 2. DÉTAILS IDTS FRONTEND ==="
kubectl describe deployment idts-front-deployment -n idts-test 2>/dev/null || echo "Non trouvé"
echo ""

echo "=== 3. DÉTAILS IDTS BACKEND ==="
kubectl describe deployment idts-back -n idts-test 2>/dev/null || echo "Non trouvé"
echo ""

echo "=== 4. SERVICES IDTS ==="
kubectl get svc -n idts-test -o wide
echo ""

echo "=== 5. ENDPOINTS IDTS ==="
kubectl get endpoints -n idts-test
echo ""

echo "=== 6. INGRESS BEEWAF (routing) ==="
kubectl get ingress -n beewaf -o wide
echo ""

echo "=== 7. DÉTAIL INGRESS dev.idts ==="
kubectl describe ingress beewaf-protects-dev-idts -n beewaf 2>/dev/null || echo "Non trouvé"
echo ""

echo "=== 8. VARIABLES D'ENVIRONNEMENT BEEWAF ==="
kubectl exec -n beewaf deployment/beewaf -- env 2>/dev/null | grep -E "BACKEND|URL|MAP" || echo "Erreur"
echo ""

echo "=== 9. LOGS BEEWAF (dernières 20 lignes) ==="
kubectl logs -n beewaf deployment/beewaf --tail=20 2>/dev/null || echo "Erreur"
echo ""

echo "=== 10. TEST CONNECTIVITÉ BEEWAF → IDTS FRONTEND ==="
kubectl exec -n beewaf deployment/beewaf -- curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" http://idts-front-service.idts-test.svc.cluster.local:80 2>/dev/null || echo "Erreur"
echo ""

echo "=== 11. TEST CONNECTIVITÉ BEEWAF → IDTS BACKEND ==="
kubectl exec -n beewaf deployment/beewaf -- curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" http://idts-back.idts-test.svc.cluster.local:80 2>/dev/null || echo "Erreur"
echo ""

echo "=== 12. PODS IDTS (détails) ==="
kubectl get pods -n idts-test -o yaml | grep -E "image:|name:|ports:" | head -30
echo ""

echo "=== 13. CONFIGMAPS IDTS ==="
kubectl get configmaps -n idts-test
echo ""

echo "=== 14. SECRETS IDTS ==="
kubectl get secrets -n idts-test
echo ""

echo "=== 15. RESSOURCES UTILISÉES ==="
kubectl top pods -n idts-test 2>/dev/null || echo "Metrics non disponible"
kubectl top pods -n beewaf 2>/dev/null || echo "Metrics non disponible"
echo ""

echo "============================================================================="
echo "                    FIN DE L'EXPLORATION"
echo "============================================================================="
