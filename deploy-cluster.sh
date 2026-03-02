#!/bin/bash
# =============================================================================
# BeeWAF v6.0 — Script Cluster (exécuter sur root@TESTHAmaster1)
# =============================================================================
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     🐝 BeeWAF v6.0 — Déploiement sur Cluster K8s          ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"

# ═══════════════════════════════════════════════════════════════
# ÉTAPE 3 : Nettoyage AVANT déploiement
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${YELLOW}═══ ÉTAPE 3: Nettoyage des pods zombies ═══${NC}"

# Forcer replicas à 1 (sécurité)
echo -e "${GREEN}[3.1] Forcer replicas=1...${NC}"
kubectl scale deployment beewaf -n beewaf --replicas=1 2>/dev/null || true

# Supprimer TOUS les pods OutOfcpu / Error qui traînent
echo -e "${GREEN}[3.2] Supprimer les pods zombies (OutOfcpu/Error)...${NC}"
kubectl get pods -n beewaf -l app=beewaf --no-headers | \
  awk '$3 == "OutOfcpu" || $3 == "Error" || $3 == "CrashLoopBackOff" {print $1}' | \
  xargs -r kubectl delete pod -n beewaf --force --grace-period=0 2>/dev/null || true

# Supprimer les ReplicaSets orphelins (0 ready)
echo -e "${GREEN}[3.3] Supprimer les ReplicaSets orphelins...${NC}"
ACTIVE_RS=$(kubectl get deploy beewaf -n beewaf -o jsonpath='{.status.conditions[?(@.type=="Progressing")].message}' | grep -oP 'ReplicaSet "\K[^"]+')
kubectl get rs -n beewaf --no-headers -l app=beewaf | while read name desired current ready age; do
  if [ "$ready" = "0" ] && [ "$name" != "$ACTIVE_RS" ]; then
    echo "  Suppression RS: $name (ready=$ready)"
    kubectl delete rs -n beewaf "$name" --force --grace-period=0 2>/dev/null || true
  fi
done

# Nettoyage des anciennes images (garder de l'espace disque)
echo -e "${GREEN}[3.4] Nettoyage anciennes images beewaf...${NC}"
echo "  Images avant nettoyage:"
ctr -n k8s.io images list | grep beewaf
# On ne supprime pas les anciennes images au cas où rollback nécessaire

echo ""
echo -e "${GREEN}[3.5] État actuel:${NC}"
kubectl get pods -n beewaf -l app=beewaf -o wide
kubectl get rs -n beewaf -l app=beewaf
echo ""

# ═══════════════════════════════════════════════════════════════
# ÉTAPE 4 : Import nouvelle image
# ═══════════════════════════════════════════════════════════════
echo -e "${YELLOW}═══ ÉTAPE 4: Import de la nouvelle image ═══${NC}"

if [ ! -f /home/baha/beewaf-latest.tar ]; then
    echo -e "${RED}❌ /home/baha/beewaf-latest.tar introuvable!${NC}"
    echo "Transférer le fichier d'abord (étape 2)"
    exit 1
fi

echo -e "${GREEN}[4.1] Import de l'image dans containerd...${NC}"
ctr -n k8s.io images import /home/baha/beewaf-latest.tar
echo ""
echo "  Nouvelle image importée:"
ctr -n k8s.io images list | grep "beewaf:latest"

# ═══════════════════════════════════════════════════════════════
# ÉTAPE 5 : Vérifier/Créer le secret TLS manquant
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${YELLOW}═══ ÉTAPE 5: Vérification secrets TLS ═══${NC}"

# Vérifier que beewaf-idts-tls existe (utilisé par 2 ingresses)
if ! kubectl get secret beewaf-idts-tls -n beewaf &>/dev/null; then
    echo -e "${YELLOW}⚠️  Secret beewaf-idts-tls manquant!${NC}"
    echo "  Les ingresses secure.idts et idts.back en ont besoin."
    echo "  Essai de copie depuis idts-test namespace..."
    
    # Tenter de copier depuis idts-test
    if kubectl get secret idts-front-tls -n idts-test &>/dev/null; then
        kubectl get secret idts-front-tls -n idts-test -o json | \
          jq 'del(.metadata.namespace,.metadata.uid,.metadata.resourceVersion,.metadata.creationTimestamp) | .metadata.name="beewaf-idts-tls"' | \
          kubectl apply -n beewaf -f -
        echo -e "${GREEN}  ✅ Secret copié depuis idts-test${NC}"
    else
        echo -e "${YELLOW}  ⚠️  Pas de cert source trouvé. Les ingresses HTTPS pour secure.idts et idts.back ne fonctionneront pas.${NC}"
        echo "  Créer manuellement: kubectl create secret tls beewaf-idts-tls -n beewaf --cert=tls.crt --key=tls.key"
    fi
else
    echo -e "${GREEN}✅ Secret beewaf-idts-tls existe${NC}"
fi

# Vérifier beewaf-dev-idts-tls
if kubectl get secret beewaf-dev-idts-tls -n beewaf &>/dev/null; then
    echo -e "${GREEN}✅ Secret beewaf-dev-idts-tls existe${NC}"
else
    echo -e "${YELLOW}⚠️  Secret beewaf-dev-idts-tls manquant${NC}"
fi

echo ""
echo "  Secrets dans beewaf namespace:"
kubectl get secrets -n beewaf

# ═══════════════════════════════════════════════════════════════
# ÉTAPE 6 : Appliquer le deployment mis à jour
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${YELLOW}═══ ÉTAPE 6: Rollout du nouveau deployment ═══${NC}"

# Rollout restart pour forcer le pull de la nouvelle image
echo -e "${GREEN}[6.1] Rollout restart...${NC}"
kubectl rollout restart deployment beewaf -n beewaf

# Attendre le rollout
echo -e "${GREEN}[6.2] Attente du rollout (timeout 120s)...${NC}"
kubectl rollout status deployment beewaf -n beewaf --timeout=120s || {
    echo -e "${RED}❌ Rollout timeout — vérification:${NC}"
    kubectl get pods -n beewaf -l app=beewaf -o wide
    kubectl logs -n beewaf deploy/beewaf --tail=30
    exit 1
}

echo ""
echo -e "${GREEN}[6.3] Pod status:${NC}"
kubectl get pods -n beewaf -l app=beewaf -o wide
echo ""

# ═══════════════════════════════════════════════════════════════
# ÉTAPE 7 : Vérifications post-déploiement
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${YELLOW}═══ ÉTAPE 7: Vérifications post-déploiement ═══${NC}"

POD=$(kubectl get pod -n beewaf -l app=beewaf --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

if [ -z "$POD" ]; then
    echo -e "${RED}❌ Aucun pod Running trouvé!${NC}"
    kubectl get pods -n beewaf -l app=beewaf
    exit 1
fi

echo -e "${GREEN}[7.1] Pod actif: $POD${NC}"

# Health check
echo -e "${GREEN}[7.2] Health check...${NC}"
kubectl exec -n beewaf "$POD" -- curl -s http://localhost:8000/health | python3 -m json.tool 2>/dev/null || \
kubectl exec -n beewaf "$POD" -- curl -s http://localhost:8000/health

# Vérifier numpy dans le container
echo ""
echo -e "${GREEN}[7.3] Vérification numpy/sklearn dans le container...${NC}"
kubectl exec -n beewaf "$POD" -- python -c "import numpy; print(f'numpy {numpy.__version__}')" 2>/dev/null && echo "  ✅ numpy OK" || echo "  ❌ numpy FAILED"
kubectl exec -n beewaf "$POD" -- python -c "import sklearn; print(f'sklearn {sklearn.__version__}')" 2>/dev/null && echo "  ✅ sklearn OK" || echo "  ❌ sklearn FAILED"

# Vérifier que les modèles ML sont chargés
echo ""
echo -e "${GREEN}[7.4] Modèles ML dans le container...${NC}"
kubectl exec -n beewaf "$POD" -- ls -lh /app/models/ 2>/dev/null || echo "  ⚠️ Pas de modèles trouvés"

# Vérifier le startup (pas de training)
echo ""
echo -e "${GREEN}[7.5] Logs de démarrage (vérifier pas de training):${NC}"
kubectl logs -n beewaf "$POD" --tail=30 | head -20

# ═══════════════════════════════════════════════════════════════
# ÉTAPE 8 : Tests fonctionnels WAF
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${YELLOW}═══ ÉTAPE 8: Tests fonctionnels WAF ═══${NC}"

WAF_IP=$(kubectl get pod -n beewaf "$POD" -o jsonpath='{.status.podIP}')
echo "  Pod IP: $WAF_IP"

# Test 1: Angular frontend (dev.idts)
echo ""
echo -e "${GREEN}[8.1] Test: dev.idts.dpc.com.tn (Angular frontend)${NC}"
CODE=$(kubectl exec -n beewaf "$POD" -- curl -s -o /dev/null -w "%{http_code}" -H "Host: dev.idts.dpc.com.tn" http://localhost:8000/ 2>/dev/null)
if [ "$CODE" = "200" ]; then
    echo -e "  ${GREEN}✅ Angular frontend → HTTP $CODE${NC}"
else
    echo -e "  ${YELLOW}⚠️  Angular frontend → HTTP $CODE${NC}"
fi

# Test 2: Backend API (secure.idts)
echo -e "${GREEN}[8.2] Test: secure.idts.dpc.com.tn (Spring Boot backend)${NC}"
CODE=$(kubectl exec -n beewaf "$POD" -- curl -s -o /dev/null -w "%{http_code}" -H "Host: secure.idts.dpc.com.tn" http://localhost:8000/ 2>/dev/null)
echo "  Backend API → HTTP $CODE"

# Test 3: JS files (pas de faux positifs)
echo -e "${GREEN}[8.3] Test: Fichiers .js (faux positifs corrigés)${NC}"
CODE=$(kubectl exec -n beewaf "$POD" -- curl -s -o /dev/null -w "%{http_code}" -H "Host: dev.idts.dpc.com.tn" http://localhost:8000/runtime.js 2>/dev/null)
echo "  runtime.js → HTTP $CODE"

# Test 4: SQLi (doit être bloqué)
echo -e "${GREEN}[8.4] Test: SQL Injection (doit être BLOQUÉ)${NC}"
CODE=$(kubectl exec -n beewaf "$POD" -- curl -s -o /dev/null -w "%{http_code}" -H "Host: dev.idts.dpc.com.tn" "http://localhost:8000/search?q=1'+OR+1=1--" 2>/dev/null)
if [ "$CODE" = "403" ]; then
    echo -e "  ${GREEN}✅ SQLi bloqué → HTTP $CODE${NC}"
else
    echo -e "  ${YELLOW}⚠️  SQLi non bloqué → HTTP $CODE${NC}"
fi

# Test 5: XSS (doit être bloqué)
echo -e "${GREEN}[8.5] Test: XSS (doit être BLOQUÉ)${NC}"
CODE=$(kubectl exec -n beewaf "$POD" -- curl -s -o /dev/null -w "%{http_code}" -d "<script>alert(1)</script>" http://localhost:8000/echo 2>/dev/null)
if [ "$CODE" = "403" ]; then
    echo -e "  ${GREEN}✅ XSS bloqué → HTTP $CODE${NC}"
else
    echo -e "  ${YELLOW}⚠️  XSS non bloqué → HTTP $CODE${NC}"
fi

# Test 6: Via Ingress (depuis le master)
echo ""
echo -e "${GREEN}[8.6] Test via Nginx Ingress (depuis le master):${NC}"
CODE=$(curl -sk -o /dev/null -w "%{http_code}" --resolve dev.idts.dpc.com.tn:32419:127.0.0.1 https://dev.idts.dpc.com.tn:32419/ 2>/dev/null)
echo "  Via Ingress HTTPS → HTTP $CODE"

# ═══════════════════════════════════════════════════════════════
# ÉTAPE 9 : Nettoyage final
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${YELLOW}═══ ÉTAPE 9: Nettoyage final ═══${NC}"

# Supprimer pods zombies restants
echo -e "${GREEN}[9.1] Nettoyage pods zombies restants...${NC}"
kubectl get pods -n beewaf -l app=beewaf --no-headers | \
  awk '$3 == "OutOfcpu" || $3 == "Error" || $3 == "CrashLoopBackOff" || $3 == "Terminating" {print $1}' | \
  xargs -r kubectl delete pod -n beewaf --force --grace-period=0 2>/dev/null || true

# Supprimer RS orphelins
echo -e "${GREEN}[9.2] Nettoyage ReplicaSets orphelins...${NC}"
kubectl get rs -n beewaf --no-headers -l app=beewaf | awk '$3==0 && $4==0 {print $1}' | \
  xargs -r kubectl delete rs -n beewaf 2>/dev/null || true

# Espace disque
echo ""
echo -e "${GREEN}[9.3] Espace disque:${NC}"
df -h /

# Nettoyage du tarball
echo -e "${GREEN}[9.4] Nettoyage tarball (économiser ~1.3GB):${NC}"
rm -f /home/baha/beewaf-latest.tar
echo "  Tarball supprimé"

# ═══════════════════════════════════════════════════════════════
# RÉSUMÉ FINAL
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║              🐝 DÉPLOIEMENT TERMINÉ                        ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "📊 État final:"
kubectl get pods -n beewaf -o wide
echo ""
echo "📋 Ingresses:"
kubectl get ingress -n beewaf
echo ""
echo "🔗 URLs de test (depuis le master):"
echo "   curl -sk --resolve dev.idts.dpc.com.tn:32419:127.0.0.1 https://dev.idts.dpc.com.tn:32419/"
echo "   curl -sk --resolve secure.idts.dpc.com.tn:32419:127.0.0.1 https://secure.idts.dpc.com.tn:32419/"
echo "   curl -sk --resolve kibana.dpc.com.tn:30439:127.0.0.1 http://kibana.dpc.com.tn:30439/"
echo ""
echo "🌐 URLs externes (via HAProxy 207.180.211.157):"
echo "   https://dev.idts.dpc.com.tn"
echo "   https://secure.idts.dpc.com.tn"
echo "   http://kibana.dpc.com.tn"
echo ""
echo "🔑 Admin API:"
echo "   curl -H 'X-API-Key: \$BEEWAF_API_KEY' http://\$POD_IP:8000/admin/rules"
echo "   curl -H 'X-API-Key: \$BEEWAF_API_KEY' http://\$POD_IP:8000/admin/ml-stats"
echo ""
