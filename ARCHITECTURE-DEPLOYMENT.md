# BeeWAF — Architecture de Déploiement Expliquée

## 📊 Vue d'ensemble

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ARCHITECTURE BEEWAF + IDTS                                │
└─────────────────────────────────────────────────────────────────────────────┘

                              ┌─────────────────┐
                              │   Utilisateur   │
                              │   (Navigateur)  │
                              └────────┬────────┘
                                       │
                                       ▼
                         ┌─────────────────────────────┐
                         │         HAProxy             │
                         │   207.180.211.157           │
                         │   (Point d'entrée public)   │
                         └─────────────┬───────────────┘
                                       │
                                       ▼
                         ┌─────────────────────────────┐
                         │      Ingress Controller     │
                         │   (nginx-ingress)           │
                         │   Namespace: ingress-nginx  │
                         └─────────────┬───────────────┘
                                       │
                    ┌──────────────────┼──────────────────┐
                    │                  │                  │
                    ▼                  ▼                  ▼
         ┌──────────────────┐  ┌──────────────┐  ┌──────────────────┐
         │ dev.idts.dpc.tn  │  │secure.idts...│  │idts.back.dpc.tn  │
         │                  │  │              │  │                  │
         │  Ingress YAML:   │  │  Ingress:    │  │  Ingress:        │
         │  beewaf-protects │  │  beewaf-     │  │  idts-back-via   │
         │  -dev-idts       │  │  protected   │  │  -waf            │
         └────────┬─────────┘  └──────┬───────┘  └────────┬─────────┘
                  │                   │                   │
                  └───────────────────┼───────────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────────┐
                         │         BEEWAF              │
                         │   (WAF - Web Application    │
                         │    Firewall)                │
                         │                             │
                         │   Namespace: beewaf         │
                         │   Service: beewaf-svc:80    │
         ┌─────────────────────────────────────────────────────────────┐
         │  ENVIRONNEMENT BEEWAF:                                      │
         │                                                              │
         │  BACKEND_URL = "http://idts-back.idts-test.svc.cluster.local:80"│
         │  BACKEND_MAP = {                                            │
         │    "dev.idts.dpc.com.tn": "http://idts-front-service..."   │
         │  }                                                          │
         └─────────────────────────────────────────────────────────────┘
                                      │
                    ┌─────────────────┴─────────────────┐
                    │                                   │
                    ▼                                   ▼
         ┌──────────────────┐              ┌──────────────────┐
         │   IDTS FRONTEND  │              │   IDTS BACKEND   │
         │   (Angular)      │              │   (Spring Boot)  │
         │                  │              │                  │
         │ Namespace:       │              │ Namespace:       │
         │ idts-test        │              │ idts-test        │
         │                  │              │                  │
         │ Service:         │              │ Service:         │
         │ idts-front-service│             │ idts-back        │
         │ Port: 80         │              │ Port: 80         │
         │                  │              │                  │
         │ Deployment:      │              │ Deployment:      │
         │ idts-front-      │              │ idts-back-5c7c...│
         │ deployment       │              │                  │
         └──────────────────┘              └──────────────────┘
```

---

## 🔧 Comment ça marche ?

### 1. Flux d'une requête utilisateur

```
1. Utilisateur tape: https://dev.idts.dpc.com.tn
   │
   ▼
2. HAProxy (207.180.211.157) reçoit la requête
   │
   ▼
3. Ingress Controller (nginx) analyse le Host: dev.idts.dpc.com.tn
   │
   ▼
4. Ingress YAML dirige vers: beewaf-svc (namespace: beewaf)
   │
   ▼
5. BeeWAF analyse la requête:
   - Vérifie les attaques (SQLi, XSS, etc.)
   - Si bloqué → retourne {"blocked": true, "reason": "..."}
   - Si OK → continue
   │
   ▼
6. BeeWAF lit BACKEND_MAP:
   - Host "dev.idts.dpc.com.tn" → http://idts-front-service.idts-test.svc.cluster.local:80
   │
   ▼
7. BeeWAF forward la requête vers IDTS Frontend (Angular)
   │
   ▼
8. IDTS Frontend répond → BeeWAF → Utilisateur
```

### 2. Configuration BeeWAF (Deployment)

```yaml
# Extrait du deployment BeeWAF
env:
  # Backend par défaut (si pas dans BACKEND_MAP)
  - name: BACKEND_URL
    value: "http://idts-back.idts-test.svc.cluster.local:80"
  
  # Mapping Host → Backend
  - name: BACKEND_MAP
    value: '{"dev.idts.dpc.com.tn": "http://idts-front-service.idts-test.svc.cluster.local:80"}'
```

**Explication:**
- `BACKEND_URL`: Le backend par défaut (API Spring Boot)
- `BACKEND_MAP`: Dictionnaire qui mappe les Hosts aux backends
  - `dev.idts.dpc.com.tn` → Frontend Angular
  - Les autres requêtes → Backend Spring Boot (par défaut)

---

## 📁 Fichiers Kubernetes impliqués

### Namespace: beewaf
```bash
kubectl get all -n beewaf
```

| Ressource | Nom | Description |
|-----------|-----|-------------|
| Deployment | beewaf | Le WAF (1 pod) |
| Service | beewaf-svc | Service ClusterIP port 80 → 8000 |
| Ingress | beewaf-protects-dev-idts | Route dev.idts.dpc.com.tn → beewaf-svc |
| Ingress | beewaf-protected-idts | Route secure.idts.dpc.com.tn → beewaf-svc |
| Ingress | idts-back-via-waf | Route idts.back.dpc.com.tn → beewaf-svc |

### Namespace: idts-test
```bash
kubectl get all -n idts-test
```

| Ressource | Nom | Description |
|-----------|-----|-------------|
| Deployment | idts-front-deployment | Frontend Angular |
| Deployment | idts-back-5c7c6b8c57 | Backend Spring Boot |
| Service | idts-front-service | Service pour le frontend |
| Service | idts-back | Service pour le backend |

---

## 🔍 Commandes pour comprendre

### Voir la configuration BeeWAF
```bash
# Sur le Master
kubectl get deployment beewaf -n beewaf -o yaml | grep -A20 "env:"

# Voir les variables d'environnement
kubectl exec -n beewaf deployment/beewaf -- env | grep -E "BACKEND|URL"
```

### Voir les Ingress
```bash
# Lister les Ingress
kubectl get ingress -n beewaf

# Voir le détail d'un Ingress
kubectl describe ingress beewaf-protects-dev-idts -n beewaf
```

### Voir les services IDTS
```bash
# Services dans idts-test
kubectl get svc -n idts-test

# Pods dans idts-test
kubectl get pods -n idts-test
```

### Tester le flux
```bash
# Depuis l'intérieur du cluster
kubectl exec -n beewaf deployment/beewaf -- curl -s http://idts-front-service.idts-test.svc.cluster.local:80
kubectl exec -n beewaf deployment/beewaf -- curl -s http://idts-back.idts-test.svc.cluster.local:80
```

---

## 📊 Résumé des URLs

| URL | Ingress | Cible BeeWAF | Backend final |
|-----|---------|--------------|---------------|
| dev.idts.dpc.com.tn | beewaf-protects-dev-idts | beewaf-svc:80 | IDTS Frontend (Angular) |
| secure.idts.dpc.com.tn | beewaf-protected-idts | beewaf-svc:80 | IDTS Backend (Spring Boot) |
| idts.back.dpc.com.tn | idts-back-via-waf | beewaf-svc:80 | IDTS Backend (Spring Boot) |

---

## 🔄 Comment BeeWAF route les requêtes

```python
# Logique simplifiée dans app/main.py

def get_backend_url(request):
    host = request.headers.get("host", "")
    
    # 1. Vérifier BACKEND_MAP
    backend_map = json.loads(os.getenv("BACKEND_MAP", "{}"))
    if host in backend_map:
        return backend_map[host]
    
    # 2. Utiliser BACKEND_URL par défaut
    return os.getenv("BACKEND_URL", "http://localhost:8080")
```

**Exemple:**
- Requête vers `dev.idts.dpc.com.tn` → BeeWAF route vers `idts-front-service`
- Requête vers `secure.idts.dpc.com.tn` → BeeWAF route vers `idts-back` (défaut)

---

## 🛠️ Comment modifier le déploiement

### Ajouter un nouveau backend
```bash
# Éditer le deployment
kubectl edit deployment beewaf -n beewaf

# Modifier BACKEND_MAP:
# {"dev.idts.dpc.com.tn": "http://idts-front...", "nouveau.dpc.com.tn": "http://nouveau-service..."}
```

### Redémarrer BeeWAF
```bash
kubectl rollout restart deployment/beewaf -n beewaf
kubectl rollout status deployment/beewaf -n beewaf
```

### Voir les logs
```bash
kubectl logs -f deployment/beewaf -n beewaf
```

---

## 📋 Checklist de déploiement

1. ✅ Namespace `beewaf` créé
2. ✅ Secret `beewaf-secrets` créé (API key)
3. ✅ Image `beewaf:latest` importée dans containerd
4. ✅ Deployment `beewaf` déployé
5. ✅ Service `beewaf-svc` créé
6. ✅ Ingress créés pour chaque domaine
7. ✅ Certificats TLS générés (cert-manager)
8. ✅ IDTS déployé dans namespace `idts-test`
