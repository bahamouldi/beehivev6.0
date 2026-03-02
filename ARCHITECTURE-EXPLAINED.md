# BeeWAF + IDTS — Architecture Expliquée

## 📊 Vue d'ensemble complète

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ARCHITECTURE COMPLÈTE BEEWAF + IDTS                       │
└─────────────────────────────────────────────────────────────────────────────┘

                              ┌─────────────────┐
                              │   Utilisateur   │
                              │   (Navigateur)  │
                              └────────┬────────┘
                                       │ https://dev.idts.dpc.com.tn
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
                                       │ Host: dev.idts.dpc.com.tn
                                       ▼
                         ┌─────────────────────────────┐
                         │    INGRESS: beewaf-protects │
                         │    -dev-idts                │
                         │                             │
                         │  Host: dev.idts.dpc.com.tn  │
                         │  → Service: beewaf-svc:80   │
                         │  → TLS: beewaf-dev-idts-tls │
                         └─────────────┬───────────────┘
                                       │
                                       ▼
                         ┌─────────────────────────────┐
                         │         BEEWAF              │
                         │   (WAF - Web Application    │
                         │    Firewall)                │
                         │                             │
                         │   Pod: beewaf-77df9d57cb... │
                         │   Port: 8000                │
         ┌─────────────────────────────────────────────────────────────┐
         │  VARIABLES D'ENVIRONNEMENT:                                │
         │                                                              │
         │  BACKEND_URL = "http://idts-back.idts-test.svc.cluster.local:80"│
         │  BACKEND_MAP = {                                            │
         │    "dev.idts.dpc.com.tn":                                   │
         │       "http://idts-front-service.idts-test.svc.cluster.local:80"│
         │  }                                                          │
         └─────────────────────────────────────────────────────────────┘
                                       │
                    ┌──────────────────┴──────────────────┐
                    │                                     │
                    │ Host = dev.idts.dpc.com.tn          │ Host = autre
                    │ → Route vers FRONTEND               │ → Route vers BACKEND
                    ▼                                     ▼
         ┌──────────────────┐              ┌──────────────────┐
         │   IDTS FRONTEND  │              │   IDTS BACKEND   │
         │   (Angular)      │              │   (Spring Boot)  │
         │                  │              │                  │
         │ Image: depot.dpc.com.tn:8443   │ Image: depot.dpc.com.tn:8443│
         │ /dev/idts-front-dev:V-0.0.15   │ /dev/idts-back-dev:V-0.0.40│
         │                  │              │                  │
         │ Namespace:       │              │ Namespace:       │
         │ idts-test        │              │ idts-test        │
         │                  │              │                  │
         │ Service:         │              │ Service:         │
         │ idts-front-service│             │ idts-back        │
         │ Port: 8000       │              │ Port: 8080       │
         │                  │              │                  │
         │ Endpoint:        │              │ Endpoint:        │
         │ 192.168.230.140  │              │ 192.168.230.143  │
         │                  │              │                  │
         │ Status: ✅ 200   │              │ Status: ⚠️ 404   │
         └──────────────────┘              └──────────────────┘
```

---

## 🔧 Explication détaillée

### 1. IDTS Frontend (Angular)

| Propriété | Valeur |
|-----------|--------|
| **Deployment** | `idts-front-deployment` |
| **Image** | `depot.dpc.com.tn:8443/dev/idts-front-dev:V-0.0.15` |
| **Port** | 8000 |
| **Service** | `idts-front-service` (LoadBalancer, port 80) |
| **Endpoint** | `192.168.230.140:8000` |
| **Namespace** | `idts-test` |

### 2. IDTS Backend (Spring Boot)

| Propriété | Valeur |
|-----------|--------|
| **Deployment** | `idts-back` |
| **Image** | `depot.dpc.com.tn:8443/dev/idts-back-dev:V-0.0.40` |
| **Port** | 8080 |
| **Service** | `idts-back` (LoadBalancer, port 80) |
| **Endpoint** | `192.168.230.143:8080` |
| **Namespace** | `idts-test` |

### 3. BeeWAF (WAF)

| Propriété | Valeur |
|-----------|--------|
| **Deployment** | `beewaf` |
| **Image** | `docker.io/library/beewaf:latest` |
| **Port** | 8000 |
| **Service** | `beewaf-svc` (ClusterIP, port 80) |
| **Namespace** | `beewaf` |

---

## 🔄 Comment le routing fonctionne

### Configuration BeeWAF

```yaml
# Variables d'environnement du pod BeeWAF
env:
  - name: BACKEND_URL
    value: "http://idts-back.idts-test.svc.cluster.local:80"
  
  - name: BACKEND_MAP
    value: '{"dev.idts.dpc.com.tn": "http://idts-front-service.idts-test.svc.cluster.local:80"}'
```

### Logique de routing

```python
# Pseudo-code du routing dans BeeWAF

def get_backend(request):
    host = request.headers.get("host")
    
    # Si le host est dans BACKEND_MAP
    if host == "dev.idts.dpc.com.tn":
        return "http://idts-front-service.idts-test.svc.cluster.local:80"
    
    # Sinon, utiliser BACKEND_URL par défaut
    return "http://idts-back.idts-test.svc.cluster.local:80"
```

### Flux d'une requête

```
1. Utilisateur tape: https://dev.idts.dpc.com.tn
   │
   ▼
2. HAProxy (207.180.211.157) reçoit la requête HTTPS
   │
   ▼
3. Ingress Controller (nginx) analyse le Host header
   │
   ▼
4. Ingress "beewaf-protects-dev-idts" match le host
   → Route vers beewaf-svc:80
   │
   ▼
5. BeeWAF reçoit la requête sur le port 8000
   │
   ├─ Analyse la requête (SQLi, XSS, etc.)
   ├─ Si attaque → Bloque et retourne {"blocked": true}
   ├─ Si OK → Continue
   │
   ▼
6. BeeWAF lit BACKEND_MAP:
   - Host "dev.idts.dpc.com.tn" → idts-front-service
   │
   ▼
7. BeeWAF forward vers IDTS Frontend (Angular)
   - URL: http://idts-front-service.idts-test.svc.cluster.local:80
   - Endpoint: 192.168.230.140:8000
   │
   ▼
8. Angular répond → BeeWAF → Utilisateur
```

---

## 📋 Tableau des URLs

| URL | Ingress | Service | Backend Final | Port |
|-----|---------|---------|---------------|------|
| `dev.idts.dpc.com.tn` | beewaf-protects-dev-idts | beewaf-svc | IDTS Frontend (Angular) | 8000 |
| `secure.idts.dpc.com.tn` | beewaf-protected-idts | beewaf-svc | IDTS Backend (Spring Boot) | 8080 |
| `idts.back.dpc.com.tn` | idts-back-via-waf | beewaf-svc | IDTS Backend (Spring Boot) | 8080 |

---

## 🐛 Problème détecté

**Backend retourne 404** quand on teste directement:
```bash
kubectl exec -n beewaf deployment/beewaf -- curl -s http://idts-back.idts-test.svc.cluster.local:80
# HTTP Status: 404
```

**Causes possibles:**
1. Le backend Spring Boot attend un path spécifique (ex: `/api/...`)
2. Le backend n'a pas de route sur `/`
3. Le service écoute sur le port 80 mais le pod écoute sur 8080

**Solution:**
```bash
# Tester avec un path API
kubectl exec -n beewaf deployment/beewaf -- curl -s http://idts-back.idts-test.svc.cluster.local:80/api/health

# Ou tester directement le pod sur le port 8080
kubectl exec -n beewaf deployment/beewaf -- curl -s http://192.168.230.143:8080/actuator/health
```

---

## 🛠️ Qui déploie quoi?

| Composant | Outil de déploiement | Qui gère |
|-----------|---------------------|----------|
| **IDTS Frontend** | ArgoCD | Équipe IDTS |
| **IDTS Backend** | ArgoCD | Équipe IDTS |
| **BeeWAF** | Manuel / ArgoCD | Équipe WAF |
| **Ingress** | ArgoCD / Manuel | Équipe DevOps |
| **ELK Stack** | Manuel | Équipe WAF |

**Preuve:**
```yaml
# Annotation ArgoCD sur IDTS Frontend
annotations:
  argocd.argoproj.io/tracking-id: idts-front-dev:apps/Deployment:idts-test/idts-front-deployment
```

---

## 📊 Résumé

```
┌─────────────────────────────────────────────────────────────────┐
│                    RÉSUMÉ ARCHITECTURE                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  dev.idts.dpc.com.tn                                            │
│  └─→ BeeWAF ─→ IDTS Frontend (Angular) ✅                       │
│                                                                 │
│  secure.idts.dpc.com.tn                                         │
│  └─→ BeeWAF ─→ IDTS Backend (Spring Boot)                       │
│                                                                 │
│  idts.back.dpc.com.tn                                           │
│  └─→ BeeWAF ─→ IDTS Backend (Spring Boot)                       │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│  Registry: depot.dpc.com.tn:8443                                │
│  Cluster: 3 masters + 2 workers (K8s v1.29.15)                  │
│  ArgoCD: Installé et actif                                      │
│  Jenkins: À installer                                           │
└─────────────────────────────────────────────────────────────────┘
```
