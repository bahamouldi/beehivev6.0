# 🐝 BeeWAF v7.0 — Description Détaillée du Projet

## Vue d'Ensemble

**BeeWAF** (Bee Web Application Firewall) est un pare-feu applicatif web (WAF) de niveau entreprise, conçu et développé entièrement from-scratch en Python avec FastAPI. Il offre une protection multi-couche combinant **9990+ règles regex**, un **moteur ML à 3 modèles ensemble** (IsolationForest + RandomForest + GradientBoosting), et **27 modules de sécurité** couvrant l'ensemble du spectre des menaces web modernes.

Le projet a été développé dans le cadre d'un PFE (Projet de Fin d'Études) et est déployé en production sur un cluster Kubernetes pour protéger l'application IDTS (Integrated Data Tracking System).

---

## 🏗️ Architecture Technique

### Stack Technologique

| Composant | Technologie |
|---|---|
| **Langage** | Python 3.11 |
| **Framework Web** | FastAPI + Uvicorn (ASGI) |
| **Machine Learning** | scikit-learn (IsolationForest, RandomForest, GradientBoosting) |
| **Conteneurisation** | Docker (python:3.11-slim) |
| **Orchestration** | Kubernetes (3 masters + 2 workers) |
| **Reverse Proxy** | HAProxy (frontend) + Nginx Ingress (K8s) |
| **Monitoring** | ELK Stack (Elasticsearch, Logstash, Kibana, Filebeat) |
| **CI/CD** | Jenkins + ArgoCD |
| **Image finale** | ~272 MB compressée |

### Flux de Traitement des Requêtes

```
Client → HAProxy (TLS) → Nginx Ingress → BeeWAF Pod → Backend App
                                              │
                                              ├─ 1. Vérification IP Blacklist
                                              ├─ 2. Rate Limiting
                                              ├─ 3. Normalisation du chemin
                                              ├─ 4. Validation des en-têtes
                                              ├─ 5. Vérification logique métier
                                              ├─ 6. 27 Modules Entreprise
                                              ├─ 7. 9990 Règles Regex
                                              ├─ 8. Moteur ML (3 modèles)
                                              ├─ 9. Détection Zero-Day
                                              ├─ 10. Apprentissage Adaptatif
                                              ├─ 11. Corrélation d'Événements
                                              ├─ 12. DLP (réponse)
                                              ├─ 13. Masquage des en-têtes
                                              └─ 14. Sécurité des cookies
```

---

## 🧠 Moteur Machine Learning

### Architecture Ensemble (3 Modèles)

Le moteur ML utilise une approche **ensemble pondéré** combinant 3 modèles pour une détection robuste :

| Modèle | Poids | Rôle | Précision |
|---|---|---|---|
| **IsolationForest** | 0% (désactivé) | Détection d'anomalies non supervisée | 77% |
| **RandomForest** | 45% | Classification supervisée | ~93% |
| **GradientBoosting** | 55% | Classification supervisée haute précision | 95.2% |

### Extraction de Features (35 caractéristiques)

Le `FeatureExtractor` analyse chaque requête et extrait 35 features :

1. **Features textuelles :** longueur du payload, ratio de caractères spéciaux, entropie
2. **Features structurelles :** nombre de mots-clés SQL/XSS/CMDI, profondeur de path, nombre de paramètres
3. **Features encodage :** ratio URL-encoding, présence de double-encoding, null bytes
4. **Features comportementales :** combinaisons suspectes de patterns

### Métriques d'Entraînement

| Métrique | Valeur |
|---|---|
| **Dataset** | CSIC 2010 HTTP (61,065 échantillons) |
| **Split** | 80% training / 20% test |
| **Accuracy ensemble** | 94.29% |
| **Precision** | 97.47% |
| **Recall** | 88.39% |
| **F1-Score** | 92.71% |
| **ROC AUC** | 99.35% |
| **Seuil de détection** | 0.65 |

### Filtre Anti Faux-Positifs

La fonction `_is_obviously_safe()` pré-filtre les requêtes clairement légitimes avant l'analyse ML :
- Requêtes JSON simples sans mots-clés d'attaque
- Requêtes form-urlencoded courtes
- Vérification de 40+ mots-clés d'attaque avec contexte de frontières de mots
- Analyse des patterns SQL dans leur contexte (SELECT dans une phrase vs. dans une requête)

---

## 🛡️ Les 27 Modules de Sécurité

### Module 1 : Rules Engine (9990 Règles Regex)

**Fichiers :** `waf/rules.py`, `rules_extended.py`, `rules_advanced.py`, `rules_v5.py`, `rules_mega_1.py` → `rules_mega_12.py`

9990 expressions régulières compilées couvrant :

| Catégorie | Nombre de règles | Exemples |
|---|---|---|
| SQL Injection | ~2000+ | `UNION SELECT`, `' OR 1=1`, `WAITFOR DELAY`, stacked queries |
| Cross-Site Scripting (XSS) | ~1500+ | `<script>`, event handlers, SVG, javascript:, encodages |
| Command Injection | ~800+ | `; cat`, `$(cmd)`, backticks, pipes |
| Path Traversal / LFI | ~500+ | `../`, `php://filter`, `/etc/passwd`, Windows paths |
| SSRF | ~300+ | metadata endpoints, internal IPs, localhost |
| XXE | ~200+ | `<!ENTITY`, DTD injection, XML bombs |
| JNDI / Log4Shell | ~100+ | `${jndi:ldap}`, variantes obfusquées |
| NoSQL Injection | ~100+ | `$gt`, `$ne`, `$regex`, MongoDB operators |
| LDAP Injection | ~50+ | `)(`, `*))`, filter manipulation |
| SSTI | ~100+ | `{{7*7}}`, Jinja2, Twig, Freemarker |
| Deserialization | ~100+ | PHP `O:`, Python pickle, Java ObjectInputStream |
| Prototype Pollution | ~50+ | `__proto__`, `constructor.prototype` |
| GraphQL | ~50+ | `__schema`, introspection queries |
| JWT Bypass | ~30+ | `alg:none`, `kid` manipulation |
| File Upload | ~100+ | double extensions, MIME manipulation |
| Shellshock | ~20+ | `() { :; };` variantes |
| Spring4Shell | ~20+ | `class.module.classLoader` |
| PHP Injection | ~200+ | `eval()`, `system()`, `passthru()` |
| Python Injection | ~100+ | `__import__`, `exec()`, `eval()` |
| Hex Encoding | ~50+ | `0x` encoded payloads |

**Fonctionnalités avancées :**
- Règles haute sévérité avec blocage automatique
- Allowlist pour patterns légitimes
- Pré-filtre pour requêtes safe (JSON, formulaires courts)
- Filtre anti faux-positifs pour timezones, GraphQL, expressions mathématiques

---

### Module 2 : Rate Limiter + IP Blacklist

**Fichier :** `waf/ratelimit.py`

| Fonctionnalité | Configuration |
|---|---|
| Fenêtre de temps | 60 secondes |
| Maximum requêtes/fenêtre | 100 (configurable via `BEEWAF_RATE_LIMIT_MAX`) |
| Seuil de blacklist | 10 infractions |
| Durée du ban | 3600 secondes (1 heure) |
| Expiration auto | Oui (nettoyage périodique) |

**Mécanisme :**
1. Chaque requête incrémente un compteur par IP
2. Au-delà du seuil, la requête est rejetée (HTTP 429)
3. Les requêtes malveillantes détectées incrémentent le compteur d'infractions
4. Après 10 infractions, l'IP est automatiquement blacklistée
5. Le blacklist expire automatiquement après 1 heure

---

### Module 3 : Bot Detector

**Fichier :** `waf/bot_detector.py`

Détection des bots et scanners automatisés via :

- **Signatures connues :** sqlmap, Nikto, Nessus, Acunetix, Burp Suite, OWASP ZAP, w3af, DirBuster, Gobuster, etc.
- **Scoring comportemental :** fréquence de requêtes, patterns de navigation, ratio de pages vs. ressources
- **Analyse User-Agent :** validation de cohérence
- **Fingerprinting :** TLS fingerprint, caractéristiques HTTP

---

### Module 4 : DLP (Data Loss Prevention)

**Fichier :** `waf/dlp.py`

Analyse des **réponses** sortantes pour détecter les fuites de données sensibles :

| Type de donnée | Pattern détecté |
|---|---|
| Numéros de carte bancaire | Visa, MasterCard, AMEX (avec validation Luhn) |
| Numéros de sécurité sociale | Format US (XXX-XX-XXXX) |
| Adresses email | Patterns RFC 5322 |
| Clés API | AWS, Google Cloud, Azure, tokens Bearer |
| Mots de passe en clair | Patterns `password=`, `passwd:` dans les réponses |
| Données médicales | Numéros de dossier médical |

---

### Module 5 : Geo Blocking

**Fichier :** `waf/geo_block.py`

Blocage géographique basé sur l'IP :
- Résolution GeoIP (MaxMind GeoLite2 ou similaire)
- Listes blanches/noires par pays
- Mode strict (n'autoriser que certains pays)
- Logging des tentatives bloquées avec pays d'origine

---

### Module 6 : Protocol Validator

**Fichier :** `waf/protocol_validator.py`

Validation stricte du protocole HTTP :

| Vérification | Description |
|---|---|
| HTTP Request Smuggling | Détection de `Transfer-Encoding: chunked` malformé |
| Double Content-Length | Blocage des en-têtes `Content-Length` dupliqués |
| Méthodes HTTP | Validation des méthodes autorisées |
| Taille des en-têtes | Limite sur la taille totale des headers |
| Encoding invalide | Détection de chunks malformés |
| HTTP version | Validation de la version du protocole |

---

### Module 7 : API Security

**Fichier :** `waf/api_security.py`

Protection spécifique aux APIs REST/GraphQL :
- Validation de schéma JSON
- Protection contre le mass assignment
- Limitation de profondeur de query GraphQL
- Protection contre les requêtes GraphQL excessivement complexes
- Validation CORS
- Rate limiting par endpoint API

---

### Module 8 : Threat Intelligence

**Fichier :** `waf/threat_intel.py`

Intégration de renseignement sur les menaces :
- Base de données d'IPs malveillantes
- Vérification contre les listes TOR exit nodes
- Détection de proxies anonymes connus
- Scoring de réputation d'IP
- Mise à jour périodique des listes

---

### Module 9 : Session Protection

**Fichier :** `waf/session_protection.py`

Protection des sessions utilisateur :
- Détection de session fixation
- Validation de tokens de session
- Protection contre le session hijacking
- Binding de session à l'IP/User-Agent
- Rotation automatique des identifiants de session

---

### Module 10 : DDoS Protection

**Fichier :** `waf/ddos_protection.py`

Protection contre les attaques par déni de service :

| Type d'attaque | Protection |
|---|---|
| HTTP Flood | Rate limiting adaptatif |
| Slowloris | Détection de connexions lentes |
| Slow POST | Timeout sur le corps de la requête |
| Application-layer DDoS | Scoring comportemental |
| Challenge-response | CAPTCHA/JS challenge en cas de suspicion |

---

### Module 11 : Evasion Detector

**Fichier :** `waf/evasion_detector.py`

**18 couches de déobfuscation** pour contrer les techniques d'évasion :

1. Double URL decoding
2. Unicode normalization (NFC, NFD, NFKC, NFKD)
3. HTML entity decoding
4. Hex decoding
5. Octal decoding
6. UTF-8 overlong detection
7. Null byte removal
8. Whitespace normalization
9. Case normalization
10. Comment removal (SQL, JavaScript)
11. String concatenation resolution
12. Character encoding detection
13. Mixed encoding detection
14. Zero-width character removal
15. Homoglyph detection
16. Right-to-left override detection
17. Combining character removal
18. Alternative representation detection

---

### Module 12 : Correlation Engine

**Fichier :** `waf/correlation_engine.py`

Moteur de corrélation d'événements pour détecter les **kill chains** :
- Corrélation temporelle (même IP, fenêtre de temps)
- Détection de patterns d'attaque multi-étapes :
  - Reconnaissance → Exploitation → Exfiltration
  - Scanner → SQLi → Data dump
- Scoring de menace cumulatif
- Alertes sur les séquences suspectes

---

### Module 13 : Adaptive Learning

**Fichier :** `waf/adaptive_learning.py`

Apprentissage adaptatif en temps réel :
- Profiling du trafic normal de l'application
- Détection d'anomalies statistiques (déviation du baseline)
- Auto-ajustement des seuils de détection
- Apprentissage des patterns de trafic légitime

---

### Module 14 : Response Cloaking

**Fichier :** `waf/response_cloaking.py`

Masquage des informations dans les réponses :

| Action | Description |
|---|---|
| Suppression Server header | Masque le serveur web (nginx, Apache, etc.) |
| Suppression X-Powered-By | Masque la technologie backend |
| Ajout Security Headers | 10+ en-têtes de sécurité |
| Masquage stack traces | Supprime les traces d'erreur détaillées |
| Normalisation des erreurs | Messages d'erreur génériques |

**En-têtes de sécurité ajoutés :**
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: geolocation=(), camera=(), microphone=()`
- `X-Permitted-Cross-Domain-Policies: none`
- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Resource-Policy: same-origin`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`

---

### Module 15 : Cookie Security

**Fichier :** `waf/cookie_security.py`

Sécurisation des cookies :
- Analyse des cookies entrants pour injections (XSS, SQLi)
- Ajout des flags `Secure`, `HttpOnly`, `SameSite=Strict`
- Validation de la taille des cookies
- Détection de cookie tampering

---

### Module 16 : Virtual Patching

**Fichier :** `waf/virtual_patching.py`

**80+ CVE** patchés virtuellement :

| CVE | Vulnérabilité |
|---|---|
| CVE-2021-44228 | Log4Shell (Apache Log4j) |
| CVE-2022-22965 | Spring4Shell (Spring Framework) |
| CVE-2014-6271 | Shellshock (Bash) |
| CVE-2021-26855 | ProxyLogon (Exchange) |
| CVE-2023-34362 | MOVEit Transfer |
| CVE-2021-34527 | PrintNightmare |
| CVE-2021-21972 | VMware vCenter |
| *... et 73+ autres* | |

---

### Module 17 : Zero-Day Detector

**Fichier :** `waf/zero_day_detector.py`

Détection heuristique de vulnérabilités inconnues :
- Analyse entropique des payloads
- Détection de patterns d'exploitation génériques
- Scoring de suspicion basé sur les caractéristiques de la requête
- Corrélation avec les patterns connus pour identifier les variantes

---

### Module 18 : WebSocket Inspector

**Fichier :** `waf/websocket_inspector.py`

Inspection du trafic WebSocket :
- Validation des frames WebSocket
- Analyse du contenu des messages
- Détection d'injections dans les messages WebSocket
- Rate limiting par connexion WebSocket

---

### Module 19 : Payload Analyzer

**Fichier :** `waf/payload_analyzer.py`

Analyse approfondie des payloads :
- Détection de types de contenu incohérents
- Analyse de la structure des données (JSON, XML, formulaires)
- Détection de payloads malveillants imbriqués
- Analyse de la complexité des requêtes

---

### Module 20 : Compliance Engine

**Fichier :** `waf/compliance_engine.py`, `waf/compliance_engine_v5.py`

Conformité à **7 frameworks réglementaires** :

| Framework | Description |
|---|---|
| **OWASP Top 10** | Protection contre les 10 risques web majeurs |
| **PCI DSS** | Norme de sécurité des données de cartes de paiement |
| **GDPR** | Règlement général sur la protection des données (EU) |
| **HIPAA** | Health Insurance Portability and Accountability Act |
| **SOC 2** | Service Organization Control 2 |
| **ISO 27001** | Norme internationale de sécurité de l'information |
| **NIST 800-53** | Contrôles de sécurité NIST |

---

### Module 21 : Bot Manager Advanced

**Fichier :** `waf/bot_manager_advanced.py`

Gestion avancée des bots :
- Classification des bots (bon/mauvais/inconnu)
- Challenge JavaScript pour les bots suspectés
- Rate limiting spécifique aux bots
- Whitelist pour les bots légitimes (Googlebot, Bingbot)
- Fingerprinting avancé (TLS, HTTP/2, comportemental)

---

### Module 22 : API Discovery

**Fichier :** `waf/api_discovery.py`

Découverte automatique des endpoints API :
- Mapping des endpoints en temps réel
- Détection des endpoints non documentés
- Analyse des patterns d'utilisation des API
- Détection d'endpoints shadow/zombie

---

### Module 23 : Threat Feed

**Fichier :** `waf/threat_feed.py`

Flux de renseignement sur les menaces :
- Intégration de feeds IoC (Indicators of Compromise)
- Mise à jour automatique des listes d'IPs malveillantes
- Corrélation avec les campagnes d'attaque connues
- Scoring de menace basé sur des sources multiples

---

### Module 24 : Cluster Manager

**Fichier :** `waf/cluster_manager.py`

Gestion en cluster pour les déploiements multi-instances :
- Synchronisation des règles entre les nœuds
- Partage de l'état (IPs blacklistées, compteurs rate limit)
- Health checks inter-nœuds
- Failover automatique

---

### Module 25 : Performance Engine

**Fichier :** `waf/performance_engine.py`

Optimisation des performances :
- Cache des résultats de règles compilées
- Short-circuit pour les requêtes clairement safe
- Profiling des règles les plus coûteuses
- Métriques de latence par module

---

### Module 26 : ClamAV Scanner

**Fichier :** `waf/clamav_scanner.py`

Intégration avec ClamAV pour la détection de malware :
- Scan des fichiers uploadés
- Détection de virus/malware dans les payloads
- Quarantaine automatique des fichiers infectés
- Mise à jour des signatures via freshclam

---

### Module 27 : Sensitive Path Protection

**Intégré dans :** `app/main.py`

Protection des chemins sensibles (120+ patterns) :

| Catégorie | Exemples |
|---|---|
| Configuration | `.env`, `.htaccess`, `web.config` |
| Contrôle de version | `.git/`, `.svn/`, `.hg/` |
| Administration | `/admin`, `/wp-admin`, `/phpmyadmin` |
| Debugging | `/debug`, `/phpinfo`, `/server-status` |
| API documentation | `/swagger`, `/api-docs`, `/graphql` |
| Spring Boot | `/actuator/*`, `/jolokia`, `/heapdump` |
| Infrastructure | `/consul`, `/etcd`, `/kubernetes` |

---

## 🔧 Prérequis et Configuration

### Prérequis Système

| Composant | Minimum | Recommandé |
|---|---|---|
| **CPU** | 1 vCPU | 2 vCPU |
| **RAM** | 1 GB | 2 GB |
| **Disque** | 500 MB | 2 GB (avec logs ELK) |
| **Python** | 3.9+ | 3.11 |
| **OS** | Linux (Ubuntu 22.04+) | Ubuntu 22.04 LTS |

### Prérequis Logiciels

| Logiciel | Version | Usage |
|---|---|---|
| **Docker** | 20.10+ | Conteneurisation |
| **Kubernetes** | 1.25+ | Orchestration |
| **containerd** | 1.6+ | Runtime de conteneurs |
| **HAProxy** | 2.4+ | Load balancer / TLS termination |
| **Nginx Ingress** | 1.5+ | Ingress controller K8s |
| **kubectl** | 1.25+ | Gestion du cluster |

### Prérequis Python (requirements.txt)

```
fastapi>=0.100.0
uvicorn[standard]>=0.22.0
httpx>=0.24.0
scikit-learn>=1.3.0
pandas>=2.0.0
numpy>=1.24.0
joblib>=1.3.0
python-multipart>=0.0.6
pyyaml>=6.0
```

### Variables d'Environnement

| Variable | Défaut | Description |
|---|---|---|
| `BACKEND_URL` | — | URL du backend (mode reverse proxy) |
| `BACKEND_MAP` | — | Map JSON host→backend (multi-backend) |
| `BEEWAF_API_KEY` | — | Clé API pour les endpoints admin |
| `BEEWAF_MODEL_PATH` | `models/model.pkl` | Chemin du modèle ML legacy |
| `BEEWAF_ML_ENGINE_PATH` | `models/ml_engine.pkl` | Chemin du modèle ML ensemble |
| `BEEWAF_ML_MODE` | `advanced` | Mode ML (`legacy` ou `advanced`) |
| `BEEWAF_RATE_LIMIT_MAX` | `100` | Max requêtes par fenêtre |
| `BEEWAF_ALLOWED_HOSTS` | — | Hosts autorisés (séparés par virgules) |
| `BEEWAF_BLOCKED_COUNTRIES` | — | Pays bloqués (codes ISO) |
| `BEEWAF_CLAMAV_HOST` | `localhost` | Hôte ClamAV |

---

## 🚀 Déploiement

### Développement Local

```bash
# Créer l'environnement virtuel
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Entraîner les modèles ML
python train_ml_models.py --data data/csic_database.csv --save models/ml_engine.pkl

# Lancer le serveur
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Docker

```bash
# Build avec entraînement ML intégré
docker build -f Dockerfile.k8s -t beewaf:sklearn .

# Run standalone
docker run -p 8000:8000 -e BACKEND_URL=http://backend:8080 beewaf:sklearn

# Run avec ELK Stack
docker-compose -f docker-compose-elk.yaml up -d
```

### Kubernetes

```bash
# Charger l'image sur le nœud cible
docker save beewaf:sklearn | gzip > beewaf-sklearn.tar.gz
# Transférer et importer sur le nœud K8s
ctr -n k8s.io images import beewaf-sklearn.tar

# Déployer
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml

# Vérifier
kubectl get pods -n beewaf
kubectl logs -n beewaf deployment/beewaf-deployment
```

### CI/CD (Jenkins + ArgoCD)

```
Pipeline Jenkins :
1. Checkout du code source
2. Exécution des tests unitaires (pytest)
3. Build de l'image Docker (avec entraînement ML)
4. Push vers le registre Docker
5. Mise à jour du manifeste K8s
6. ArgoCD synchronise automatiquement le déploiement
```

---

## 📊 Monitoring et Logging

### ELK Stack

- **Elasticsearch :** Stockage des logs WAF
- **Logstash :** Pipeline d'ingestion avec parsing des événements
- **Kibana :** Dashboards de visualisation :
  - Requêtes bloquées par catégorie
  - Top IPs attaquantes
  - Score ML moyen
  - Taux de faux positifs
  - Tendances temporelles

### Format des Logs

```json
{
  "timestamp": "2026-03-02T23:30:15Z",
  "client_ip": "192.168.1.100",
  "method": "POST",
  "path": "/api/login",
  "status": "blocked",
  "reason": "regex-sqli",
  "ml_score": 0.988,
  "payload_preview": "' OR 1=1--",
  "user_agent": "sqlmap/1.7",
  "response_code": 403,
  "processing_time_ms": 12
}
```

---

## 🧪 Tests

### Tests Unitaires

```bash
pytest -v                           # Tous les tests
pytest tests/test_admin_rules.py -v # Tests des règles admin
pytest tests/test_rate_limit.py -v  # Tests du rate limiter
```

### Tests d'Intégration

```bash
./tests/test_waf.sh                 # Tests WAF complets
python tests/run_tests.py           # Tests d'attaques manuels
```

### Tests de Performance

```bash
python mega_test_10k.py             # 10,000 requêtes de test
python generate_kibana_traffic.py   # Génération de trafic pour Kibana
```

---

## 📈 Résultats de Tests (Production)

| Métrique | Valeur |
|---|---|
| **Taux de détection global** | 96% |
| **Faux positifs** | 0% |
| **Catégories d'attaques testées** | 28 |
| **Total tests exécutés** | 85+ |
| **Attaques OWASP Top 10** | 100% détectées |
| **Score ML moyen (attaques)** | >0.96 |
| **Latence ajoutée** | <15 ms |
| **Temps de réponse p99** | <50 ms |

---

## 📜 Licence et Auteurs

**Projet :** BeeWAF v7.0  
**Type :** Projet de Fin d'Études (PFE)  
**Année :** 2024-2026  
**Technologie :** Python / FastAPI / scikit-learn / Kubernetes

---

*BeeWAF — Protection intelligente pour applications web modernes* 🐝🛡️
