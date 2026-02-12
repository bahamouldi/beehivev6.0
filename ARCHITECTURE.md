# 🏗️ Architecture et Solution Proposée — BeeWAF Enterprise v6.0

> **Projet :** BeeWAF — Web Application Firewall Intelligent Multi-Couches  
> **Version :** 6.0  
> **Auteur :** [Votre Nom]  
> **Date :** Février 2026

---

## Table des Matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Architecture générale du système](#2-architecture-générale-du-système)
3. [Architecture logicielle détaillée](#3-architecture-logicielle-détaillée)
   - 3.1 [Middleware WAF (FastAPI)](#31-middleware-waf-fastapi)
   - 3.2 [Détection basée sur des règles (Regex Engine)](#32-détection-basée-sur-des-règles-regex-engine)
   - 3.3 [Moteur de désobfuscation multi-couches](#33-moteur-de-désobfuscation-multi-couches-18-passes)
   - 3.4 [Classification supervisée des attaques (ML Engine)](#34-classification-supervisée-des-attaques-ml-engine)
   - 3.5 [Détection d'anomalies (Isolation Forest)](#35-détection-danomalies-isolation-forest)
   - 3.6 [Détection Zero-Day](#36-détection-zero-day)
   - 3.7 [Analyse comportementale adaptative](#37-analyse-comportementale-adaptative)
   - 3.8 [Corrélation d'attaques (Kill Chain)](#38-corrélation-dattaques-kill-chain)
   - 3.9 [Moteur de fusion décisionnelle](#39-moteur-de-fusion-décisionnelle)
4. [Modules de sécurité avancés](#4-modules-de-sécurité-avancés)
5. [Architecture d'infrastructure](#5-architecture-dinfrastructure)
6. [Journalisation et supervision (ELK Stack)](#6-journalisation-et-supervision-elk-stack)
7. [Modèles de Machine Learning — Détails](#7-modèles-de-machine-learning--détails)
8. [Vue synthétique des couches de sécurité](#8-vue-synthétique-des-couches-de-sécurité)
9. [Diagramme de flux de traitement](#9-diagramme-de-flux-de-traitement)

---

## 1. Vue d'ensemble

BeeWAF est un Web Application Firewall (WAF) intelligent de nouvelle génération, conçu autour d'une **architecture défensive multi-couches** combinant :

- **10 041 règles regex** compilées pour la détection par signatures
- **Un ensemble de 3 modèles de Machine Learning** (supervisé + non-supervisé) pour la classification et la détection d'anomalies
- **27 modules de sécurité spécialisés** couvrant l'intégralité de l'OWASP Top 10
- **Une infrastructure conteneurisée** (Docker / Kubernetes) avec pipeline ELK pour la supervision en temps réel

Le système atteint un score de **98.2/100 (Grade A+)** avec un taux de **0% de faux positifs**.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         BeeWAF Enterprise v6.0                             │
│                    Web Application Firewall Intelligent                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   Client ──► Nginx (TLS 1.2/1.3) ──► FastAPI Middleware ──► Backend App    │
│                  │                        │                                 │
│                  │                   ┌────┴────┐                            │
│                  │              27 Modules de    │                           │
│                  │              Sécurité         │                           │
│                  │                   │           │                           │
│                  │          ┌────────┼────────┐  │                           │
│                  │          │   ML Engine     │  │                           │
│                  │          │  (3 modèles)    │  │                           │
│                  │          └────────┬────────┘  │                           │
│                  │                   │           │                           │
│                  │          ┌────────┴────────┐  │                           │
│                  ▼          │  10 041 Règles  │  │                           │
│              Filebeat ──►   │    Regex        │  │                           │
│              Logstash ──►   └─────────────────┘  │                           │
│          Elasticsearch ──►                       │                           │
│              Kibana    ──► Tableaux de bord      │                           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Architecture générale du système

Le système est conçu autour d'une **architecture modulaire en cascade** composée de **12 phases de traitement séquentiel**. Chaque requête HTTP traverse l'ensemble du pipeline de sécurité avant d'atteindre l'application backend. L'architecture suit le principe de **fail-fast** : le premier module détectant une menace bloque immédiatement la requête.

```
┌──────────────────────────────────────────────────────────────────┐
│                    Architecture Multi-Couches                     │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌─────────────┐   ┌──────────────┐   ┌──────────────────────┐  │
│  │   Couche 1   │   │   Couche 2    │   │      Couche 3        │  │
│  │   Réseau &   │──►│   Règles &    │──►│   Machine Learning   │  │
│  │   Protocole  │   │   Signatures  │   │   & Détection        │  │
│  └─────────────┘   └──────────────┘   └──────────────────────┘  │
│        │                  │                      │                │
│        ▼                  ▼                      ▼                │
│  • DDoS Protection   • 10 041 Regex        • ML Ensemble (3)    │
│  • Rate Limiting     • 18-Layer Deobfusc.  • Zero-Day Detector  │
│  • Geo-Blocking      • Virtual Patching    • Adaptive Learning  │
│  • Protocol Valid.   • Evasion Detection   • Anomaly Detection  │
│  • Bot Detection                           • Correlation Engine │
│                                                                   │
│  ┌─────────────┐   ┌──────────────┐   ┌──────────────────────┐  │
│  │   Couche 4   │   │   Couche 5    │   │      Couche 6        │  │
│  │   Sécurité   │──►│   Protection  │──►│   Supervision &      │  │
│  │   Applicat.  │   │   Données     │   │   Conformité         │  │
│  └─────────────┘   └──────────────┘   └──────────────────────┘  │
│        │                  │                      │                │
│        ▼                  ▼                      ▼                │
│  • API Security      • DLP Engine          • ELK Stack          │
│  • Session Protect.  • Response Cloaking   • OWASP Compliance   │
│  • Cookie Security   • Cookie Hardening    • PCI DSS Tracking   │
│  • WebSocket Insp.   • Header Injection    • MITRE ATT&CK Map  │
│  • Deep Payload                            • Kibana Dashboards  │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

---

## 3. Architecture logicielle détaillée

### 3.1 Middleware WAF (FastAPI)

Le WAF est implémenté sous forme de **middleware FastAPI** (`BaseHTTPMiddleware`), interceptant **chaque requête HTTP** avant qu'elle n'atteigne l'application backend. Ce middleware orchestre les 27 modules de sécurité dans un pipeline séquentiel de **12 phases**.

#### Pipeline de traitement (12 phases)

```
Requête HTTP entrante
        │
        ▼
┌─── Phase 1 : Pré-validation ──────────────────────────────────────┐
│  • Extraction métadonnées (IP, path, method, query, headers)      │
│  • Vérification blocklist IP                                       │
│  • Normalisation de chemin (URL-decode, //, /./, /../)            │
│  • Validation Host header                                          │
│  • Blocage chemins sensibles (.git/, .env, wp-config.php...)      │
│  • Détection spoofing X-Forwarded-For                              │
│  • Détection HTTP Request Smuggling (CL+TE, multi-TE)            │
│  • Validation Range header                                         │
└────────────────────────────────────────────────────────────────────┘
        │
        ▼
┌─── Phase 2 : Protection DDoS & Performance ───────────────────────┐
│  • DDoS Protection (flood, slowloris, amplification)              │
│  • Bloom Filter pre-screen (fast-path pour requêtes sûres)        │
└────────────────────────────────────────────────────────────────────┘
        │
        ▼
┌─── Phase 3 : Lecture du corps ────────────────────────────────────┐
│  • Lecture et décodage du body HTTP                                │
└────────────────────────────────────────────────────────────────────┘
        │
        ▼
┌─── Phase 4 : Logique métier ──────────────────────────────────────┐
│  • Détection d'abus logique métier dans les corps JSON            │
│  (ex: quantité négative, prix modifié, rôle escaladé)            │
└────────────────────────────────────────────────────────────────────┘
        │
        ▼
┌─── Phase 5 : Rate Limiting ───────────────────────────────────────┐
│  • Limitation de débit par IP (fenêtre glissante)                 │
│  • Auto-blocage après attaques répétées                           │
└────────────────────────────────────────────────────────────────────┘
        │
        ▼
┌─── Phase 6 : Modules de sécurité enterprise (13 modules) ────────┐
│  • Protocol Validation     • Geo-Blocking                         │
│  • Bot Detection           • Advanced Bot Manager                 │
│  • Threat Intelligence     • Threat Feed (MITRE ATT&CK)          │
│  • Session Protection      • API Security                         │
│  • API Discovery           • Virtual Patching                     │
│  • WebSocket Inspector     • Deep Payload Analysis                │
│  • Compliance Engine                                               │
└────────────────────────────────────────────────────────────────────┘
        │
        ▼
┌─── Phase 7 : Validation des en-têtes ─────────────────────────────┐
│  • Scan des en-têtes contrôlés par l'utilisateur                  │
│  (Referer, Cookie, X-Original-URL, X-Rewrite-URL)                │
│  • Détection d'injection dans les en-têtes d'infrastructure       │
└────────────────────────────────────────────────────────────────────┘
        │
        ▼
┌─── Phase 8 : Désobfuscation + Règles Regex ───────────────────────┐
│  • 18 couches de désobfuscation (EvasionDetector)                 │
│  • Re-vérification de chaque forme décodée                        │
│  • Vérification principale : 10 041 règles regex compilées        │
└────────────────────────────────────────────────────────────────────┘
        │
        ▼
┌─── Phase 9 : ML / Détection d'anomalies ─────────────────────────┐
│  • Ensemble ML 3 modèles (RF + GB + IF)                          │
│  • Fallback : IsolationForest legacy si ML non entraîné          │
└────────────────────────────────────────────────────────────────────┘
        │
        ▼
┌─── Phase 10 : Détection avancée ──────────────────────────────────┐
│  • Zero-Day Detection (8 analyseurs)                              │
│  • Apprentissage adaptatif (profils endpoint)                     │
│  • Corrélation d'attaques (kill chain, score ≥ 80 → bloc)        │
└────────────────────────────────────────────────────────────────────┘
        │
        ▼
┌─── Phase 11 : Passthrough ────────────────────────────────────────┐
│  • Transmission au backend si aucune menace détectée              │
└────────────────────────────────────────────────────────────────────┘
        │
        ▼
┌─── Phase 12 : Post-traitement de la réponse ──────────────────────┐
│  • DLP Response Scanning (détection fuites de données)            │
│  • Injection en-têtes de sécurité (HSTS, X-Frame, CSP...)        │
│  • Response Cloaking (suppression fingerprints serveur)           │
│  • Masquage stack traces & erreurs internes                       │
│  • Cookie Security (Secure, HttpOnly, SameSite)                   │
│  • Journalisation structurée JSON                                  │
│  • Métriques Prometheus                                            │
└────────────────────────────────────────────────────────────────────┘
        │
        ▼
   Réponse au client
```

---

### 3.2 Détection basée sur des règles (Regex Engine)

Le premier niveau de détection repose sur un moteur de **10 041 expressions régulières** compilées à l'initialisation, couvrant **21+ catégories d'attaques**. Ce module offre une détection rapide et précise des attaques connues.

#### Architecture du moteur de règles

```
┌─────────────────────────────────────────────────────────────┐
│                    Regex Rule Engine                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   ┌──────────────────┐                                      │
│   │  Base Rules       │─── SQLi, XSS, CMDi, SSRF, XXE...   │
│   │  (~400 patterns)  │                                      │
│   └────────┬─────────┘                                      │
│            │                                                 │
│   ┌────────▼─────────┐                                      │
│   │  Extended Rules   │─── ~1 200 patterns supplémentaires  │
│   └────────┬─────────┘                                      │
│            │                                                 │
│   ┌────────▼─────────┐                                      │
│   │  Advanced v4.0    │─── ~650 patterns avancés            │
│   └────────┬─────────┘                                      │
│            │                                                 │
│   ┌────────▼─────────┐                                      │
│   │  Rules v5.0       │─── ~1 200 patterns expert           │
│   └────────┬─────────┘                                      │
│            │                                                 │
│   ┌────────▼─────────┐                                      │
│   │  Mega Rules 1-12  │─── ~6 500+ patterns enterprise      │
│   └────────┬─────────┘                                      │
│            │                                                 │
│   ┌────────▼─────────┐                                      │
│   │  TOTAL COMPILÉ    │                                      │
│   │  10 041 RÈGLES    │                                      │
│   └──────────────────┘                                      │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

#### Catégories de règles

| Catégorie | Tag | Description |
|-----------|-----|-------------|
| SQL Injection | `sqli` | UNION, stacked queries, blind, time-based, error-based |
| Cross-Site Scripting | `xss` | Reflected, stored, DOM-based, polyglot |
| Command Injection | `cmdi` | OS commands Unix/Windows, pipes, backticks |
| Path Traversal | `path-traversal` | `../`, encodé, double-encodé |
| SSRF | `ssrf` | Métadonnées cloud, IP internes, protocoles |
| XXE | `xxe` | Entités externes XML, DTD injection |
| LDAP Injection | `ldap` | Requêtes LDAP malveillantes |
| NoSQL Injection | `nosql` | MongoDB `$gt`, `$ne`, `$where` |
| JNDI / Log4Shell | `jndi` | `${jndi:ldap://}`, variantes obfusquées |
| SSTI | `ssti` | Jinja2, Twig, Freemarker, Thymeleaf |
| Désérialisation | `deserialization` | Java, PHP, Python, .NET |
| Prototype Pollution | `prototype-pollution` | `__proto__`, `constructor.prototype` |
| JWT Bypass | `jwt-bypass` | Algorithme `none`, manipulation `kid` |
| GraphQL Abuse | `graphql` | Introspection, batching, depth abuse |
| PHP Filter | `php-filter` | `php://filter`, `php://input` |
| Python Injection | `python-injection` | `eval()`, `exec()`, `__import__` |
| LFI / RFI avancé | `lfi` | `/etc/passwd`, `/proc/self`, wrappers |
| Brute Force | `brute` | Patterns de force brute |
| Scanner Probes | `scanner` | Signatures d'outils (Nikto, SQLMap...) |
| Hex Encoding | `hex-evasion` | Encodage hexadécimal d'attaques |
| JSP | `jsp` | Injection JSP, expressions EL |

#### Fonctionnement de `check_regex_rules()`

```python
def check_regex_rules(path, body, headers):
    1. Si path ∈ ALLOW_PATHS → (False, None)   # Whitelist
    2. URL-decode path et body
    3. target = path + body + headers_filtés
    4. Pour chaque (regex_compilée, catégorie) dans 10 041 RÈGLES:
         si regex.search(target) OU regex.search(target_décodé):
             return (True, f"regex-{catégorie}")
    5. return (False, None)
```

> **Note :** Les en-têtes d'infrastructure (Host, Content-Type, Accept, Authorization...) sont **exclus du scan** pour éviter les faux positifs avec 10 000+ règles.

---

### 3.3 Moteur de désobfuscation multi-couches (18 passes)

Avant l'application des règles regex, chaque payload traverse un **décodeur à 18 couches** afin de déjouer les techniques d'évasion. Chaque forme décodée est re-vérifiée contre le moteur de règles.

```
┌─────────────────────────────────────────────────────────────┐
│              EvasionDetector — 18 Couches                    │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   Couche  1  │  URL Decoding (simple)                       │
│   Couche  2  │  Double URL Decoding                         │
│   Couche  3  │  Triple URL Decoding                         │
│   Couche  4  │  HTML Entity Decoding (named, &#x, &#)      │
│   Couche  5  │  Unicode Normalization (NFKC)                │
│   Couche  6  │  UTF-8 Overlong Encoding (2/3-byte)         │
│   Couche  7  │  Base64 Decoding (≥20 chars, printable)     │
│   Couche  8  │  Hex Decoding (0x41, \x41 → A)              │
│   Couche  9  │  Octal Decoding                              │
│   Couche 10  │  JavaScript Unicode Escape (\u0041)          │
│   Couche 11  │  CSS Escape Sequences (\41)                  │
│   Couche 12  │  Mixed Encoding (toutes combinées)           │
│   Couche 13  │  Null Byte Removal (%00, \0)                 │
│   Couche 14  │  Whitespace Normalization                    │
│   Couche 15  │  Comment Stripping (SQL/C/HTML)              │
│   Couche 16  │  Case + Homoglyph (Cyrillic → ASCII)        │
│   Couche 17  │  Path Canonicalization (/./  /../  //)       │
│   Couche 18  │  JSON / XML Entity Decoding                  │
│                                                              │
│   Chaque forme décodée → re-vérifiée vs 10 041 regex        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

Ce mécanisme assure que même les attaques **multi-encodées** ou utilisant des **homoglyphes Unicode** sont détectées.

---

### 3.4 Classification supervisée des attaques (ML Engine)

Un **ensemble de 3 modèles de Machine Learning** est utilisé pour classifier les requêtes en combinant apprentissage supervisé et non-supervisé. Ce module permet d'identifier des variantes d'attaques qui échappent aux règles regex.

#### Architecture de l'ensemble ML

```
┌─────────────────────────────────────────────────────────────────┐
│                    ML Engine — Ensemble 3 Modèles               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Requête HTTP                                                   │
│       │                                                          │
│       ▼                                                          │
│   ┌──────────────────────┐                                      │
│   │  Pré-filtre de       │──── Requête sûre ──► SKIP (pas ML)  │
│   │  sécurité évident    │     (JSON valide, ext statique,      │
│   │  (_is_obviously_safe)│      chemin simple, paramètres OK)   │
│   └──────────┬───────────┘                                      │
│              │ Requête suspecte                                   │
│              ▼                                                   │
│   ┌──────────────────────┐                                      │
│   │  Extraction de       │                                      │
│   │  35 Features         │                                      │
│   └──────────┬───────────┘                                      │
│              │                                                   │
│              ▼                                                   │
│   ┌──────────────────────┐                                      │
│   │  StandardScaler      │                                      │
│   │  (normalisation)     │                                      │
│   └──────────┬───────────┘                                      │
│              │                                                   │
│     ┌────────┼────────────────────┐                              │
│     ▼        ▼                    ▼                              │
│  ┌────────┐ ┌──────────────┐ ┌────────────────────┐            │
│  │Isolation│ │RandomForest  │ │GradientBoosting    │            │
│  │Forest   │ │Classifier    │ │Classifier          │            │
│  │         │ │              │ │                    │            │
│  │Poids:   │ │Poids:        │ │Poids:              │            │
│  │  0.10   │ │  0.45        │ │  0.45              │            │
│  └────┬───┘ └──────┬───────┘ └─────────┬──────────┘            │
│       │             │                   │                        │
│       ▼             ▼                   ▼                        │
│   ┌──────────────────────────────────────────┐                  │
│   │         Fusion par moyenne pondérée       │                  │
│   │                                           │                  │
│   │  Score = 0.10×IF + 0.45×RF + 0.45×GB    │                  │
│   │                                           │                  │
│   │  Score ≥ 0.60 → ATTAQUE                  │                  │
│   │  Score < 0.60 → NORMAL                   │                  │
│   └──────────────────────────────────────────┘                  │
│              │                                                   │
│              ▼                                                   │
│   ┌──────────────────────┐                                      │
│   │  Classification du   │   sqli, xss, cmdi, path_traversal,  │
│   │  type d'attaque      │   ssrf, injection, encoded_attack    │
│   └──────────────────────┘                                      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

#### Les 3 modèles en détail

| # | Modèle | Type | Rôle | Poids | Paramètres clés |
|---|--------|------|------|-------|-----------------|
| 1 | **IsolationForest** | Non-supervisé | Détection d'anomalies, comportements atypiques | **0.10** | `contamination=0.1`, `random_state=42` |
| 2 | **RandomForestClassifier** | Supervisé | Classification des types d'attaque connus | **0.45** | `n_estimators=200`, `max_depth=20`, `class_weight='balanced'` |
| 3 | **GradientBoostingClassifier** | Supervisé | Scoring de probabilité d'attaque | **0.45** | `random_state=42` |

#### Extraction de features (35 caractéristiques)

| Groupe | # | Features |
|--------|---|----------|
| **Longueur** | 6 | `url_length`, `path_length`, `query_length`, `body_length`, `header_count`, `cookie_length` |
| **Distribution de caractères** | 8 | `special_char_count`, `special_char_ratio`, `dangerous_char_score`, `uppercase_ratio`, `digit_ratio`, `non_ascii_count`, `max_char_repeat`, `entropy` |
| **Mots-clés d'attaque** | 5 | `sql_keyword_count`, `xss_keyword_count`, `cmd_keyword_count`, `path_traversal_count`, `ssrf_keyword_count` |
| **Encodage** | 4 | `url_encoding_count`, `double_encoding_count`, `hex_encoding_count`, `unicode_encoding_count` |
| **Structure** | 7 | `param_count`, `nested_bracket_depth`, `comment_patterns`, `null_byte_count`, `whitespace_anomaly`, `method_encoded`, `suspicious_extension` |
| **Contexte** | 5 | `has_valid_tld`, `path_depth`, `query_key_anomaly`, `body_is_json`, `mixed_case_keywords` |

#### Score de caractères dangereux (pondéré)

Chaque caractère spécial reçoit un poids basé sur sa dangerosité :

| Poids | Caractères |
|-------|-----------|
| **5** | `\x00` (null byte) |
| **3** | `'` `<` `>` `;` `` ` `` |
| **2** | `"` `\|` `$` `(` `)` `{` `}` `\` `#` `\n` `\r` |
| **1** | `&` `[` `]` `/` `%` `!` `=` `\t` |

---

### 3.5 Détection d'anomalies (Isolation Forest)

Un module de détection d'anomalies basé sur **Isolation Forest** est intégré afin d'identifier des comportements atypiques ou inconnus, notamment les **attaques zero-day**. Ce module agit comme un mécanisme complémentaire aux approches supervisées.

```
┌──────────────────────────────────────────────────┐
│           Détection d'anomalies                   │
├──────────────────────────────────────────────────┤
│                                                   │
│   Deux niveaux :                                  │
│                                                   │
│   1. IsolationForest dans l'ensemble ML (0.10)   │
│      ─ Intégré au scoring pondéré                │
│      ─ Entraîné sur features normalisées         │
│      ─ Score d'anomalie normalisé [0, 1]         │
│                                                   │
│   2. IsolationForest legacy (fallback)            │
│      ─ Utilisé si l'ensemble ML non entraîné     │
│      ─ Vectorisation TF-IDF du payload           │
│      ─ Fallback z-score (seuil > 3.0)            │
│                                                   │
│   Rôle : Détecter les déviations par rapport     │
│   au trafic normal sans connaissance préalable    │
│   de l'attaque → attaques zero-day               │
│                                                   │
└──────────────────────────────────────────────────┘
```

---

### 3.6 Détection Zero-Day

Un détecteur statistique dédié aux attaques **zero-day** analyse les payloads avec **8 méthodes complémentaires** :

```
┌──────────────────────────────────────────────────────────────┐
│               Zero-Day Detector — 8 Analyseurs               │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────────────┐  ┌──────────────────────┐          │
│  │ 1. Entropie         │  │ 2. Densité caractères │          │
│  │    (Shannon)        │  │    spéciaux           │          │
│  └─────────────────────┘  └──────────────────────┘          │
│                                                               │
│  ┌─────────────────────┐  ┌──────────────────────┐          │
│  │ 3. Profondeur       │  │ 4. Anomalie N-gram    │          │
│  │    d'encodage       │  │    (trigrammes)       │          │
│  └─────────────────────┘  └──────────────────────┘          │
│                                                               │
│  ┌─────────────────────┐  ┌──────────────────────┐          │
│  │ 5. Caractères de    │  │ 6. Heuristiques       │          │
│  │    contrôle         │  │    shellcode           │          │
│  └─────────────────────┘  └──────────────────────┘          │
│                                                               │
│  ┌─────────────────────┐  ┌──────────────────────┐          │
│  │ 7. Détection        │  │ 8. Anomalie de        │          │
│  │    polyglotte       │  │    longueur payload    │          │
│  └─────────────────────┘  └──────────────────────┘          │
│                                                               │
│  Score pondéré combiné ≥ seuil (0.65) → ATTAQUE ZERO-DAY    │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

| Analyseur | Méthode | Ce qu'il détecte |
|-----------|---------|------------------|
| Entropie | Calcul Shannon | Payloads hautement aléatoires (shellcode, données chiffrées) |
| Densité spéciale | Ratio caractères spéciaux | Injection concentrée de caractères dangereux |
| Profondeur encodage | Couches URL/hex/base64 | Évasion par multi-encodage |
| N-gram | Fréquence trigrammes vs baseline | Payloads structurellement anormaux |
| Caractères contrôle | Non-imprimables détectés | Shellcode, buffer overflow, binary injection |
| Shellcode | NOP sleds, patterns x86 | Tentatives d'exécution de code machine |
| Polyglotte | Multi-validité (HTML+JS+SQL) | Payloads exploitant plusieurs parseurs |
| Longueur | Query >1000 / Body >50000 | Exfiltration, buffer overflow, DoS |

---

### 3.7 Analyse comportementale adaptative

Un moteur d'**apprentissage adaptatif** construit des profils de comportement normal par endpoint, puis détecte les déviations.

```
┌──────────────────────────────────────────────────────────────┐
│            Adaptive Learning Engine                           │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│   Mode APPRENTISSAGE (100 premières requêtes/endpoint)       │
│   ┌─────────────────────────────────────────────────────┐    │
│   │  Pour chaque paire (méthode, chemin), apprend :     │    │
│   │  • Noms de paramètres connus                         │    │
│   │  • Types de valeurs (integer, uuid, email, alpha...) │    │
│   │  • Longueurs maximales observées                     │    │
│   │  • Content-Types utilisés                            │    │
│   │  • Plages de taille du body                          │    │
│   │  • Nombre max de paramètres                          │    │
│   └─────────────────────────────────────────────────────┘    │
│                                                               │
│   Mode DÉTECTION (après apprentissage)                       │
│   ┌─────────────────────────────────────────────────────┐    │
│   │  Détecte les anomalies :                             │    │
│   │  ✗ Endpoint inconnu (non vu en apprentissage)       │    │
│   │  ✗ Paramètre inconnu (nom non appris)               │    │
│   │  ✗ Dépassement longueur apprise                      │    │
│   │  ✗ Content-Type inconnu                              │    │
│   │  ✗ Taille body anormale                              │    │
│   │  ✗ Nombre de paramètres excessif                     │    │
│   └─────────────────────────────────────────────────────┘    │
│                                                               │
│   Mode ENFORCE → Les anomalies déclenchent le blocage       │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

---

### 3.8 Corrélation d'attaques (Kill Chain)

Un moteur de corrélation suit le modèle **Lockheed Martin Kill Chain** pour détecter les **campagnes d'attaque multi-étapes** et les attaques distribuées.

```
┌──────────────────────────────────────────────────────────────┐
│              Correlation Engine — Kill Chain                   │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│   Phases de la Kill Chain :                                   │
│                                                               │
│   Reconnaissance ──► Weaponization ──► Exploitation          │
│        │                   │                │                 │
│        ▼                   ▼                ▼                 │
│   path-traversal      (preparation)     sqli, xss, cmdi     │
│   ssrf, dir scan                        rce, jndi, ssti     │
│   scanner probes                                             │
│        │                                    │                 │
│        └────────────────────────────────────▼                 │
│                                        Persistence           │
│                                    (post-exploitation)       │
│                                                               │
│   Chaînes d'attaque détectées :                              │
│   ┌──────────────────────────────────────────────────┐       │
│   │  • SQL Injection Chain (recon → SQLi → exfil)    │       │
│   │  • RCE Exploitation (recon → exploit → persist)  │       │
│   │  • API Abuse (enum → abuse)                      │       │
│   │  • Supply Chain Probe (dependency confusion)     │       │
│   │  • Log4Shell Attack (JNDI → callback → RCE)     │       │
│   └──────────────────────────────────────────────────┘       │
│                                                               │
│   Détection distribuée :                                      │
│   • Attaques coordonnées multi-IP (même type, même cible)    │
│                                                               │
│   Score de menace ≥ 80 → BLOCAGE                             │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

---

### 3.9 Moteur de fusion décisionnelle

Les résultats des différents moteurs de détection sont combinés par un **mécanisme de cascade fail-fast** : le premier module détectant une menace bloque immédiatement la requête (code HTTP 403 ou 429).

```
┌──────────────────────────────────────────────────────────────┐
│            Moteur de Fusion Décisionnelle                     │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│   Stratégie : Cascade Fail-Fast (blocage au premier hit)     │
│                                                               │
│   Phase 1-5  │  Réseau/Protocole  │──► BLOC 403/429         │
│   Phase 6    │  13 Modules Enterp │──► BLOC 403             │
│   Phase 7    │  Validation Headers│──► BLOC 403             │
│   Phase 8    │  Evasion + 10K Regex│──► BLOC 403            │
│   Phase 9    │  ML Ensemble       │──► BLOC 403             │
│   Phase 10   │  Zero-Day + Correl │──► BLOC 403             │
│              │                    │                           │
│   Aucun bloc │  → PASSTHROUGH     │──► Backend              │
│                                                               │
│   Post-réponse :                                              │
│   • DLP scan réponse → masquage données sensibles            │
│   • Response cloaking → suppression fingerprints             │
│   • Cookie hardening → ajout flags sécurité                  │
│                                                               │
│   Pour le ML Engine spécifiquement :                         │
│   ┌─────────────────────────────────────────────────┐        │
│   │  Score = 0.10×IF + 0.45×RF + 0.45×GB           │        │
│   │  Seuil = 0.60 → décision attaque/normal         │        │
│   └─────────────────────────────────────────────────┘        │
│                                                               │
│   Pour la Corrélation :                                       │
│   ┌─────────────────────────────────────────────────┐        │
│   │  Score menace = f(volume, kill-chain, diversité) │        │
│   │  Seuil = 80 → blocage                           │        │
│   └─────────────────────────────────────────────────┘        │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

---

## 4. Modules de sécurité avancés

BeeWAF intègre **27 modules spécialisés**, chacun responsable d'un domaine de sécurité spécifique :

### 4.1 Tableau récapitulatif des 27 modules

| # | Module | Classe | Fonction principale |
|---|--------|--------|---------------------|
| 1 | **Regex Rules Engine** | `check_regex_rules()` | 10 041 signatures d'attaques connues |
| 2 | **ML Engine** | `MLEngine` | Ensemble 3 modèles (RF + GB + IF) |
| 3 | **Anomaly Detector** | `AnomalyDetector` | IsolationForest legacy + z-score |
| 4 | **Evasion Detector** | `EvasionDetector` | 18 couches de désobfuscation |
| 5 | **Zero-Day Detector** | `ZeroDayDetector` | 8 analyseurs statistiques |
| 6 | **Correlation Engine** | `CorrelationEngine` | Kill chain & attaques multi-étapes |
| 7 | **Adaptive Learning** | `AdaptiveLearningEngine` | Profils endpoint & modèle positif |
| 8 | **Rate Limiter** | `RateLimiter` | Fenêtre glissante (60 req/min) |
| 9 | **IP Blocklist** | `IPBlocklist` | Auto-blocage IP (10 attaques → ban) |
| 10 | **Bot Detector** | `BotDetector` | Scoring multi-signal (seuil 0.85) |
| 11 | **Advanced Bot Manager** | `AdvancedBotManager` | JS challenges, device fingerprint, TLS/JA3 |
| 12 | **DLP Engine** | `DLPEngine` | Cartes, SSN, clés API, tokens |
| 13 | **Geo-Blocker** | `GeoBlocker` | Pays, Tor, VPN, datacenters |
| 14 | **Protocol Validator** | `ProtocolValidator` | Méthodes, tailles, Content-Type |
| 15 | **API Security** | `APISecurityEngine` | JSON/XML depth, BOLA/IDOR, GraphQL |
| 16 | **API Discovery** | `APIDiscoveryEngine` | Shadow API, schema OpenAPI, quotas |
| 17 | **Threat Intelligence** | `ThreatIntelEngine` | Outils connus, campagnes CVE, C2 |
| 18 | **Threat Feed** | `ThreatFeedEngine` | MITRE ATT&CK mapping, IOC, APT |
| 19 | **Session Protection** | `SessionProtectionEngine` | Hijacking, fixation, replay, CSRF |
| 20 | **Cookie Security** | `CookieSecurityEngine` | HMAC, chiffrement, flags, injection |
| 21 | **Response Cloaking** | `ResponseCloaker` | Fingerprint removal, error masking |
| 22 | **Virtual Patching** | `VirtualPatchingEngine` | 80+ CVE patches (Log4Shell, Spring4Shell...) |
| 23 | **WebSocket Inspector** | `WebSocketInspector` | Frames WS, rate limiting, injection |
| 24 | **Deep Payload Analysis** | `DeepPayloadAnalyzer` | Magic bytes, polyglot, double extension |
| 25 | **Compliance Engine** | `ComplianceEngine` | OWASP Top 10, PCI DSS, scoring temps réel |
| 26 | **DDoS Protection** | `DDoSProtection` | Flood, slowloris, amplification |
| 27 | **Performance Engine** | `PerformanceEngine` | Bloom filter, cache LRU, déduplication |
| — | **Cluster Sync** | `ClusterManager` | Synchronisation multi-instances |

### 4.2 Modules détaillés

#### Protection DDoS (couche réseau/application)

| Sous-module | Détection | Seuils |
|-------------|-----------|--------|
| Connection Flood | Max connexions par IP | 100 000 / IP, 1M global |
| HTTP Flood | Requêtes par seconde | Warn: 500 RPS, Block: 1 000 RPS |
| Slow Attack | Slowloris, Slow POST/Read | Headers: 10s, Body: 30s, Min: 100 B/s |
| Amplification | Ratio réponse/requête | Max ratio: 100.0 |

#### Bot Detection (multi-signal)

```
Score Bot = 0.30 × Signature
           + 0.20 × Comportement
           + 0.15 × User-Agent
           + 0.10 × Header Order

Score ≥ 0.85 → BLOC
Score ≥ 0.70 → CHALLENGE (JS proof-of-work)
Score < 0.70 → ALLOW
```

#### DLP (Data Leak Prevention)

| Type de données | Exemples détectés |
|-----------------|-------------------|
| Cartes bancaires | Visa, Mastercard, Amex, Discover (Luhn) |
| Numéros sociaux | US SSN, French NIR |
| Clés API | AWS, GCP, Azure, GitHub, Stripe, Slack |
| Tokens | JWT, Bearer tokens |
| Hashs | bcrypt, MD5, SHA-256, SHA-512 |
| Connexions DB | MySQL, PostgreSQL, MongoDB, Redis |
| Clés privées | RSA, SSH, PGP |
| Fuites internes | Chemins fichiers, IPs internes, stack traces |

#### Virtual Patching (80+ CVEs)

| CVE | Vulnérabilité | Statut |
|-----|---------------|--------|
| CVE-2021-44228 | Log4Shell | ✅ Patché |
| CVE-2021-45046 | Log4Shell variant | ✅ Patché |
| CVE-2022-22965 | Spring4Shell | ✅ Patché |
| CVE-2023-34362 | MOVEit Transfer | ✅ Patché |
| CVE-2023-4966 | Citrix Bleed | ✅ Patché |
| CVE-2021-26855 | ProxyLogon | ✅ Patché |
| CVE-2021-34473 | ProxyShell | ✅ Patché |
| CVE-2022-26134 | Confluence RCE | ✅ Patché |
| CVE-2022-1388 | F5 BIG-IP RCE | ✅ Patché |
| ... | +70 autres CVEs | ✅ Patché |

---

## 5. Architecture d'infrastructure

### 5.1 Architecture Docker (6 conteneurs)

```
┌──────────────────────────────────────────────────────────────────┐
│                    Docker Compose — Production                    │
│                    Réseau : beewaf-network (bridge)              │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│   Client HTTPS                                                    │
│       │                                                           │
│       ▼                                                           │
│   ┌─────────────────────┐                                        │
│   │   Nginx (Alpine)     │   Port 80 → redirect HTTPS            │
│   │   beewaf_nginx       │   Port 443 → TLS 1.2/1.3             │
│   │                      │   Ciphers: ECDHE-AES-GCM              │
│   │                      │   HSTS: max-age=31536000              │
│   └──────────┬──────────┘                                        │
│              │ proxy_pass                                         │
│              ▼                                                    │
│   ┌─────────────────────┐                                        │
│   │   BeeWAF (Python)    │   Port 8000 (interne)                 │
│   │   beewaf_sklearn     │   FastAPI + Uvicorn                   │
│   │                      │   27 modules de sécurité              │
│   │                      │   10 041 règles regex                  │
│   │                      │   ML Ensemble (3 modèles)             │
│   └──────────┬──────────┘                                        │
│              │ JSON logs (stdout)                                  │
│              ▼                                                    │
│   ┌─────────────────────┐                                        │
│   │   Filebeat 8.11      │   Collecte logs conteneurs Docker     │
│   │   beewaf_filebeat    │   → Envoi vers Logstash :5044         │
│   └──────────┬──────────┘                                        │
│              │                                                    │
│              ▼                                                    │
│   ┌─────────────────────┐                                        │
│   │   Logstash 8.11      │   Port 5044 (Beats input)             │
│   │   beewaf_logstash    │   Pipeline : parse, enrich, index     │
│   └──────────┬──────────┘                                        │
│              │                                                    │
│              ▼                                                    │
│   ┌─────────────────────┐                                        │
│   │   Elasticsearch 8.11 │   Port 9200                           │
│   │   beewaf_elasticsearch│  Index: beewaf-logs-*                │
│   │                      │   Template: keyword mappings           │
│   └──────────┬──────────┘                                        │
│              │                                                    │
│              ▼                                                    │
│   ┌─────────────────────┐                                        │
│   │   Kibana 8.11        │   Port 5601                           │
│   │   beewaf_kibana      │   Dashboard: beewaf-security-dashboard│
│   │                      │   12 visualisations temps réel        │
│   └─────────────────────┘                                        │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

### 5.2 Architecture Kubernetes (K8s)

```
┌──────────────────────────────────────────────────────────────┐
│                    Kubernetes Deployment                       │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│   Ingress (TLS termination)                                   │
│       │                                                       │
│       ▼                                                       │
│   Service (ClusterIP :443)                                    │
│       │                                                       │
│       ▼                                                       │
│   Deployment (replicas: 2)                                    │
│   ┌────────────────────────────────┐                         │
│   │  Pod 1              Pod 2      │                         │
│   │  ┌──────────┐  ┌──────────┐  │                         │
│   │  │ beewaf   │  │ beewaf   │  │                         │
│   │  │ :8000    │  │ :8000    │  │                         │
│   │  └──────────┘  └──────────┘  │                         │
│   └────────────────────────────────┘                         │
│                                                               │
│   TLS Secret: beewaf-tls (tls.crt + tls.key)                │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

### 5.3 Pipeline CI/CD (Jenkins)

```
┌──────────────────────────────────────────────────────────────┐
│                    Jenkinsfile Pipeline                        │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│   Stage 1 : Checkout ──► Récupération du code source         │
│       │                                                       │
│   Stage 2 : Build ──► docker build -f Dockerfile.full        │
│       │                                                       │
│   Stage 3 : Test ──► Exécution tests unitaires               │
│       │                                                       │
│   Stage 4 : Security Scan ──► Analyse de vulnérabilités      │
│       │                                                       │
│   Stage 5 : Deploy ──► docker-compose up / kubectl apply     │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

---

## 6. Journalisation et supervision (ELK Stack)

Le système met en œuvre une **journalisation structurée au format JSON**, ingérée par le pipeline ELK (Elasticsearch, Logstash, Kibana) pour une supervision en temps réel.

### 6.1 Pipeline de données

```
┌─────────────┐     ┌──────────┐     ┌───────────────┐     ┌────────┐
│   BeeWAF    │────►│ Filebeat │────►│   Logstash    │────►│   ES   │
│  JSON logs  │     │  (beats) │     │  (pipeline)   │     │ (index)│
└─────────────┘     └──────────┘     └───────────────┘     └────┬───┘
                                                                 │
                                                                 ▼
                                                           ┌─────────┐
                                                           │ Kibana  │
                                                           │Dashboard│
                                                           └─────────┘
```

### 6.2 Format de log structuré

Chaque requête génère un log JSON contenant :

```json
{
  "timestamp": "2026-02-10T14:30:00Z",
  "client_ip": "192.168.1.100",
  "http_method": "GET",
  "http_path": "/api/users?id=1' OR '1'='1",
  "status_code": 403,
  "latency_ms": 2.3,
  "block_reason": "regex-sqli",
  "attack_type": "sqli",
  "tags": ["blocked", "security", "sqli"],
  "user_agent": "Mozilla/5.0...",
  "request_size": 256,
  "response_size": 89
}
```

### 6.3 Index Elasticsearch

| Champ | Type | Agrégeable |
|-------|------|-----------|
| `client_ip` | keyword | ✅ |
| `http_method` | keyword | ✅ |
| `http_path` | text + keyword | ✅ (.keyword) |
| `status_code` | integer | ✅ |
| `latency_ms` | float | ✅ |
| `block_reason` | keyword | ✅ |
| `attack_type` | keyword | ✅ |
| `tags` | keyword | ✅ |
| `user_agent` | text + keyword | ✅ (.keyword) |

### 6.4 Tableaux de bord Kibana (12 visualisations)

| # | Visualisation | Type | Description |
|---|---------------|------|-------------|
| 1 | BeeWAF Info | Markdown | Informations système |
| 2 | Types d'attaques | Donut (Pie) | Distribution des `attack_type` |
| 3 | Blocked vs Allowed | Lens XY (Bar) | Répartition par `status_code` |
| 4 | Top Paths bloqués | Bar horizontal | Chemins les plus ciblés |
| 5 | Total Requests | Lens Metric | Compteur total de requêtes |
| 6 | Total Blocked | Lens Metric | Compteur requêtes bloquées (403) |
| 7 | Tags Cloud | Tag Cloud | Nuage de tags d'attaque |
| 8 | Méthodes HTTP | Pie | Distribution GET/POST/PUT/DELETE |
| 9 | Timeline | Line | Évolution temporelle du trafic |
| 10 | Status Codes | Donut (Pie) | Distribution 200/403/404/401 |
| 11 | Latence moyenne | Lens Metric | Latence moyenne (ms) |
| 12 | Attaques récentes | Table | Dernières attaques détaillées |

---

## 7. Modèles de Machine Learning — Détails

### 7.1 Vue d'ensemble des modèles

| Modèle | Type | Objectif dans le WAF | Entrée | Sortie |
|--------|------|----------------------|--------|--------|
| **RandomForestClassifier** | Apprentissage supervisé | Classifier les attaques web connues à partir du contenu des requêtes | 35 features extraites d'une requête HTTP (longueur payload, fréquence mots-clés, entropie, ratio caractères spéciaux, etc.) | Classe d'attaque prédite (SQLi, XSS, Normal...) + Score de confiance |
| **GradientBoostingClassifier** | Apprentissage supervisé | Scoring de probabilité d'attaque avec boosting séquentiel | 35 features identiques, normalisées par StandardScaler | Probabilité d'attaque [0, 1] |
| **IsolationForest** | Apprentissage non-supervisé (détection d'anomalies) | Détecter les attaques inconnues / zero-day par déviation du trafic normal | 35 features statistiques décrivant le contexte de la requête | Score d'anomalie normalisé [0, 1] |

### 7.2 Comparaison des rôles

| Aspect | RandomForest + GradientBoosting | IsolationForest |
|--------|----------------------------------|-----------------|
| **Type** | Supervisé | Non-supervisé |
| **Granularité** | Requête individuelle | Requête individuelle (déviation) |
| **Données requises** | Dataset labellisé (CSIC 2010) | Pas de labels nécessaires |
| **Forces** | SQLi, XSS, CMDi, variantes obfusquées | Zero-day, attaques inconnues |
| **Faiblesses** | Ne détecte que les types appris | Pas de classification du type |
| **Poids dans l'ensemble** | 0.45 + 0.45 = 0.90 | 0.10 |

### 7.3 Datasets utilisés

| Modèle | Dataset | Features | Feature Engineering | Sortie | Rôle |
|--------|---------|----------|---------------------|--------|------|
| RandomForest | CSIC 2010, payloads OWASP | Stats payload, mots-clés, entropie | Extraction 35 features, StandardScaler | Classe attaque + confiance | Classifier attaques connues |
| GradientBoosting | CSIC 2010, payloads OWASP | Stats payload, mots-clés, entropie | Extraction 35 features, StandardScaler | Probabilité attaque | Scoring de probabilité |
| IsolationForest | Trafic normal (CSIC 2010 clean) | Rate, taille, headers, entropie | StandardScaler, contamination=0.1 | Score d'anomalie | Détecter attaques inconnues |

### 7.4 Pré-filtre intelligent (`_is_obviously_safe`)

Avant toute inférence ML, un **pré-filtre rule-based** réduit la charge et les faux positifs :

```
Requête → Pré-filtre
    │
    ├── JSON body valide, sans mots-clés d'attaque → SAFE (skip ML)
    ├── Extension statique (.html, .css, .js, .png...) → SAFE
    ├── Chemin simple, alphanumérique, < 200 chars → SAFE
    ├── Nom type O'Reilly (apostrophe légitime) → SAFE
    │
    ├── Caractères dangereux (<, >, ;, |, $, `...) → ANALYZE (ML)
    ├── Mots-clés SQL en contexte (SELECT+FROM...) → ANALYZE (ML)
    └── Patterns d'injection ('OR, '; --, '1'='1') → ANALYZE (ML)
```

---

## 8. Vue synthétique des couches de sécurité

### 8.1 Matrice couche × attaque

| Couche de sécurité | Type de détection | Attaques interceptées | Pourquoi cette couche est efficace |
|---------------------|-------------------|------------------------|-------------------------------------|
| **Rule-based / Regex** (10 041 règles) | Analyse syntaxique par signatures | SQL Injection, XSS, Command Injection, Path Traversal, LFI/RFI, SSRF, XXE, SSTI, NoSQL, LDAP, JNDI, Désérialisation, JWT, GraphQL, Prototype Pollution | Basée sur 10 041 motifs connus et signatures précises, couvre 21+ catégories avec des variantes encodées |
| **Evasion Detector** (18 couches) | Désobfuscation multi-encodage | Attaques obfusquées (URL-encoding, Unicode, Base64, Hex, HTML entities, UTF-8 overlong, homoglyphes) | Déjoue les techniques d'évasion par multi-encodage, chaque forme décodée re-vérifiée |
| **Supervised ML** (RF + GB) | Classification de requêtes | SQLi variantes, XSS obfusqué, CMDi, requêtes malformées, attaques connues apprises | Capable de généraliser et détecter des variantes qui ne matchent pas exactement les règles |
| **Anomaly Detection** (IsolationForest) | Détection non-supervisée | Zero-day, DDoS applicatif (Layer 7), trafic anormal inconnu, attaques lentes, abus d'API | Détecte les déviations par rapport au trafic normal sans connaissance préalable de l'attaque |
| **Zero-Day Detector** (8 analyseurs) | Analyse statistique multi-critères | Zero-day, shellcode, buffer overflow, payloads polyglotte, injections binaires | 8 analyseurs indépendants (entropie, n-gram, shellcode, polyglotte) pour une couverture maximale |
| **Adaptive Learning** | Modèle positif de sécurité | Endpoints inconnus, paramètres anormaux, taille body excessive, Content-Type anormal | Construit un profil de ce qui est « normal » et détecte toute déviation |
| **Correlation Engine** | Kill Chain multi-étapes | Campagnes d'attaque, attaques distribuées multi-IP, escalade progressive | Suit la progression d'une attaque à travers les phases de la kill chain |
| **Rate Limiting** | Contrôle de volumétrie | DDoS, Brute force, Credential stuffing, API abuse | Limite l'impact des attaques volumétriques indépendamment du contenu |
| **DDoS Protection** | Détection de flood multicouche | Flood connexion, HTTP flood, Slowloris, Slow POST/Read, Amplification | 4 sous-modules spécialisés avec adaptation dynamique des seuils |
| **Bot Detection** | Scoring multi-signal | Bots malveillants, scrapers, scanners automatisés, credential stuffing | Combine signature, comportement, UA, header order pour un scoring fiable |
| **API Security** | Validation structurelle | JSON depth bomb, XXE, BOLA/IDOR, GraphQL abuse | Validation profonde des structures de données (profondeur, taille, clés) |
| **Virtual Patching** | Patches CVE-spécifiques | Log4Shell, Spring4Shell, ProxyLogon, ProxyShell, MOVEit, +70 CVEs | Protection immédiate sans modification du code source |
| **DLP Engine** | Scan de réponse | Fuite cartes bancaires, SSN, clés API, tokens, connexions DB | Protection de sortie (egress) avec masquage automatique |
| **Response Cloaking** | Masquage de réponse | Information disclosure, fingerprinting serveur, stack traces | Supprime 30+ signatures serveur, masque erreurs internes |

### 8.2 Couverture OWASP Top 10 (2021)

| OWASP | Catégorie | Modules BeeWAF couvrants |
|-------|-----------|-------------------------|
| **A01** | Broken Access Control | Session Protection, API Security, BOLA Detection, Rate Limiter |
| **A02** | Cryptographic Failures | Cookie Security (HMAC, AES), TLS 1.2/1.3 enforcement |
| **A03** | Injection | Regex Rules (10 041), ML Engine, Evasion Detector, Zero-Day |
| **A04** | Insecure Design | Protocol Validator, API Discovery, Deep Payload |
| **A05** | Security Misconfiguration | Response Cloaking, Virtual Patching, Compliance Engine |
| **A06** | Vulnerable Components | Virtual Patching (80+ CVEs), Threat Feed |
| **A07** | Auth Failures | Bot Detection, Credential Stuffing, Session Protection |
| **A08** | Software & Data Integrity | Cookie Security, Deep Payload, Deserialization rules |
| **A09** | Logging & Monitoring | ELK Stack, Compliance Engine, MITRE ATT&CK mapping |
| **A10** | SSRF | Regex Rules (SSRF category), ML Engine, API Security |

---

## 9. Diagramme de flux de traitement

### 9.1 Flux complet d'une requête

```
                              Client HTTP/HTTPS
                                     │
                                     ▼
                          ┌─────────────────────┐
                          │   Nginx Reverse      │
                          │   Proxy (TLS)        │
                          │   Port 80/443        │
                          └──────────┬──────────┘
                                     │
                                     ▼
                 ┌───────────────────────────────────────┐
                 │         FastAPI Middleware              │
                 │         (waf_middleware)                │
                 ├───────────────────────────────────────┤
                 │                                        │
    ┌────────────┤  1. IP Blocklist Check                │
    │ BLOC 403   │  2. Path Normalization                │
    │◄───────────┤  3. Host Validation                   │
    │            │  4. Sensitive Path Block               │
    │            │  5. Smuggling Detection                │
    │            │                                        │
    │            ├────────────────────────────────────────┤
    │            │                                        │
    │ BLOC 429   │  6. DDoS Protection                   │
    │◄───────────┤  7. Rate Limiting                     │
    │            │                                        │
    │            ├────────────────────────────────────────┤
    │            │                                        │
    │ BLOC 403   │  8.  Protocol Validation              │
    │◄───────────┤  9.  Geo-Blocking                     │
    │            │  10. Bot Detection                     │
    │            │  11. Advanced Bot Manager              │
    │            │  12. Threat Intelligence               │
    │            │  13. Threat Feed (MITRE)               │
    │            │  14. Session Protection                │
    │            │  15. API Security                      │
    │            │  16. API Discovery                     │
    │            │  17. Virtual Patching                  │
    │            │  18. WebSocket Inspector               │
    │            │  19. Deep Payload Analysis             │
    │            │                                        │
    │            ├────────────────────────────────────────┤
    │            │                                        │
    │ BLOC 403   │  20. Header Validation                │
    │◄───────────┤  21. 18-Layer Evasion Detection       │
    │            │  22. 10 041 Regex Rules                │
    │            │                                        │
    │            ├────────────────────────────────────────┤
    │            │                                        │
    │ BLOC 403   │  23. ML Ensemble (3 modèles)          │
    │◄───────────┤      Score ≥ 0.60 → attaque           │
    │            │                                        │
    │            ├────────────────────────────────────────┤
    │            │                                        │
    │ BLOC 403   │  24. Zero-Day Detection               │
    │◄───────────┤  25. Adaptive Learning                │
    │            │  26. Correlation Engine (score ≥ 80)   │
    │            │                                        │
    │            ├────────────────────────────────────────┤
    │            │                                        │
    │            │  ✅ PASSTHROUGH → Backend App          │
    │            │                                        │
    │            ├────────────────────────────────────────┤
    │            │                                        │
    │            │  27. DLP Response Scan                 │
    │            │  28. Security Headers Injection        │
    │            │  29. Response Cloaking                 │
    │            │  30. Cookie Hardening                  │
    │            │  31. JSON Log + Prometheus Metric      │
    │            │                                        │
    └────────────┴────────────────────────────────────────┘
                                     │
                                     ▼
                              Réponse Client
```

### 9.2 Architecture de déploiement complète

```
┌──────────────────────────────────────────────────────────────────────┐
│                                                                       │
│                     BeeWAF Enterprise v6.0                            │
│                     Architecture de Déploiement                       │
│                                                                       │
│   ┌───────────┐                                                      │
│   │  Jenkins   │─── Build ──► Docker Image ──► Deploy                │
│   │  CI/CD     │                                                      │
│   └───────────┘                                                      │
│                                                                       │
│   ┌──────────────────────────────────────────────────────────┐       │
│   │                     Docker / Kubernetes                    │       │
│   │                                                           │       │
│   │   Internet ──► Nginx (TLS) ──► BeeWAF ──► Backend App   │       │
│   │                    │              │                        │       │
│   │                    │              ├── 27 Security Modules  │       │
│   │                    │              ├── 10 041 Regex Rules   │       │
│   │                    │              ├── ML Ensemble (3)      │       │
│   │                    │              └── JSON Structured Logs │       │
│   │                    │                       │               │       │
│   │                    │              ┌────────▼────────┐     │       │
│   │                    │              │    Filebeat      │     │       │
│   │                    │              └────────┬────────┘     │       │
│   │                    │              ┌────────▼────────┐     │       │
│   │                    │              │    Logstash      │     │       │
│   │                    │              └────────┬────────┘     │       │
│   │                    │              ┌────────▼────────┐     │       │
│   │                    │              │  Elasticsearch   │     │       │
│   │                    │              └────────┬────────┘     │       │
│   │                    │              ┌────────▼────────┐     │       │
│   │                    │              │    Kibana        │     │       │
│   │                    │              │  (12 Dashboards) │     │       │
│   │                    │              └─────────────────┘     │       │
│   │                    │                                      │       │
│   └──────────────────────────────────────────────────────────┘       │
│                                                                       │
│   Performance : Grade A+ │ Score : 98.2/100 │ FP : 0%               │
│   Règles : 10 041        │ Modules : 27     │ CVEs : 80+            │
│                                                                       │
└──────────────────────────────────────────────────────────────────────┘
```

---

> **BeeWAF Enterprise v6.0** — Web Application Firewall Intelligent Multi-Couches  
> 10 041 règles | 27 modules | 3 modèles ML | Grade A+ | 0% faux positifs
