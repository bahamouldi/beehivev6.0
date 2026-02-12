# 🐝 BeeWAF — Guide Complet : Build, Transfert & Déploiement

## Architecture sur le cluster DPC

```
Internet → HAProxy (207.180.211.157)
             :80  → NodePort 30439 → Nginx Ingress
             :443 → NodePort 32419 → Nginx Ingress
                                        │
                                        ├─ beewaf.dpc.com.tn  → BeeWAF (2 pods)
                                        ├─ kibana.dpc.com.tn  → Kibana
                                        └─ app.dpc.com.tn     → App protégée (plus tard)

Namespace "beewaf" sur K8s v1.29 :
┌─────────────────────────────────────────────────────────────┐
│  BeeWAF Deployment (2 replicas)                             │
│  ├─ 27 modules sécurité                                     │
│  ├─ 10 041 règles regex compilées                           │
│  ├─ ML Ensemble (Random Forest + Gradient Boosting + IF)    │
│  ├─ Rate Limiter (100 req/min)                              │
│  ├─ IP Blocklist (10 attaques → ban 1h)                     │
│  └─ DDoS Protection (flood/slowloris/amplification)         │
│                                                             │
│  Elasticsearch StatefulSet (1 replica + PVC 5Gi)            │
│  Logstash Deployment (1 replica)                            │
│  Kibana Deployment (1 replica)                              │
│  Filebeat DaemonSet (1 pod par node = 5 pods)               │
└─────────────────────────────────────────────────────────────┘
```

## Comment TOUT fonctionne ensemble

### Flux d'une requête :
```
Client → HAProxy → Nginx Ingress → BeeWAF Pod
                                      │
                                      ├─ 1. Deobfuscation (18 couches)
                                      ├─ 2. Regex Engine (10 041 règles)
                                      ├─ 3. ML Engine (3 modèles ensemble)
                                      ├─ 4. Rate Limiter + IP Blocklist
                                      ├─ 5. Bot Detection
                                      ├─ 6. Protocol Validation
                                      ├─ 7. Session Fingerprinting
                                      ├─ 8. Security Headers
                                      └─ 9. Log JSON → stdout
                                              │
                                              ▼
                                    Filebeat (lit stdout du conteneur)
                                              │
                                              ▼
                                    Logstash (parse + enrichit)
                                              │
                                              ▼
                                    Elasticsearch (stocke + indexe)
                                              │
                                              ▼
                                    Kibana (dashboards temps réel)
```

### Flux des logs ELK :
```
BeeWAF écrit du JSON structuré sur stdout
  → containerd capture les logs dans /var/log/containers/beewaf-*.log
  → Filebeat (DaemonSet sur chaque node) lit ces fichiers
  → Envoie à Logstash (port 5044)
  → Logstash parse le JSON, enrichit (geoip, anomaly score, etc.)
  → Indexe dans Elasticsearch (index beewaf-YYYY.MM.dd)
  → Kibana affiche les dashboards
```

---

## Étape 1 : Build de l'image BeeWAF (sur ta machine Kali)

```bash
cd ~/Downloads/beehivepfe2-main

# Build avec Dockerfile.k8s (inclut l'entraînement ML)
# Ça prend 3-5 min car ça entraîne les 3 modèles ML
docker build -f Dockerfile.k8s -t beewaf:latest .

# Vérifier que l'image marche
docker run --rm -p 8000:8000 beewaf:latest &
sleep 10
curl http://localhost:8000/health
# Doit retourner {"status":"ok"}
curl "http://localhost:8000/test?q=1'+OR+'1'='1"
# Doit retourner 403 (attaque bloquée)
docker stop $(docker ps -q --filter ancestor=beewaf:latest)
```

## Étape 2 : Exporter les images pour le cluster

Le cluster DPC utilise containerd sans registry privé.
Il faut transférer les images manuellement.

```bash
# Sur ta machine Kali :

# 1. Sauvegarder l'image BeeWAF
docker save beewaf:latest -o beewaf-latest.tar
echo "Taille: $(du -h beewaf-latest.tar)"

# 2. Les images ELK — si les workers ont accès à Internet,
#    elles seront pull automatiquement depuis Docker Hub.
#    Sinon, les sauvegarder aussi :
docker pull docker.elastic.co/elasticsearch/elasticsearch:8.11.0
docker pull docker.elastic.co/logstash/logstash:8.11.0
docker pull docker.elastic.co/kibana/kibana:8.11.0
docker pull docker.elastic.co/beats/filebeat:8.11.0

docker save docker.elastic.co/elasticsearch/elasticsearch:8.11.0 -o es-8.11.tar
docker save docker.elastic.co/logstash/logstash:8.11.0 -o logstash-8.11.tar
docker save docker.elastic.co/kibana/kibana:8.11.0 -o kibana-8.11.tar
docker save docker.elastic.co/beats/filebeat:8.11.0 -o filebeat-8.11.tar
```

## Étape 3 : Transférer sur les workers

```bash
# Connexion via bastion DPC
ssh -p 258 user@passrelle.dpc.com.tn

# Depuis le bastion, envoyer les images aux workers :
# (adapter le user et le chemin)
for NODE in 192.168.90.40 192.168.90.50; do
    echo "=== Transfert vers $NODE ==="
    scp beewaf-latest.tar user@$NODE:/tmp/
    # Seulement si pas d'Internet sur les workers :
    # scp es-8.11.tar logstash-8.11.tar kibana-8.11.tar filebeat-8.11.tar user@$NODE:/tmp/
done

# Sur CHAQUE worker node (192.168.90.40 et .50) :
ssh user@192.168.90.40
sudo ctr -n k8s.io images import /tmp/beewaf-latest.tar
# Si pas d'Internet :
# sudo ctr -n k8s.io images import /tmp/es-8.11.tar
# sudo ctr -n k8s.io images import /tmp/logstash-8.11.tar
# sudo ctr -n k8s.io images import /tmp/kibana-8.11.tar
# sudo ctr -n k8s.io images import /tmp/filebeat-8.11.tar
rm /tmp/*.tar

# Vérifier
sudo ctr -n k8s.io images list | grep -E "beewaf|elastic|kibana|logstash|filebeat"
```

## Étape 4 : Déployer sur K8s

```bash
# Sur un master node (192.168.90.10) :
ssh user@192.168.90.10
cd /path/to/beehivepfe2-main

# Déploiement complet (BeeWAF + ELK)
sudo bash k8s/deploy.sh

# Ou sans ELK (juste le WAF)
sudo bash k8s/deploy.sh --no-elk
```

## Étape 5 : Configurer le DNS

Ajouter dans le DNS DPC (ou dans `/etc/hosts` pour tester) :

```
207.180.211.157  beewaf.dpc.com.tn
207.180.211.157  kibana.dpc.com.tn
207.180.211.157  app.dpc.com.tn
```

## Étape 6 : Vérifier que TOUT marche

```bash
# Depuis ta machine Kali (via le bastion/HAProxy) :

# 1. Health check
curl -k https://beewaf.dpc.com.tn/health
# → {"status":"ok"}

# 2. Requête normale (doit passer)
curl -k https://beewaf.dpc.com.tn/
# → 200 OK

# 3. Test SQLi (doit être bloqué)
curl -k "https://beewaf.dpc.com.tn/test?id=1' OR '1'='1"
# → 403 Forbidden

# 4. Test XSS (doit être bloqué)
curl -k "https://beewaf.dpc.com.tn/test?q=<script>alert(1)</script>"
# → 403 Forbidden

# 5. Kibana (si ELK déployé)
curl http://kibana.dpc.com.tn
# → Page Kibana

# 6. Sur un master, vérifier tous les pods :
kubectl get pods -n beewaf -o wide
# beewaf-xxxxx      1/1  Running  (worker .40)
# beewaf-yyyyy      1/1  Running  (worker .50)
# elasticsearch-0   1/1  Running
# logstash-xxxxx    1/1  Running
# kibana-xxxxx      1/1  Running
# filebeat-xxxxx    1/1  Running  (un par node)

# 7. Vérifier les logs dans ES
kubectl exec -n beewaf elasticsearch-0 -- \
  curl -s "http://localhost:9200/beewaf-*/_count"
# → {"count":N} (N > 0 si des requêtes ont été faites)
```

---

## StorageClass requis pour Elasticsearch

Elasticsearch utilise un PersistentVolumeClaim (5Gi).
Vérifier qu'une StorageClass existe :

```bash
kubectl get storageclass
```

Si aucune StorageClass n'est disponible :

```bash
# Option 1 : Installer local-path-provisioner (le plus simple)
kubectl apply -f https://raw.githubusercontent.com/rancher/local-path-provisioner/v0.0.26/deploy/local-path-storage.yaml

# Le marquer comme default
kubectl patch storageclass local-path -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'
```

Ou modifier `k8s/elk/elasticsearch.yaml` pour utiliser un `hostPath` à la place du PVC.

---

## Commandes utiles

```bash
# Logs BeeWAF en temps réel
kubectl logs -f deployment/beewaf -n beewaf

# Logs Elasticsearch
kubectl logs -f statefulset/elasticsearch -n beewaf

# Logs Logstash
kubectl logs -f deployment/logstash -n beewaf

# Accéder à l'admin API BeeWAF
kubectl exec -n beewaf deploy/beewaf -- \
  curl -s -H "X-API-Key: $BEEWAF_API_KEY" http://localhost:8000/admin/stats

# Port-forward pour accès local
kubectl port-forward svc/beewaf-svc 8080:80 -n beewaf
kubectl port-forward svc/kibana 5601:5601 -n beewaf

# Supprimer tout
sudo bash k8s/deploy.sh --delete
```

---

## Résumé : Qu'est-ce qui marche dans chaque composant

| Composant | Ce qu'il fait | Fonctionne ? |
|-----------|--------------|:---:|
| **10 041 regex** | Détection SQLi/XSS/LFI/RCE/etc. | ✅ Compilé au démarrage |
| **ML Engine** | 3 modèles ensemble (RF+GB+IF) | ✅ Pré-entraîné dans l'image |
| **Rate Limiter** | 100 req/min par IP | ✅ |
| **IP Blocklist** | Ban après 10 attaques | ✅ |
| **DDoS Protection** | Flood/slowloris/amplification | ✅ |
| **Deobfuscation** | 18 couches (hex, unicode, etc.) | ✅ |
| **Bot Detection** | Fingerprinting UA + behavior | ✅ |
| **Virtual Patching** | 80+ CVEs (Log4j, etc.) | ✅ |
| **Protocol Validation** | HTTP/headers/body checks | ✅ |
| **Security Headers** | CSP, HSTS, X-Frame, etc. | ✅ |
| **Response Cloaking** | Masque serveur backend | ✅ |
| **Elasticsearch** | Stockage + indexation logs | ✅ (avec StorageClass) |
| **Logstash** | Parse + enrichissement | ✅ |
| **Kibana** | Dashboards temps réel | ✅ |
| **Filebeat** | Collecte logs containers | ✅ (DaemonSet RBAC) |
| **ClamAV** | Scan antivirus fichiers | ⚠️ Non implémenté (code présent mais pas appelé) |
