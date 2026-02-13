#!/bin/bash
# =============================================================================
# 🐝 BeeWAF — Préparation des Images ELK pour Cluster Offline
#
# Si le cluster K8s ne peut pas télécharger les images depuis internet,
# ce script les prépare localement sur Kali puis les transfère.
#
# Étape 1: Exécuter sur Kali (machine locale avec Docker)
# Étape 2: Transférer les fichiers .tar.gz vers testhamaster1
# Étape 3: Importer avec ctr sur le master
#
# Usage: bash k8s/prepare-elk-images.sh
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

IMAGES=(
    "docker.elastic.co/elasticsearch/elasticsearch:8.11.0"
    "docker.elastic.co/logstash/logstash:8.11.0"
    "docker.elastic.co/kibana/kibana:8.11.0"
    "docker.elastic.co/beats/filebeat:8.11.0"
    "busybox:1.36"
)

OUTPUT_DIR="./elk-images"
mkdir -p "$OUTPUT_DIR"

echo -e "${BOLD}${CYAN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  🐝 BeeWAF — Préparation Images ELK (Cluster Offline)      ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Étape 1 : Pull des images ──
echo -e "${YELLOW}[1/3] Téléchargement des images Docker...${NC}"
echo -e "  ⚠️  Taille totale: ~3.5 GB — cela peut prendre du temps"
echo ""

for IMG in "${IMAGES[@]}"; do
    SHORT=$(echo "$IMG" | awk -F'/' '{print $NF}' | tr ':' '-')
    echo -ne "  📦 $IMG... "
    if docker pull "$IMG" 2>/dev/null; then
        echo -e "${GREEN}✅${NC}"
    else
        echo -e "${RED}❌ Échec pull${NC}"
        continue
    fi
done

# ── Étape 2 : Sauvegarder en tar.gz ──
echo -e "\n${YELLOW}[2/3] Sauvegarde des images en tar.gz...${NC}"

for IMG in "${IMAGES[@]}"; do
    SHORT=$(echo "$IMG" | awk -F'/' '{print $NF}' | tr ':' '-')
    TARFILE="$OUTPUT_DIR/${SHORT}.tar.gz"
    echo -ne "  💾 ${SHORT}.tar.gz... "
    if docker save "$IMG" | gzip > "$TARFILE" 2>/dev/null; then
        SIZE=$(du -h "$TARFILE" | cut -f1)
        echo -e "${GREEN}✅ ($SIZE)${NC}"
    else
        echo -e "${RED}❌${NC}"
    fi
done

echo -e "\n${YELLOW}[3/3] Instructions de transfert...${NC}"

echo ""
echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}📋 INSTRUCTIONS:${NC}"
echo ""
echo -e "${BOLD}A) Transférer vers testhamaster1 via la chaîne SSH:${NC}"
echo ""
echo "  # Option 1 — SCP via tunnel (recommandé):"
echo "  # D'abord, créer un tunnel SSH:"
echo "  ssh -L 2222:192.168.90.10:22 user@passerelle.dpc.com.tn -p 258"
echo ""
echo "  # Puis transférer (dans un autre terminal):"
echo "  scp -P 2222 elk-images/*.tar.gz user@localhost:/tmp/"
echo ""
echo "  # Option 2 — SCP direct (si accès direct):"
echo "  scp elk-images/*.tar.gz user@192.168.90.10:/tmp/"
echo ""
echo -e "${BOLD}B) Sur testhamaster1, importer les images dans containerd:${NC}"
echo ""
echo '  for f in /tmp/elasticsearch-8.11.0.tar.gz \\'
echo '           /tmp/logstash-8.11.0.tar.gz \\'
echo '           /tmp/kibana-8.11.0.tar.gz \\'
echo '           /tmp/filebeat-8.11.0.tar.gz \\'
echo '           /tmp/busybox-1.36.tar.gz; do'
echo '      echo "Importing $f..."'
echo '      gunzip -c "$f" | sudo ctr -n k8s.io images import -'
echo '      echo "Done: $f"'
echo '  done'
echo ""
echo -e "${BOLD}C) Vérifier les images importées:${NC}"
echo ""
echo "  sudo ctr -n k8s.io images ls | grep -E 'elastic|filebeat|busybox'"
echo ""
echo -e "${BOLD}D) Déployer la stack ELK:${NC}"
echo ""
echo "  cd /chemin/vers/beehivepfe2-main"
echo "  bash k8s/deploy-elk.sh"
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"

echo ""
echo -e "${GREEN}✅ Images prêtes dans ${OUTPUT_DIR}/:${NC}"
ls -lh "$OUTPUT_DIR/"
echo ""
echo -e "${BOLD}Taille totale:${NC} $(du -sh "$OUTPUT_DIR" | cut -f1)"
