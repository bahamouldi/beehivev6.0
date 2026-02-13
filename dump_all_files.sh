#!/bin/bash
# Dumps all 13 requested files with ===FILE: filename=== markers
FILES=(
  "k8s/elk/elasticsearch.yaml"
  "k8s/elk/logstash.yaml"
  "k8s/elk/kibana.yaml"
  "k8s/elk/filebeat.yaml"
  "k8s/deployment.yaml"
  "k8s/service.yaml"
  "k8s/ingress.yaml"
  "elk/logstash/pipeline/beewaf.conf"
  "k8s/namespace.yaml"
  "k8s/secrets.yaml"
  "setup_kibana_dashboard.py"
  "generate_kibana_traffic.py"
  "app/main.py"
)

OUTPUT="all_files_dump.txt"
> "$OUTPUT"

for f in "${FILES[@]}"; do
  echo "===FILE: $f===" >> "$OUTPUT"
  cat "$f" >> "$OUTPUT"
  echo "" >> "$OUTPUT"
done

echo "✅ All 13 files dumped to $OUTPUT"
echo "   Total lines: $(wc -l < "$OUTPUT")"
