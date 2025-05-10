#!/bin/bash

set -euo pipefail

export PATH="$PATH:$(pwd)/bin"

# where to read generated RBAC
CONFIG_RBAC="config/.tmp/rbac"
# where to write your chart templates
CHART_TEMPLATES="chart/templates"

echo "➤ Syncing RBAC from $CONFIG_RBAC → $CHART_TEMPLATES"
for src in "${CONFIG_RBAC}"/*.yaml; do
  base=$(basename "$src")
  if [[ "$base" == "kustomization.yaml" ]]; then
    echo "  • skipping $base"
    continue
  fi

  dest="${CHART_TEMPLATES}/${base}"

  apiVersion=$(yq e '.apiVersion' "$src")
  kind=$(yq e '.kind' "$src")

  # grab everything except apiVersion, kind, and metadata
  body=$(yq e 'del(.apiVersion, .kind, .metadata)' --no-doc "$src")

  cat >"$dest" <<EOF
apiVersion: ${apiVersion}
kind: ${kind}
metadata:
  name: {{ include "chart.fullname" . }}-${base%.yaml}
  labels:
    {{- include "chart.labels" . | nindent 4 }}
  annotations:
    description: Grants permission to manage exposed secrets.
${body}
EOF

  echo "  • wrote $dest"
done
rm -rf "$CONFIG_RBAC"
echo "✅ RBAC sync complete."
