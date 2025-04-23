#!/usr/bin/env bash
set -euo pipefail

CHART_DIR="./chart"
CONFIG_DIR="./config"
GENERATED_DIR="$CONFIG_DIR/generated"
RBAC_DIR="$CONFIG_DIR/rbac"
CRD_BASES_DIR="$CONFIG_DIR/crd/bases"
DEFAULT_DIR="$CONFIG_DIR/default"

echo "➤ Cleaning up old generated manifests..."
rm -rf "$GENERATED_DIR"
mkdir -p "$GENERATED_DIR"

echo "➤ Rendering Helm chart to YAML..."
VERSION=$(git describe --tags --abbrev=0 --match 'v*' 2>/dev/null || echo "v0.0.0")
helm template secret-detection-operator \
  --version "${VERSION#v}" \
  --namespace "secret-detection-system" \
  --set "image.tag=$VERSION" \
  "$CHART_DIR" >"$GENERATED_DIR/manifests.yaml"

echo "➤ Splitting multi-doc into individual files..."
(
  cd "$GENERATED_DIR"
  yq eval-all --split-exp '.metadata.name + "-" + .kind' --no-doc manifests.yaml
  # normalize extension
  for f in *.yml; do mv "$f" "${f%.yml}.yaml"; done
  rm manifests.yaml
)

echo "➤ Segregating RBAC resources..."
for file in "$GENERATED_DIR"/*.yaml; do
  kind=$(yq e '.kind' "$file")
  case "$kind" in
  ClusterRole | ClusterRoleBinding | Role | RoleBinding | ServiceAccount)
    mv "$file" "$RBAC_DIR"/
    ;;
  *) ;;
  esac
done

echo "➤ Rebuilding kustomizations via kustomize CLI..."
for base in "$CRD_BASES_DIR" "$RBAC_DIR" "$GENERATED_DIR"; do
  echo "   • $base"
  rm -f "$base/kustomization.yaml"
  (cd "$base" && kustomize create --autodetect)
done

echo "   • $DEFAULT_DIR"
rm -f "$DEFAULT_DIR/kustomization.yaml"
(
  cd "$DEFAULT_DIR"
  kustomize create
  kustomize edit add resource ../crd
  kustomize edit add resource ../rbac
  kustomize edit add resource ../generated
)

echo "🎉 Done!"
