.DEFAULT_GOAL := help
SHELL := /bin/bash

CONTROLLER_GEN = $(shell pwd)/bin/controller-gen
YQ = $(shell pwd)/bin/yq
KUSTOMIZE = $(shell pwd)/bin/kustomize

.PHONY: help
help: ## Display this help
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "\033[36m%-20s\033[0m- %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: gen
gen: $(CONTROLLER_GEN) ## Run code generation for deepcopy, defaults, etc.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: rbac-crd
rbac-crd: $(CONTROLLER_GEN) ## Generate RBAC manifests
	$(CONTROLLER_GEN) rbac:roleName=secret-detection-operator crd \
	  paths="./apis/..." paths="./controllers" \
	  output:crd:dir=config/crd/bases \
	  output:rbac:dir=config/.tmp/rbac
	@find config/crd/bases -type f -name '*.yaml' ! -name 'kustomization.yaml' -exec cp {} chart/crds/ \;

.PHONY: manifests
manifests: rbac-crd webhook sync-chart sync-kustomize ## Generate manifests

.PHONY: sync-chart
sync-chart: $(YQ) ## Sync manifests to the Helm chart
	@hack/sync-chart.sh

.PHONY: sync-kustomize
sync-kustomize: $(KUSTOMIZE) ## Sync Kustomize manifests to Helm chart
	@hack/sync-kustomize.sh

$(CONTROLLER_GEN): ## Install controller-gen
	GOBIN=$(shell pwd)/bin go install sigs.k8s.io/controller-tools/cmd/controller-gen@latest

$(YQ): ## Install yq
	GOBIN=$(shell pwd)/bin go install github.com/mikefarah/yq/v4@latest
	
$(KUSTOMIZE): ## Install kustomize
	GOBIN=$(shell pwd)/bin GO111MODULE=on go install sigs.k8s.io/kustomize/kustomize/v5@latest