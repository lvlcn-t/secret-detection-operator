.DEFAULT_GOAL := help
SHELL := /bin/bash

CONTROLLER_GEN = $(shell pwd)/bin/controller-gen

.PHONY: help
help: ## Display this help
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "\033[36m%-20s\033[0m- %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: gen
gen: $(CONTROLLER_GEN) ## Run code generation for deepcopy, defaults, etc.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: manifests
manifests: $(CONTROLLER_GEN) ## Generate CRDs and RBAC manifests
	$(CONTROLLER_GEN) rbac:roleName=secret-detection-operator crd \
	  paths="./apis/..." paths="./controllers" \
	  output:crd:dir=config/crd/bases \
	  output:rbac:dir=config/.tmp/rbac
	@find config/crd/bases -type f -name '*.yaml' ! -name 'kustomization.yaml' -exec cp {} chart/crds/ \;
	@$(MAKE) sync-helm-rbac

.PHONY: sync-helm-rbac
sync-helm-rbac: ## Sync RBAC manifests to Helm chart
	@hack/sync-helm-rbac.sh

$(CONTROLLER_GEN): ## Install controller-gen
	GOBIN=$(shell pwd)/bin go install sigs.k8s.io/controller-tools/cmd/controller-gen@latest
