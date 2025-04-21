.DEFAULT_GOAL := generate
SHELL := /bin/bash

CONTROLLER_GEN = $(shell pwd)/bin/controller-gen

.PHONY: generate manifests $(CONTROLLER_GEN)

generate: $(CONTROLLER_GEN) ## Run code generation for deepcopy, defaults, etc.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

manifests: $(CONTROLLER_GEN) ## Generate CRD YAMLs
	$(CONTROLLER_GEN) rbac:roleName=secret-detection-operator crd \
		paths="./apis/..." \
		paths="./controllers" \
		output:crd:dir=config/crd/bases \
		output:rbac:dir=config/rbac
	@cp config/crd/bases/*.yaml chart/crds/

$(CONTROLLER_GEN):
	GOBIN=$(shell pwd)/bin go install sigs.k8s.io/controller-tools/cmd/controller-gen@latest
