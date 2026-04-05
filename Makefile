.DEFAULT_GOAL := help
SHELL := /bin/bash

BIN_DIR = $(CURDIR)/bin
CONTROLLER_GEN_VERSION = v0.18.0
CONTROLLER_GEN_BIN_DIR = $(BIN_DIR)/controller-gen-$(CONTROLLER_GEN_VERSION)
CONTROLLER_GEN_FALLBACK = $(CONTROLLER_GEN_BIN_DIR)/controller-gen
CONTROLLER_GEN = $(or $(shell command -v controller-gen 2>/dev/null),$(CONTROLLER_GEN_FALLBACK))
YQ = $(or $(shell command -v yq 2>/dev/null),$(BIN_DIR)/yq)
KUSTOMIZE = $(or $(shell command -v kustomize 2>/dev/null),$(BIN_DIR)/kustomize)
KIND = $(or $(shell command -v kind 2>/dev/null),$(BIN_DIR)/kind)
GOFUMPT = $(or $(shell command -v gofumpt 2>/dev/null),$(BIN_DIR)/gofumpt)
GORELEASER = $(or $(shell command -v goreleaser 2>/dev/null),$(BIN_DIR)/goreleaser)

KIND_CLUSTER = e2e
E2E_RELEASE = secret-detection-operator
E2E_NAMESPACE = secret-detection-system
E2E_IMAGE_REPOSITORY = ghcr.io/lvlcn-t/secret-detection-operator
E2E_IMAGE_TAG = commit-$(shell git rev-parse --short HEAD)
E2E_IMAGE = $(E2E_IMAGE_REPOSITORY):$(E2E_IMAGE_TAG)

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
manifests: rbac-crd sync-chart sync-kustomize ## Generate manifests

.PHONY: sync-chart
sync-chart: rbac-crd $(YQ) ## Sync manifests to the Helm chart
	@hack/sync-chart.sh

.PHONY: sync-kustomize
sync-kustomize: $(KUSTOMIZE) ## Sync Kustomize manifests to Helm chart
	@hack/sync-kustomize.sh

.PHONY: fmt
fmt: $(GOFUMPT) ## Format all Go files with gofumpt
	@$(GOFUMPT) -l -w .

.PHONY: lint
lint: ## Lint with golangci-lint
	@golangci-lint run --config .golangci.yaml --timeout 5m ./...

.PHONY: test
test: ## Run all unit tests (short mode)
	@go test -race -count=1 -v -test.short ./...

.PHONY: kind-cluster
kind-cluster: $(KIND) ## Create local kind cluster named e2e
	@if $(KIND) get clusters | grep -q '^$(KIND_CLUSTER)$$'; then \
		echo "kind cluster '$(KIND_CLUSTER)' already exists"; \
	else \
		$(KIND) create cluster --name $(KIND_CLUSTER); \
	fi

.PHONY: kind-delete
kind-delete: $(KIND) ## Delete local kind cluster named e2e
	@if $(KIND) get clusters | grep -q '^$(KIND_CLUSTER)$$'; then \
		$(KIND) delete cluster --name $(KIND_CLUSTER); \
	else \
		echo "No '$(KIND_CLUSTER)' cluster found, nothing to delete."; \
	fi

.PHONY: e2e-image
e2e-image: $(GORELEASER) _check-docker ## Build local e2e image via goreleaser snapshot
	@$(GORELEASER) release --snapshot --clean --config .goreleaser-ci.yaml

.PHONY: e2e-load-image
e2e-load-image: kind-cluster e2e-image ## Load local e2e image into kind cluster
	@$(KIND) load docker-image $(E2E_IMAGE) --name $(KIND_CLUSTER)

.PHONY: e2e-deploy
e2e-deploy: e2e-load-image ## Deploy operator with Helm to local kind cluster
	@helm upgrade --install $(E2E_RELEASE) ./chart \
	  --namespace $(E2E_NAMESPACE) \
	  --create-namespace \
	  --set image.repository=$(E2E_IMAGE_REPOSITORY) \
	  --set image.tag=$(E2E_IMAGE_TAG) \
	  --set image.pullPolicy=Never \
	  --set serviceMonitor.enabled=false \
	  --wait \
	  --timeout 300s

.PHONY: test-e2e
test-e2e: e2e-deploy ## Build, deploy, and run e2e tests locally
	@go test -tags=e2e -v -race -count=1 ./test/e2e/...

.PHONY: _check-docker
_check-docker:
	$(if $(shell command -v docker 2>/dev/null),,$(error docker is required but not found in PATH. Please install Docker first.))

$(CONTROLLER_GEN_FALLBACK): ## Install controller-gen
	@mkdir -p $(CONTROLLER_GEN_BIN_DIR)
	GOBIN=$(CONTROLLER_GEN_BIN_DIR) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION)

$(YQ): ## Install yq
	GOBIN=$(BIN_DIR) go install github.com/mikefarah/yq/v4@latest
	
$(KUSTOMIZE): ## Install kustomize
	GOBIN=$(BIN_DIR) GO111MODULE=on go install sigs.k8s.io/kustomize/kustomize/v5@latest

$(KIND): ## Install kind
	GOBIN=$(BIN_DIR) go install sigs.k8s.io/kind/cmd/kind

$(GOFUMPT): ## Install gofumpt
	GOBIN=$(BIN_DIR) go install mvdan.cc/gofumpt@latest

$(GORELEASER): ## Install goreleaser
	GOBIN=$(BIN_DIR) go install github.com/goreleaser/goreleaser/v2@latest
