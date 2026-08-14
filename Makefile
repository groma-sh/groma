LOCALBIN ?= $(shell pwd)/bin
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
CONTROLLER_GEN_VERSION ?= v0.21.0
GOLANGCI_LINT ?= $(LOCALBIN)/golangci-lint
GOLANGCI_LINT_VERSION ?= v2.12.2
GO_LICENSES ?= $(LOCALBIN)/go-licenses

KIND_CLUSTER ?= groma-dev
KIND_NODE_IMAGE ?= kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5

$(LOCALBIN):
	mkdir -p $(LOCALBIN)

.PHONY: controller-gen
controller-gen: $(LOCALBIN)
	GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION)

.PHONY: golangci-lint
golangci-lint: $(LOCALBIN)
	GOBIN=$(LOCALBIN) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

.PHONY: go-licenses
go-licenses: $(LOCALBIN)
	GOBIN=$(LOCALBIN) go install github.com/google/go-licenses@v1.6.0

.PHONY: generate
generate: controller-gen ## Regenerate api/v1alpha1 deepcopy methods.
	$(CONTROLLER_GEN) object:headerFile="" paths="./api/v1alpha1/..."

.PHONY: manifests
manifests: controller-gen ## Regenerate CRD YAML in config/crd/bases.
	$(CONTROLLER_GEN) crd paths="./api/v1alpha1/..." output:crd:artifacts:config=config/crd/bases

.PHONY: build
build: ## Build the groma CLI and the controller-manager.
	go build -o bin/groma ./cmd/groma
	go build -o bin/groma-manager ./cmd/manager

.PHONY: test
test: ## Run unit tests.
	go test ./...

.PHONY: test-race
test-race: ## Run unit tests under the race detector with coverage.
	go test -race -covermode=atomic -coverprofile=coverage.out -coverpkg=./... ./...

.PHONY: cover
cover: test-race ## Show per-function coverage.
	go tool cover -func=coverage.out

.PHONY: lint
lint: golangci-lint ## Run golangci-lint (same config as CI).
	$(GOLANGCI_LINT) run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint with --fix.
	$(GOLANGCI_LINT) run --fix

.PHONY: vuln
vuln: ## Reachability-aware vulnerability scan, gated by .github/govulncheck-allow.txt (same as CI).
	./hack/govulncheck.sh

.PHONY: licenses
licenses: go-licenses ## Fail on a forbidden or unknown licence in the build closure.
	$(GO_LICENSES) check ./cmd/... --disallowed_types=forbidden,restricted,unknown \
		--ignore github.com/alibabacloud-go/cr-20160607

.PHONY: verify
verify: verify-generated verify-tidy ## Everything CI checks that needs no cluster.
	$(MAKE) lint
	$(MAKE) test-race

.PHONY: verify-generated
verify-generated: generate manifests ## Fail if generated files are stale.
	@git diff --exit-code -- api/ config/ \
		|| { echo "generated files are stale: run 'make generate manifests' and commit"; exit 1; }

.PHONY: verify-tidy
verify-tidy: ## Fail if go.mod/go.sum are not tidy.
	@go mod tidy
	@git diff --exit-code -- go.mod go.sum \
		|| { echo "go.mod/go.sum not tidy: run 'go mod tidy' and commit"; exit 1; }
	@go mod verify

.PHONY: docker-build-manager
docker-build-manager: ## Build the controller-manager image (see Dockerfile.manager).
	docker build -f Dockerfile.manager -t groma-manager:latest .

.PHONY: kind-up
kind-up: ## Create a local kind cluster with the default (non-enforcing) CNI.
	kind create cluster --name $(KIND_CLUSTER) --image $(KIND_NODE_IMAGE) \
		--config .github/kind/default.yaml

.PHONY: kind-down
kind-down: ## Delete the local kind cluster.
	kind delete cluster --name $(KIND_CLUSTER)

.PHONY: e2e-local
e2e-local: build ## Run the CLI against the demo workloads on the current context.
	kubectl apply -f examples/demo/namespaces.yaml
	kubectl apply -f examples/demo/policy.yaml
	./bin/groma --intent examples/intent.yaml --mode both --output evidence.json --html report.html

.PHONY: e2e-manager
e2e-manager: docker-build-manager ## Load the manager into kind and install it.
	kind load docker-image groma-manager:latest --name $(KIND_CLUSTER)
	kubectl apply -f config/crd/bases/
	kubectl apply -f deploy/rbac.yaml
	kubectl apply -f deploy/manager.yaml
	kubectl -n groma-system rollout status deployment/groma-manager --timeout=5m

.PHONY: help
help: ## List targets.
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
