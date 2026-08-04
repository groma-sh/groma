LOCALBIN ?= $(shell pwd)/bin
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
CONTROLLER_GEN_VERSION ?= v0.21.0

$(LOCALBIN):
	mkdir -p $(LOCALBIN)

.PHONY: controller-gen
controller-gen: $(LOCALBIN)
	GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION)

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
test:
	go test ./...

.PHONY: docker-build-manager
docker-build-manager: ## Build the controller-manager image (see Dockerfile.manager).
	docker build -f Dockerfile.manager -t groma-manager:latest .
