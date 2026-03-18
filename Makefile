SHELL := /usr/bin/env bash

.PHONY: test-local test-local-clean

## Run local e2e smoke test (Mongo + app + /actuator/health)
test-local:
	@mkdir -p scripts
	@chmod +x scripts/e2e_local.sh || true
	@./scripts/e2e_local.sh

## Stop containers, remove network. Set REMOVE_VOLUME=1 to delete Mongo volume.
test-local-clean:
	@REMOVE_VOLUME=$${REMOVE_VOLUME:-0} ./scripts/e2e_local.sh clean
