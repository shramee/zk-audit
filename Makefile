SKILL := plugins/zk-audit/skills/zk-audit
TOOL := $(SKILL)/tools/gnark-inventory

.PHONY: check vet test test-types fixtures lint-kb sync-schemas sync-agents vendor eval-pocs

## check: everything CI runs (offline)
check: vet test lint-kb

vet:
	cd $(TOOL) && go vet ./...

test:
	cd $(TOOL) && go test ./...

## fixtures: download gnark for the test fixtures (network), then run the
## typed-mode tests that are otherwise skipped
fixtures:
	cd $(TOOL)/testdata/pool && go mod download
	cd $(TOOL)/testdata/edge && go mod download
	cd $(TOOL)/testdata/pool && go vet ./...
	cd $(TOOL)/testdata/edge && go vet ./...

test-types: fixtures
	cd $(TOOL) && ZK_INVENTORY_REQUIRE_TYPES=1 go test -count=1 ./internal/inventory/

lint-kb:
	cd $(TOOL) && go run . lint-kb ../..

## eval-pocs: run the pool fixture's eval PoCs in a sanitized scratch copy
## (network for the fixture modules, like test-types)
eval-pocs: fixtures
	EVAL_GOPROXY="$$(go env GOPROXY)" plugins/zk-audit/evals/run-pocs pool "$$(mktemp -d)"

## sync-schemas: copy the canonical schemas into the tool's embed directory
sync-schemas:
	cp $(SKILL)/schemas/*.schema.json $(TOOL)/internal/validate/schemas/

## sync-agents: copy the skill's agent briefs (canonical) to the plugin's agents/
sync-agents:
	cp $(SKILL)/agents/*.md plugins/zk-audit/agents/

vendor:
	cd $(TOOL) && go mod tidy && go mod vendor
