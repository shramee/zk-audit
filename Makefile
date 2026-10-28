TOOL := plugins/zk-audit/tools/gnark-inventory
SKILL := plugins/zk-audit/skills/zk-audit

.PHONY: check vet test test-types fixtures lint-kb sync-schemas vendor

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
	cd $(TOOL) && go run . lint-kb ../../skills/zk-audit

## sync-schemas: copy the canonical schemas into the tool's embed directory
sync-schemas:
	cp plugins/zk-audit/schemas/*.schema.json $(TOOL)/internal/validate/schemas/

vendor:
	cd $(TOOL) && go mod tidy && go mod vendor
