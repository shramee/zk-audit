SKILL := plugins/zk-audit/skills/zk-audit
TOOL := $(SKILL)/tools/gnark-inventory

.PHONY: check vet test test-types fixtures lint-kb standalone sync-schemas sync-agents vendor eval-pocs eval-score eval-audit

## check: everything CI runs (offline)
check: vet test lint-kb standalone eval-score

vet:
	cd $(TOOL) && go vet ./...

test:
	cd $(TOOL) && go test ./...

## fixtures: download gnark for the test fixtures (network), then run the
## typed-mode tests that are otherwise skipped
fixtures:
	cd testdata/pool && go mod download
	cd testdata/edge && go mod download
	cd testdata/pool && go vet ./...
	cd testdata/edge && go vet ./...

test-types: fixtures
	cd $(TOOL) && ZK_INVENTORY_REQUIRE_TYPES=1 go test -count=1 ./internal/inventory/

lint-kb:
	cd $(TOOL) && go run . lint-kb ../..

## standalone: copy only the skill folder into a throwaway ~/.claude/skills and
## run the deterministic pipeline from the copy (the pashov-style install)
standalone:
	test/standalone-skill.sh

## eval-pocs: run the pool fixture's eval PoCs in a sanitized scratch copy
## (network for the fixture modules, like test-types)
eval-pocs: fixtures
	EVAL_GOPROXY="$$(go env GOPROXY)" evals/run-pocs pool "$$(mktemp -d)"

## sync-schemas: copy the canonical schemas into the tool's embed directory
sync-schemas:
	cp $(SKILL)/schemas/*.schema.json $(TOOL)/internal/validate/schemas/

## sync-agents: copy the skill's agent briefs (canonical) to the plugin's agents/
sync-agents:
	cp $(SKILL)/agents/*.md plugins/zk-audit/agents/

vendor:
	cd $(TOOL) && go mod tidy && go mod vendor

## eval-score: unit tests of the eval scorer (offline)
eval-score:
	cd evals/score && go vet ./... && go test ./...

## eval-audit: run audit cases headless and score them (model calls, costs
## money). CASES=pool-quick RUNS=3 BUDGET=30 by default.
CASES ?= pool-quick
RUNS ?= 3
BUDGET ?= 30
eval-audit:
	evals/run-audit --runs $(RUNS) --budget $(BUDGET) $(CASES)
