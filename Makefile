SKILL := plugins/zk-audit/skills/zk-audit
TOOL := $(SKILL)/tools/gnark-inventory

.PHONY: check vet test test-types fixtures lint-kb standalone sync-schemas sync-agents sync-profiles vendor eval-pocs eval-score eval-audit

## check: everything CI runs (offline)
check: vet test lint-kb standalone eval-score

vet:
	cd $(TOOL) && go vet ./...

test:
	cd $(TOOL) && go test ./...

## fixtures: download gnark for every test fixture module (network), then vet
## each, so typed loading and the eval PoCs work offline afterwards. A module
## whose go.mod needs Go >= 1.25 (the advisory replays on gnark >= v0.15) is
## best-effort: it is skipped with a warning when no such toolchain is reachable,
## so the offline pipeline is not blocked. Modules that build on Go 1.24 are
## strict (a failure fails the target).
fixtures:
	@fail=0; for m in $$(find testdata -maxdepth 2 -name go.mod | sort); do \
	  d=$$(dirname $$m); \
	  need=$$(sed -n 's/^go \(1\.[0-9]*\).*/\1/p' $$m | head -1); \
	  newer=$$(printf '%s\n1.25\n' "$$need" | sort -V | tail -1); \
	  echo "fixtures: $$d (go $$need)"; \
	  if (cd $$d && go mod download && GOFLAGS=-mod=mod go vet ./...); then :; \
	  elif [ "$$newer" = "$$need" ]; then \
	    echo "fixtures: WARNING: $$d needs Go >= $$need and did not build; skipping (set GOTOOLCHAIN to a 1.25+ toolchain to include it)" >&2; \
	  else fail=1; fi; \
	done; [ $$fail -eq 0 ]

test-types: fixtures
	cd $(TOOL) && ZK_INVENTORY_REQUIRE_TYPES=1 go test -count=1 ./internal/inventory/ ./internal/verifier/

lint-kb:
	cd $(TOOL) && go run . lint-kb ../..

## standalone: copy only the skill folder into a throwaway ~/.claude/skills and
## run the deterministic pipeline from the copy (the pashov-style install)
standalone:
	test/standalone-skill.sh

## eval-pocs: run every fixture's eval PoCs (Go, and Foundry for the integration
## fixtures) in sanitized scratch copies, inside the skill's sandbox and
## offline. Go fixtures run directly (the gnark-inventory harness wrappers of
## lib-gadgets included); the Foundry ones (liveness-roots, sol-gnark-abi, and
## the mock-verifier integration fixtures) need forge. Missing modules (testify
## for gnark/test) and the pinned solc are fetched first, outside the sandbox,
## by `go list` and a compile-only `forge build`
eval-pocs: fixtures
	EVAL_GOPROXY="$$(go env GOPROXY)" evals/run-pocs all "$$(mktemp -d)"

## sync-schemas: copy the canonical schemas into the tool's embed directory
sync-schemas:
	cp $(SKILL)/schemas/*.schema.json $(TOOL)/internal/validate/schemas/

## sync-agents: copy the skill's agent briefs (canonical) to the plugin's agents/
sync-agents:
	cp $(SKILL)/agents/*.md plugins/zk-audit/agents/

## sync-profiles: regenerate the profile and agent tables in SKILL.md and
## references/orchestration.md from the tool's profiles.json
sync-profiles:
	cd $(TOOL) && go run . profiles --sync-docs ../..

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
