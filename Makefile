SKILL := plugins/zk-audit/skills/zk-audit
TOOL := $(SKILL)/tools/gnark-inventory

.PHONY: check vet test test-types fixtures lint-kb standalone sync-schemas sync-agents sync-profiles vendor eval-pocs eval-score eval-audit fmt-check cover validate-plugin release-check

## check: everything CI runs (offline)
check: vet test lint-kb standalone eval-score

vet:
	cd $(TOOL) && go vet ./...

test:
	cd $(TOOL) && go test ./...

## fixtures: download gnark for the test fixtures (network), then run the
## typed-mode and verifier-regeneration tests that are otherwise skipped
fixtures:
	cd testdata/pool && go mod download
	cd testdata/edge && go mod download
	cd testdata/sol-gnark-abi && go mod download
	cd testdata/lib-gadgets && go mod download
	cd testdata/pool && go vet ./...
	cd testdata/edge && go vet ./...
	cd testdata/sol-gnark-abi && go vet ./...
	cd testdata/lib-gadgets && go vet ./...

test-types: fixtures
	cd $(TOOL) && ZK_INVENTORY_REQUIRE_TYPES=1 go test -count=1 ./internal/inventory/ ./internal/verifier/

lint-kb:
	cd $(TOOL) && go run . lint-kb ../..

## standalone: copy only the skill folder into a throwaway ~/.claude/skills and
## run the deterministic pipeline from the copy (the pashov-style install)
standalone:
	test/standalone-skill.sh

## eval-pocs: run the eval PoCs of the pool and lib-gadgets (Go; the
## latter through gnark-inventory harness wrappers), liveness-roots and
## sol-gnark-abi (Foundry; the second against a real gnark-exported verifier
## with a real proof) fixtures in sanitized scratch copies, inside the skill's sandbox and
## offline; missing modules (testify for gnark/test) and the pinned solc are
## fetched first, outside the sandbox, by `go list` and a compile-only
## `forge build`
eval-pocs: fixtures
	EVAL_GOPROXY="$$(go env GOPROXY)" evals/run-pocs pool "$$(mktemp -d)"
	EVAL_GOPROXY="$$(go env GOPROXY)" evals/run-pocs liveness-roots "$$(mktemp -d)"
	EVAL_GOPROXY="$$(go env GOPROXY)" evals/run-pocs sol-gnark-abi "$$(mktemp -d)"
	EVAL_GOPROXY="$$(go env GOPROXY)" evals/run-pocs lib-gadgets "$$(mktemp -d)"

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

## fmt-check: gofmt over every Go file in the repository (tool, scorer,
## fixtures, eval PoCs), vendored code excluded
fmt-check:
	@files="$$(gofmt -l $$(git ls-files '*.go' | grep -v '/vendor/'))"; \
	if [ -n "$$files" ]; then echo "gofmt needed:"; echo "$$files"; exit 1; fi; echo "gofmt: clean"

## cover: unit-test coverage of the tool and the scorer; writes
## coverage/*.out and coverage/summary.md, fails under COVER_MIN percent.
## Run after `make fixtures` so the typed-mode tests count.
COVER_MIN ?= 65
cover:
	mkdir -p coverage
	cd $(TOOL) && go test -count=1 -coverprofile=$(CURDIR)/coverage/gnark-inventory.out ./... >/dev/null
	cd evals/score && go test -count=1 -coverprofile=$(CURDIR)/coverage/score.out ./... >/dev/null
	@{ echo "| Module | Statements covered |"; echo "|---|---|"; \
	  for m in gnark-inventory score; do \
	    d=$(TOOL); [ $$m = score ] && d=evals/score; \
	    t="$$(cd $$d && go tool cover -func=$(CURDIR)/coverage/$$m.out | awk '/^total:/ {print $$NF}')"; \
	    echo "| $$m | $$t |"; done; } | tee coverage/summary.md
	@for m in gnark-inventory score; do \
	  d=$(TOOL); [ $$m = score ] && d=evals/score; \
	  t="$$(cd $$d && go tool cover -func=$(CURDIR)/coverage/$$m.out | awk '/^total:/ {sub("%","",$$NF); print $$NF}')"; \
	  awk -v t="$$t" -v min=$(COVER_MIN) -v m=$$m 'BEGIN { if (t + 0 < min) { printf "coverage of %s is %s%%, under the floor of %s%%\n", m, t, min; exit 1 } }'; \
	done

## validate-plugin: claude plugin validate on the marketplace and the plugin
## (needs the Claude Code CLI, no API key). Add --profile directory once a
## LICENSE exists (docs/licence-options.md).
validate-plugin:
	claude plugin validate .
	claude plugin validate --strict plugins/zk-audit

## release-check: VERSION, plugin.json, marketplace.json and the tool's
## Version agree, and CHANGELOG.md is in shape; TAG=zk-audit--vX.Y.Z also
## checks the tag name and its CHANGELOG section (the release workflow)
release-check:
	scripts/release-check $(if $(TAG),--tag $(TAG))
