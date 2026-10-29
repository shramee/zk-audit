# Design notes

Where the implementation deviates from `PLAN.md`, or makes a choice the plan
left open, it is recorded here with the reason.

## Packaging

- **Entry point name.** Claude Code namespaces plugin skills and commands as
  `/<plugin>:<name>`. The skill is named `zk-audit`, so the full form is
  `/zk-audit:zk-audit`; `/zk-audit` works where the runtime resolves
  unambiguous short names. `setup`, `recon` and `diff` are commands
  (`/zk-audit:setup` etc.) as in PLAN §7, and also skill arguments
  (`/zk-audit setup|recon|diff`), which is the only form a standalone skill
  install has. The commands are thin wrappers around
  `references/modes/<mode>.md`.
- **Self-contained skill folder** (deviation from PLAN §7, which put
  `tools/`, `scripts/` and `schemas/` at the plugin root). They live under
  `plugins/zk-audit/skills/zk-audit/` so the folder can be copied alone into
  `~/.claude/skills/zk-audit`, the pashov/skills install route
  (`docs/pashov-parity.md`). Every path in the skill is `{skill}/...`; a docs
  test forbids `{plugin}` and paths above `{skill}`, and
  `test/standalone-skill.sh` (in `make check`) runs the pipeline from a copy.
- **Agent files exist twice.** Claude Code discovers plugin agents only in
  `plugins/zk-audit/agents/`, and a standalone copy needs the briefs inside the
  skill. `skills/zk-audit/agents/*.md` is canonical; `make sync-agents` copies
  it and `TestAgentBriefsInSync` fails on drift. Without the plugin agent
  types, Phase 4 briefs a general-purpose agent with the file.
- **Read-only agent types.** Hunters and critics run as `zk-audit:hunter`
  and `zk-audit:critic` (one generic hunter type; the lens comes from the
  bundle), with `tools: Read, Grep, Glob` like the refuter, so in a plugin
  install read-only on the target is structural (x-ray P-1). Plugin agents
  support `name`, `description`, `tools`, `disallowedTools` and `model`
  frontmatter; `claude plugin validate` passes any `tools:` value, so
  `TestReadOnlyAgentsHaveNoWriteTools` checks that the three read-only
  agents declare a `tools:` list (an agent without one inherits every tool)
  that holds no write-capable tool. A standalone install has no agent types:
  the orchestrator briefs a general-purpose agent with the same file and
  limits its tools by prompt. Because hunters have no shell, `bundle`
  resolves the gnark std directory in the module cache itself and writes
  its absolute path (or "not available") into every bundle.
- **Version.** `skills/zk-audit/VERSION` (semver) equals `plugin.json` and the
  tool's `Version` (tested). `scripts/check-version` is a non-blocking update
  check modelled on pashov's: one GET of the published `VERSION`, a warning
  only when the local copy is older, silent otherwise, opt-out with
  `ZK_AUDIT_NO_UPDATE_CHECK=1`. It is the one network call hard rule 8 allows
  without asking; it sends nothing about the target.
- **No `allowed-tools` on the skill.** The skill needs Agent, Bash, Read, Write
  (output dir only) and AskUserQuestion. Restricting the list risks silently
  dropping a tool on another runtime, and the read-only rule is enforced by the
  agent prompts and agent `tools:` allowlists instead.
- **`references/severity.md` is folded into `judging.md`.** Severity and
  confidence are assigned in the same pass as the gates, so one file avoids
  drift between them.
- **Two extra reference files**: `companions.md` (detection and install
  commands for §6 companions, used by setup mode and Phase 0) and
  `poc-templates.md` (the `PoC:` field of each vector names a template there).

## gnark-inventory

- **Module location.** `plugins/zk-audit/skills/zk-audit/tools/gnark-inventory` is
  its own Go module (`go 1.24`). It depends only on `golang.org/x/tools`
  (`go/packages`), which is **vendored** so the tool builds offline. Hard rule
  8 of the skill (no network during an audit) would otherwise be broken by the
  first build.
- **Schemas are duplicated** inside the tool (`internal/validate/schemas/*.json`) because
  `go:embed` cannot reach `../../schemas`. A unit test fails if the copies
  differ from `plugins/zk-audit/skills/zk-audit/schemas/*.json`.
- **Advisory table.** The canonical machine-readable table is
  `internal/advisory/advisories.json` in the tool. `references/gnark-versions.md`
  carries the same JSON in a fenced block; a unit test fails if they differ.
- **Advisory table v2 (gnark and gnark-crypto).** Each row names its
  `package`; `detect` matches gnark rows against the gnark version and
  gnark-crypto rows against the gnark-crypto version of every `go.mod`. A
  row may carry `extra_ranges` (GHSA-fj2x has a fix backported to the 0.18
  line). `verified` now needs `verified_by`: `osv` (the OSV record matches)
  or `source` (OSV and the Go vulnerability database do not list the
  advisory and its GitHub page is unreachable from the build environment, so
  the fix was located in the released gnark source in the module cache;
  `evidence` names the file and version). The three gnark rows that were
  `verified: false` are `source` rows: the fix versions (v0.16.4, v0.16.2,
  v0.16.0) are confirmed in code, the advisory texts are not. The table has
  an `as_of` date that `detect` copies into `stack.json` and the report
  prints.
- **`advisories --osv` (opt-in network).** Offline by default. With
  `--osv` it posts the module name and pinned version of gnark and
  gnark-crypto to `api.osv.dev/v1/query`, and diffs the result: OSV ids no
  row covers (by id or alias) are `new`; a row whose own OSV record (or,
  when that is not returned, an alias record such as `GO-…`) has other
  ranges is `changed`; a row that affects the pin but that OSV does not
  return is looked up by id, and is `not_in_osv` when OSV does not have it.
  It is the only network call the tool makes, so the skill asks first
  (hard rules 4 and 8). Tests replay OSV responses recorded on 2026-10-29
  from `testdata/osv/` through `httptest`; no test uses the network. Known
  difference: GO-2025-3929 lists GHSA-9fvj with no lower bound, the GHSA
  record (and the table) start at v0.12.0.
- **`preflight` (D16).** A deterministic check before recon: for every
  `go.mod` that pins gnark or gnark-crypto it looks up both in the module
  cache (extracted source for the agents, and the `cache/download` `.mod`
  and `.zip` the go command builds from with `GOPROXY=off`), every other
  requirement's download entry, and the go directive of the module, gnark
  and gnark-crypto against the local `go env GOVERSION`. It prints what is
  missing and simple commands (no `&&`) that fetch it: `go -C <out> mod
  download gnark@v gnark-crypto@v` (outside the repository), `go -C
  <out>/worktree mod download` (only the scratch worktree's `go.sum` can
  change) and `GOTOOLCHAIN=goX go -C <out> version` for a toolchain. It
  runs none of them. The sandbox keeps `GOTOOLCHAIN=local`, so a target
  that needs a newer Go runs with a cached toolchain's own `bin/go`, which
  preflight finds in `golang.org/toolchain@…` and prints as `use_go`.
  `internal/modcache` holds the cache lookups for preflight and `bundle`
  (which writes the absolute gnark std path, and now the gnark-crypto
  path, into every bundle). Tests use a fake `GOMODCACHE`.
- **Version matrix (D17).** `test/versions/run` (repository only, not
  shipped) builds one throwaway module per gnark release with one package
  per Go PoC template, so a template whose API is missing fails alone
  ("API differs") instead of breaking the build of the others. It
  downloads gnark's module graph and the toolchain with the network, then
  runs everything with `GOPROXY=off`: online, `go mod tidy` and `go test
  -mod=mod` resolved `constraint/solver` for v0.8.1 by silently upgrading
  gnark to v0.16.4, which made the first run report v0.8.1 as working.
  The Foundry check reads the `verifyProof` ABI from the exported contract
  (three forms across v0.8 to v0.16). The typed-mode finding (a tool built
  with Go 1.24 cannot type-check a `go 1.25` package) led to
  `ZK_AUDIT_GO` in the wrapper rather than to raising the tool's own Go
  requirement, which would break offline builds on Go 1.24 machines.
- **Fallback loader.** If `go/packages` cannot type-check the target (missing
  dependencies, wrong toolchain), the tool falls back to `go/parser` and marks
  unresolved items (`resolved: false`). gnark ≥ v0.15 needs Go ≥ 1.25 and
  v0.16.4 needs Go 1.26, so type loading of a current gnark project needs a
  newer toolchain than the tool itself (`GOTOOLCHAIN=auto` handles this when
  the network allows it).
- **Offline by default.** The loader sets `GOPROXY=off` and strips `-mod=`
  from an inherited `GOFLAGS` before calling the go command, so loading a target
  never downloads modules and the target decides between its `vendor/` and the
  module cache. `--allow-network` is the explicit opt-in (PLAN §3 "never
  surprises the user").
- **Syntax-mode std shapes.** Without type information, a small table of gnark
  std struct shapes (`twistededwards.Point`, `eddsa.PublicKey/Signature`,
  `emulated.Element`, `sw_emulated.AffinePoint`, `ecdsa` types,
  `merkle.MerkleProof`, `uints.U8/U32/U64`) lets the walker lay out common
  witnesses. Other external types become `opaque` groups and make later
  offsets symbolic.
- **Witness-walk fidelity.** The walker reproduces `frontend/schema/walk.go`,
  including two behaviours that surprise users: tags on embedded fields are
  ignored, and nil pointers contribute no leaves. Expected layouts in the tests
  were produced by running gnark v0.14.0's own `schema.Walk` on the fixtures.
- **Hint reachability is a heuristic.** It is a per-function taint pass from
  `NewHint` results through assignments, range loops and API arithmetic to a
  list of constraining calls. "reached" means "flows into at least one
  constraint", never "bound". Outputs that leave the function (return, struct
  field, call to a non-API helper, composite literal) are `escapes`.
- **Fixtures.** `testdata/pool` and `testdata/edge` (repository root, outside
  the plugin directory) are separate modules that
  compile against gnark v0.14.0 (the newest release whose `go` directive works
  with Go 1.24). CI's offline step skips the typed-mode tests when the fixture
  dependencies are not cached; `make test-types` downloads them and requires
  typed mode. Tests find them through `internal/fixture`, which walks up to
  the repository root and skips in a standalone copy of the skill folder.
  The assembler's golden reports are in `testdata/assemble/`.
- **`bundle` subcommand (M3 skeleton).** Context sharding is implemented in the
  Go tool rather than a separate `scripts/build-context`: circuit, integration,
  prover and all shards, with one circuit shard per package when there are more
  than two circuit packages. Bundles list source files with line counts and
  never inline source (PLAN §2 "Leave: full source duplicated in all bundles").
- **`assemble` subcommand (Phase 6).** Like `bundle`, the report assembler
  lives in the Go tool (`gnark-inventory assemble`, wrapped by
  `scripts/assemble`) rather than a separate Node script, so the plugin keeps
  one zero-dependency binary. Judgment prose the assembler cannot derive
  (posture, out-of-scope notes, companion availability, hardening notes) is
  carried in optional top-level `findings.json` fields, so the report is a
  pure function of validated inputs. It quotes constraint lines from the
  audited tree, refuses invalid input and forbidden clean claims, and counts
  coverage only from the ledger.
- **Docs lint.** `docs_test.go` fails when the skill, a command or an agent
  names a script, subcommand, flag, `validate` kind, reference file or
  `zk-audit:` agent that does not exist.
- **Verifier regeneration.** The deep profile's "regenerate `Verifier.sol`
  and diff" is `gnark-inventory verifier regen` (see "Verifier provenance").

## Profiles and lenses (one source of truth)

- **`profiles.json`** (`tools/gnark-inventory/internal/profile/profiles.json`,
  embedded in the tool) defines every lens (id, name, lens file, vector slice,
  group, shard, the profiles that select it, the ledger classes it owns), the
  critics, and every profile (PoC policy, critics, targeted waves, passes,
  memory). It replaces the four copies x-ray P-17 listed (`SKILL.md` table,
  `orchestration.md`, `bundle.Agents`, the ledger seeder's class lists).
  It lives in the tool rather than in `{skill}/` so it is embedded without a
  synced copy (unlike the schemas); `gnark-inventory profiles` prints it.
- **Readers.** `bundle` selects lenses from it; the ledger seeder creates one
  unit per `ledger.seed` subject (each production circuit, or each verifying
  / state-writing contract function) and class; `validate ledger` accepts a
  unit `class` only if a lens owns it and a `lenses` entry only if it is a
  lens id or `V` (the ledger schema uses patterns instead of enums for both,
  so a new lens does not need a schema edit); `args` takes the profile ids and
  the default pass count from it.
- **Generated docs.** The profile table in `SKILL.md` and the agent table in
  `references/orchestration.md` sit between `<!-- generated:... -->` markers
  and are rewritten by `make sync-profiles`
  (`gnark-inventory profiles --sync-docs`). `TestGeneratedDocsInSync` fails on
  drift, `TestEveryLensFileIsUsed` fails when a file in `references/agents/`
  is not named by any lens, and `CheckFiles` fails when a lens names a
  missing file.

### Adding a lens

1. Write the lens file `references/agents/<ID>-<name>.md` (or, for a
   vector-scan shard, a slice under `references/attack-vectors/` that
   `lint-kb` accepts).
2. Add one entry to `lenses` in `profiles.json`: `id` (capitalised, e.g.
   `T1`), `name`, `file`, optional `slice`, `group`, `shard`
   (`circuit` / `integration` / `prover` / `all`) and `profiles`. If the lens
   owns coverage, add `ledger: {classes: [...], seed: "circuit" |
   "contract-fn" | "privileged" | "entry" | "custom-verifier", with: [...]}`;
   a class that needs a new subject kind (not one unit per circuit, per
   contract function, per privileged surface, per entry point or per
   non-gnark verifier) also needs seeding code in `internal/ledger/seed.go`.
   A vector-scan shard that owns a class is listed on its units as `V`.
   A lens that only makes sense for some targets names a condition in
   `when` (`profile.Conditions`, evaluated by `bundle.ConditionHolds`); the
   bundle is skipped with the condition's reason when it does not hold.
3. Run `make sync-profiles` and `make check`.

Nothing else changes: bundles, ledger seeding and validation, the docs
tables and `gnark-inventory profiles` all follow the entry.

## Library mode (gadget libraries)

- **Detection.** `detect` parses (syntax only) the non-test, non-`main`
  Go files that import gnark's `frontend` or `std/math/emulated` and counts
  exported functions and methods with a `frontend.API` or
  `(*)emulated.Field[T]` parameter (gadgets) and non-test `Define` methods
  (production circuits). `library.mode` is true when there are gadgets, no
  production circuit and no verifier contract. It is a profile
  (`library`), not a mode word, so `/zk-audit library` needs no parser
  change; Phase 0 preselects it in the profile question. A repository with
  circuits and exported helpers is a normal audit; `deep` adds L1 there
  (`when: exported-gadgets`).
- **Auditing gnark std in place.** A directory with no `go.mod` reads the
  enclosing one (`gomod.Enclosing`): `detect` reports gnark itself at the
  version in the module cache path (`gnark@vX`) and the loader type-checks
  the packages under the directory with the enclosing module. Checked on
  gnark v0.14.0 `std/math/bits` (7 gadgets), `std/rangecheck` (1: `New`;
  the checkers are unexported types) and `std/math/cmp` (11), typed mode.
  The output looked right: every `Assert*` and comparison input is
  `constrained`, `cmp.IsEqual`'s inputs `escape` (`IsZero` of the
  difference), and `bits.FromBase`'s doc ("its canonical representation")
  draws a `promise-canonical` check, a real doc-versus-constraint question.
- **Gadget inventory.** The hint taint pass is split into steps
  (`findSites`, `propagate`, `sinks`) so the gadget pass can root one state
  per parameter next to the hint states, and an `onCall` hook follows
  same-package callees (memoised per callee parameter, depth 4), so
  `ToBits → recompose → AssertIsEqual` reads as constrained. Doc comments
  are split into sentences and classified by regular expressions:
  preconditions (`caller must`, `assumes`, `must be`, `not checked`, …)
  and promises by property (boolean, range, canonical, on-curve, nonzero,
  relation). `doc_checks` are deliberately coarse facts for L1: a promised
  property with no constraining call of a matching name in the gadget or
  its same-package callees, a returned hint output no constraint touches,
  a witness input that reaches no constraint and that no precondition
  names. Constraints behind an interface or in another package are not
  followed, so a missing check proves nothing; L1 reads the code.
- **Lens and ledger.** L1 owns class `doc-contract`, seeded per gadget
  (seed kind `gadget`, ledger kind `gadget`). Without a production circuit
  the `circuit`-seeded classes get one unit per gadget package (ledger kind
  `package`) instead of none, so C1-C6 coverage is still tracked. Gadget
  packages join the circuit shard.
- **Harness.** `gnark-inventory harness` generates the wrapper from the
  inventory alone (no go command): inputs become witness fields, `int` and
  `bool` parameters `gnark:"-"` fields, outputs `Out<i>` fields asserted
  equal (element outputs with `Field.AssertIsEqual`, with a comment that a
  canonical promise needs a limb-by-limb check), variadic options are
  dropped with a note. In-package by default so unexported hints are in
  reach; `--external` writes `<pkg>_test` for packages that `gnark/test`
  or the builders import (gnark std: in-package tests import-cycle). It
  refuses a destination inside the audited repository. The eval PoCs of
  `lib-gadgets` use the generated files unchanged and a tool test fails
  when the generator drifts from them, so the generator is compiled and
  run in CI (`make eval-pocs`).
- **Differential tests** are a template (T-DIFFERENTIAL), not a tool
  command: the native reference differs per library (its own Go code,
  gnark-crypto, `math/big`). Mutants are guidance for deep, not automated.

## Solidity scan: inheritance, imports and several verifiers

- **Two phases, still lexical.** The scan first splits every file into
  contracts (bases, function headers with parameter and return types,
  variables, `using` directives) and follows imports, with remappings from
  `remappings.txt`, `foundry.toml` and Foundry's `lib/<name>/src` rule, into
  files outside the scan, which are read as peripheral contracts (types and
  inheritance only, never in scope). The second phase resolves what a
  per-file pass missed: modifiers and state declared in a base, the declared
  type of each verify call's receiver (parameter, local, state variable,
  mapping or array element, cast), library and `using ... for` calls, calls
  to an inherited verifier, and low-level `staticcall`/`call` built with
  `encodeWithSelector`, `encodeWithSignature` or `encodeCall` (whether the
  success flag is checked and the return data decoded as bool).
- **Call sites to verifiers.** Every call is mapped to the verifier
  contracts it can reach (`direct`, `inherits`, `selector`, `name-only`,
  `inherited-call`), overloads are counted by arity, and canonical ABI
  signatures carry their selectors (a small Keccak-256 in `internal/keccak`,
  so the tool keeps its single dependency). A call made in a base contract
  lists the contracts that inherit it. The binding table names each call's
  verifier and picks circuits by the verifier's input width.
- **Generators.** Verifier classification names the generator and template
  (gnark Groth16 and PLONK templates by version range, snarkjs, ZoKrates,
  Barretenberg, Halo2, SP1, RISC Zero, hand-written) and the precompiles it
  calls. A verifier whose generator is not gnark routes the V-custom shard.
- **Entry points.** External and public state-changing functions of every
  non-verifier contract, with their gate and effects (`eth-out`, `erc20`,
  `external-call`, `low-level-call`, `delegatecall`, `signature`, `oracle`,
  `verify`, `state-write`, `reentrancy-guard`, `initializer`), are the S1
  contract-review units.
- **Fixtures.** `testdata/sol-inherit` (a `lib/` base through a
  remapping, an abstract base holding the call and a modifier),
  `testdata/sol-multi` (two verifiers, overloaded interfaces, three
  low-level encodings) and `testdata/sol-library` (library and inherited
  hand-written verifiers, a non-verifier `verify`).

## Verifier provenance

- **What runs where.** `gnark-inventory verifier abi|diff|vk|bytecode|regen|ceremony`.
  Every profile's inventory runs `abi` and `ceremony` (offline, no target
  code; `provenance` in `profiles.json` lists the steps per profile). Deep
  adds `regen`, run by the orchestrator in Turn 2 inside the sandbox; its
  `diff.json` reaches the integration bundles. `bytecode` and `regen --vk`
  run only on artifacts the user supplies.
- **ABI check (measurement finding 5).** Both measured pool runs found the
  caller-interface/exported-verifier mismatch only by reading gnark's
  template. The tool now compares each call's selector, return value and
  input width with the repository's verifiers and with the verifier the
  pinned gnark exports (`internal/verifier/templates.json`, read from gnark
  v0.8.0 to v0.16.4), and notes mismatches on the verifier-contract ledger
  units.
- **What needs network or the user.**

  | Check | Needs |
  |---|---|
  | ABI check, template check, ceremony scan, `verifier vk`, `verifier diff` | nothing (offline, static) |
  | `verifier regen --main/--circuit` (deep) | the target's modules in the local cache (offline in the sandbox; fails otherwise) |
  | VK constants equal to the committed verifier | a verifying-key file or ceremony output (`regen --vk`); a fresh `--circuit` setup compares structure only |
  | deployed bytecode | a runtime-bytecode file from the user (`--deployed`), or `--rpc URL --address` (network: only when the user asks) |
  | which VK is deployed, who ran the setup | not decidable from the repository: a `needs_validation` blocker |

- **Ceremony scan.** Single-party `groth16.Setup` / `plonk.Setup`, unsafe
  SRS, `mpcsetup` phase 1 and 2 calls, and key or ceremony files (gnark
  `.vk` / `.pk`, mpcsetup phase files, snarkjs `.zkey` / `.ptau` with their
  recorded contribution counts) seed one trusted-party setup unit each.

## Contract review (S1, V-contract) and custom verifiers (V-custom)

- **Why both a lens and a companion.** I1–I3 read only the proof seam, and
  the report used to say "Solidity beyond the ZK integration: companion
  only". pashov's `solidity-auditor` covers that ground more widely but is
  optional, so S1 and the `contract-review.md` slice are the embedded
  fallback, and they also run when the companion runs (its output is
  converted, never trusted as is).
- **Units.** S1 owns `contract-review`, one unit per entry point. V-custom
  owns `custom-verifier`, one unit per verifier gnark did not generate,
  shared with I2. V-custom is in every profile but runs only when the
  inventory finds such a verifier or a call to an SP1 or RISC Zero gateway
  (`when: non-gnark-verifier`), so a gnark-only target pays nothing for it.
- **Sources.** Every V-SA and V-CV vector cites a public audit finding
  (zkSecurity reports, checked against the report's finding list), an EIP,
  the SWC registry, an advisory or the gnark template it contrasts with.
  Oracle manipulation has no vector with an allowed source yet; it is an S1
  checklist step.
- **PoCs.** Contract findings use T-FOUNDRY-VERIFIER (now concrete: the
  verifier gnark exports with a real proof made in the worktree, the
  committed one when its proving key is committed, or a mock with the
  target's selector) and custom-verifier findings T-FOUNDRY-MALLEATE. Which
  findings get a PoC is still the profile's PoC policy (deep: every layer).

## solidity-auditor converter

- **Call site.** Turn 4 runs the companion once (standard, deep) as a
  general-purpose agent with `--loop 1` on the scratch worktree, because it
  writes `.solidity-auditor/` into the directory it audits and the target is
  read-only. `gnark-inventory convert pashov` turns its runs directory into
  `<out>/companions/solidity-auditor.json`.
- **Format source.** github.com is not reachable from the build host, so
  the shapes were read from pashov/skills fetched as a Go module through
  proxy.golang.org (pseudo-version `v0.0.0-20261021092205-eacfc09b365d`,
  `solidity-auditor/VERSION` 4.1): `references/dedup-and-assembly.md` (run
  files with `<!--RUN-->` and `<!--F key=... conf=... kind=...-->` markers)
  and `references/report-formatting.md` (`full-report.md`). The converter
  reads both; a later format change breaks the fixture test, not silently
  the audit.
- **Everything is a lead.** The run files keep a finding's title,
  location, description and fix, not its exploit proof, so a converted
  FINDING enters judging as a `lead` with its confidence and run count in
  `code_smells`; the judge promotes it after re-deriving the call sequence.
  Its fix diff, kind and confidence stay under `items`. Items on contracts
  the inventory does not know go to `unresolved`, which the judge lists in
  `out_of_scope`.

## Foundry PoCs in CI

`make eval-pocs` runs `evals/fixtures/sol-gnark-abi/pocs/AbiMismatch.t.sol`
against the verifier gnark v0.14.0 exported for `testdata/sol-gnark-abi`
with a real proof (sanity), the caller's mismatched interface (attack) and
the exported interface (control), in the skill's sandbox and offline. The
fixture pins `solc_version = "0.8.24"` and `evals/run-pocs` fetches it with
a compile-only `forge build` before the sandboxed run; CI installs Foundry
v1.7.1 with `foundry-rs/foundry-toolchain`. There is no forge-std in the
fixtures, so Foundry PoCs declare the cheatcodes they use.

## Trusted parties (T1)

- **Why a lens.** The pool fixture's two trusted-party items (the owner swaps
  the verifier; the owner posts Merkle roots) were missed or half-credited in
  every measured run, and the critic could not see the gap because no ledger
  unit asked anyone to look (shramee/zk-audit#10). Admin powers were
  checklist lines inside I2 and I3 and "do not report" in the shared rules.
- **Deterministic surface.** The Solidity scan lists privileged functions
  (access modifiers, sender checks, initializers, ungated writers of
  verifier / VK / authority / implementation state), roles (Ownable and
  AccessControl bases, role constants, authority-named address variables,
  modifier parties) and upgrade paths (proxy bases, `upgradeTo`,
  `_authorizeUpgrade`, `delegatecall`, `selfdestruct`). It is lexical like
  the rest of the scan: a gate implemented in a base contract outside the
  scanned files (an inherited `onlyOwner` used without the base in scope) is
  still found by name, but a custom gate in an unscanned library is not.
- **Ledger.** Class `trusted-party`, seed kind `privileged`: one unit per
  privileged function (`contract-fn:`), declared role (`role:`) and
  production setup site (`setup:`, from `FG-DEV-SETUP`). `role` and `setup`
  are new unit kinds in the ledger schema.
- **In quick too.** Quick missed both trusted-party items in the 2026-10-27
  and 2026-10-29 runs; they were its only misses. A quick hunter costs about
  49k tokens (20 agents for 9.16 USD in the 2026-10-29 run), so T1 adds about
  5 % to a quick run. The alternative, leaving trusted parties to standard,
  keeps quick's one systematic blind spot. T1 reads the `all` shard because
  setup sites live in prover code.

## Privacy (PR1)

- **Lens and class.** PR1 owns the ledger class `privacy`, one unit per
  production circuit (seed `circuit`, with the vector scan): privacy is a
  property of a statement and of the flow that consumes it, so the circuit is
  the subject; the lens reads the `all` shard for events, relayers and
  prover services. Id `PR1`, not `P1`: `P0` is the Phase 0 pseudo-agent of
  advisory records and the pool answer key numbers its items P1–P15.
- **Profiles.** Standard and deep, not quick: quick's budget is about ten
  minutes and the measured runs have no privacy item to justify the cost
  there. The `V-privacy` vector-scan shard follows the same rule.
- **Vectors.** `attack-vectors/privacy.md`, V-PR1–V-PR7: secret exposed
  through public inputs, events or calldata; nullifier computable from public
  data; a tag repeated across contexts; amount, timing and fee fingerprints;
  relayer, indexer and sequencer metadata; the witness leaving the user
  (delegated provers, services, timing); a distinguishable member of an
  anonymity set. Sources are published zkSecurity reports (intmax zERC20,
  ZK Email, Demox, Silent Protocol, Aleo synthesizer, HumanityLink), the
  PLUME paper (eprint 2022/1255), Tutela (arXiv 2201.06811), "Blockchain is
  Watching You" (arXiv 2005.14051), the Zcash anonymity study (USENIX Security
  2018), the remote side-channel paper (eprint 2020/220), Semaphore v4 and the
  Tornado Cash relayer at a pinned commit. All hosts were already on the
  `lint-kb` allow-list; witness logging stays V-PV5 and commitments to
  private values stay V-CM2, which the slice cross-references.
- **PoC template.** `T-LINKAGE`: recompute the public value natively over a
  realistic candidate set and show it singles out the user; the honest
  control is the corrected formula, for which nothing matches.

## Gas and liveness

- **Vectors.** `attack-vectors/gas-liveness.md`, V-LV1–V-LV5: verification
  gas above the block or relayer limit (gnark's Groth16 template does one
  `ECMUL` and one `ECADD` per public input, EIP-1108 prices), unbounded loops
  (SWC-128), unbounded proof or calldata payloads (GHSA-cph5, zkSecurity
  OpenVM #0f), root windows that expire or can be flushed (Tornado Cash's
  30-root ring buffer, Semaphore's root duration), and fillable capacity
  (Tornado Cash's full tree, zkSecurity zkLighter block #01). Scanned by the
  `V-liveness` shard in standard and deep.
- **Ledger class `liveness`**, owned by I3 and seeded per verifying or
  state-writing contract function, like `protocol-state`: whether an honest
  proof can always be accepted in time is a property of the function that
  accepts it. It doubles I3's contract-function units; a separate lens was
  not worth a hunter, since the checks read the same state I3 already reads.
- **Stale-root PoC.** `T-FOUNDRY-STALE-ROOT` in `poc-templates.md` (no
  forge-std: it declares the two cheatcodes it uses) and a runnable copy on
  the `testdata/liveness-roots` fixture (`evals/fixtures/liveness-roots/`:
  key, answer key, `pocs/StaleRoot.t.sol`). `evals/run-pocs` now runs
  Foundry fixtures: it copies `*.t.sol` into the directory named in
  `PACKAGE`, fetches the solc pinned in `foundry.toml` with a compile-only
  `forge build` when network is allowed, and runs `forge test --offline` in
  the sandbox. `make eval-pocs` runs both fixtures; CI installs Foundry
  v1.7.1 with `foundry-rs/foundry-toolchain`.

## Report sections for trusted parties, privacy and coverage limits

- **Section order.** Sections 7 (Trusted parties), 8 (Privacy) and 11 (Not
  covered) are new; Hardening moved to 9 and Coverage to 10. Every
  cross-reference in the rendered text uses the section constants, so the
  numbers cannot drift.
- **Trusted parties** lists records with a `trust` object (status: needs
  validation, confirmed through an unprivileged path, lead, or accepted risk
  with its `zk-audit.md` line), the top-level `accepted_risks` (risks the
  guidance file accepts that no record covers), and the `trusted-party`
  ledger coverage. An accepted record leaves the needs-validation table and
  is counted separately in the posture totals; it is never dropped.
- **Privacy** lists records with `property: privacy` (a new optional record
  field), a `V-PR*` vector or `trust.breaks` privacy, and the `privacy`
  ledger coverage, or says the profile does not run PR1.
- **Not covered** is a fixed list of what the skill never examines (gnark
  internals beyond advisories, other frameworks, cryptographic assumptions,
  deployed state and off-repository infrastructure, economic and governance
  attacks, formal verification), followed by run-specific lines computed
  from `profiles.json`, the ledger and `companions`.

## Severity calibration

- **Anchors, not a table of adjectives.** `references/severity-calibration.md`
  holds 21 anchors (`SC-*`), each a fact pattern with the verdicts and
  severities it allows, the ledger classes and vectors it applies to, and a
  rule for choosing inside the range. Records name their anchor in
  `calibration`; `validate findings` refuses a verdict or severity outside
  it and warns when a confirmed or needs-validation record names none. The
  2026-10-29 runs rated an unused remainder hint `medium` three times (key:
  low or info) and judged one owner-gated circuit check `confirmed low` twice
  and `lead` once (shramee/zk-audit#10): `SC-UNUSED-FREE-VALUE` caps the first
  at `low`, and Gate 4's "nobody is harmed" rules now send the second to
  `SC-MASKED-BYPASS` (`confirmed low` with a chain) instead of "rejected or
  lead".
- **Published labels.** 60 published findings back the anchors: the
  zkSecurity gnark std, Kudelski gnark-crypto and Sigma Prime KZG reports in
  `gnark/audits/` (the Least Authority reports there carry no severity
  labels), gnark GitHub advisories, and 29 public zkSecurity reports read on
  2026-10-29. Where library audits rate a latent flaw higher than an
  application audit would (zkSecurity gnark std 05, Medium, unreachable with
  current parameters), the anchor says so and rates for application audits.
  zkSecurity's scale has no Critical, so its High maps to `high` or
  `critical`.
- **Machine-readable copy.** The JSON lives in the tool
  (`internal/calibration/calibration.json`, embedded) and in the reference's
  fenced block; `lint-kb` keeps them identical (like the advisory table) and
  checks that every anchor is in the human table, has a published example,
  names existing vectors and ledger classes, and that every reference is an
  allowed host or a report in `gnark/audits/`.
- **Pool key unchanged.** The new rules move P13/P14 to `needs_validation`
  and P6 to `confirmed`, both already in the key's expected verdicts; no new
  verdict class was needed.

## Sandbox (PoCs and recon)

- **`gnark-inventory sandbox`** (wrapped by `scripts/sandbox`) is the one
  way the skill executes target code: PoC `go test` and `forge test`, and
  the inventory's `go list` (x-ray P-3, items 1 and 3). It is in the Go tool,
  not a shell script, so the environment hardening is shared with the loader
  and testable, and it needs no new dependency.
- **Engines.** Linux: bubblewrap, probed once per process (a `bwrap` that
  cannot create namespaces, e.g. on a host that restricts unprivileged user
  namespaces, counts as absent). macOS: `sandbox-exec` with a deny-network,
  deny-write-outside profile; it is not exercised in CI (no macOS runner), and
  reads are not restricted there because a deny-read profile breaks the go
  command in ways that cannot be tested here. Elsewhere, or with
  `--engine none`: a warning on stderr and only the limits below.
  `--require` turns the fallback into an error (exit 125).
- **Limits without OS support.** The tool re-executes itself as a second
  stage inside the sandbox that sets `RLIMIT_AS` (per process; a cgroup would
  limit the total but needs privileges or systemd) and `RLIMIT_CORE=0`, then
  execs the command. The wall-clock limit kills the whole process group (and
  with bubblewrap the PID namespace, through `--die-with-parent`); exit 124
  as `timeout(1)`.
- **Build cache.** Sandboxed commands use `~/.zk-audit/gocache`, not the
  user's `GOCACHE`: test code runs with write access to the build cache, and a
  planted entry must not reach the user's own builds. The first sandboxed
  type load or PoC run of a gnark project compiles gnark once (about 20 s
  here).
- **Home directory hidden.** bubblewrap mounts an empty tmpfs over `$HOME`
  and re-binds only the module cache, Go root, the tool binary and Foundry's
  directories read-only, so a PoC cannot read SSH keys or tokens. Running as
  root still reads root-owned files outside `$HOME`.
- **Recon.** `inventory` reruns itself in the sandbox (repository
  read-only, output directory writable) unless `--syntax-only`,
  `--sandbox off`, or already inside a sandbox. The loader itself also sets
  `CGO_ENABLED=0`, `GOWORK=off`, an empty `GOFLAGS` and, offline,
  `GOTOOLCHAIN=local` (x-ray G-14).
- **Command forms.** Docs and agent briefs use `go -C <dir>`,
  `forge test --root <dir>` and single commands, because the 2026-10-29
  measurement runs showed permission allowlists refusing `cd … && …` and
  pipes (shramee/zk-audit#10).
- **Evals.** `evals/run-pocs` (and so `make eval-pocs` and CI) runs the pool
  PoCs through the sandbox, offline.

## Writes into the target

- **Refused, not warned** (x-ray G-16). `detect --out`, `inventory --out`,
  `bundle`, `assemble --out` and `assemble --report` inside the audited
  repository exit 2 before writing anything. Containment is checked on
  resolved paths (`fsutil.Resolve` follows symlinks through the longest
  existing ancestor), so a symlink to or from the repository does not get
  around it. `assemble --file-output` mirrors the skill flag: it writes the
  one allowed file, `<repo>/zk-audit-report-<run-id>.md`, next to
  `<out>/REPORT.md`.
- **Quotes** (x-ray G-13). The assembler resolves the repository root and
  the quoted file with `filepath.EvalSymlinks`, requires the real file to be
  a regular file inside the real root, and otherwise prints no quote.

## Evidence truthfulness (validate and assemble)

- **Checked against files** (x-ray G-3, G-8). `validate ... --out <out>`
  and `assemble` check that every `poc.path` is a regular file under
  `<out>/pocs/` and that every agent of a `covered` or `candidate` unit has
  a saved output in `<out>/agents/`. Covered units' `reviewed_paths` must be
  repository-relative and include the unit's own file. Missing evidence for
  a claim (a POC without its file, coverage without an agent output) is an
  error; gaps that do not make the report false (orphan PoC files, a PoC
  that did not run, unknown agent ids, no `demonstrates`) are warnings. The
  table is in `references/report-format.md`.
- **Schema additions** from the 2026-10-29 measurement runs
  (shramee/zk-audit#10): `poc.result: demonstrated_on_model` (a model-circuit
  PoC with `ANALYSIS` read as a contradiction), `poc.demonstrates:
  soundness|completeness` (a completeness-only PoC was labelled POC for a
  soundness claim), `poc.package` (to re-run after the worktree is gone),
  `poc` on non-confirmed records (a demoted record keeps its PoC), and
  `refuter.mechanism` / `refuter.impact` (the one refutation was about
  impact, not the mechanism). `assemble` writes `pocs/MANIFEST.json` with
  every PoC file's hash and record.
- **`candidate` is not coverage.** Examined = `covered` only; a candidate
  unit is listed as not examined until judging closes it. The runs showed 28
  of 39 units as candidates reported as "39 of 39 examined".
- **Agents row.** Ids that are no lens or critic (orchestrator phases, wave
  labels) go to an "Other sources" row instead of being listed as agents.

## Ledger and agent outputs through the tool

- **`ledger mark` / `ledger add` / `ledger show`** and **`agents save` /
  `agents list`** replace hand edits. The 2026-10-29 runs rewrote the 17 KB
  ledger with Write after every update (a shell `jq` was refused), saved
  agent outputs inconsistently and listed phase labels as agents
  (shramee/zk-audit#10). `ledger mark` selects units (id, id substring,
  lens, kind, class, current status), appends evidence, and validates the
  whole ledger with the `--out` checks before an atomic write, so a unit
  cannot be marked covered by an agent whose output was never saved.
- **Stopped or refused agents.** `agents save --status refused|failed|blocked
  --reason` records them in `agents/index.json` with an attempt count; the
  orchestration rule is one plain-worded retry, then `blocked` units with the
  reason, so the report shows them as not examined instead of silently
  dropping them.

## Diff triggers

- **`gnark-inventory diff`** flags diff mode's triggers deterministically
  (PLAN §3, `references/modes/diff.md`). It reads both sides with `git
  cat-file` and `git diff --no-ext-diff --no-textconv` under `-c
  core.fsmonitor= -c core.hooksPath=/dev/null`, so a hostile repository
  config cannot run commands, and it refuses revisions that start with `-`.
- **Go**: per function, the count of constraint calls (the inventory's sink
  list) in the merge base and in the head: fewer is `constraint-removed`
  (`range-check-removed` for decompositions and range checks), more of them
  under a Go `if` is `constraint-now-conditional`, more `NewHint` /
  `RegisterHint` calls is `hint-added`. Public inputs: the ordered
  `gnark`-tagged fields of each struct; a change among the public ones
  (add, remove, re-order, re-tag) is `public-input-changed`. Test files are
  skipped. This is syntax-level: a constraint moved to a helper function
  shows as removed in one function (a false positive the agent pass
  resolves), and a hint output that stops reaching a constraint is not
  detected (the mode compares the two inventories for that).
- **go.mod**: gnark / gnark-crypto version or replace changes.
  **Solidity**: a file that looks like a generated verifier (two of
  `verifyProof`, VK constants, pairing) is `verifier-contract-changed`;
  otherwise added or removed lines with verifier calls, verifier
  assignments or setters, or public-input arrays are `verify-call-changed`.
  **VK files** by name.

## Loop memory

- **`gnark-inventory memory`** holds loop mode (PLAN §3 `--loop N`, deep's 3
  passes). The 2026-10-29 deep run never ran a second pass: it counted a
  targeted wave as "pass 2", tagged every record NEW, and stopped although
  the critic still listed missing units (shramee/zk-audit#10). Now a pass is
  defined as Turns 3–7 in full, each pass's judged records go to
  `<out>/passes/<p>/findings.json`, and `memory merge` assigns NEW / KNOWN,
  counts "seen in k/N", keeps rejected items, writes the cumulative
  `findings.json`, and applies the stop rule (no new fingerprint and no
  missing unit from the critic, or all planned passes). It refuses
  out-of-order merges and passes after a stop; re-merging the last pass
  replaces it.
- **Known list.** `bundle` inlines `memory known` into every bundle when
  `memory.json` exists, so hunters see what earlier passes found; they
  answer a known item with a `KNOWN:` line, which the judge turns into a
  copy of the record so the pass counts it.
- **Schema.** `run_tag` (existing) and `seen: {passes, of}` (new) are set
  only by `memory merge`; the assembler prints `[KNOWN · seen in 2/3 passes]`.
- **Not cross-run.** Memory lives in one run's output directory; seeding a
  run from an earlier run's `memory.json` is not implemented.

## Invocation parsing

- **`gnark-inventory args`** turns the words after `/zk-audit` into JSON
  (mode, profile, scope, flags, `out`, `run_id`, diff range) so the
  orchestrator never parses flags. It splits a single quoted string with
  shell-like quoting, rejects unknown flags, scope paths that do not exist or
  leave the repository (after resolving symlinks), `--loop` outside 1–10 or
  outside a full audit, and an `--out` inside the repository. `--loop`
  defaults to the profile's `passes` from `profiles.json`. Commands that fix
  the mode (`/zk-audit:diff`) pass `--mode`. Added flag: `--profile P`, the
  same as the bare profile word.

## Evals

- **Blind runs.** Fixtures keep their `// BUG:` comments for the inventory
  tests. `evals/sanitize` copies a fixture outside the
  repository, strips the hints with a per-fixture sed script and fails if
  hint text survives. Answer keys and eval PoCs live in `evals/<fixture>/`.
  `evals/` and `testdata/` are at the repository root, so neither a plugin
  install nor a standalone skill copy carries them
  (`TestInstallShipsNoFixtures`); no skill file references them, and a docs test keeps fixture identifiers out
  of every plugin doc so hunters are not primed.
- **Answer keys score real impact, not the planted comment.** Several pool
  `BUG:` comments describe patterns that are harmless in context (one is a
  decoy), so the key records the reviewed ground truth and the accepted
  verdict range per item.
- **Eval PoCs** (`evals/pool/pocs`) run against gnark v0.14.0 in a sanitized
  scratch copy (`evals/run-pocs`, `make eval-pocs`, CI). They pin the
  templates in `poc-templates.md` to working code.

## Knowledge base

- **Source policy.** Every vector cites at least one of: a GHSA advisory, an
  audit report or the gnark PR that fixed an audit finding (taken from the
  "Client Response" links in `gnark/audits/2024-05 - zksecurity - gnark std.pdf`),
  a Least Authority report shipped in `gnark/audits/`, a `gnark/<path>`
  source reference at v0.16.4 that states the behaviour, a `gnark/CHANGELOG.md`
  entry, or the zkSecurity zk-skills entry a generic vector was ported from.
  `lint-kb` restricts URL hosts to an allow-list and, with `--gnark-src`,
  checks that every cited gnark path exists (it does, for v0.16.4).
- **Integration vectors without a ZK-specific source were left out.** Admin
  swap of a verifier or VK, nullifier check-then-store atomicity and reentrancy
  around verification are covered as checklist items in the I2 and I3 lens
  files instead of as catalog vectors, because no source in the allowed set
  documents them for gnark.
- **Vector count.** 79 vectors in 12 slices at first (PLAN target "about
  80"); 91 in 14 with the privacy and gas-liveness slices. Slice and
  id scheme: V-H (hints), V-R (range), V-F (field), V-S (selector), V-M (hash /
  Merkle), V-E (curves / signatures), V-CM (commitments / recursion), V-PI
  (public inputs), V-VC (verifier contracts), V-PS (protocol state), V-PV
  (prover service), V-G (generic, ported from zkSecurity), V-PR (privacy),
  V-LV (gas and liveness).
- **PoC templates were executed.** T-HINT-OVERRIDE, T-PROVE-VERIFY,
  T-ASSERT-OVERRIDE and T-ALIAS were run against gnark v0.14.0 on small
  circuits (a remainder hint without `r < b`, and `OmitModulusCheck`), and
  each demonstrated the bug with its honest control. `test.WithReplacementHint`
  exists only from v0.15 and is documented as such.

## Knowledge base facts that differ from `docs/research.md`

Advisory data was re-checked against the OSV database (api.osv.dev, fetched
2026-10-27) and the gnark source tree (`v0.16.4`, `audits/`):

- **GHSA-7p92-x423-vwj6** is the PLONK Solidity verifier deriving the
  KZG batch-opening randomness from only the first 32 bytes of state
  (`batch_verify_multi_points`). It is the bug the "Last Challenge" paper
  (eprint 2024/398) describes; the advisory text is quoted for accuracy.
- **Severities follow the GitHub advisory**: GHSA-498w (CVE-2023-44378) is
  Moderate, GHSA-9xcg (CVE-2024-45040) is High, GHSA-9fvj (CVE-2025-58157)
  affects v0.12.x only and is fixed in v0.13.0.
- **GHSA-cph5 / CVE-2024-50354**: the GHSA says fixed in v0.11.1, the Go vuln
  DB (GO-2024-3244) says v0.12.0. The table uses v0.11.1 and notes the
  discrepancy.
- **GHSA-3mvx-pp85-pm65, GHSA-7fx8-hmgc-82jp, GHSA-fwf3-jmp7-gmrj** are not
  in OSV and the GitHub advisory pages were not reachable from the build
  environment. Their rows use `docs/research.md` and are marked
  `"verified": false` in the machine-readable table. For GHSA-fwf3 the research
  notes say "fixed after v0.15.0"; the table uses v0.16.0 (the next release)
  and flags it.
- **zkSecurity gnark-std audit numbering** follows the report PDF in
  `gnark/audits/2024-05 - zksecurity - gnark std.pdf` (00 MultiCommitter …
  0b leaky abstraction), which differs from the order in `research.md`.
- **Emulated witness width.** In gnark v0.16.4, `emulated.Field` methods call
  `enforceWidthConditional` on non-internal elements, so witness limbs are
  width-checked on first use. The residual risks the footgun covers are: the
  value is not reduced below the modulus (`Reduce` vs `ReduceStrict` /
  `AssertIsInRange`) and direct use of `Element.Limbs` in native arithmetic,
  which bypasses the width check (zkSecurity 0b, "won't fix").
