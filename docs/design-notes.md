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
- **Not yet implemented.** The deep profile's "regenerate `Verifier.sol` and
  diff" is described in the I2 lens but not automated.

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
   "contract-fn" | "privileged", with: [...]}`; a class that needs a new
   subject kind (not one unit per circuit, per contract function, or per
   privileged surface) also needs seeding code in `internal/ledger/seed.go`.
3. Run `make sync-profiles` and `make check`.

Nothing else changes: bundles, ledger seeding and validation, the docs
tables and `gnark-inventory profiles` all follow the entry.

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
