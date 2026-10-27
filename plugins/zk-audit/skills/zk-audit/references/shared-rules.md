# Shared rules for every hunting agent

<!-- Adapted from zkSecurity zk-skills circom-auditor shared-rules.md (MIT, (c) 2026 zkSecurity) and pashov skills solidity-auditor shared-rules.md (MIT, (c) 2024 AI Skills Contributors). Rewritten for gnark circuits and their integrations. -->

These rules are appended to every agent bundle. They override anything in a
lens file that conflicts with them.

## 1. Read-only

You audit someone else's repository. **Do not create, edit, move or delete any
file in it.** Do not run `go mod tidy`, `go generate`, `forge build`, formatters
or anything else that writes inside the repository. Do not install anything.
If you want to run code, describe the PoC in your output; the `poc-builder`
runs it later in a scratch worktree. The only place you may write is the output
directory given in your prompt, and only if your prompt says so.

## 2. Reading your bundle

Your bundle lists, in order:

1. **Source shard**: the paths and line counts of the in-scope files for your
   circuit or contract group. Read them all before you write anything. Use
   offsets for long files.
2. **`binding-table.md`**: public inputs in public-witness order, joined to the
   contract's input array.
3. **`inventory.md` excerpts**: hint sites with their reachability, footgun
   hits, witness layout. They are leads for you, not conclusions. "reached"
   only means "an output flows into some constraint".
4. **Peripheral files** (gnark std, vendored libraries): listed, not inlined.
   Read one only when your path goes through it. The pinned gnark version is in
   `stack.json`; read std code at that version (module cache) and not at
   master.
5. `senior-auditor-sop.md`, your lens file, and these rules.

## 3. Mental-tool markers (mandatory)

The three tools in `senior-auditor-sop.md` have triggers. When a trigger fires,
write the marker in your working text before you continue. Markers never appear
inside FINDING or LEAD blocks.

| Trigger | Marker | Content |
|---|---|---|
| You open a `Define` method, a gadget, or a contract function that calls a verifier | `[Feynman: <name>]` | What does it prove (or accept), in plain words, without gnark vocabulary? Where the explanation gets vague, there is a free value. |
| A constraint or check whose purpose is unclear | `[Socratic: <file:line> — what does this force? what stays free?]` | Ask "why" until you reach the assumption it rests on. |
| A constraint or guard looks sufficient | `[Inversion: <name>]` | A concrete malicious witness or call sequence that satisfies it and breaks intent: `x = r - 1`, `b = 0`, `flag = 0`, `S + n`, the same proof from another address. |

The orchestrator counts markers. Skipped markers lower the value of your
output.

## 4. Scope discipline

- **Vector-scan shards** classify every vector in their slice (Skip / Drop /
  Investigate) before anything else. Then they hunt the Investigate set.
- **Single-lens agents** (C1–C6, I1–I4, A1, F1) own one lens. Cross-flag
  freely: a duplicate is cheap, a miss is not.
- **Gap hunters** (G1–G3) own the seams between lenses. **Drop any finding
  that one lens alone can express.**

## 5. Weaponize every pattern

When you find a bug, search for the same shape everywhere in your shard and the
inventory:

1. **Same primitive, more callers.** A broken helper or gadget breaks every
   circuit that calls it. List them.
2. **Same idiom, other files.** An unbound hint output in one gadget: check
   every other `NewHint` site.
3. **Same shape, other context.** A wrapped comparison in one circuit: check
   every `Cmp` / `AssertIsLessOrEqual`.

Then escalate to the worst reachable variant. A completeness bug can hide a
soundness bug, and a soundness bug in the circuit is worse when the contract
moves funds on it.

## 6. Do not report

- Style, naming, comments, constraint-count or prover-speed issues that do not
  change what verifies.
- Self-harm only: the prover can only break its own proof, and no third party
  loses anything.
- "The admin can do X" without a concrete path that an unprivileged actor
  triggers or amplifies. Record it under trusted parties instead.
- Defence-in-depth wishes ("also check Y") when nothing breaks without them.
- Behaviour of gnark itself that the pinned version fixed. Version-matched
  advisories come from Phase 0, not from you.

## 7. Output

Return only blocks; no preamble or summary. Mental-tool markers may precede
the blocks. A vector-scan shard starts with its classification block.

**A FINDING has a `proof:`.** The proof is concrete values from the actual code:
a witness assignment, hint outputs, a call sequence, or a PoC sketch with the
template id. No proof means LEAD. There are no exceptions.

**One root cause per item.** Same root cause in two places: one item listing
both. Two fixes needed: two items.

```text
FINDING | layer: circuit | scope: TallyCircuit.Define | local: avg[0] | bug_class: hint-output-unconstrained | group_key: TallyCircuit | avg[0] | hint-output-unconstrained
detected_by: <agent-id>
vector_id: V-H3            (if a catalog vector applies; omit otherwise)
location: tally/circuit.go:40-44
code: avg, _ := api.Compiler().NewHint(meanHint, 1, c.Sum, c.Count)
path: prover sets meanHint output → only avg·Count ≤ Sum is checked → public Mean is wrong
proof: Sum=10, Count=2, Mean=1; override meanHint → 1; ccs.Solve succeeds; honest hint (5) fails (T-HINT-OVERRIDE)
impact: one sentence — who loses what
description: one sentence, 25 words or fewer, active voice
fix: one sentence; a diff if you have one

LEAD | layer: integration | scope: Ballot.cast | local: pub[3] | bug_class: voter-not-bound | group_key: Ballot | cast | voter-not-bound
detected_by: <agent-id>
location: contracts/Ballot.sol:27
code: pub[3] = uint256(uint160(voter));
code_smells: Voter reaches no constraint except a range check
unverified: whether the Groth16 input commitment alone binds Voter
description: one or two sentences
```

The examples use invented names on purpose. Never copy names or locations
from them; every name, `location` and `code` line comes from your shard.

Field rules:

- `layer`: `circuit`, `integration`, `prover`, `dependency` or `setup`.
- `scope`: `Circuit.Method` or `Contract.function` or `file:func`, exactly as in
  the source.
- `group_key`: `<circuit or gadget> | <signal or local> | <bug-class>` for
  circuit items, `<contract> | <function> | <bug-class>` for contract items.
  `bug-class` is lower-kebab-case and names the defect, not the consequence:
  `hint-output-unconstrained`, not `funds-stolen`.
- `location` and `code`: open the file and copy the first line of the cited
  range verbatim into `code:`. A `location` whose line does not hold that code
  is wrong; fix it before you return. Line numbers in the bundle's inventory
  excerpts are authoritative.
- `detected_by`: exactly your agent id from the prompt, with no suffix (for example `C1`, `V-hints`,
  `G2`).
- `location`: repo-relative `file:line` or `file:start-end`.
- Add the lens-specific fields your lens file asks for.

## 8. Language

`description:` and `fix:` are printed in the report. Write them in plain,
short, active sentences: one idea, at most 25 words, present tense, and name
the actor ("Any prover can …", "A front-runner takes …"). Never soften with
"could potentially". If you are unsure, it is a LEAD and the `unverified:`
field says what is unsure. Identifiers, `bug_class` labels, code and diffs are
copied exactly from the source and never reworded.
