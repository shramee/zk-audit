# Attack vectors: generic ZK shapes

<!-- Ported to gnark from zkSecurity zk-skills circom-auditor (MIT, (c) 2026 zkSecurity): V-A3, V-A4, V-D6, V-D7, V-H7, V-H8. The Circom-only vectors (L1, L3-L5, B6, B7, A2) are not ported. -->

Slice: constraint shapes that are not tied to one gnark API. They come from
zkSecurity's Circom catalog and are rewritten for gnark idioms. Use this slice
also for `.circom` files in scope when the `circom-auditor` companion is not
installed. 6 vectors, V-G1–V-G6.

Mantra: **for every constraint ask what *other* witness also satisfies it.**

---

**V-G1. Value computed outside the constraints and checked by one polynomial**

- **D:** A value is produced by a hint (or, in Circom, `<--`) and then checked
  by a single relation that has more than one solution. Examples:
  `inv·x == 1` without handling `x = 0`, `q·b == a` without a remainder bound,
  `y² == x` without fixing the sign of `y`. The prover picks the other root, the
  other quotient, or a free value at the degenerate point.
- **FP:** The relation has a unique solution on the reachable input domain, or
  extra constraints (sign bit, range, non-zero) remove the others.
- **Source:** zkSecurity zk-skills circom-auditor V-A3 "Witness-only division paired with one polynomial check" https://github.com/zksecurity/zk-skills; `gnark/frontend/api.go` (`DivUnchecked`)
- **Seed:** FG-HINT-UNREACHED, FG-DIV-UNCHECKED
- **PoC:** T-HINT-OVERRIDE

**V-G2. Boolean algebra on values that are not proven boolean**

- **D:** XOR, AND or NOT written as field arithmetic (`a + b - 2ab`, `a·b`,
  `1 - a`) is only boolean logic when `a, b ∈ {0, 1}`. On other values it
  produces field elements that later "bits" logic misreads. gnark's `api.Xor`,
  `api.And` and `api.Or` constrain booleanity; the hand-written forms do not.
- **FP:** Operands come from a decomposition or `AssertIsBoolean`, or the `api`
  bit operations are used.
- **Source:** zkSecurity zk-skills circom-auditor V-A4 "XOR via a + b - 2ab without booleanity and recomposition" https://github.com/zksecurity/zk-skills; `gnark/frontend/api.go` (`Xor`, `Or`, `And`: "This function constrain a and b to be boolean")
- **Seed:** grep: `api\.Sub\(api\.Add\(.*api\.Mul\(2,`
- **PoC:** T-INVALID-ASSIGNMENT

**V-G3. One-hot or index decoding without uniqueness**

- **D:** An index `i` is turned into indicator values `e_j` (`e_j = 1` iff
  `j == i`) by a hint, and only `Σ e_j == 1` or only `Σ j·e_j == i` is
  checked. Without booleanity of each `e_j` and both sums, several indicators can
  be non-zero and the selected value becomes a linear combination chosen by the
  prover. gnark's `selector.Map` documents a related case: with duplicate keys,
  "the output could be any linear combination of all the corresponding values".
- **FP:** `selector.Mux` / `selector.Map` with distinct keys, or custom decoders
  that assert booleanity and both sums.
- **Source:** zkSecurity zk-skills circom-auditor V-D6 "One-hot decoder without IsZero pairing" https://github.com/zksecurity/zk-skills; `gnark/std/selector/multiplexer.go` (`Map` doc comment)
- **Seed:** FG-SELECTOR; grep: `NewHint\(.*(indicator|onehot|decoder)`
- **PoC:** T-HINT-OVERRIDE

**V-G4. Several valid witnesses for one public output (non-determinism)**

- **D:** The circuit's public outputs do not determine the private intermediate
  values uniquely. If any of those intermediates is later exposed, hashed into a
  nullifier, or compared, the prover chooses among them. Non-determinism is
  often harmless for hiding, but harmful wherever uniqueness is assumed.
- **FP:** Every value that is exposed, hashed or compared is uniquely determined
  by the bound inputs. The C1 and C2 lenses checked each hint and decomposition
  on the path.
- **Source:** zkSecurity zk-skills circom-auditor V-D7 "Non-determinism / multiple valid witnesses for one public output" https://github.com/zksecurity/zk-skills
- **Seed:** manual
- **PoC:** T-HINT-OVERRIDE

**V-G5. Expiry or time bound absorbed into a hash but never compared**

- **D:** A credential carries an expiry or timestamp that is hashed (so the
  signature or commitment covers it) but never compared with the current time.
  The circuit proves possession of an expired credential exactly as of a valid
  one.
- **FP:** The circuit compares the bounded timestamp with a public "now" that
  the contract supplies (`block.timestamp` or an epoch), and the contract checks
  that public input.
- **Source:** zkSecurity zk-skills circom-auditor V-H7 "Time-bound credential fed only into a hash, never compared" https://github.com/zksecurity/zk-skills
- **Seed:** grep: `(?i)(expir|deadline|timestamp|validuntil)`
- **PoC:** T-INVALID-ASSIGNMENT

**V-G6. A privacy flag disables only half of a comparison**

- **D:** A mode flag is meant to turn a comparison off ("do not reveal the
  relation"). Only the equality part is gated, while an inequality on the same
  private value still constrains a public signal. The proof leaks a bound on the
  private value in the mode that promises not to.
- **FP:** Every constraint that involves the protected value is gated by the same
  flag, or the disabled branch replaces the public output with a fixed value.
- **Source:** zkSecurity zk-skills circom-auditor V-H8 "Privacy leak via comparison constraint not fully gated by privacy flag" https://github.com/zksecurity/zk-skills
- **Seed:** FG-GATED-ASSERT; FG-CMP-UNBOUNDED
- **PoC:** T-ANALYSIS
