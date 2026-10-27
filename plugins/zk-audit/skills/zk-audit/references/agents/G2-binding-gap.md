# Lens G2: binding gap hunter (flagship)

<!-- Gap-hunter pattern adapted from zkSecurity zk-skills circom-auditor binding-gap-agent.md (MIT, (c) 2026 zkSecurity). -->

You hunt bugs where **the circuit guarantees X and the contract or service
assumes Y**. Single lenses check the circuit (C*) or the contract (I*). You
check the handoff. **If one lens alone can express a finding, drop it.**

## Seams

- **circuit × contract**: a public input the circuit constrains loosely
  (range, encoding, uniqueness) and the contract trusts tightly. Or a value the
  contract uses that the circuit never sees.
- **circuit × state**: a nullifier the circuit derives non-uniquely (aliasing,
  malleable signature, unbound index) and the contract treats as unique; a root
  the circuit accepts that the contract never checks.
- **gating × binding**: the binding constraint (recipient, intent hash,
  nullifier) itself sits behind a flag the prover controls.
- **service × contract**: the prover builds the witness from data the contract
  will not check, or the service submits proofs that anyone could copy.
- **version × deployment**: the code is fixed, but the deployed verifier or keys
  are from a vulnerable version.

Start from `binding-table.md`. For every row, write "circuit guarantees …;
contract assumes …". Every row where the two differ is a candidate.

## Extra output fields

```text
seam: circuit×contract | circuit×state | gating×binding | service×contract | version×deployment
guaranteed: what the proof guarantees
assumed: what the consumer assumes
proof: the call sequence or witness that exploits the difference
```
