# Lens PR1: privacy

Ledger class: `privacy`. You own one `privacy` unit per production circuit:
what the statement, the contract and the services around it reveal about
the values the protocol claims to hide.

The proof is zero-knowledge; everything next to it is not. You find what an
observer of the chain, a relayer, an indexer or a prover operator learns, and
what links two actions of one user.

## Work plan

1. **Claim.** From `zk-audit.md`, the README or the code, write what the
   protocol says it hides (sender, recipient, amount, which note, membership,
   vote) and from whom (everyone, other users, the operator). No claim means
   no privacy finding: say so in one line and stop.
2. **Public data.** For every public input (binding table), every event field
   and every calldata argument next to the proof: is it one of the hidden
   values, or a function of one that an observer can invert or enumerate
   (V-PR1)? Small ranges (amounts, indices, timestamps) count as enumerable.
3. **Tags.** For the nullifier and every other per-user public value: can an
   observer recompute it from public data (V-PR2)? Does it repeat across
   actions or contexts that should be unlinkable (V-PR3, V-PS4)?
4. **Correlation.** Amounts, fees, refunds, gas payers, timing between
   deposit and withdrawal, address reuse (V-PR4). Note what the contract fixes
   and what the user chooses.
5. **Operators.** Relayers, indexers, sequencers, delegated provers and
   scanners: what does each receive, can it link, log or censor, and does the
   trust model name it (V-PR5, V-PR6)? An operator that sees links is a
   trusted party: add the T1 fields (`party:`, `power:`, `breaks: privacy`,
   `assumption:`).
6. **Leaks in the circuit.** Debug prints of witness values (V-PV5),
   commitments to private values without hiding (V-CM2), a privacy flag that
   gates only half a check (V-G6), a decoy set whose real member is
   distinguishable (V-PR7).

## Output

A FINDING needs the concrete link: the public value, the candidate set an
observer has, and the computation that singles out the user (T-LINKAGE).
Correlations that need chain statistics are LEADs. Add:

```text
hidden: the value the protocol claims to hide
observer: who learns it (anyone on chain, relayer, indexer, prover operator)
link: the public data and the computation that reveals or links it
```

Use `bug_class` labels that name the leak: `public-input-leaks-secret`,
`linkable-nullifier`, `static-tag-across-contexts`, `amount-fingerprint`,
`relayer-sees-recipient`, `witness-sent-to-service`,
`anonymity-set-distinguishable`.
