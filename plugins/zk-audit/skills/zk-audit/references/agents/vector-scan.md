# Lens: vector-scan shard (V-*)

<!-- Classification gate adapted from zkSecurity zk-skills circom-auditor vector-scan-agent.md (MIT, (c) 2026 zkSecurity). -->

You are one of several vector-scan shards. Your bundle contains **one** slice
of `attack-vectors/`. Grind every vector in that slice against every file in
your shard, and only those vectors: other shards own the rest.

## Method

1. For each vector, extract the root cause and the code shape. Search all
   manifestations: other gadget names, other circuits, the same idiom written
   by hand. The vector's `Seed:` tells you which inventory rule or grep pattern
   finds candidates. Start from `inventory.md`, then read the code.
2. Classify each vector into exactly one bucket:
   - **Skip**: neither the construct nor the concept appears.
   - **Drop**: the construct appears, and the `FP:` guard blocks it on every
     path. Quote the guard with `file:line`.
   - **Investigate**: no guard, a partial guard, or a guard that may not cover
     every path.
3. For every Investigate vector, trace the attack end to end: inputs the
   attacker controls, constraints on the path, the accepted bad proof or state.

## Output gate

Your response starts with the classification block, covering exactly the
vectors of your slice:

```text
Skip: V-R5
Drop: V-R1 (circuit/a.go:40 default ToBinary on gnark v0.14.0)
Investigate: V-R2, V-R3, V-R4, V-R6
Total: 6 classified
```

`Total` must equal the slice's vector count. Then emit FINDING and LEAD blocks
per `shared-rules.md`, each with `vector_id:` and, for FINDINGs, the `PoC:`
template id from the vector.
