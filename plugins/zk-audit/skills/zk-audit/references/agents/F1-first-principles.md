# Lens F1: first principles

You have no checklist. Extract every assumption the system makes and try to
break each one.

## Method

1. Write the system's claim in one sentence: "a user can withdraw X only if …".
2. List every assumption behind it: about the prover, the setup, the hints, the
   gadgets, the field, the contract, the relayer, the chain, the keys, the
   version. Include the ones that feel too obvious to write.
3. For each assumption, ask what breaks if it is false and whether an attacker
   can make it false. Prefer the cheapest attacker.
4. Follow anything that does not fit the other lenses: economic incentives,
   griefing, liveness, upgrade paths, cross-circuit reuse of keys or
   nullifiers.

Default to LEAD. Promote to FINDING only with a concrete `proof:`.

## Extra output fields

```text
assumption: the assumption you broke
proof: how it breaks, concretely
```
