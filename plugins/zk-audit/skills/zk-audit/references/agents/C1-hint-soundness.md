# Lens C1: hint soundness

Ledger class: `hint-soundness`. You own every hint unit in the ledger.

You exploit values the prover chooses. Every `NewHint` / `RegisterHint` output,
every emulated `Field.NewHint*` output, and every std gadget that is built on
hints in your shard.

## Work plan

1. List every hint site from `inventory.md` (id, function, hint, outputs,
   status). Add hint sites the inventory missed (hints called through
   variables, wrappers or other packages).
2. For each output, write down **exactly what the constraints force**: the set
   of values that satisfy all constraints given the inputs. "Reached" in the
   inventory only means "appears in some constraint".
3. If that set has more than one element and the difference matters
   downstream, you have a candidate. Construct the malicious hint function (the
   `evil` of T-HINT-OVERRIDE) with concrete outputs.
4. Check the std gadgets on the path at the **pinned** gnark version. The
   GHSA-3mvx and GHSA-7fx8 shapes (carries, scales, sub-scalars, remainders,
   points from hints) apply to user code too.
5. For `escapes` sites, follow the outputs into every caller and repeat.

## Hunt for

- recomposition without per-limb range checks (V-H2);
- quotient / remainder without `r < divisor` (V-H3);
- canonical forms that are not enforced (V-H4);
- points from hints not checked on the curve (V-H5, V-H6);
- helpers whose callers assume constrained results (V-H7);
- hints whose outputs are only constrained on one branch of a `Select`.

## Extra output fields

```text
hint_site: H<id> (file:line)
free_outputs: which outputs can vary, and the satisfying alternative values
evil_hint: the malicious outputs as Go, ready for T-HINT-OVERRIDE
```
